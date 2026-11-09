//! Firecracker's sandbox on the host, built without privileges.
//!
//! Firecracker emulates the VM's devices, so a bug in it is the way out of
//! the guest; what an escaped Firecracker can reach is decided here.  It
//! is started in new user, mount, network, IPC, UTS and cgroup namespaces
//! (the user namespace maps only the user's own uid and gid, so nothing
//! needs root and files keep their owner), on a root of its own: an empty
//! tmpfs holding just what it uses - its binary and the system libraries,
//! the kernel, the disk images, the session's runtime directory (the vsock
//! sockets and the config file) and `/dev/kvm` - at the same paths as on
//! the host, read-only except the scratch and cache disks and the runtime
//! directory.  No home directory, no project, no network: the guest's only
//! way out stays the vsock sockets agentcracker serves.  Firecracker's own
//! jailer does the same with root (chroot, setuid); this is that without.
//!
//! With or without the namespaces, Firecracker gets `no_new_privs`, no core
//! dumps (they would hold guest memory) and a bounded number of open files.
//! Where unprivileged user namespaces are not allowed (some distributions
//! restrict them), [`crate::vm::boot`] runs Firecracker without the
//! namespaces and says so.
//!
//! [`Jail::enter`] runs in the child between fork and exec, where only
//! async-signal-safe calls are allowed: everything it needs - paths, mount
//! flags, the uid map - is prepared beforehand by [`Jail::new`], and it
//! only makes system calls.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::util::{Context, Result};

/// Most files Firecracker may have open: it uses a few dozen.
const MAX_FILES: libc::rlim_t = 4096;

/// One step of building the new root, in order.
enum Step {
    /// Create a directory (an existing one is fine).
    Mkdir(CString),
    /// Create an empty file to bind a file onto.
    Touch(CString),
    /// Create a symbolic link: (target, link).
    Symlink(CString, CString),
    /// Bind-mount `src` on `dst`; `ro` is the remount flags that make it
    /// read-only (keeping the flags the source has, which a user namespace
    /// may not drop).
    Bind { src: CString, dst: CString, rec: bool, ro: Option<libc::c_ulong> },
}

/// A prepared sandbox: see the module docs.
pub struct Jail {
    /// The directory the tmpfs root is mounted on (on the host).
    root: CString,
    /// `<uid> <uid> 1` and `<gid> <gid> 1`.
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    steps: Vec<Step>,
}

fn cstr(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).expect("path without NUL")
}

/// The mount flags of the filesystem holding `p` that a bind mount in a
/// user namespace must keep when it is remounted.
fn locked_flags(p: &Path) -> Result<libc::c_ulong> {
    let c = cstr(p);
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error()).ctx(format!("statvfs {}", p.display()));
    }
    let mut f = 0;
    for (st_flag, ms) in [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ] {
        if st.f_flag & st_flag != 0 {
            f |= ms;
        }
    }
    Ok(f)
}

impl Jail {
    /// Prepare a sandbox whose root is mounted on `root` (an empty
    /// directory, made here), exposing `ro` read-only and `rw` writable,
    /// each at its own path, plus the system libraries and `/dev/kvm`.
    /// Entries may be files or directories; a path inside a directory
    /// already exposed is left to that directory.
    pub fn new(root: &Path, ro: &[&Path], rw: &[&Path]) -> Result<Jail> {
        std::fs::create_dir_all(root).ctx(format!("create {}", root.display()))?;
        let mut steps = Vec::new();
        let mut dirs = BTreeSet::new();
        let mut exposed: Vec<PathBuf> = Vec::new();
        let at = |p: &Path| root.join(p.strip_prefix("/").unwrap_or(p));

        // the dynamic loader and libraries (Firecracker is linked against
        // the host's libc): /usr, and /lib and /lib64 as links or binds
        let mut entries: Vec<(PathBuf, bool)> = vec![(PathBuf::from("/usr"), false)];
        for l in ["/lib", "/lib64"] {
            match std::fs::symlink_metadata(l) {
                Ok(m) if m.file_type().is_symlink() => {
                    let target = std::fs::read_link(l)?;
                    steps.push(Step::Symlink(cstr(&target), cstr(&at(Path::new(l)))));
                }
                Ok(m) if m.is_dir() => entries.push((PathBuf::from(l), false)),
                _ => {}
            }
        }
        entries.push((PathBuf::from("/etc/ld.so.cache"), false));
        entries.extend(ro.iter().map(|p| (p.to_path_buf(), false)));
        entries.extend(rw.iter().map(|p| (p.to_path_buf(), true)));
        entries.push((PathBuf::from("/dev/kvm"), true));

        let mut binds = Vec::new();
        for (p, writable) in entries {
            let Ok(m) = std::fs::metadata(&p) else { continue };
            if exposed.iter().any(|d| p.starts_with(d)) {
                continue;
            }
            let dst = at(&p);
            for a in dst.ancestors().skip(1) {
                if a == root {
                    break;
                }
                dirs.insert(a.to_path_buf());
            }
            let ro = if writable { None } else { Some(libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | locked_flags(&p)?) };
            if m.is_dir() {
                exposed.push(p.clone());
                binds.push((Step::Mkdir(cstr(&dst)), Step::Bind { src: cstr(&p), dst: cstr(&dst), rec: true, ro }));
            } else {
                binds.push((Step::Touch(cstr(&dst)), Step::Bind { src: cstr(&p), dst: cstr(&dst), rec: false, ro }));
            }
        }
        // parents before children (a BTreeSet of paths sorts them so)
        let mut all: Vec<Step> = dirs.iter().map(|d| Step::Mkdir(cstr(d))).collect();
        all.append(&mut steps);
        for (mk, b) in binds {
            all.push(mk);
            all.push(b);
        }
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Ok(Jail {
            root: cstr(root),
            uid_map: format!("{uid} {uid} 1").into_bytes(),
            gid_map: format!("{gid} {gid} 1").into_bytes(),
            steps: all,
        })
    }

    /// Enter the sandbox: called in the child, between fork and exec (see
    /// the module docs).  Returns the first error; the caller then fails
    /// the spawn.
    pub fn enter(&self) -> io::Result<()> {
        unsafe {
            let ns = libc::CLONE_NEWUSER
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWCGROUP;
            check(libc::unshare(ns))?;
            write_file(c"/proc/self/setgroups", b"deny")?;
            write_file(c"/proc/self/uid_map", &self.uid_map)?;
            write_file(c"/proc/self/gid_map", &self.gid_map)?;
            // nothing done here may reach the host's mounts
            check(libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()))?;
            check(libc::mount(c"tmpfs".as_ptr(), self.root.as_ptr(), c"tmpfs".as_ptr(), libc::MS_NOSUID, c"mode=0755".as_ptr().cast()))?;
            for s in &self.steps {
                match s {
                    Step::Mkdir(d) => {
                        if libc::mkdir(d.as_ptr(), 0o755) != 0 && *libc::__errno_location() != libc::EEXIST {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    Step::Touch(f) => {
                        let fd = libc::open(f.as_ptr(), libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC, 0o600);
                        check(fd)?;
                        libc::close(fd);
                    }
                    Step::Symlink(target, link) => check(libc::symlink(target.as_ptr(), link.as_ptr()))?,
                    Step::Bind { src, dst, rec, ro } => {
                        let flags = libc::MS_BIND | if *rec { libc::MS_REC } else { 0 };
                        check(libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), flags, std::ptr::null()))?;
                        if let Some(f) = ro {
                            check(libc::mount(std::ptr::null(), dst.as_ptr(), std::ptr::null(), *f, std::ptr::null()))?;
                        }
                    }
                }
            }
            // the tmpfs becomes / and the host's tree is detached
            check(libc::chdir(self.root.as_ptr()))?;
            check(libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) as libc::c_int)?;
            check(libc::umount2(c".".as_ptr(), libc::MNT_DETACH))?;
            check(libc::chdir(c"/".as_ptr()))?;
        }
        Ok(())
    }
}

/// The limits Firecracker runs with, sandboxed or not: no privilege gain
/// on exec, no core dumps, at most [`MAX_FILES`] open files.  Called in the
/// child between fork and exec.
pub fn limit() -> io::Result<()> {
    unsafe {
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        check(libc::setrlimit(libc::RLIMIT_CORE, &none))?;
        let mut cur: libc::rlimit = std::mem::zeroed();
        check(libc::getrlimit(libc::RLIMIT_NOFILE, &mut cur))?;
        let n = MAX_FILES.min(cur.rlim_max);
        check(libc::setrlimit(libc::RLIMIT_NOFILE, &libc::rlimit { rlim_cur: n, rlim_max: n }))?;
    }
    Ok(())
}

fn check(r: libc::c_int) -> io::Result<()> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Write `data` to the file `path` (one write, as `/proc` maps need).
unsafe fn write_file(path: &std::ffi::CStr, data: &[u8]) -> io::Result<()> {
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        check(fd)?;
        let n = libc::write(fd, data.as_ptr().cast(), data.len());
        libc::close(fd);
        if n != data.len() as isize {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
