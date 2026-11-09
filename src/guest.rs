//! acinit: PID 1 inside the microVM.
//!
//! The kernel boots with the base image as a read-only EROFS root and runs
//! `/acinit` - this same program, statically linked.  It then:
//!
//! 1. mounts /proc, /sys and /dev (with pts and shm), dials the host over
//!    vsock (retrying for up to 5 s) and reads the [`GuestConfig`];
//! 2. sets the clock and hostname, mounts the scratch disk (ext4, the only
//!    writable device) at /scratch and the read-only images under /lower;
//! 3. assembles the new root at /newroot from overlays whose upper and work
//!    directories live on the scratch disk:
//!
//!    ```text
//!    /newroot           base image   + /scratch/root/upper
//!    /newroot/usr       usr.img      + /scratch/usr/upper
//!    /newroot/<tool>    tools.img    + /scratch/tools/<i>/upper   (each root)
//!    /newroot/<cwd>     lower.img    + /scratch/proj/upper
//!    ```
//!
//!    so the guest looks like the host - same paths, same tools - while
//!    every write lands on scratch.  Overlay features that would complicate
//!    exporting the upper layer (redirect_dir, metacopy, index, xino) are
//!    off;
//! 4. mounts proc, sysfs, cgroup2, /dev and /run inside the new root, brings
//!    up loopback, unpacks the home seed into the user's home and, with
//!    networking enabled, starts the loopback proxy that relays to the host;
//! 5. runs the command as the invoking user, chrooted into /newroot, on a
//!    pty (or pipes, when the host side is not a terminal), relaying its I/O
//!    to the host;
//! 6. when the command exits: lets output drain, kills everything else,
//!    syncs, sends EXIT, exports the project's upper layer and the agent
//!    state paths as file streams, sends DONE and powers off (with
//!    `reboot=k`, Firecracker exits when the guest resets).
//!
//! The scratch disk persists with the session, so a resumed session finds
//! its overlays and home as it left them.  Any failure is reported to the
//! host as an ERROR frame before powering off.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

use crate::proto::*;
use crate::util::{Context, Result, cstr, last_os_error};

/// Where the guest's real root is assembled; the command is chrooted into it.
const NEWROOT: &str = "/newroot";
/// The control connection, set once connected, so [`main`] can report a
/// failure to the host.
static CTRL: OnceLock<Arc<Mutex<UnixStream>>> = OnceLock::new();

/// acinit's entry point, called from the crate's `main` when running as
/// PID 1.
///
/// Runs setup and the command ([`run`]).  On error, prints it to the
/// console and sends it to the host as an ERROR frame (if connected by
/// then).  Always ends by powering off; never returns.
pub fn main() -> ! {
    if let Err(e) = run() {
        eprintln!("acinit: {e}");
        if let Some(c) = CTRL.get() {
            if let Ok(mut c) = c.lock() {
                let _ = write_frame(&mut *c, M_ERROR, e.0.as_bytes());
            }
        }
    }
    poweroff()
}

/// Sync filesystems and reset the VM.  With `reboot=k` on the kernel
/// command line, Firecracker treats the reset as "VM stopped" and exits.
/// Never returns (it sleeps forever should the reboot call fail).
fn poweroff() -> ! {
    unsafe {
        libc::sync();
        // with reboot=k Firecracker treats the reset as "VM stopped" and exits
        libc::reboot(libc::RB_AUTOBOOT);
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Thin wrapper around `mount(2)`.
///
/// `src`, `tgt`: source and mount point; `fstype`: filesystem type, empty
/// for bind mounts; `flags`: `MS_*` flags; `data`: comma-separated options,
/// empty for none.  Returns an error naming all of them on failure.
fn mount(src: &str, tgt: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> Result<()> {
    let (s, t, f, d) = (cstr(src), cstr(tgt), cstr(fstype), cstr(data));
    let r = unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            if fstype.is_empty() { std::ptr::null() } else { f.as_ptr() },
            flags,
            if data.is_empty() { std::ptr::null() } else { d.as_ptr().cast() },
        )
    };
    if r != 0 {
        return last_os_error(format!("mount {src} on {tgt} ({fstype} {data})"));
    }
    Ok(())
}

/// `mkdir -p p` (root-owned, default mode).  Returns an error naming the
/// path on failure.
fn mkdirs(p: &str) -> Result<()> {
    std::fs::create_dir_all(p).ctx(format!("mkdir {p}"))
}

/// Escape `\`, `,` and `:` in path `p` for overlayfs mount options, where
/// they separate options and layers.  Returns the escaped path.
fn ovl_escape(p: &str) -> String {
    p.replace('\\', "\\\\").replace(',', "\\,").replace(':', "\\:")
}

/// Mount an overlay at `target`: `lower` as the read-only layer, with the
/// upper and work directories at `/scratch/<scratch_name>/{upper,work}`.
///
/// When the upper directory does not exist yet (the session's first boot)
/// it is created with the owner and mode of `lower`, because the overlay
/// root takes its attributes from the upper directory.  On later boots the
/// existing upper layer is reused, which is how `resume` sees earlier
/// changes.
///
/// Returns an error if the directories cannot be created or the mount fails.
fn overlay(lower: &str, scratch_name: &str, target: &str) -> Result<()> {
    overlay_layers(&[lower], scratch_name, target)
}

/// [`overlay`] with several read-only layers, topmost first.
fn overlay_layers(lowers: &[&str], scratch_name: &str, target: &str) -> Result<()> {
    let lower = lowers[0];
    let up = format!("/scratch/{scratch_name}/upper");
    let wk = format!("/scratch/{scratch_name}/work");
    let fresh = !Path::new(&up).exists();
    mkdirs(&up)?;
    mkdirs(&wk)?;
    if fresh {
        // the overlay root takes its owner and mode from the upper dir
        if let Ok(md) = std::fs::metadata(lower) {
            let c = cstr(&up);
            unsafe {
                libc::chown(c.as_ptr(), md.uid(), md.gid());
                libc::chmod(c.as_ptr(), md.mode() & 0o7777);
            }
        }
    }
    mount(
        "overlay",
        target,
        "overlay",
        0,
        &format!(
            "lowerdir={},upperdir={},workdir={},redirect_dir=off,metacopy=off,index=off,xino=off",
            lowers.iter().map(|l| ovl_escape(l)).collect::<Vec<_>>().join(":"),
            ovl_escape(&up),
            ovl_escape(&wk)
        ),
    )
}

/// Open a stream connection to vsock port `port` on the host (CID 2).
///
/// Returns it wrapped in a `UnixStream`: only the generic socket calls
/// (read, write, shutdown) are used on it, and those work on any socket.
/// Errors if the socket cannot be created or nothing listens on the host
/// yet.
fn vsock_connect(port: u32) -> io::Result<UnixStream> {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_HOST;
        addr.svm_port = port;
        let r = libc::connect(
            fd,
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        if r != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        // read/write/shutdown are generic socket ops; UnixStream is just a handy wrapper
        Ok(UnixStream::from_raw_fd(fd))
    }
}

/// `mkdir -p` of `rel` below `root`, giving the directories it creates to
/// `uid`:`gid` (their mode comes from the umask).  Existing components,
/// including symlinks, are left alone.
///
/// Returns an error if a directory cannot be created.
fn mkdirs_owned(root: &Path, rel: &Path, uid: u32, gid: u32) -> Result<()> {
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        if std::fs::symlink_metadata(&cur).is_err() {
            std::fs::create_dir(&cur).ctx(format!("mkdir {}", cur.display()))?;
            let c = cstr(cur.as_os_str());
            unsafe { libc::lchown(c.as_ptr(), uid, gid) };
        }
    }
    Ok(())
}

/// `mkdir -p` of `rel` below `root`, where each directory created copies the
/// owner and mode the host reported for the same path (so, for example,
/// `/tmp/claude-1000` stays the user's).
///
/// `dirs`: the `(host path, uid, gid, mode)` list from the host; directories
/// it does not mention are created root-owned with mode 0755.  Existing
/// components are left alone.  Returns an error if a directory cannot be
/// created.
fn mkdirs_mirror(root: &Path, rel: &Path, dirs: &[(String, u32, u32, u32)]) -> Result<()> {
    let mut cur = root.to_path_buf();
    let mut host = PathBuf::from("/");
    for c in rel.components() {
        cur.push(c);
        host.push(c);
        if std::fs::symlink_metadata(&cur).is_err() {
            std::fs::create_dir(&cur).ctx(format!("mkdir {}", cur.display()))?;
            let (uid, gid, mode) = dirs
                .iter()
                .find(|d| Path::new(&d.0) == host)
                .map(|d| (d.1, d.2, d.3))
                .unwrap_or((0, 0, 0o755));
            let c = cstr(cur.as_os_str());
            unsafe {
                libc::lchown(c.as_ptr(), uid, gid);
                libc::chmod(c.as_ptr(), mode & 0o7777);
            }
        }
    }
    Ok(())
}

/// Bring the loopback interface up, so the guest proxy on 127.0.0.1 and any
/// local servers work.  There is no other network interface.  Failures are
/// ignored.
fn lo_up() {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return;
        }
        let mut ifr = [0u8; 40];
        ifr[..2].copy_from_slice(b"lo");
        if libc::ioctl(s, libc::SIOCGIFFLAGS, ifr.as_mut_ptr()) == 0 {
            let mut flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
            flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
            ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
            libc::ioctl(s, libc::SIOCSIFFLAGS, ifr.as_mut_ptr());
        }
        libc::close(s);
    }
}

/// Set the realtime clock to `t` (Unix seconds, from the host) if it is off
/// by more than 2 seconds.  A wrong clock breaks TLS certificate checks and
/// the timestamp comparisons of build tools.
fn set_clock(t: u64) {
    unsafe {
        let mut now: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut now);
        if (now.tv_sec - t as libc::time_t).abs() > 2 {
            let ts = libc::timespec { tv_sec: t as libc::time_t, tv_nsec: 0 };
            libc::clock_settime(libc::CLOCK_REALTIME, &ts);
        }
    }
}

/// Relay bytes both ways between `a` (the vsock connection to the host
/// proxy) and `b` (the local client) until both directions are done,
/// half-closing each direction when its source reaches EOF.  Blocks until
/// finished; errors simply end the relay.
fn splice(a: UnixStream, b: std::net::TcpStream) {
    let (Ok(a2), Ok(b2)) = (a.try_clone(), b.try_clone()) else { return };
    let t = std::thread::spawn(move || {
        let (mut a2, mut b2) = (a2, b2);
        let _ = io::copy(&mut a2, &mut b2);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    let (mut a, mut b) = (a, b);
    let _ = io::copy(&mut b, &mut a);
    let _ = a.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
}

/// Start the guest side of the egress proxy: a listener on
/// [`GUEST_PROXY_ADDR`], which `HTTPS_PROXY` points at.
///
/// Each accepted connection gets a new vsock connection to [`PORT_PROXY`]
/// and is spliced to it byte for byte; the host end parses the CONNECT
/// request and applies the allowlist.  Returns immediately: the listener
/// and relays run on their own threads.  If the port cannot be bound, logs
/// to the console and returns.
fn start_proxy() {
    let Ok(l) = std::net::TcpListener::bind(GUEST_PROXY_ADDR) else {
        eprintln!("acinit: cannot bind proxy port");
        return;
    };
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            std::thread::spawn(move || {
                if let Ok(v) = vsock_connect(PORT_PROXY) {
                    splice(v, c);
                }
            });
        }
    });
}

/// Unpack the home seed stream at `stream_path` into `home`.
///
/// Directories are created (or kept) with the stream's permission bits;
/// files and symlinks replace whatever is at their path; deletions remove
/// files; missing parent directories are created.  Everything is then owned
/// by `uid`:`gid`, since the stream carries no owners.  Paths are
/// validated by the stream reader; the seed comes from the host, so this is
/// not a security boundary.
///
/// Returns an error on a malformed stream or a failed filesystem operation.
fn extract_seed(stream_path: &Path, home: &Path, uid: u32, gid: u32) -> Result<()> {
    let f = std::fs::File::open(stream_path)?;
    let mut r = StreamReader::new(io::BufReader::new(f));
    while let Some(e) = r.next()? {
        let rel = PathBuf::from(std::ffi::OsStr::from_bytes(e.path()));
        let dst = home.join(&rel);
        if let Some(parent) = rel.parent() {
            mkdirs_owned(home, parent, uid, gid)?;
        }
        match &e {
            Entry::Dir { mode, .. } | Entry::Opaque { mode, .. } => {
                if !dst.is_dir() {
                    let _ = std::fs::remove_file(&dst);
                    std::fs::create_dir(&dst)?;
                }
                std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(*mode & 0o777))?;
            }
            Entry::File { mode, .. } => {
                let _ = std::fs::remove_file(&dst);
                let mut out = std::fs::File::create(&dst)?;
                r.data_to(&mut out)?;
                out.set_permissions(std::fs::Permissions::from_mode(*mode & 0o777))?;
            }
            Entry::Symlink { target, .. } => {
                let _ = std::fs::remove_file(&dst);
                std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(target), &dst)?;
            }
            Entry::Delete { .. } => {
                let _ = std::fs::remove_file(&dst);
            }
        }
        let c = cstr(dst.as_os_str());
        unsafe { libc::lchown(c.as_ptr(), uid, gid) };
    }
    Ok(())
}

/// Export the overlay upper directory `root`, from its subdirectory `rel`
/// down, as a file stream, entries in sorted order.
///
/// Each upper-layer entry maps to one record: overlay whiteouts (character
/// devices 0:0) become deletions; directories marked opaque
/// (`trusted.overlay.opaque=y`: removed and recreated) become opaque
/// records, other directories plain ones; regular files and symlinks are
/// sent with their contents.  Anything else (FIFOs, sockets, real devices)
/// is dropped.  With metacopy off, every file in the upper layer is there in
/// full - including files only copied up by a chmod or touch; the host
/// filters out those that did not really change.
///
/// `sw`: the output stream; `root`: the upper directory; `rel`: the
/// current subdirectory relative to `root` (empty at the top).  Returns an
/// error if the stream cannot be written or a symlink cannot be read.
fn export_upper<W: Write>(sw: &mut StreamWriter<W>, root: &Path, rel: &[u8]) -> Result<()> {
    let dir = if rel.is_empty() { root.to_path_buf() } else { root.join(std::ffi::OsStr::from_bytes(rel)) };
    let mut names: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.file_name()).collect(),
        Err(_) => return Ok(()),
    };
    names.sort();
    for n in names {
        let mut p = rel.to_vec();
        if !p.is_empty() {
            p.push(b'/');
        }
        p.extend_from_slice(n.as_bytes());
        let full = dir.join(&n);
        let Ok(md) = std::fs::symlink_metadata(&full) else { continue };
        let ft = md.mode() & libc::S_IFMT;
        match ft {
            libc::S_IFCHR if md.rdev() == 0 => sw.delete(&p)?,
            libc::S_IFDIR => {
                let mut buf = [0u8; 8];
                let c = cstr(full.as_os_str());
                let name = CString::new("trusted.overlay.opaque").unwrap();
                let n = unsafe { libc::lgetxattr(c.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
                if n == 1 && buf[0] == b'y' {
                    sw.opaque(&p, md.mode())?;
                } else {
                    sw.dir(&p, md.mode())?;
                }
                export_upper(sw, root, &p)?;
            }
            libc::S_IFREG => {
                if let Ok(mut f) = std::fs::File::open(&full) {
                    sw.file(&p, md.mode(), md.len(), &mut f)?;
                }
            }
            libc::S_IFLNK => {
                let t = std::fs::read_link(&full)?;
                sw.symlink(&p, t.as_os_str().as_bytes())?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// The running command: its pid, and the parent's ends of its standard
/// streams.
/// Is any process other than acinit itself still alive?  Kernel threads
/// (empty cmdline) and zombies (already exited) do not count.
fn user_processes_left() -> bool {
    let me = std::process::id().to_string();
    let Ok(rd) = std::fs::read_dir("/proc") else { return false };
    rd.filter_map(|e| e.ok()).any(|e| {
        let n = e.file_name();
        let n = n.to_string_lossy();
        if !n.bytes().all(|b| b.is_ascii_digit()) || n == me {
            return false;
        }
        let stat = std::fs::read_to_string(e.path().join("stat")).unwrap_or_default();
        let zombie = stat.rsplit(')').next().is_some_and(|r| r.trim_start().starts_with('Z'));
        !zombie && std::fs::metadata(e.path().join("cmdline")).is_ok() && std::fs::read(e.path().join("cmdline")).is_ok_and(|c| !c.is_empty())
    })
}

struct Child {
    /// Process id; also its process group and session id, after `setsid`.
    pid: libc::pid_t,
    /// write end of the command's stdin (the pty master when on a tty)
    input: RawFd,
    /// read end of the command's stdout (the pty master when on a tty)
    output: RawFd,
    /// read end of the command's stderr; None on a tty (it shares the pty)
    errors: Option<RawFd>,
}

/// Create a close-on-exec pipe.  Returns `(read end, write end)`.
fn pipe() -> Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return last_os_error("pipe2");
    }
    Ok((fds[0], fds[1]))
}

/// Start the command described by `cfg` in the new root.
///
/// On a host terminal the command gets a pty of its own, sized like the
/// host window, as its controlling terminal; otherwise plain pipes, so it
/// sees what it would see on the host (`git log | cat` does not page, `ls`
/// prints one name per line, stderr stays separate).
///
/// The child starts a new session, clears its signal mask, restores the
/// default SIGPIPE disposition, chroots into [`NEWROOT`], changes to the
/// project directory (falling back to `/`), switches to the user's uid and
/// gid (its only supplementary group being the primary group) and executes
/// `cmd[0]`, trying each `$PATH` entry in turn unless the name contains a
/// `/`.  Everything is prepared before `fork`, so the child does not
/// allocate.  Exit status 126 means the chroot or the user switch failed;
/// 127 means the command was not found.
///
/// Returns the child's pid and the parent's ends of its streams; errors if
/// the pty, the pipes or the fork cannot be created.
fn spawn(cfg: &GuestConfig) -> Result<Child> {
    let ws = libc::winsize { ws_row: cfg.rows.max(1), ws_col: cfg.cols.max(1), ws_xpixel: 0, ws_ypixel: 0 };
    // On a host terminal the command gets a pty of its own; otherwise plain
    // pipes, so it sees what it would see on the host (`git log | cat` does
    // not page, `ls` prints one name per line, stderr stays separate).
    // fds: [stdin, stdout, stderr] for the child, then the parent's ends.
    let (child_fds, input, output, errors) = if cfg.tty {
        let (mut master, mut slave) = (0, 0);
        if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &ws) } != 0 {
            return last_os_error("openpty");
        }
        unsafe { libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC) };
        unsafe { libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC) };
        ([slave, slave, slave], master, master, None)
    } else {
        let (in_r, in_w) = pipe()?;
        let (out_r, out_w) = pipe()?;
        let (err_r, err_w) = pipe()?;
        ([in_r, out_w, err_w], in_w, out_r, Some(err_r))
    };
    let tty = cfg.tty;
    // everything the child needs, prepared before fork (no allocation after)
    let root = cstr(NEWROOT);
    let cwd = cstr(&cfg.cwd);
    let slash = cstr("/");
    let argv_c: Vec<CString> = cfg.cmd.iter().map(cstr).collect();
    let mut argv: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());
    let env_c: Vec<CString> = cfg.env.iter().map(|(k, v)| cstr(format!("{k}={v}"))).collect();
    let mut envp: Vec<*const libc::c_char> = env_c.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());
    let prog = &cfg.cmd[0];
    let cands: Vec<CString> = if prog.contains('/') {
        vec![cstr(prog)]
    } else {
        cfg.path.split(':').filter(|d| !d.is_empty()).map(|d| cstr(format!("{d}/{prog}"))).collect()
    };
    let notfound = format!("agentcracker: {prog}: command not found in the guest{}", if cfg.tty { "\r\n" } else { "\n" });
    let gid = cfg.gid;
    let uid = cfg.uid;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return last_os_error("fork");
    }
    if pid == 0 {
        unsafe {
            libc::setsid();
            if tty {
                libc::ioctl(child_fds[0], libc::TIOCSCTTY, 0);
            }
            // dup2 clears close-on-exec on the copies; every other fd here
            // is close-on-exec
            for (i, &fd) in child_fds.iter().enumerate() {
                libc::dup2(fd, i as RawFd);
            }
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            if libc::chroot(root.as_ptr()) != 0 {
                libc::_exit(126);
            }
            if libc::chdir(cwd.as_ptr()) != 0 {
                libc::chdir(slash.as_ptr());
            }
            let groups = [gid];
            libc::setgroups(1, groups.as_ptr());
            if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                libc::_exit(126);
            }
            for c in &cands {
                libc::execve(c.as_ptr(), argv.as_ptr(), envp.as_ptr());
            }
            libc::write(2, notfound.as_ptr().cast(), notfound.len());
            libc::_exit(127);
        }
    }
    let mut closed = vec![];
    for fd in child_fds {
        if !closed.contains(&fd) {
            unsafe { libc::close(fd) };
            closed.push(fd);
        }
    }
    Ok(Child { pid, input, output, errors })
}

/// The body of acinit (see the module docs for the sequence); on return
/// [`main`] powers off.
///
/// The command's output is relayed by one thread per stream, and input and
/// resize frames from the host by another, while this thread reaps every
/// process (as PID 1 must) until the command itself exits.  Then trailing
/// output gets up to 0.5 s to drain, all remaining processes get SIGTERM
/// and, 0.2 s later, SIGKILL, and output gets another 0.5 s.  If the
/// connection to the host is lost, the command's process group gets SIGHUP.
///
/// The exit code sent to the host is the command's exit status, or 128 +
/// the signal number if a signal killed it.
///
/// Returns `Ok(())` once DONE has been sent; an error for any failed setup
/// step or protocol violation.
/// Send everything read from `fd` to the host as frames of type `kind`
/// (in a new thread), then signal `done`.
fn stream_output(fd: RawFd, kind: u8, wr: Arc<Mutex<UnixStream>>, done: mpsc::Sender<()>) {
    std::thread::spawn(move || {
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = vec![0u8; 32768];
        loop {
            match f.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if write_frame(&mut *wr.lock().unwrap(), kind, &buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        std::mem::forget(f); // fd closed at poweroff
        let _ = done.send(());
    });
}

/// Feed frames from the host to a command: input, end of input, terminal
/// size, and STOP (SIGTERM to its process group, SIGKILL 5 s later).  When
/// the host goes away the command's process group gets SIGHUP.
///
/// `input`: the command's stdin (the pty master when `tty`); `cpid`: the
/// command, which leads its own process group.
fn pump_input(mut rd: UnixStream, input: RawFd, tty: bool, cpid: libc::pid_t, host_gone: Option<mpsc::Sender<()>>) {
    let mut last = b'\n';
    let mut input_closed = false;
    let mut stopping = false;
    loop {
        let Ok((t, d)) = read_frame(&mut rd) else {
            // host went away: end the command
            unsafe { libc::kill(-cpid, libc::SIGHUP) };
            if let Some(tx) = host_gone {
                let _ = tx.send(());
            }
            break;
        };
        match t {
            M_STDIN if !input_closed => {
                if let Some(&l) = d.last() {
                    last = l;
                }
                let _ = write_all_fd(input, &d);
            }
            M_STDIN_EOF if tty => {
                let eof: &[u8] = if last == b'\n' { b"\x04" } else { b"\x04\x04" };
                let _ = write_all_fd(input, eof);
            }
            M_STDIN_EOF if !input_closed => {
                unsafe { libc::close(input) };
                input_closed = true;
            }
            M_RESIZE if d.len() == 4 => {
                let ws = libc::winsize {
                    ws_row: u16::from_be_bytes([d[0], d[1]]),
                    ws_col: u16::from_be_bytes([d[2], d[3]]),
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                if tty {
                    unsafe { libc::ioctl(input, libc::TIOCSWINSZ, &ws) };
                }
            }
            M_STOP if !stopping => {
                stopping = true;
                unsafe { libc::kill(-cpid, libc::SIGTERM) };
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(5));
                    unsafe { libc::kill(-cpid, libc::SIGKILL) };
                });
            }
            _ => {}
        }
    }
}

/// Exit statuses of processes other than the session's command, as reaped
/// by the main loop, for [`run_exec`] to collect.
fn reaped() -> &'static (Mutex<std::collections::HashMap<libc::pid_t, i32>>, std::sync::Condvar) {
    static R: OnceLock<(Mutex<std::collections::HashMap<libc::pid_t, i32>>, std::sync::Condvar)> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Record that `pid` exited with wait status `status`.
fn record_exit(pid: libc::pid_t, status: i32) {
    let (m, cv) = reaped();
    let mut g = m.lock().unwrap();
    if g.len() > 4096 {
        g.clear(); // orphans nobody waits for; never grow without bound
    }
    g.insert(pid, status);
    cv.notify_all();
}

/// Wait for `pid`'s exit status, as recorded by [`record_exit`].
fn wait_exit(pid: libc::pid_t) -> i32 {
    let (m, cv) = reaped();
    let mut g = m.lock().unwrap();
    loop {
        if let Some(st) = g.remove(&pid) {
            return st;
        }
        g = cv.wait(g).unwrap();
    }
}

/// Exit code for a wait status: the exit status, or 128 + signal.
fn exit_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// Accept connections from the host on [`PORT_EXEC`] and run each one's
/// command in this session (see [`run_exec`]).  Connections from anywhere
/// but the host (CID 2) are dropped.
fn exec_server(cfg: GuestConfig) {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return;
    }
    unsafe {
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = PORT_EXEC;
        let len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        if libc::bind(fd, (&addr as *const libc::sockaddr_vm).cast(), len) != 0 || libc::listen(fd, 8) != 0 {
            libc::close(fd);
            return;
        }
    }
    loop {
        let mut peer: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        let c = unsafe { libc::accept4(fd, (&mut peer as *mut libc::sockaddr_vm).cast(), &mut len, libc::SOCK_CLOEXEC) };
        if c < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return;
        }
        let conn = unsafe { UnixStream::from_raw_fd(c) };
        if peer.svm_cid != libc::VMADDR_CID_HOST {
            continue; // dropped: only the host may start commands
        }
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let _ = run_exec(conn, cfg);
        });
    }
}

/// Run one [`ExecRequest`] arriving on `conn`: start the command like the
/// session's own (same root, user, environment, directory), relay its
/// input and output, and send its exit status.
fn run_exec(conn: UnixStream, mut cfg: GuestConfig) -> Result<()> {
    let mut rd = conn.try_clone()?;
    let wr = Arc::new(Mutex::new(conn));
    let (t, d) = read_frame(&mut rd)?;
    if t != M_EXEC {
        crate::bail!("expected an exec request");
    }
    let req: ExecRequest = serde_json::from_slice(&d)?;
    if req.cmd.is_empty() {
        crate::bail!("empty command");
    }
    cfg.cmd = req.cmd;
    cfg.tty = req.tty;
    cfg.rows = req.rows;
    cfg.cols = req.cols;
    if let Some(term) = req.term {
        cfg.env.retain(|(k, _)| k != "TERM");
        cfg.env.push(("TERM".into(), term));
    }
    let child = match spawn(&cfg) {
        Ok(c) => c,
        Err(e) => {
            let _ = write_frame(&mut *wr.lock().unwrap(), M_ERROR, e.0.as_bytes());
            return Err(e);
        }
    };
    write_frame(&mut *wr.lock().unwrap(), M_READY, &[])?;
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let mut n = 1;
    stream_output(child.output, M_STDOUT, wr.clone(), done_tx.clone());
    if let Some(e) = child.errors {
        stream_output(e, M_STDERR, wr.clone(), done_tx.clone());
        n += 1;
    }
    drop(done_tx);
    let (cpid, input, tty) = (child.pid, child.input, cfg.tty);
    std::thread::spawn(move || pump_input(rd, input, tty, cpid, None));
    let code = exit_code(wait_exit(child.pid));
    let end = std::time::Instant::now() + Duration::from_millis(500);
    for _ in 0..n {
        if done_rx.recv_timeout(end.saturating_duration_since(std::time::Instant::now())).is_err() {
            break;
        }
    }
    let mut w = wr.lock().unwrap();
    write_frame(&mut *w, M_EXIT, &code.to_be_bytes())?;
    let _ = w.shutdown(std::net::Shutdown::Both);
    // the child's fds are left open: the relay threads may still hold them
    // (a pty's input and output are one fd), and closing under them could
    // hit a reused descriptor; a few fds per extra shell are harmless
    Ok(())
}

fn run() -> Result<()> {
    let _ = std::fs::create_dir_all("/dev");
    let _ = mount("proc", "/proc", "proc", 0, "");
    let _ = mount("sysfs", "/sys", "sysfs", 0, "");
    let _ = mount("devtmpfs", "/dev", "devtmpfs", 0, "");
    let _ = std::fs::create_dir_all("/dev/pts");
    let _ = mount("devpts", "/dev/pts", "devpts", 0, "mode=620,ptmxmode=666");
    let _ = std::fs::create_dir_all("/dev/shm");
    let _ = mount("tmpfs", "/dev/shm", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, "mode=1777");

    // dial the host
    let mut ctrl = None;
    for _ in 0..100 {
        match vsock_connect(PORT_CONTROL) {
            Ok(s) => {
                ctrl = Some(s);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let ctrl = ctrl.ctx("cannot reach the host over vsock")?;
    let mut rd = ctrl.try_clone()?;
    let wr = Arc::new(Mutex::new(ctrl));
    let _ = CTRL.set(wr.clone());

    let (t, data) = read_frame(&mut rd)?;
    if t != M_CONFIG {
        crate::bail!("expected config, got frame {t}");
    }
    let cfg: GuestConfig = serde_json::from_slice(&data)?;
    set_clock(cfg.time);
    let hn = b"agentcracker";
    unsafe { libc::sethostname(hn.as_ptr().cast(), hn.len()) };

    // KVM, for acrboot's test VMs: the user's with `boot = true`, nobody's
    // otherwise (devtmpfs makes it root's, 0600, and nothing here runs as
    // root after this)
    if cfg.boot {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions("/dev/kvm", PermissionsExt::from_mode(0o666));
        // the base and /usr images, read-only, for `acrboot --run` (the
        // user can read every file on them anyway)
        for dev in [crate::acrboot::DEV_BASE, cfg.dev_usr.as_str()] {
            let _ = std::fs::set_permissions(dev, PermissionsExt::from_mode(0o644));
        }
    } else {
        let _ = std::fs::remove_file("/dev/kvm");
    }

    // disks
    // the scratch image is a fresh sparse file whose inode tables already
    // read as zeroes: don't let ext4lazyinit write ~1G of zeroes into it
    mount(&cfg.dev_scratch, "/scratch", "ext4", libc::MS_NOATIME, "noinit_itable")?;
    mount(&cfg.dev_usr, "/lower/usr", "erofs", libc::MS_RDONLY, "")?;
    mount(&cfg.dev_tools, "/lower/tools", "erofs", libc::MS_RDONLY, "")?;
    mount(&cfg.dev_lower, "/lower/proj", "erofs", libc::MS_RDONLY, "")?;
    if let Some(d) = &cfg.dev_lower_delta {
        mount(d, "/lower/projdelta", "erofs", libc::MS_RDONLY, "")?;
    }
    mount("/", "/lower/base", "", libc::MS_BIND, "")?;

    // the new root: base + writable layer, then /usr, toolchains, project
    overlay("/lower/base", "root", NEWROOT)?;
    overlay("/lower/usr", "usr", &format!("{NEWROOT}/usr"))?;
    // acinit is also the acrboot command (it says so if booting is off)
    let _ = std::os::unix::fs::symlink("/acinit", format!("{NEWROOT}/usr/bin/acrboot"));
    let nr = Path::new(NEWROOT);
    let home_rel = Path::new(&cfg.home).strip_prefix("/").unwrap_or(Path::new(""));
    mkdirs_owned(nr, home_rel, 0, 0)?;
    let home = nr.join(home_rel);
    {
        let c = cstr(home.as_os_str());
        unsafe { libc::chown(c.as_ptr(), cfg.uid, cfg.gid) };
    }
    if let Some(dev) = &cfg.dev_cache {
        // a previous guest wrote this disk: if it will not mount, the
        // session goes on without it rather than failing
        if let Err(e) = mount_cache(dev, &home, cfg.uid, cfg.gid) {
            eprintln!("acinit: build cache not mounted: {e}");
        }
    }
    for (i, t) in cfg.tools.iter().enumerate() {
        let rel = Path::new(t).strip_prefix("/").unwrap_or(Path::new(t));
        let lower = Path::new("/lower/tools").join(rel);
        if !lower.is_dir() {
            continue;
        }
        mkdirs_mirror(nr, rel, &cfg.dirs)?;
        overlay(&lower.to_string_lossy(), &format!("tools/{i}"), &nr.join(rel).to_string_lossy())?;
    }
    let cwd_rel = Path::new(&cfg.cwd).strip_prefix("/").unwrap_or(Path::new(""));
    mkdirs_mirror(nr, cwd_rel, &cfg.dirs)?;
    let proj_layers: &[&str] = if cfg.dev_lower_delta.is_some() { &["/lower/projdelta", "/lower/proj"] } else { &["/lower/proj"] };
    overlay_layers(proj_layers, "proj", &nr.join(cwd_rel).to_string_lossy())?;

    // pseudo filesystems inside the new root
    mount("proc", &format!("{NEWROOT}/proc"), "proc", 0, "")?;
    mount("sysfs", &format!("{NEWROOT}/sys"), "sysfs", 0, "")?;
    let _ = mount("cgroup2", &format!("{NEWROOT}/sys/fs/cgroup"), "cgroup2", 0, "");
    mount("/dev", &format!("{NEWROOT}/dev"), "", libc::MS_BIND | libc::MS_REC, "")?;
    mount("tmpfs", &format!("{NEWROOT}/run"), "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, "mode=755")?;

    lo_up();

    // home seed (agent config + credentials)
    let seed = Path::new("/scratch/seed.stream");
    {
        let mut f = std::fs::File::create(seed)?;
        loop {
            let (t, d) = read_frame(&mut rd)?;
            match t {
                M_SEED => f.write_all(&d)?,
                M_SEED_END => break,
                _ => crate::bail!("unexpected frame {t} during seed"),
            }
        }
    }
    extract_seed(seed, &home, cfg.uid, cfg.gid).ctx("seeding $HOME")?;
    // (never fatal: the session is still useful without them)
    if let Err(e) = write_agent_files(&home, &cfg.agent_files, cfg.uid, cfg.gid) {
        eprintln!("acinit: agent guidance not written: {e}");
    }
    if let Some((name, commit)) = &cfg.git_branch {
        if let Err(e) = start_branch(&nr.join(cwd_rel), name, commit, cfg.uid, cfg.gid) {
            eprintln!("acinit: branch {name} not created: {e}");
        }
    }
    let _ = std::fs::remove_file(seed);

    if cfg.net {
        start_proxy();
    }

    let child = spawn(&cfg)?;
    write_frame(&mut *wr.lock().unwrap(), M_READY, &[])?;

    // command output -> host (stdout, plus stderr when it has its own pipe)
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let mut streams = vec![(child.output, M_STDOUT)];
    if let Some(e) = child.errors {
        streams.push((e, M_STDERR));
    }
    let n_streams = streams.len();
    for (fd, kind) in streams {
        stream_output(fd, kind, wr.clone(), done_tx.clone());
    }
    drop(done_tx);
    // wait (up to `t` in total) for every output stream to reach EOF
    let mut drained = 0;
    let mut drain = move |t: Duration| {
        let end = std::time::Instant::now() + t;
        while drained < n_streams {
            let left = end.saturating_duration_since(std::time::Instant::now());
            if done_rx.recv_timeout(left).is_err() {
                break;
            }
            drained += 1;
        }
    };

    // host -> command input
    let (cpid, input, tty) = (child.pid, child.input, cfg.tty);
    let (gone_tx, gone_rx) = mpsc::channel();
    std::thread::spawn(move || pump_input(rd, input, tty, cpid, Some(gone_tx)));

    // extra commands in this running session (`agentcracker shell`)
    {
        let cfg = cfg.clone();
        std::thread::spawn(move || exec_server(cfg));
    }

    // reap everything; stop when the command itself exits
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(-1, &mut status, 0) };
        if r == child.pid {
            break;
        }
        if r > 0 {
            record_exit(r, status);
        }
        if r < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
    let code = exit_code(status);
    // let trailing output drain, then stop stragglers (background jobs)
    drain(Duration::from_millis(500));
    unsafe { libc::kill(-1, libc::SIGTERM) };
    // give them up to 200ms to go, but don't wait when nothing is left
    let end = std::time::Instant::now() + Duration::from_millis(200);
    while user_processes_left() && std::time::Instant::now() < end {
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
        std::thread::sleep(Duration::from_millis(5));
    }
    unsafe { libc::kill(-1, libc::SIGKILL) };
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
    drain(Duration::from_millis(500));
    unsafe { libc::sync() };

    let mut w = wr.lock().unwrap();
    write_frame(&mut *w, M_EXIT, &code.to_be_bytes())?;
    {
        let fw = FrameWriter::new(&mut *w, M_EXPORT, M_EXPORT_END);
        let mut sw = StreamWriter::new(io::BufWriter::with_capacity(1 << 20, fw));
        export_upper(&mut sw, Path::new("/scratch/proj/upper"), b"")?;
        sw.end()?;
        let fw = sw.w.into_inner().map_err(|e| crate::util::Error(e.to_string()))?;
        fw.finish()?;
    }
    {
        let fw = FrameWriter::new(&mut *w, M_STATE, M_STATE_END);
        let mut sw = StreamWriter::new(io::BufWriter::with_capacity(1 << 20, fw));
        for p in &cfg.state_paths {
            if let Some(rel) = crate::util::safe_rel_path(p.as_bytes()) {
                stream_tree(&mut sw, &home.join(rel), p.as_bytes())?;
            }
        }
        sw.end()?;
        let fw = sw.w.into_inner().map_err(|e| crate::util::Error(e.to_string()))?;
        fw.finish()?;
    }
    write_frame(&mut *w, M_DONE, &[])?;
    let _ = w.flush();
    let _ = w.shutdown(std::net::Shutdown::Write);
    drop(w);
    // Don't reset the VM until the host has closed the connection, which it
    // does only after reading DONE: bytes still queued in the vsock device
    // would otherwise be lost when Firecracker stops (seen on a loaded CI
    // runner as a session whose exit status arrived but whose changes did
    // not).  The timeout covers a host that has gone away.
    let _ = gone_rx.recv_timeout(Duration::from_secs(10));
    Ok(())
}

/// Create git branch `name` at `commit` in the repository at `project` and
/// check it out (`--branch`, see [`crate::proto::GuestConfig::git_branch`]),
/// by writing the ref and `HEAD` directly: the index and work tree already
/// match `commit`, which is HEAD on the host.  As the user, like
/// [`write_agent_files`].
fn start_branch(project: &Path, name: &str, commit: &str, uid: u32, gid: u32) -> Result<()> {
    let Some(rel) = crate::util::safe_rel_path(name.as_bytes()) else { crate::bail!("invalid branch name") };
    if !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        crate::bail!("invalid commit");
    }
    let git = project.join(".git");
    unsafe {
        libc::setfsgid(gid);
        libc::setfsuid(uid);
    }
    let r = (|| -> Result<()> {
        let r = git.join("refs/heads").join(rel);
        if let Some(d) = r.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&r, format!("{commit}\n"))?;
        std::fs::write(git.join("HEAD"), format!("ref: refs/heads/{name}\n"))?;
        Ok(())
    })();
    unsafe {
        libc::setfsuid(0);
        libc::setfsgid(0);
    }
    r
}

/// Write the agent guidance files (see [`crate::guidance`]) into `home`,
/// with the user's filesystem credentials (`setfsuid`), so a symlink the
/// agent left in its home cannot point these writes at root's files, and
/// what is created belongs to the user.
fn write_agent_files(home: &Path, files: &[crate::proto::AgentFile], uid: u32, gid: u32) -> Result<()> {
    unsafe {
        libc::setfsgid(gid);
        libc::setfsuid(uid);
    }
    let r = (|| -> Result<()> {
        for f in files {
            let Some(rel) = crate::util::safe_rel_path(f.path.as_bytes()) else { continue };
            let p = home.join(rel);
            match &f.content {
                None => {
                    if std::fs::remove_file(&p).is_ok() {
                        if let Some(d) = p.parent() {
                            let _ = std::fs::remove_dir(d);
                        }
                    }
                }
                Some(c) => {
                    if let Some(d) = p.parent() {
                        std::fs::create_dir_all(d)?;
                    }
                    let text = if f.block { crate::guidance::with_section(&std::fs::read_to_string(&p).unwrap_or_default(), c) } else { c.clone() };
                    std::fs::write(&p, text)?;
                }
            }
        }
        Ok(())
    })();
    unsafe {
        libc::setfsuid(0);
        libc::setfsgid(0);
    }
    r
}

/// Mount the build cache disk `dev` and bind its `home` directory (created
/// on first use, owned by `uid`:`gid`) onto `$HOME/.cache` (`home` is the
/// home directory inside the new root).  Returns the first error.
fn mount_cache(dev: &str, home: &Path, uid: u32, gid: u32) -> Result<()> {
    // (the guest's own / is read-only: the mount point is on the scratch disk)
    std::fs::create_dir_all("/scratch/cache")?;
    // a sparse image's unused inode tables read as zeroes (see /scratch)
    mount(dev, "/scratch/cache", "ext4", libc::MS_NOATIME | libc::MS_NOSUID | libc::MS_NODEV, "noinit_itable")?;
    let own = |p: &Path| {
        let c = cstr(p.as_os_str());
        unsafe { libc::chown(c.as_ptr(), uid, gid) };
    };
    let src = Path::new("/scratch/cache/home");
    if !src.is_dir() {
        std::fs::create_dir(src)?;
        own(src);
    }
    let dst = home.join(".cache");
    if !dst.is_dir() {
        std::fs::create_dir(&dst)?;
        own(&dst);
    }
    mount("/scratch/cache/home", &dst.to_string_lossy(), "", libc::MS_BIND, "")
}

/// Write all of `d` to raw file descriptor `fd`, retrying after EINTR and
/// short writes.  Returns the first other error.
fn write_all_fd(fd: RawFd, mut d: &[u8]) -> io::Result<()> {
    while !d.is_empty() {
        let n = unsafe { libc::write(fd, d.as_ptr().cast(), d.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        d = &d[n as usize..];
    }
    Ok(())
}
