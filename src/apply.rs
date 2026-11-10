//! Applying a change set to the host: the only time data crosses from the
//! guest to the host, so it is paranoid.  Paths resolve with
//! openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS) ([`Confined`]), files
//! are written to a temporary name and renamed into place,
//! setuid/setgid/sticky bits are dropped, `.git/` internals are never
//! written, and anything the host changed since the snapshot is reported as
//! a conflict and skipped unless the user chooses to overwrite it
//! ([`apply`]).

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use crate::changes::{Change, ChangeSet, Op, St};
use crate::util::{Context, Result, cstr, safe_rel_path};


/// `openat2(2)` resolve flag: refuse `/proc/<pid>/fd`-style magic links.
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
/// `openat2(2)` resolve flag: refuse to traverse any symlink.
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
/// `openat2(2)` resolve flag: refuse to resolve outside the starting
/// directory (no `..` escape, no absolute paths).
const RESOLVE_BENEATH: u64 = 0x08;

/// `struct open_how`, the argument of `openat2(2)`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Open `rel` relative to directory `root` with `openat2(2)`, refusing to
/// leave `root` and to follow any symlink or magic link on the way.
///
/// `rel`: a relative path (empty means `root` itself); `flags`: `open(2)`
/// flags (`O_CLOEXEC` is added).  Returns the new fd.  Errors with the
/// kernel's error, e.g. `EXDEV` or `ELOOP` when the path would escape or
/// crosses a symlink, `ENOENT` when it is missing.  Needs Linux 5.6 or
/// later.
fn openat2_beneath(root: RawFd, rel: &Path, flags: i32) -> io::Result<OwnedFd> {
    let p = if rel.as_os_str().is_empty() { cstr(".") } else { cstr(rel.as_os_str()) };
    let how = OpenHow { flags: (flags | libc::O_CLOEXEC) as u64, mode: 0, resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS };
    let fd = unsafe { libc::syscall(libc::SYS_openat2, root, p.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Writes confined beneath a root directory.
///
/// Every operation opens the parent directory of its target with
/// [`openat2_beneath`], so neither `..` nor a symlink - including one
/// created earlier in the same apply - can send a write outside the root,
/// and then acts on the final name relative to that directory.  New content
/// is written under a temporary name (`.agentcracker-<tag>-<n>.tmp`) and
/// renamed over the target, so readers never see a half-written file, and a
/// symlink at the target is replaced rather than followed.
pub struct Confined {
    /// The root directory, held open (later renames of its path do not matter).
    root: OwnedFd,
    /// The root's path, for messages.
    root_path: PathBuf,
    /// Part of temporary file names (the session id).
    tag: String,
    /// Counter for temporary file names.
    n: u64,
}

impl Confined {
    /// Open `root` as the confinement root.
    ///
    /// `tag`: goes into temporary file names.  Returns the writer; errors if
    /// `root` cannot be opened.
    pub fn new(root: &Path, tag: &str) -> Result<Confined> {
        let f = File::open(root).ctx(format!("open {}", root.display()))?;
        Ok(Confined { root: f.into(), root_path: root.to_path_buf(), tag: tag.to_string(), n: 0 })
    }

    /// Open the parent directory of `rel` (as an `O_PATH` fd), confined beneath
    /// the root, creating missing directories on the way.
    ///
    /// Each missing directory is created with mode 0755 through a confined open
    /// of its own parent.  Returns the fd; errors if a component is a symlink
    /// or not a directory, or a directory cannot be created.
    fn parent(&self, rel: &Path) -> io::Result<OwnedFd> {
        let parent = rel.parent().unwrap_or(Path::new(""));
        match openat2_beneath(self.root.as_raw_fd(), parent, libc::O_PATH | libc::O_DIRECTORY) {
            Ok(fd) => Ok(fd),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                let mut acc = PathBuf::new();
                for c in parent.components() {
                    let pfd = openat2_beneath(self.root.as_raw_fd(), &acc, libc::O_PATH | libc::O_DIRECTORY)?;
                    let name = cstr(c.as_os_str());
                    if unsafe { libc::mkdirat(pfd.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
                        let e = io::Error::last_os_error();
                        if e.raw_os_error() != Some(libc::EEXIST) {
                            return Err(e);
                        }
                    }
                    acc.push(c);
                }
                openat2_beneath(self.root.as_raw_fd(), parent, libc::O_PATH | libc::O_DIRECTORY)
            }
            Err(e) => Err(e),
        }
    }

    /// Returns a fresh temporary file name, unique within this writer.
    fn tmpname(&mut self) -> std::ffi::CString {
        self.n += 1;
        cstr(format!(".agentcracker-{}-{}.tmp", self.tag, self.n))
    }

    /// `lstat` entry `name` of directory `pfd`.  Returns its `S_IFMT` type
    /// bits, or `None` if it does not exist (or cannot be stat()ed).
    fn kind_at(pfd: RawFd, name: &std::ffi::CStr) -> Option<u32> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(pfd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return None;
        }
        Some(st.st_mode & libc::S_IFMT)
    }

    /// Remove entry `name` of directory `pfd`, if it exists.
    ///
    /// A directory is removed recursively, through `/proc/self/fd/<pfd>/<name>`
    /// (`remove_dir_all` never follows symlinks); anything else is unlinked.
    /// Returns `Ok(())` if there was nothing to remove, or an I/O error.
    fn remove_at(&self, pfd: RawFd, name: &std::ffi::CStr) -> io::Result<()> {
        match Self::kind_at(pfd, name) {
            None => Ok(()),
            Some(libc::S_IFDIR) => {
                // std's remove_dir_all never follows symlinks
                let p = PathBuf::from(format!("/proc/self/fd/{pfd}")).join(OsStr::from_bytes(name.to_bytes()));
                std::fs::remove_dir_all(p)
            }
            Some(_) => {
                if unsafe { libc::unlinkat(pfd, name.as_ptr(), 0) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }
        }
    }

    /// Returns the last component of `rel` as a C string; `InvalidInput` if
    /// `rel` has none.
    fn name_of(rel: &Path) -> io::Result<std::ffi::CString> {
        rel.file_name().map(cstr).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))
    }

    /// Write a regular file at `rel` with permission bits `mode & 0o777`
    /// (setuid, setgid and sticky are always dropped), containing the `size`
    /// bytes at offset `off` in `src`.
    ///
    /// The data goes to a temporary file created with `O_EXCL | O_NOFOLLOW`,
    /// which is then renamed over the target; a directory at the target is
    /// removed first.  On failure the temporary file is removed.  Returns an
    /// I/O error on failure.
    pub fn write_file(&mut self, rel: &Path, mode: u32, src: &File, off: u64, size: u64) -> io::Result<()> {
        let pfd = self.parent(rel)?;
        let name = Self::name_of(rel)?;
        let tmp = self.tmpname();
        let fd = unsafe {
            libc::openat(pfd.as_raw_fd(), tmp.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let out = unsafe { File::from_raw_fd(fd) };
        let res = (|| -> io::Result<()> {
            let mut buf = vec![0u8; 1 << 20];
            let mut pos = 0u64;
            while pos < size {
                let n = ((size - pos) as usize).min(buf.len());
                src.read_exact_at(&mut buf[..n], off + pos)?;
                out.write_all_at(&buf[..n], pos)?;
                pos += n as u64;
            }
            // no setuid/setgid/sticky, ever
            if unsafe { libc::fchmod(out.as_raw_fd(), mode & 0o777) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if Self::kind_at(pfd.as_raw_fd(), &name) == Some(libc::S_IFDIR) {
                self.remove_at(pfd.as_raw_fd(), &name)?;
            }
            if unsafe { libc::renameat(pfd.as_raw_fd(), tmp.as_ptr(), pfd.as_raw_fd(), name.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        if res.is_err() {
            unsafe { libc::unlinkat(pfd.as_raw_fd(), tmp.as_ptr(), 0) };
        }
        res
    }

    /// Create a symlink at `rel` pointing at `target`, replacing whatever is
    /// there (a directory is removed first).  The target is stored as it is and
    /// never followed here.  Returns an error if `target` contains a NUL byte
    /// or a system call fails.
    pub fn symlink(&mut self, rel: &Path, target: &[u8]) -> io::Result<()> {
        let pfd = self.parent(rel)?;
        let name = Self::name_of(rel)?;
        let tmp = self.tmpname();
        let t = std::ffi::CString::new(target).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUL in symlink"))?;
        if unsafe { libc::symlinkat(t.as_ptr(), pfd.as_raw_fd(), tmp.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if Self::kind_at(pfd.as_raw_fd(), &name) == Some(libc::S_IFDIR) {
            self.remove_at(pfd.as_raw_fd(), &name)?;
        }
        if unsafe { libc::renameat(pfd.as_raw_fd(), tmp.as_ptr(), pfd.as_raw_fd(), name.as_ptr()) } != 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::unlinkat(pfd.as_raw_fd(), tmp.as_ptr(), 0) };
            return Err(e);
        }
        Ok(())
    }

    /// Make sure `rel` is a directory.  An existing directory is kept as it is
    /// (its mode is not changed); anything else at that path is removed; a new
    /// directory gets permission bits `mode & 0o777` (subject to the umask).
    /// Returns an I/O error on failure.
    pub fn mkdir(&mut self, rel: &Path, mode: u32) -> io::Result<()> {
        let pfd = self.parent(rel)?;
        let name = Self::name_of(rel)?;
        match Self::kind_at(pfd.as_raw_fd(), &name) {
            Some(libc::S_IFDIR) => return Ok(()),
            Some(_) => self.remove_at(pfd.as_raw_fd(), &name)?,
            None => {}
        }
        if unsafe { libc::mkdirat(pfd.as_raw_fd(), name.as_ptr(), (mode & 0o777) as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Remove `rel`, recursively if it is a directory.  A missing path, or a
    /// missing parent, is not an error.  Returns an I/O error on failure,
    /// including when a parent is a symlink.
    pub fn delete(&mut self, rel: &Path) -> io::Result<()> {
        let pfd = match self.parent(rel) {
            Ok(p) => p,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(e) => return Err(e),
        };
        let name = Self::name_of(rel)?;
        self.remove_at(pfd.as_raw_fd(), &name)
    }

    /// Returns the root directory's path.  (Currently unused.)
    #[allow(dead_code)]
    pub fn root(&self) -> &Path {
        &self.root_path
    }
}

/// The result of [`apply`].
pub struct Applied {
    /// Files and symlinks written (directories are not counted).
    pub written: usize,
    /// Entries removed.
    pub deleted: usize,
    /// changes the host already had
    pub in_place: usize,
    /// Conflicting changes left out.
    pub skipped: Vec<PathBuf>,
    /// Per-path failures, as `path: reason`; applying carries on past them.
    pub errors: Vec<String>,
}

/// Apply the change set to the real tree, confined beneath the project
/// directory (see [`Confined`]).
///
/// Deletions run first, then everything else in stream order (parents
/// before children).  Conflicting changes are skipped, and listed, unless
/// `include_conflicts`; ignored ones are left out unless
/// [`ChangeSet::include_ignored`]; `.git/` changes are never applied.  A failure on
/// one path is recorded in [`Applied::errors`] and does not stop the rest.
///
/// `cs`: the change set; `tag`: used in temporary file names (the session
/// id); `include_conflicts`: overwrite host files that changed since the
/// snapshot.
///
/// Returns the counts; errors only if the stream or the project directory
/// cannot be opened.
pub fn apply(cs: &ChangeSet, tag: &str, include_conflicts: bool) -> Result<Applied> {
    let src = File::open(&cs.stream)?;
    let mut w = Confined::new(&cs.cwd, tag)?;
    let mut res = Applied { written: 0, deleted: 0, in_place: 0, skipped: vec![], errors: vec![] };
    let skip = |c: &Change| c.conflict && !include_conflicts;
    let mut in_place = 0;
    // deletions first, then creations in stream (parent-first) order
    for c in cs.changes.iter().filter(|c| c.st == St::Deleted && cs.wanted(c)) {
        if c.in_place {
            in_place += 1;
            continue;
        }
        if skip(c) {
            res.skipped.push(c.path().to_path_buf());
            continue;
        }
        match w.delete(c.path()) {
            Ok(()) => res.deleted += 1,
            Err(e) => res.errors.push(format!("{}: {e}", crate::util::safe_path(c.path()))),
        }
    }
    for c in cs.changes.iter().filter(|c| c.st != St::Deleted && cs.wanted(c)) {
        if safe_rel_path(&c.raw).is_none() {
            res.errors.push(format!("{}: unsafe path", crate::util::safe_path(c.path())));
            continue;
        }
        if c.in_place {
            in_place += 1;
            continue;
        }
        if skip(c) {
            res.skipped.push(c.path().to_path_buf());
            continue;
        }
        let r = match &c.op {
            Op::File { mode, off, size } => w.write_file(c.path(), *mode, &src, *off, *size).map(|_| 1),
            Op::Symlink { target } => w.symlink(c.path(), target).map(|_| 1),
            Op::Dir { mode } => w.mkdir(c.path(), *mode).map(|_| 0),
            Op::Delete => Ok(0),
        };
        match r {
            Ok(n) => res.written += n,
            Err(e) => res.errors.push(format!("{}: {e}", crate::util::safe_path(c.path()))),
        }
    }
    res.in_place = in_place;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::StreamWriter;
    use crate::util::TestDir;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// A project directory `proj` and a directory `outside` next to it, in
    /// a fresh test directory.
    fn dirs(name: &str) -> (TestDir, PathBuf, PathBuf) {
        let t = TestDir::new(name);
        let (p, o) = (t.0.join("proj"), t.0.join("outside"));
        std::fs::create_dir(&p).unwrap();
        std::fs::create_dir(&o).unwrap();
        std::fs::write(o.join("victim"), "untouched").unwrap();
        (t, p, o)
    }

    /// Apply the stream `build` writes (a guest's export, as hostile as it
    /// likes) to `proj`, as `agentcracker apply` would, overwriting
    /// conflicts.  Returns the per-path errors.
    fn apply_stream(t: &TestDir, proj: &Path, build: impl FnOnce(&mut StreamWriter<Vec<u8>>)) -> Vec<String> {
        let mut w = StreamWriter::new(Vec::new());
        build(&mut w);
        w.end().unwrap();
        let stream = t.0.join("changes.stream");
        std::fs::write(&stream, &w.w).unwrap();
        let cs = ChangeSet::from_stream(&stream, &[], proj).unwrap();
        apply(&cs, "test", true).unwrap().errors
    }

    fn untouched(o: &Path) {
        let names: Vec<_> = std::fs::read_dir(o).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["victim"], "nothing was added outside the project");
        assert_eq!(std::fs::read_to_string(o.join("victim")).unwrap(), "untouched");
    }

    #[test]
    fn a_symlink_in_the_stream_cannot_carry_later_writes_outside() {
        let (t, p, o) = dirs("apply-symlink-then-write");
        let errors = apply_stream(&t, &p, |w| {
            w.symlink(b"d", o.as_os_str().as_bytes()).unwrap();
            w.file(b"d/victim", 0o644, 5, &mut &b"owned"[..]).unwrap();
            w.file(b"d/new", 0o644, 5, &mut &b"owned"[..]).unwrap();
            w.dir(b"d/sub", 0o755).unwrap();
            w.symlink(b"d/link", b"/").unwrap();
            w.symlink(b"r", b"../outside").unwrap();
            w.file(b"r/new2", 0o644, 5, &mut &b"owned"[..]).unwrap();
        });
        untouched(&o);
        assert_eq!(errors.len(), 5, "each write beneath the symlink fails: {errors:?}");
        assert!(std::fs::symlink_metadata(p.join("d")).unwrap().file_type().is_symlink(), "the symlink itself is applied");
    }

    #[test]
    fn a_symlink_already_on_the_host_is_not_followed() {
        let (t, p, o) = dirs("apply-host-symlink");
        symlink(&o, p.join("d")).unwrap();
        symlink(o.join("victim"), p.join("f")).unwrap();
        let errors = apply_stream(&t, &p, |w| {
            w.file(b"d/victim", 0o644, 5, &mut &b"owned"[..]).unwrap();
            w.file(b"d/x", 0o644, 5, &mut &b"owned"[..]).unwrap();
            w.file(b"f", 0o644, 4, &mut &b"mine"[..]).unwrap();
        });
        untouched(&o);
        assert_eq!(errors.len(), 2, "writes through the symlinked directory fail: {errors:?}");
        assert_eq!(std::fs::read_to_string(p.join("f")).unwrap(), "mine", "a symlink at the target is replaced, not written through");
        assert!(std::fs::symlink_metadata(p.join("f")).unwrap().is_file());
    }

    #[test]
    fn deletions_never_reach_through_a_symlink() {
        let (_t, p, o) = dirs("apply-delete");
        symlink(&o, p.join("d")).unwrap();
        let mut w = Confined::new(&p, "test").unwrap();
        assert!(w.delete(Path::new("d/victim")).is_err());
        assert!(w.delete(Path::new("../outside/victim")).is_err());
        untouched(&o);
        w.delete(Path::new("d")).unwrap();
        assert!(!p.join("d").exists(), "the symlink itself is removed");
        untouched(&o);
    }

    #[test]
    fn confined_writes_refuse_paths_out_of_the_root() {
        let (_t, p, o) = dirs("apply-dotdot");
        let src = File::open(o.join("victim")).unwrap();
        let mut w = Confined::new(&p, "test").unwrap();
        for rel in ["../outside/victim", "../outside/new", "/tmp/acr-test-abs", "a/../../outside/new"] {
            assert!(w.write_file(Path::new(rel), 0o644, &src, 0, 5).is_err(), "{rel}");
            assert!(w.mkdir(Path::new(rel), 0o755).is_err(), "{rel}");
            assert!(w.symlink(Path::new(rel), b"x").is_err(), "{rel}");
        }
        untouched(&o);
        assert!(!Path::new("/tmp/acr-test-abs").exists());
    }

    #[test]
    fn modes_are_permission_bits_only_and_git_is_never_written() {
        let (t, p, _o) = dirs("apply-modes");
        std::fs::create_dir(p.join(".git")).unwrap();
        let errors = apply_stream(&t, &p, |w| {
            w.file(b"suid", 0o6755, 1, &mut &b"x"[..]).unwrap();
            w.dir(b"sticky", 0o1777).unwrap();
            w.file(b".git/hooks/post-checkout", 0o755, 1, &mut &b"x"[..]).unwrap();
            w.file(b".git/config", 0o644, 1, &mut &b"x"[..]).unwrap();
        });
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(std::fs::metadata(p.join("suid")).unwrap().permissions().mode() & 0o7777, 0o755);
        assert_eq!(std::fs::metadata(p.join("sticky")).unwrap().permissions().mode() & 0o7000, 0);
        assert!(!p.join(".git/hooks").exists() && !p.join(".git/config").exists());
    }
}
