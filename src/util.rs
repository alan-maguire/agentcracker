//! Small shared helpers used by both the host CLI and acinit.
//!
//! - Errors: the string-based [`Error`], the crate-wide [`Result`], the
//!   [`bail!`](crate::bail) macro, and the [`Context`] extension trait that
//!   prefixes a failure with what was being attempted.
//! - Hashing: [`Fnv`], a stable FNV-1a hasher used for cache keys.
//! - Paths: the XDG cache/state/config/runtime directories, `~` display
//!   shortening, and [`safe_rel_path`], the validator applied to every path
//!   that arrives from the guest.
//! - Locking: [`try_lock`] and [`lock`], `flock(2)` advisory locks.
//! - Matching: [`glob_match`] and the gitignore-flavoured [`Excludes`].
//! - Formatting and terminal helpers: human-readable sizes, ages and
//!   durations, passwd/group lookups, and a single-key prompt.

use std::ffi::{CString, OsStr};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The crate-wide error: just a human-readable message.
///
/// Errors are only ever shown to the user, never matched on, so the message
/// is all that is kept.  Any `std::error::Error` converts into one with `?`
/// (keeping its `Display` text); add context with [`Context::ctx`].
pub struct Error(pub String);

impl fmt::Display for Error {
    /// Format the error as its message, unchanged.
    ///
    /// `f`: the formatter.  Returns the formatter's result.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Debug for Error {
    /// Format the error as its bare message (no `Error("...")` wrapper), so an
    /// unwrapped or `{:?}`-printed error is still readable.
    ///
    /// `f`: the formatter.  Returns the formatter's result.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl<E: std::error::Error> From<E> for Error {
    /// Wrap any standard error, keeping its `Display` text.  This is what lets
    /// `?` propagate io, serde and parse errors as [`Error`].
    ///
    /// `e`: the source error.  Returns the wrapped error.
    fn from(e: E) -> Self {
        Error(e.to_string())
    }
}

/// The crate-wide result type, with [`Error`] as the error.
pub type Result<T> = std::result::Result<T, Error>;

/// Return early from the enclosing function with an [`Error`] built from a
/// `format!`-style message, e.g. `crate::bail!("cannot open {}", p.display())`.
///
/// The enclosing function must return the crate's [`Result`].
#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => { return Err($crate::util::Error(format!($($t)*))) };
}

/// Attach context to a failure: `op().ctx("reading config")?` turns error
/// `e` into `"reading config: e"`.
///
/// Implemented for `Result` (prefixes the original error) and for `Option`
/// (turns `None` into an error carrying only the context).
pub trait Context<T> {
    /// Convert `self` into the crate [`Result`], describing a failure with `c`.
    ///
    /// `c`: what was being attempted.  Returns the success value unchanged, or
    /// an [`Error`] whose message starts with `c`.
    fn ctx<C: fmt::Display>(self, c: C) -> Result<T>;
}
impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    /// `Ok(v)` passes through; `Err(e)` becomes `Error("{c}: {e}")`.
    fn ctx<C: fmt::Display>(self, c: C) -> Result<T> {
        self.map_err(|e| Error(format!("{c}: {e}")))
    }
}
impl<T> Context<T> for Option<T> {
    /// `Some(v)` becomes `Ok(v)`; `None` becomes `Error("{c}")`.
    fn ctx<C: fmt::Display>(self, c: C) -> Result<T> {
        self.ok_or_else(|| Error(c.to_string()))
    }
}

/// Build an error from `errno` right after a failed libc call.
///
/// `what`: description of the failed operation.  Always returns `Err` with
/// the message `"{what}: {OS error text}"`; the generic `T` lets callers
/// write `return last_os_error("pipe")` from any function.
pub fn last_os_error<T>(what: impl fmt::Display) -> Result<T> {
    Err(Error(format!("{what}: {}", std::io::Error::last_os_error())))
}

/// Convert an OS string (a path, argument or mount option) into a
/// NUL-terminated C string for a libc call.
///
/// `p`: the string; its bytes are used as they are.  Returns the C string.
/// A string with an interior NUL cannot be represented and becomes `"?"`, so
/// the libc call then fails cleanly (e.g. with `ENOENT`) instead of the
/// program panicking.
pub fn cstr(p: impl AsRef<OsStr>) -> CString {
    CString::new(p.as_ref().as_bytes()).unwrap_or_else(|_| CString::new("?").unwrap())
}

/// 64-bit FNV-1a hasher, used for cache keys and content fingerprints.
///
/// Unlike `std::hash`, its output is stable across builds and Rust
/// versions, so keys written to disk (image file names, the credentials
/// hash in `meta.json`) stay valid after an upgrade.  It is not
/// cryptographic: it tells inputs apart but authenticates nothing.  Calls
/// chain: `Fnv::new().str(a).u64(b).hex()`.
pub struct Fnv(u64);
impl Fnv {
    /// Start a hash from the standard FNV-1a 64-bit offset basis.  Returns the
    /// empty hasher.
    pub fn new() -> Self {
        Fnv(0xcbf29ce484222325)
    }
    /// Mix one field into the hash: the bytes of `b`, then a separator byte, so
    /// consecutive fields cannot run together (`("ab", "c")` and `("a", "bc")`
    /// hash differently).
    ///
    /// `b`: the field.  Returns `self` for chaining.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        for &x in b {
            self.0 ^= x as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
        // length separator so ("ab","c") != ("a","bc")
        self.0 ^= 0xff;
        self.0 = self.0.wrapping_mul(0x100000001b3);
        self
    }
    /// Mix an integer into the hash as one field (8 little-endian bytes).
    ///
    /// `v`: the value.  Returns `self` for chaining.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }
    /// Mix a string into the hash as one field (its UTF-8 bytes).
    ///
    /// `s`: the string.  Returns `self` for chaining.
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }
    /// Returns the current hash as 16 lowercase hex digits.  The hasher is not
    /// consumed or reset.
    pub fn hex(&self) -> String {
        format!("{:016x}", self.0)
    }
}

/// Returns the current wall-clock time in whole seconds since the Unix
/// epoch (0 if the clock reads earlier than 1970).
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Generate `nbytes` random bytes and return them as `2 * nbytes` lowercase
/// hex digits.
///
/// Uses `getrandom(2)`; if that fails, falls back to bits of the current
/// time mixed with the pid.  Used for session ids and image UUIDs, where
/// uniqueness matters but unpredictability does not.
pub fn random_hex(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    let ok = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), nbytes, 0) } == nbytes as isize;
    if !ok {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (t >> (i * 8 % 120)) as u8 ^ std::process::id() as u8;
        }
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns the user's home directory from `$HOME`, or `/` if it is unset.
pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Resolve an XDG base directory.
///
/// `var`: the environment variable (e.g. `XDG_CACHE_HOME`); `default`: the
/// path relative to `$HOME` to use when the variable is unset, empty or
/// not absolute (as the XDG spec requires).  Returns the base directory,
/// without the `agentcracker` component.
fn xdg(var: &str, default: &str) -> PathBuf {
    match std::env::var_os(var) {
        Some(v) if !v.is_empty() && Path::new(&v).is_absolute() => PathBuf::from(v),
        _ => home().join(default),
    }
}

/// Returns `$XDG_CACHE_HOME/agentcracker` (default
/// `~/.cache/agentcracker`), the shared image cache (`usr/`, `tools/`,
/// `base/`, `lower/`).  Not created here.
pub fn cache_dir() -> PathBuf {
    xdg("XDG_CACHE_HOME", ".cache").join("agentcracker")
}
/// Returns `$XDG_STATE_HOME/agentcracker` (default
/// `~/.local/state/agentcracker`), which holds the session store.  Not
/// created here.
pub fn state_dir() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state").join("agentcracker")
}
/// Returns `$XDG_CONFIG_HOME/agentcracker` (default
/// `~/.config/agentcracker`), where `config.toml` is looked for.
pub fn config_dir() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config").join("agentcracker")
}
/// Returns the directory for per-boot runtime files (Firecracker's config
/// and vsock sockets): `$XDG_RUNTIME_DIR/agentcracker`, or
/// `/tmp/agentcracker-<uid>` when that is unset.
///
/// These are kept apart from the (possibly deep) state directory because
/// unix socket paths are limited to 108 bytes.  Not created here.
pub fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(v) if !v.is_empty() => PathBuf::from(v).join("agentcracker"),
        _ => PathBuf::from(format!("/tmp/agentcracker-{}", unsafe { libc::getuid() })),
    }
}

/// Create directory `p` and any missing parents with mode 0700 (subject to
/// the umask).  Directories that already exist are left as they are.
///
/// Returns `Ok(())` on success or if `p` already exists; an error naming
/// the path otherwise.
pub fn mkdir_private(p: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .ctx(format!("mkdir {}", p.display()))
}

/// Returns true if file descriptor `fd` refers to a terminal.
pub fn isatty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// Format a byte count for humans in binary units: `512B`, `1.5K`, `12M`,
/// `3.2G`, `1T`.
///
/// `n`: size in bytes.  Returns the string, with one decimal place below
/// 10 units and none above.
pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else if v < 10.0 {
        format!("{v:.1}{}", U[i])
    } else {
        format!("{v:.0}{}", U[i])
    }
}

/// Format an age as one coarse, truncated unit: `45s`, `12m`, `3h`, `9d`.
///
/// `secs`: elapsed seconds.  Returns the string.
pub fn human_age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    }
}

/// Format a duration with two units: `42s`, `3m05s`, `2h07m`.
///
/// `secs`: the duration in seconds.  Returns the string.
pub fn human_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Shorten a path for display by replacing a leading `$HOME` with `~`.
///
/// `p`: the path.  Returns `~`, `~/rest`, or the path unchanged if it is
/// outside home (or home is `/`).  For display only: the result is lossy
/// and must not be used to open files.
pub fn tilde(p: &Path) -> String {
    let h = home();
    match p.strip_prefix(&h) {
        Ok(rest) if h != Path::new("/") => {
            if rest.as_os_str().is_empty() {
                "~".into()
            } else {
                format!("~/{}", rest.display())
            }
        }
        _ => p.display().to_string(),
    }
}

/// Parse a memory size into MiB.
///
/// `s`: a whole number with an optional `M`, `G` or `T` suffix (either
/// case; surrounding whitespace ignored).  A bare number is already MiB, so
/// `"4096"`, `"4096M"` and `"4G"` are equal.  Returns `None` if the number
/// does not parse.
pub fn parse_mem_mib(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last()? {
        'G' | 'g' => (&s[..s.len() - 1], 1024),
        'M' | 'm' => (&s[..s.len() - 1], 1),
        'T' | 't' => (&s[..s.len() - 1], 1024 * 1024),
        _ => (s, 1),
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// Take an exclusive, non-blocking `flock(2)` on `path`, creating the file
/// if needed.
///
/// Returns `Ok(Some(file))` if the lock was taken: it is held until `file`
/// is dropped, or the process exits, so a crashed holder never leaves a
/// stale lock.  Returns `Ok(None)` if another process holds it, and `Err`
/// if the file cannot be opened.
pub fn try_lock(path: &Path) -> Result<Option<std::fs::File>> {
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .ctx(format!("open {}", path.display()))?;
    let r = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    Ok(if r == 0 { Some(f) } else { None })
}

/// Take an exclusive `flock(2)` on `path`, creating the file if needed and
/// blocking until the lock is free.
///
/// Returns the open file; the lock is released when it is dropped.  Errors
/// if the file cannot be opened or locked.
pub fn lock(path: &Path) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .ctx(format!("open {}", path.display()))?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return last_os_error(format!("lock {}", path.display()));
    }
    Ok(f)
}

/// Match `s` against the shell-style pattern `pat`, both as raw bytes.
///
/// `*` matches any run (possibly empty) of characters other than `/`; `?`
/// matches one character other than `/`; every other byte matches itself.
/// There are no character classes or escapes, and the match is anchored at
/// both ends.  Returns true on a match.  Iterative, with backtracking to
/// the most recent `*` only, so it never recurses.
pub fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    let (mut star_p, mut star_i) = (usize::MAX, 0usize);
    while i < s.len() {
        if p < pat.len() && (pat[p] == b'?' && s[i] != b'/' || pat[p] == s[i] && pat[p] != b'*') {
            p += 1;
            i += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star_p = p;
            star_i = i;
            p += 1;
        } else if star_p != usize::MAX && s[star_i] != b'/' {
            p = star_p + 1;
            star_i += 1;
            i = star_i;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// A gitignore-flavoured exclusion list, used when walking trees into images.
///
/// - `name` matches a file or directory called `name` at any depth.
/// - `dir/` matches only directories called `dir`, at any depth.
/// - `a/b` (containing a slash) matches that path relative to the walk
///   root; a leading slash anchors a single name the same way (`/build`).
/// - `*` and `?` work within a path component (see [`glob_match`]).
///
/// There is no negation (`!pattern`).  An excluded directory is skipped
/// together with everything beneath it.
pub struct Excludes {
    pats: Vec<(Vec<u8>, bool, bool)>, // (pattern, dir_only, anchored)
}

impl Excludes {
    /// Compile a list of patterns.
    ///
    /// `list`: the patterns as written in the config; blank entries are ignored
    /// and surrounding whitespace is trimmed.  Returns the matcher.
    pub fn new(list: &[String]) -> Self {
        let pats = list
            .iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                let s = s.trim();
                let dir_only = s.ends_with('/');
                let s = s.trim_end_matches('/');
                let anchored = s.contains('/');
                let s = s.trim_start_matches('/');
                (s.as_bytes().to_vec(), dir_only, anchored)
            })
            .collect();
        Excludes { pats }
    }
    /// Decide whether an entry is excluded.
    ///
    /// `rel`: the entry's path relative to the walk root; `is_dir`: whether it
    /// is a directory (directory-only patterns ignore everything else).
    /// Returns true if any pattern matches: unanchored patterns are tested
    /// against the last path component, anchored ones against all of `rel`.
    pub fn matches(&self, rel: &Path, is_dir: bool) -> bool {
        let full = rel.as_os_str().as_bytes();
        let name = rel.file_name().map(|n| n.as_bytes()).unwrap_or(full);
        self.pats.iter().any(|(p, dir_only, anchored)| {
            if *dir_only && !is_dir {
                return false;
            }
            if *anchored {
                glob_match(p, full)
            } else {
                glob_match(p, name)
            }
        })
    }
}

/// Validate a relative path received from the guest (or read from a file
/// stream).
///
/// This is the first line of defence for everything that crosses the VM
/// boundary.  `b` is accepted only if it is non-empty, at most 4096 bytes,
/// relative (no leading `/`), free of NUL bytes, and every `/`-separated
/// component is non-empty, not `.` or `..`, and at most 255 bytes long.
///
/// Returns the path, or `None` if it must be rejected.  An accepted path
/// cannot climb out of the directory it is joined to by name alone;
/// symlinks along the way are dealt with separately by the confined writer
/// in `changes`.
pub fn safe_rel_path(b: &[u8]) -> Option<PathBuf> {
    if b.is_empty() || b.len() > 4096 || b[0] == b'/' || b.contains(&0) {
        return None;
    }
    for comp in b.split(|&c| c == b'/') {
        if comp.is_empty() || comp == b"." || comp == b".." || comp.len() > 255 {
            return None;
        }
    }
    Some(PathBuf::from(OsStr::from_bytes(b)))
}

/// Look up the login name of `uid` in the passwd database.
///
/// Returns the name, or, if there is no entry (e.g. in a container with a
/// minimal `/etc/passwd`), `$USER`, or failing that `u<uid>`.
pub fn user_name(uid: u32) -> String {
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return std::env::var("USER").unwrap_or_else(|_| format!("u{uid}"));
        }
        std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
    }
}

/// Returns the login shell of `uid` from the passwd database, falling back
/// to `$SHELL` and finally `/bin/sh`.  Used by `agentcracker shell` and as
/// `$SHELL` in the guest.
pub fn user_shell(uid: u32) -> String {
    unsafe {
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            let s = std::ffi::CStr::from_ptr((*pw).pw_shell).to_string_lossy().into_owned();
            if !s.is_empty() {
                return s;
            }
        }
    }
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
}

/// Look up the name of group `gid`.  Returns it, or `g<gid>` if the group
/// database has no entry.
pub fn group_name(gid: u32) -> String {
    unsafe {
        let gr = libc::getgrgid(gid);
        if gr.is_null() {
            return format!("g{gid}");
        }
        std::ffi::CStr::from_ptr((*gr).gr_name).to_string_lossy().into_owned()
    }
}

/// Ask a single-choice question on the terminal and return the answer.
///
/// Prints `prompt` to stderr and reads a line from stdin, repeating until
/// the first character of the trimmed line, lowercased, is one of `valid`.
/// Put `'\n'` in `valid` to accept an empty line (just Enter); it is
/// returned as `'\n'`.
///
/// Returns the chosen character, or `None` on end of input or a read error,
/// which callers treat as "cancel".
pub fn prompt_key(prompt: &str, valid: &str) -> Option<char> {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    loop {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).ok()? == 0 {
            return None;
        }
        let c = line.trim().chars().next().map(|c| c.to_ascii_lowercase());
        match c {
            Some(c) if valid.contains(c) => return Some(c),
            None if valid.contains('\n') => return Some('\n'),
            _ => {}
        }
    }
}

/// Startup profiling: with AGENTCRACKER_TIMING set, print the time since the
/// program started at each named point.
pub fn mark(what: &str) {
    static ON: std::sync::OnceLock<Option<std::time::Instant>> = std::sync::OnceLock::new();
    let start = ON.get_or_init(|| std::env::var_os("AGENTCRACKER_TIMING").map(|_| std::time::Instant::now()));
    if let Some(t) = start {
        eprintln!("\x1b[2m[{:7.3}s] {what}\x1b[0m", t.elapsed().as_secs_f64());
    }
}

/// Make text that came from the guest safe to show on a terminal.
///
/// Everything the agent controls - file names, symlink targets, file
/// contents in a diff, branch names, host names, transcript text, error
/// messages - can carry terminal control sequences that would move the
/// cursor, rewrite lines (hiding parts of a diff under review), change the
/// window title or write the clipboard.  This shows every C0 control
/// (except tab, and newline when `multiline`), DEL, every C1 control and the
/// bidirectional-override characters (which can reorder what is displayed)
/// as visible escapes such as `\x1b` or `\u{202e}`; invalid UTF-8 becomes
/// U+FFFD.
pub fn safe_text(b: &[u8], multiline: bool) -> String {
    let s = String::from_utf8_lossy(b);
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let bidi = matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}' | '\u{061c}');
        match c {
            '\t' => out.push(c),
            '\n' if multiline => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{7f}' => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if ('\u{80}'..='\u{9f}').contains(&c) || bidi => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// [`safe_text`] for a path, on one line.
pub fn safe_path(p: &std::path::Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    safe_text(p.as_os_str().as_bytes(), false)
}

/// Run `git -C <dir> <args...>` on the host.  Returns its standard output,
/// trimmed; errors with git's own message if it fails, or if git cannot be
/// run.  (Callers that only need to know whether it worked use `.ok()`.)
pub fn git(dir: &std::path::Path, args: &[&str]) -> Result<String> {
    let o = std::process::Command::new("git").arg("-C").arg(dir).args(args).output().ctx("running git")?;
    if !o.status.success() {
        crate::bail!("git {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Space kept free on any filesystem the host writes guest-driven output
/// to (a session's change and state streams, its console log, the
/// command's output when that goes to a file): writing stops below it, so
/// a runaway or hostile guest cannot fill the host's disk.  The same floor
/// applies to the session's own disks, which the guest grows by writing to
/// them: a session does not start below it, and is stopped if it gets
/// there (see `vm::watch_space`).  The tests raise each separately, with
/// `AGENTCRACKER_MIN_FREE` and `AGENTCRACKER_MIN_FREE_SESSION` (bytes), to
/// see them work.
pub const MIN_FREE: u64 = 2 << 30;

/// [`MIN_FREE`] for files the host writes, or `AGENTCRACKER_MIN_FREE`.
pub fn min_free() -> u64 {
    std::env::var("AGENTCRACKER_MIN_FREE").ok().and_then(|v| v.parse().ok()).unwrap_or(MIN_FREE)
}

/// [`MIN_FREE`] for the session's disks, or `AGENTCRACKER_MIN_FREE_SESSION`.
pub fn min_free_session() -> u64 {
    std::env::var("AGENTCRACKER_MIN_FREE_SESSION").ok().and_then(|v| v.parse().ok()).unwrap_or(MIN_FREE)
}

/// Bytes the user can still write on the filesystem holding `fd`, or
/// `None` if `fd` is not a regular file (a terminal or pipe has no space to
/// run out of) or the filesystem cannot be asked.
pub fn free_space(fd: std::os::fd::RawFd) -> Option<u64> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstatvfs(fd, &mut vfs) } == 0).then(|| vfs.f_bavail as u64 * vfs.f_frsize as u64)
}

/// Checks, as guest-driven output is written to a file, that its filesystem
/// keeps [`MIN_FREE`]: every 64 MiB, so the check costs nothing.
#[derive(Default)]
pub struct SpaceGuard {
    since: u64,
}

impl SpaceGuard {
    /// Account for `n` more bytes about to be written to `fd`.  Errors once
    /// the filesystem has less than [`MIN_FREE`] left.
    pub fn allow(&mut self, fd: std::os::fd::RawFd, n: usize) -> Result<()> {
        self.since += n as u64;
        if self.since < 64 << 20 {
            return Ok(());
        }
        self.since = 0;
        match free_space(fd) {
            Some(f) if f < min_free() => crate::bail!("less than {} free on the host's disk", human_bytes(min_free())),
            _ => Ok(()),
        }
    }
}
