//! The change set: the guest's exported upper layer, interpreted against the
//! manifest of the project as it was when the session started.
//!
//! Reading.  [`ChangeSet::from_stream`] reads `changes.stream` (the
//! project's overlay upper layer, see `guest::export_upper`) and classifies
//! each entry against `manifest.json` and against the host tree as it is
//! now:
//!
//! - added, modified or deleted, dropping entries that were merely copied
//!   up (same content and mode);
//! - `conflict` if the host copy changed since the snapshot (by mode,
//!   inode, size or mtime): applying would overwrite someone's work;
//! - `sensitive` if the path configures or runs tools on the host (build
//!   files, CI config, editor settings, dotfiles, newly executable files):
//!   such changes are highlighted for review;
//! - `.git/` entries are set aside: they are never applied, but the agent's
//!   commits can be imported as a branch ([`import_branch`]).
//!
//! File contents are never copied out of the stream: a [`Change`] records
//! where its data is in `changes.stream`, and readers seek there.
//!
//! Presentation.  [`print_list`], [`render_diff`] and [`show_diff`] produce
//! the review shown after a session and by `agentcracker diff`.
//!
//! Applying.  Applying is the only time data crosses from guest to host, so
//! it is paranoid: paths resolve with openat2(RESOLVE_BENEATH |
//! RESOLVE_NO_SYMLINKS), files are written to a temporary name and renamed
//! into place, setuid/setgid/sticky bits are dropped, `.git/` internals are
//! never written, and anything the host changed since the snapshot is
//! reported as a conflict and skipped unless the user chooses to overwrite
//! it ([`apply`], [`Confined`]).
//!
//! Agent state.  [`extract_state`] unpacks the exported agent state (just as
//! carefully), [`sync_credentials`] carries refreshed OAuth tokens back to
//! the host, and [`transcripts`] summarises Claude Code transcripts for
//! `agentcracker show`.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::erofs::ManifestEntry;
use crate::proto::{Entry, StreamReader};
use crate::session::{Session, Summary};
use crate::util::{Context, Result, cstr, safe_rel_path};

/// What applying a change does to its path.
#[derive(Debug, Clone)]
pub enum Op {
    /// Write a regular file with permission bits `mode`; its `size` bytes of
    /// data are at offset `off` in `changes.stream`.
    File { mode: u32, off: u64, size: u64 },
    /// Create a symlink to `target`.
    Symlink { target: Vec<u8> },
    /// Create a directory with permission bits `mode`.
    Dir { mode: u32 },
    /// Remove the path (recursively for a directory).
    Delete,
}

/// How a change relates to the snapshot the session started from.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum St {
    /// The path did not exist in the snapshot.
    Added,
    /// The path existed, and its content, type or mode changed.
    Modified,
    /// The path existed and was removed.
    Deleted,
    /// A directory that exists before and after; it is in the upper layer only
    /// because something beneath it changed.  Neither shown nor counted.
    Container,
}

/// One change to the project, classified for review.
#[derive(Debug, Clone)]
pub struct Change {
    /// The path relative to the project root, as raw bytes.
    pub raw: Vec<u8>,
    /// What applying it does.
    pub op: Op,
    /// Its classification.
    pub st: St,
    /// The host copy changed since the session started (or, for an added path,
    /// something now exists there): applying would overwrite it.
    pub conflict: bool,
    /// The path runs or configures tools on the host (see [`is_sensitive`]),
    /// or became executable: flagged for careful review.
    pub sensitive: bool,
    /// Only the permission bits changed; the content is identical.
    pub mode_only: bool,
    /// For a deleted directory: the number of snapshot entries beneath it.
    pub nested: usize,
    /// the host already looks like the result (applied before, or the same
    /// edit made by hand): never a conflict, and apply leaves it alone
    pub in_place: bool,
}

impl Change {
    /// Returns the change's path, relative to the project root.
    pub fn path(&self) -> &Path {
        Path::new(OsStr::from_bytes(&self.raw))
    }
    /// Returns true if the change is shown and counted, i.e. it is not a
    /// [`St::Container`].
    pub fn shown(&self) -> bool {
        self.st != St::Container
    }
}

/// The interpreted contents of a session's `changes.stream`.
pub struct ChangeSet {
    /// Path of `changes.stream`; file data is read from it by offset.
    pub stream: PathBuf,
    /// Changes outside `.git/`, in stream order (parents before children),
    /// plus the deletions inferred from opaque directories.
    pub changes: Vec<Change>,
    /// Raw entries under `.git/`: never applied, used for branch import.
    pub git: Vec<(Vec<u8>, Op)>,
    /// The project directory on the host that the changes apply to.
    pub cwd: PathBuf,
}

/// Returns true if path `p` (relative to the project root) names a file the
/// host will later execute, or one that configures tools on the host.
///
/// That covers build files (`Makefile`, `Cargo.toml`, `build.rs`,
/// `package.json`, `setup.py`, ...), environment and shell files
/// (`.envrc`, `.env`, `.bashrc`, ...), git attribute and module files, CI
/// and container configuration, and anything under editor, CI or agent
/// configuration directories such as `.vscode/`, `.github/` or `.claude/`,
/// at any depth.  Such changes are highlighted in the review, not blocked.
pub fn is_sensitive(p: &[u8]) -> bool {
    let s = String::from_utf8_lossy(p);
    let name = s.rsplit('/').next().unwrap_or(&s);
    const NAMES: &[&str] = &[
        ".envrc", ".env", "Makefile", "makefile", "GNUmakefile", ".gitattributes", ".gitmodules",
        ".pre-commit-config.yaml", ".npmrc", ".yarnrc", ".yarnrc.yml", "package.json", "setup.py",
        "pyproject.toml", "build.rs", "Cargo.toml", ".bashrc", ".zshrc", ".profile", ".bash_profile",
        "Justfile", "justfile", "Taskfile.yml", "Dockerfile", ".editorconfig", ".clang-format", "conftest.py",
        ".gitlab-ci.yml", "Jenkinsfile", "flake.nix", "shell.nix", "direnv.toml",
    ];
    const DIRS: &[&str] = &[".vscode/", ".idea/", ".github/", ".husky/", ".devcontainer/", ".circleci/", ".claude/", ".cargo/"];
    NAMES.contains(&name) || DIRS.iter().any(|d| s.starts_with(d) || s.contains(&format!("/{d}")))
}

/// The conflict test: returns true if the host entry for manifest entry
/// `m`, below project directory `cwd`, still looks as it did when the
/// snapshot was taken - same mode and inode and, for anything but a
/// directory, the same size and mtime (to the nanosecond).  A missing entry
/// does not match.
fn host_matches_manifest(cwd: &Path, m: &ManifestEntry) -> bool {
    match std::fs::symlink_metadata(cwd.join(OsStr::from_bytes(&m.raw))) {
        Ok(md) => {
            let mt = md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128;
            let is_dir = md.is_dir();
            md.mode() == m.mode && md.ino() == m.ino && (is_dir || (md.size() == m.size && mt == m.mtime_ns))
        }
        Err(_) => false,
    }
}

/// Does the host already hold what `op` would produce?
fn host_has(stream: &File, op: &Op, host: &Path) -> bool {
    let md = std::fs::symlink_metadata(host);
    match op {
        Op::File { mode, off, size } => {
            md.is_ok_and(|m| m.file_type().is_file() && m.mode() & 0o777 == mode & 0o777) && same_content(stream, *off, *size, host)
        }
        Op::Symlink { target } => std::fs::read_link(host).is_ok_and(|t| t.as_os_str().as_bytes() == target.as_slice()),
        Op::Dir { .. } => md.is_ok_and(|m| m.file_type().is_dir()),
        Op::Delete => md.is_err(),
    }
}

/// Compare the `size` bytes at offset `off` in change stream `stream` with
/// the host file `host`.
///
/// Returns true only if the host file exists, is exactly `size` bytes long
/// and has identical content; any read error counts as a difference.
fn same_content(stream: &File, off: u64, size: u64, host: &Path) -> bool {
    let Ok(h) = File::open(host) else { return false };
    let Ok(md) = h.metadata() else { return false };
    if md.len() != size {
        return false;
    }
    let mut a = vec![0u8; 1 << 16];
    let mut b = vec![0u8; 1 << 16];
    let mut pos = 0u64;
    while pos < size {
        let n = ((size - pos) as usize).min(a.len());
        if stream.read_exact_at(&mut a[..n], off + pos).is_err() || h.read_exact_at(&mut b[..n], pos).is_err() {
            return false;
        }
        if a[..n] != b[..n] {
            return false;
        }
        pos += n as u64;
    }
    true
}

impl ChangeSet {
    /// Load the change set of session `s`.
    ///
    /// Returns `Ok(None)` if the session has no `changes.stream` (the VM never
    /// shut down cleanly), and the change set otherwise.  Errors if the
    /// manifest is missing or the stream is malformed.
    pub fn load(s: &Session) -> Result<Option<ChangeSet>> {
        let stream = s.path("changes.stream");
        if !stream.exists() {
            return Ok(None);
        }
        let manifest = s.manifest()?;
        Ok(Some(Self::from_stream(&stream, &manifest, &s.meta.cwd)?))
    }

    /// Read and classify a change stream.
    ///
    /// `stream`: the exported upper layer; `manifest`: the project snapshot's
    /// manifest; `cwd`: the project directory on the host, consulted to detect
    /// conflicts and to drop copy-ups that changed nothing.
    ///
    /// Each entry outside `.git/` is handled as follows:
    ///
    /// - a file or symlink that existed: dropped if the host copy is unchanged
    ///   and identical (for a file whose mode alone differs, kept as
    ///   `mode_only`); otherwise Modified, and a conflict if the host copy
    ///   changed;
    /// - a file or symlink that did not exist: Added - unless an identical file
    ///   has appeared on the host since, in which case it is dropped - and a
    ///   conflict if anything is at that path now; a new executable file is
    ///   sensitive;
    /// - a directory: a Container if it already existed as a directory, Modified
    ///   if it replaced a file or symlink.  For an opaque directory, everything
    ///   the snapshot had beneath it that the upper layer lacks is reported as
    ///   Deleted (only the topmost such entries, with `nested` counts);
    /// - a deletion: Deleted (with `nested` set for a directory), and a conflict
    ///   if the host copy changed; deletions of paths that were not in the
    ///   snapshot are dropped.
    ///
    /// Returns the change set; errors if the stream cannot be read or is
    /// malformed.
    pub fn from_stream(stream: &Path, manifest: &[ManifestEntry], cwd: &Path) -> Result<ChangeSet> {
        let man: HashMap<&[u8], &ManifestEntry> = manifest.iter().map(|m| (m.raw.as_slice(), m)).collect();
        let f = File::open(stream)?;
        let mut r = StreamReader::new(BufReader::new(f.try_clone()?));
        let mut entries: Vec<(Vec<u8>, Op, bool)> = Vec::new(); // (path, op, opaque)
        while let Some(e) = r.next()? {
            let off = r.offset;
            let (p, op, opaque) = match e {
                Entry::File { path, mode, size } => (path, Op::File { mode, off, size }, false),
                Entry::Symlink { path, target } => (path, Op::Symlink { target }, false),
                Entry::Dir { path, mode } => (path, Op::Dir { mode }, false),
                Entry::Opaque { path, mode } => (path, Op::Dir { mode }, true),
                Entry::Delete { path } => (path, Op::Delete, false),
            };
            entries.push((p, op, opaque));
        }
        let in_stream: HashSet<Vec<u8>> = entries.iter().map(|e| e.0.clone()).collect();
        let mut git = Vec::new();
        let mut changes = Vec::new();
        let under = |p: &[u8], dir: &[u8]| p.len() > dir.len() && p.starts_with(dir) && p[dir.len()] == b'/';
        for (raw, op, opaque) in entries {
            if raw == b".git" || raw.starts_with(b".git/") {
                git.push((raw, op));
                continue;
            }
            let m = man.get(raw.as_slice()).copied();
            let host = cwd.join(OsStr::from_bytes(&raw));
            let mut c = Change { raw: raw.clone(), op: op.clone(), st: St::Added, conflict: false, sensitive: is_sensitive(&raw), mode_only: false, nested: 0, in_place: false };
            match (&op, m) {
                (Op::File { mode, off, size }, Some(m)) => {
                    let was_file = m.mode & libc::S_IFMT == libc::S_IFREG;
                    let unchanged_host = host_matches_manifest(cwd, m);
                    if was_file && unchanged_host && same_content(&f, *off, *size, &host) {
                        if (m.mode & 0o777) == (*mode & 0o777) {
                            continue; // copied up but not changed
                        }
                        c.mode_only = true;
                    }
                    c.st = St::Modified;
                    c.conflict = !unchanged_host;
                    if (*mode & 0o111) != 0 && (m.mode & 0o111) == 0 {
                        c.sensitive = true; // newly executable
                    }
                }
                (Op::File { off, size, mode }, None) => {
                    if host.symlink_metadata().is_ok() {
                        if same_content(&f, *off, *size, &host) {
                            continue;
                        }
                        c.conflict = true;
                    }
                    if *mode & 0o111 != 0 {
                        c.sensitive = true;
                    }
                }
                (Op::Symlink { target }, Some(m)) => {
                    let unchanged_host = host_matches_manifest(cwd, m);
                    if m.mode & libc::S_IFMT == libc::S_IFLNK
                        && unchanged_host
                        && std::fs::read_link(&host).is_ok_and(|t| t.as_os_str().as_bytes() == target.as_slice())
                    {
                        continue;
                    }
                    c.st = St::Modified;
                    c.conflict = !unchanged_host;
                }
                (Op::Symlink { .. }, None) => {
                    c.conflict = host.symlink_metadata().is_ok();
                }
                (Op::Dir { .. }, Some(m)) if m.mode & libc::S_IFMT == libc::S_IFDIR => {
                    c.st = St::Container;
                    if opaque {
                        // directory was removed and recreated: everything the
                        // base had beneath it and the upper does not is gone
                        for mm in manifest.iter().filter(|mm| under(&mm.raw, &raw) && !in_stream.contains(&mm.raw)) {
                            // report only the topmost missing entry
                            let parent = &mm.raw[..mm.raw.iter().rposition(|&b| b == b'/').unwrap_or(0)];
                            if parent != raw.as_slice() && !in_stream.contains(parent) {
                                continue;
                            }
                            let nested = manifest.iter().filter(|x| under(&x.raw, &mm.raw)).count();
                            changes.push(Change {
                                raw: mm.raw.clone(),
                                op: Op::Delete,
                                st: St::Deleted,
                                conflict: !host_matches_manifest(cwd, mm),
                                sensitive: is_sensitive(&mm.raw),
                                mode_only: false,
                                nested,
                                in_place: false,
                            });
                        }
                    }
                }
                (Op::Dir { .. }, Some(_)) => {
                    c.st = St::Modified; // was a file/symlink, now a directory
                    c.conflict = !host_matches_manifest(cwd, m.unwrap());
                }
                (Op::Dir { .. }, None) => {
                    if host.is_dir() {
                        c.st = St::Container;
                    }
                }
                (Op::Delete, Some(m)) => {
                    c.st = St::Deleted;
                    c.conflict = !host_matches_manifest(cwd, m);
                    c.nested = manifest.iter().filter(|x| under(&x.raw, &raw)).count();
                }
                (Op::Delete, None) => continue,
            }
            changes.push(c);
        }
        for c in changes.iter_mut().filter(|c| c.conflict) {
            if host_has(&f, &c.op, &cwd.join(OsStr::from_bytes(&c.raw))) {
                c.in_place = true;
                c.conflict = false;
            }
        }
        Ok(ChangeSet { stream: stream.to_path_buf(), changes, git, cwd: cwd.to_path_buf() })
    }

    /// Count the changes for display and for `meta.json`: added files and
    /// symlinks (new directories are not counted), modified and deleted
    /// entries, and `.git/` entries.  Returns the counts.
    pub fn summary(&self) -> Summary {
        let mut s = Summary { git_internal: self.git.len(), ..Default::default() };
        for c in &self.changes {
            let is_dir = matches!(c.op, Op::Dir { .. });
            match c.st {
                St::Added if !is_dir => s.added += 1,
                St::Modified => s.modified += 1,
                St::Deleted => s.deleted += 1,
                _ => {}
            }
        }
        s
    }

    /// Returns the changes shown to the user: everything but containers, and
    /// without added directories that contain added content (which implies
    /// them).  Empty new directories are shown.
    pub fn shown(&self) -> impl Iterator<Item = &Change> {
        self.changes.iter().filter(|c| c.shown() && !(c.st == St::Added && matches!(c.op, Op::Dir { .. }) && self.has_children(&c.raw)))
    }

    /// Returns true if some change lies strictly beneath directory `dir`.
    fn has_children(&self, dir: &[u8]) -> bool {
        self.changes.iter().any(|c| c.raw.len() > dir.len() && c.raw.starts_with(dir) && c.raw[dir.len()] == b'/')
    }

    /// Returns true if there is nothing to show; `.git/` changes do not count.
    pub fn is_empty(&self) -> bool {
        self.shown().next().is_none()
    }

    /// Every shown change is already on the host.
    pub fn all_in_place(&self) -> bool {
        let mut it = self.shown().filter(|c| c.st != St::Container).peekable();
        it.peek().is_some() && it.all(|c| c.in_place)
    }

    /// Returns the shown changes whose host copy changed since the session
    /// started.
    pub fn conflicts(&self) -> Vec<&Change> {
        self.changes.iter().filter(|c| c.conflict && c.shown()).collect()
    }
}

// ---------------------------------------------------------------------------
// presentation
// ---------------------------------------------------------------------------

/// Describe `s` in one line for the review, e.g.
/// `3 files changed: 1 modified, 2 added`, or `no changes`.  `.git/`
/// entries are not included.
pub fn summary_line(s: &Summary) -> String {
    let n = s.added + s.modified + s.deleted;
    if n == 0 {
        return "no changes".into();
    }
    let mut parts = vec![];
    if s.modified > 0 {
        parts.push(format!("{} modified", s.modified));
    }
    if s.added > 0 {
        parts.push(format!("{} added", s.added));
    }
    if s.deleted > 0 {
        parts.push(format!("{} deleted", s.deleted));
    }
    format!("{n} file{} changed: {}", if n == 1 { "" } else { "s" }, parts.join(", "))
}

/// Describe `s` compactly for `agentcracker ls`: `+added ~modified -deleted`,
/// or `-` when nothing changed.
pub fn short_summary(s: &Summary) -> String {
    if s.added + s.modified + s.deleted == 0 {
        return "-".into();
    }
    format!("+{} ~{} -{}", s.added, s.modified, s.deleted)
}

/// Print the review list of `cs` to stderr, at most `limit` entries.
///
/// One line per change: an A/M/D tag, the path (with `/` for a directory,
/// the target of a symlink, the entry count of a deleted directory) and
/// notes for mode-only changes, conflicts and sensitive paths.  Coloured
/// when stderr is a terminal.  If there are more changes, says how many
/// and points at `agentcracker diff`.
pub fn print_list(cs: &ChangeSet, limit: usize) {
    let color = crate::util::isatty(2);
    let (g, r, y, b, d, z) = if color { ("\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[1m", "\x1b[2m", "\x1b[0m") } else { ("", "", "", "", "", "") };
    let shown: Vec<&Change> = cs.shown().collect();
    for c in shown.iter().take(limit) {
        let (tag, col) = match c.st {
            St::Added => ("A", g),
            St::Modified => ("M", y),
            St::Deleted => ("D", r),
            St::Container => (" ", ""),
        };
        let mut p = c.path().display().to_string();
        match &c.op {
            Op::Dir { .. } => p.push('/'),
            Op::Symlink { target } => p.push_str(&format!(" -> {}", String::from_utf8_lossy(target))),
            Op::Delete if c.nested > 0 => p.push_str(&format!("/ ({} entries)", c.nested)),
            _ => {}
        }
        let mut notes = vec![];
        if c.mode_only {
            notes.push("mode only".to_string());
        }
        if c.conflict {
            notes.push(format!("{r}{b}conflict: changed on the host since the session started{z}"));
        }
        if c.in_place {
            notes.push("already on the host".to_string());
        }
        if c.sensitive {
            notes.push(format!("{y}runs or configures tools on the host - review carefully{z}"));
        }
        let notes = if notes.is_empty() { String::new() } else { format!("  {d}({z}{}{d}){z}", notes.join(", ")) };
        eprintln!("  {col}{tag}{z} {p}{notes}");
    }
    if shown.len() > limit {
        eprintln!("  {d}... and {} more (agentcracker diff){z}", shown.len() - limit);
    }
}

/// Add ANSI colours to the unified diff text `diff`: headers bold, added
/// lines green, removed lines red, hunk headers cyan.  Colours never span a
/// newline.  Returns the coloured copy.
fn colorize(diff: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(diff.len() + diff.len() / 8);
    for line in diff.split_inclusive(|&c| c == b'\n') {
        let col: &[u8] = if line.starts_with(b"+++") || line.starts_with(b"---") || line.starts_with(b"diff ") {
            b"\x1b[1m"
        } else if line.starts_with(b"+") {
            b"\x1b[32m"
        } else if line.starts_with(b"-") {
            b"\x1b[31m"
        } else if line.starts_with(b"@@") {
            b"\x1b[36m"
        } else {
            b""
        };
        if col.is_empty() {
            out.extend_from_slice(line);
        } else {
            let (body, nl) = match line.strip_suffix(b"\n") {
                Some(b) => (b, &b"\n"[..]),
                None => (line, &b""[..]),
            };
            out.extend_from_slice(col);
            out.extend_from_slice(body);
            out.extend_from_slice(b"\x1b[0m");
            out.extend_from_slice(nl);
        }
    }
    out
}

/// Render the change set as a unified diff.
///
/// Each file is extracted from the stream to `tmpdir/new` and compared with
/// the system `diff -u` against the current host copy (or `/dev/null` for
/// an added file), labelled `a/<path>` and `b/<path>`, with git-style mode
/// lines.  A deletion diffs the host file against `/dev/null` (or names the
/// deleted directory and its entry count).  Symlinks and new directories
/// get a one-line description.  A conflicting change carries a `# CONFLICT`
/// line: its `a/` side is then the current host file, not the snapshot.
///
/// `cs`: the change set; `tmpdir`: a scratch directory, created if needed.
/// Returns the diff; errors if `diff` cannot be run or the stream cannot be
/// read.
pub fn render_diff(cs: &ChangeSet, tmpdir: &Path) -> Result<Vec<u8>> {
    std::fs::create_dir_all(tmpdir)?;
    let f = File::open(&cs.stream)?;
    let mut out: Vec<u8> = Vec::new();
    let newf = tmpdir.join("new");
    for c in cs.shown() {
        let p = c.path().display().to_string();
        let host = cs.cwd.join(c.path());
        let mut header = format!("diff agentcracker a/{p} b/{p}\n");
        if c.conflict {
            header.push_str("# CONFLICT: the host copy changed since the session started; a/ shows the current host file\n");
        }
        match (&c.op, c.st) {
            (Op::File { mode, off, size }, _) => {
                {
                    let mut w = File::create(&newf)?;
                    let mut left = *size;
                    let mut pos = *off;
                    let mut buf = vec![0u8; 1 << 16];
                    while left > 0 {
                        let n = (left as usize).min(buf.len());
                        f.read_exact_at(&mut buf[..n], pos)?;
                        w.write_all(&buf[..n])?;
                        pos += n as u64;
                        left -= n as u64;
                    }
                }
                let old = if c.st == St::Added || !host.is_file() { PathBuf::from("/dev/null") } else { host.clone() };
                if let Ok(md) = std::fs::symlink_metadata(&host) {
                    if (md.mode() & 0o777) != (*mode & 0o777) && c.st == St::Modified {
                        header.push_str(&format!("old mode {:o}\nnew mode {:o}\n", md.mode() & 0o777, mode & 0o777));
                    }
                } else {
                    header.push_str(&format!("new file mode {:o}\n", mode & 0o777));
                }
                out.extend_from_slice(header.as_bytes());
                let o = Command::new("diff")
                    .args(["-u", "--label", &format!("a/{p}"), "--label", &format!("b/{p}")])
                    .arg(&old)
                    .arg(&newf)
                    .output()
                    .ctx("running diff")?;
                out.extend_from_slice(&o.stdout);
            }
            (Op::Delete, _) => {
                out.extend_from_slice(header.as_bytes());
                if host.is_file() {
                    let o = Command::new("diff")
                        .args(["-u", "--label", &format!("a/{p}"), "--label", "/dev/null"])
                        .arg(&host)
                        .arg("/dev/null")
                        .output()
                        .ctx("running diff")?;
                    out.extend_from_slice(&o.stdout);
                } else if host.is_dir() {
                    out.extend_from_slice(format!("deleted directory {p}/ ({} entries)\n", c.nested).as_bytes());
                } else {
                    out.extend_from_slice(format!("deleted {p}\n").as_bytes());
                }
            }
            (Op::Symlink { target }, _) => {
                out.extend_from_slice(header.as_bytes());
                if let Ok(t) = std::fs::read_link(&host) {
                    out.extend_from_slice(format!("-symlink -> {}\n", t.display()).as_bytes());
                }
                out.extend_from_slice(format!("+symlink -> {}\n", String::from_utf8_lossy(target)).as_bytes());
            }
            (Op::Dir { .. }, _) => {
                out.extend_from_slice(header.as_bytes());
                out.extend_from_slice(format!("new directory {p}/\n").as_bytes());
            }
        }
    }
    let _ = std::fs::remove_file(&newf);
    Ok(out)
}

/// Show the change set as a diff, with a note about `.git/` changes.
///
/// On a terminal the diff is coloured and piped through `$PAGER` (default
/// `less`, with `LESS=-RFX` unless `LESS` is set), falling back to plain
/// output if the pager cannot be started; otherwise it is written to stdout
/// uncoloured.
///
/// `cs`: the change set; `tmpdir`: scratch directory for [`render_diff`].
/// Returns an error if rendering or writing fails.
pub fn show_diff(cs: &ChangeSet, tmpdir: &Path) -> Result<()> {
    let mut d = render_diff(cs, tmpdir)?;
    if !cs.git.is_empty() {
        d.extend_from_slice(format!("\n# plus {} changes inside .git/ (never applied; see `agentcracker branch`)\n", cs.git.len()).as_bytes());
    }
    if crate::util::isatty(1) {
        let d = colorize(&d);
        let pager = std::env::var("PAGER").unwrap_or_else(|_| "less".into());
        let mut parts = pager.split_whitespace();
        let prog = parts.next().unwrap_or("less");
        let mut cmd = Command::new(prog);
        cmd.args(parts).stdin(std::process::Stdio::piped());
        if prog == "less" && std::env::var_os("LESS").is_none() {
            cmd.env("LESS", "-RFX");
        }
        match cmd.spawn() {
            Ok(mut ch) => {
                if let Some(mut si) = ch.stdin.take() {
                    let _ = si.write_all(&d);
                }
                let _ = ch.wait();
            }
            Err(_) => {
                io::stdout().write_all(&d)?;
            }
        }
    } else {
        io::stdout().write_all(&d)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// confined writes
// ---------------------------------------------------------------------------

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

    /// Write `data` to a file at `rel` with permission bits `mode & 0o777`,
    /// through a temporary file renamed into place.  Unlike
    /// [`Confined::write_file`], it does not remove a directory at the target.
    /// Returns an I/O error on failure.
    pub fn write_bytes(&mut self, rel: &Path, mode: u32, data: &[u8]) -> io::Result<()> {
        let pfd = self.parent(rel)?;
        let name = Self::name_of(rel)?;
        let tmp = self.tmpname();
        let fd = unsafe {
            libc::openat(pfd.as_raw_fd(), tmp.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode & 0o777)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut out = unsafe { File::from_raw_fd(fd) };
        out.write_all(data)?;
        if unsafe { libc::renameat(pfd.as_raw_fd(), tmp.as_ptr(), pfd.as_raw_fd(), name.as_ptr()) } != 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::unlinkat(pfd.as_raw_fd(), tmp.as_ptr(), 0) };
            return Err(e);
        }
        Ok(())
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
/// `include_conflicts`; `.git/` changes are never applied.  A failure on
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
    for c in cs.changes.iter().filter(|c| c.st == St::Deleted) {
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
            Err(e) => res.errors.push(format!("{}: {e}", c.path().display())),
        }
    }
    for c in cs.changes.iter().filter(|c| c.st != St::Deleted) {
        if safe_rel_path(&c.raw).is_none() {
            res.errors.push(format!("{}: unsafe path", c.path().display()));
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
            Err(e) => res.errors.push(format!("{}: {e}", c.path().display())),
        }
    }
    res.in_place = in_place;
    Ok(res)
}

// ---------------------------------------------------------------------------
// git: turn the agent's commits into a branch on the host
// ---------------------------------------------------------------------------

/// Read the data of file operation `op` from the change stream into memory.
/// Returns `None` for an operation that is not a file, a file over 16 MiB,
/// or a read error.
fn read_stream_file(cs: &ChangeSet, op: &Op) -> Option<Vec<u8>> {
    let Op::File { off, size, .. } = op else { return None };
    if *size > 1 << 24 {
        return None;
    }
    let f = File::open(&cs.stream).ok()?;
    let mut v = vec![0u8; *size as usize];
    f.read_exact_at(&mut v, *off).ok()?;
    Some(v)
}

/// Read `.git/<rel>` as the agent left it: from the change stream if the
/// agent changed it, otherwise from the host repository.  Returns `None` if
/// neither has it.
fn git_file(cs: &ChangeSet, rel: &str) -> Option<Vec<u8>> {
    let want = format!(".git/{rel}");
    if let Some((_, op)) = cs.git.iter().find(|(p, _)| p.as_slice() == want.as_bytes()) {
        return read_stream_file(cs, op);
    }
    std::fs::read(cs.cwd.join(&want)).ok()
}

/// Returns true if `s` looks like a full git object id: 40 hex digits
/// (SHA-1) or 64 (SHA-256).
fn is_sha(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The commit the agent's HEAD points to, if it differs from `base`.
///
/// Resolves `.git/HEAD` as the agent left it: a symbolic ref
/// (`ref: refs/...`, validated) is looked up as a loose ref, then in
/// `packed-refs`; a detached HEAD is used as is.
///
/// `cs`: the change set; `base`: the HEAD commit when the session started.
/// Returns `(commit id, branch name or "HEAD")`, or `None` if the project
/// is not a git repository, nothing changed inside `.git/`, HEAD cannot be
/// resolved, or it still points at `base`.
pub fn agent_head(cs: &ChangeSet, base: Option<&str>) -> Option<(String, String)> {
    if !cs.cwd.join(".git").is_dir() || cs.git.is_empty() {
        return None;
    }
    let head = String::from_utf8(git_file(cs, "HEAD")?).ok()?;
    let head = head.trim();
    let (sha, name) = if let Some(r) = head.strip_prefix("ref: ") {
        let r = r.trim();
        if safe_rel_path(r.as_bytes()).is_none() || !r.starts_with("refs/") {
            return None;
        }
        let sha = match git_file(cs, r) {
            Some(v) => String::from_utf8(v).ok()?.trim().to_string(),
            None => {
                let packed = String::from_utf8(git_file(cs, "packed-refs")?).ok()?;
                packed.lines().find_map(|l| {
                    let (s, n) = l.split_once(' ')?;
                    (n.trim() == r).then(|| s.to_string())
                })?
            }
        };
        (sha, r.trim_start_matches("refs/heads/").to_string())
    } else {
        (head.to_string(), "HEAD".to_string())
    };
    if !is_sha(&sha) || Some(sha.as_str()) == base {
        return None;
    }
    Some((sha, name))
}

/// Run `git -C <dir> <args...>`.  Returns its stdout, trimmed; errors with
/// git's stderr if it fails, or if git cannot be run.
fn git(args: &[&str], dir: &Path) -> Result<String> {
    let o = Command::new("git").arg("-C").arg(dir).args(args).output().ctx("running git")?;
    if !o.status.success() {
        crate::bail!("git {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Import the agent's new git objects into the host repository via a
/// scratch repository and `git fetch` (with fsck), creating the branch
/// `agentcracker/<id>`.
///
/// Only object files are taken from the change stream - loose objects
/// (`objects/xx/<hex>`) and packs (`objects/pack/pack-<hex>.{pack,idx,rev}`),
/// with validated names - and written read-only, through [`Confined`], into
/// a bare scratch repository under the session's `tmp/`.  That repository
/// borrows the host repository's objects through `alternates` and gets a
/// ref for the agent's HEAD; the host repository then fetches from it with
/// `fetch.fsckObjects`, so malformed objects are rejected, and no hooks,
/// config or refs from the guest are ever used.  An existing branch with
/// the same name is overwritten.
///
/// `cs`: the change set; `s`: the session (id and base commit).  Returns
/// the branch name and a description such as `3 commit(s) on main`.  Errors
/// if the agent made no new commits or a git step fails.
pub fn import_branch(cs: &ChangeSet, s: &Session) -> Result<(String, String)> {
    let Some((sha, from)) = agent_head(cs, s.meta.git_head.as_deref()) else {
        crate::bail!("the agent made no new commits");
    };
    let tmp = s.path("tmp/import.git");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    git(&["init", "-q", "--bare", "."], &tmp)?;
    let mut w = Confined::new(&tmp, &s.meta.id)?;
    let src = File::open(&cs.stream)?;
    let hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit());
    for (p, op) in &cs.git {
        let Op::File { mode, off, size } = op else { continue };
        let Some(rel) = std::str::from_utf8(p).ok().and_then(|p| p.strip_prefix(".git/")) else { continue };
        let parts: Vec<&str> = rel.split('/').collect();
        let ok = match parts.as_slice() {
            ["objects", d, f] if d.len() == 2 && hex(d) && (f.len() == 38 || f.len() == 62) && hex(f) => true,
            ["objects", "pack", f] => {
                f.strip_prefix("pack-").and_then(|r| r.rsplit_once('.')).is_some_and(|(h, ext)| hex(h) && ["pack", "idx", "rev"].contains(&ext))
            }
            _ => false,
        };
        if ok {
            w.write_file(Path::new(rel), *mode & 0o444, &src, *off, *size)?;
        }
    }
    let objects = cs.cwd.join(".git/objects");
    std::fs::write(tmp.join("objects/info/alternates"), format!("{}\n", objects.display()))?;
    git(&["update-ref", "refs/heads/agent", &sha], &tmp)?;
    let branch = format!("agentcracker/{}", s.meta.id);
    let tmp_s = tmp.display().to_string();
    git(
        &["-c", "fetch.fsckObjects=true", "fetch", "-q", "--no-tags", "--no-write-fetch-head", &tmp_s, &format!("+refs/heads/agent:refs/heads/{branch}")],
        &cs.cwd,
    )?;
    let _ = std::fs::remove_dir_all(&tmp);
    let count = match &s.meta.git_head {
        Some(base) => git(&["rev-list", "--count", &format!("{base}..{sha}")], &cs.cwd).unwrap_or_default(),
        None => String::new(),
    };
    let desc = if count.is_empty() { format!("from {from}") } else { format!("{count} commit(s) on {from}") };
    Ok((branch, desc))
}

// ---------------------------------------------------------------------------
// agent state
// ---------------------------------------------------------------------------

/// Unpack `state.stream` into `<session>/state/`, confined like [`apply`].
///
/// Any previous `state/` is replaced.  Directories get at least mode 0700
/// so they stay traversable; symlinks and deletions in the stream are
/// ignored.  `s`: the session.  Returns `Ok(())` if there is no state
/// stream; errors on a malformed stream or a failed write.
pub fn extract_state(s: &Session) -> Result<()> {
    let stream = s.path("state.stream");
    if !stream.exists() {
        return Ok(());
    }
    let dir = s.path("state");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let f = File::open(&stream)?;
    let mut r = StreamReader::new(BufReader::new(f.try_clone()?));
    let mut w = Confined::new(&dir, &s.meta.id)?;
    while let Some(e) = r.next()? {
        let off = r.offset;
        let rel = PathBuf::from(OsStr::from_bytes(e.path()));
        let res = match &e {
            Entry::Dir { mode, .. } | Entry::Opaque { mode, .. } => w.mkdir(&rel, *mode | 0o700),
            Entry::File { mode, size, .. } => w.write_file(&rel, *mode, &f, off, *size),
            Entry::Symlink { .. } | Entry::Delete { .. } => Ok(()),
        };
        res.ctx(format!("state: {}", rel.display()))?;
    }
    Ok(())
}

/// If the guest refreshed the Claude OAuth token and the host copy has not
/// changed since it was seeded, write the refreshed token back (refresh
/// tokens rotate, so the host copy would otherwise stop working).
///
/// It writes only if all of these hold: the exported credentials differ
/// from what was seeded (`meta.cred_seed`); the host file still has the
/// seeded hash, so the host did not refresh it meanwhile; and the new file
/// is a JSON object with a `claudeAiOauth` key.  The write is confined to
/// the credentials file's directory, atomic and mode 0600, and `cred_seed`
/// is updated so the next boot compares against the new file.
///
/// `s`: the session (the caller saves it).  Returns `Ok(true)` if the host
/// file was updated, `Ok(false)` if that was unnecessary or not safe, and
/// an error if the write failed.
pub fn sync_credentials(s: &mut Session) -> Result<bool> {
    let guest = s.path("state").join(crate::vm::CRED_PATH);
    let Ok(data) = std::fs::read(&guest) else { return Ok(false) };
    let gh = crate::util::Fnv::new().bytes(&data).hex();
    let host = crate::util::home().join(crate::vm::CRED_PATH);
    let Some(seed) = s.meta.cred_seed.clone() else { return Ok(false) };
    if gh == seed || crate::vm::hash_file(&host).as_deref() != Some(seed.as_str()) {
        return Ok(false);
    }
    let v: serde_json::Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    if !v.is_object() || v.get("claudeAiOauth").is_none() {
        return Ok(false);
    }
    let parent = host.parent().unwrap();
    let mut w = Confined::new(parent, &s.meta.id)?;
    w.write_bytes(Path::new(host.file_name().unwrap()), 0o600, &data)?;
    s.meta.cred_seed = Some(gh);
    Ok(true)
}

/// Summary of one Claude Code transcript (`.jsonl`) captured from the guest.
pub struct Transcript {
    /// The conversation id: the file name without `.jsonl`.
    pub id: String,
    /// Number of user and assistant messages (meta messages excluded).
    pub messages: usize,
    /// The first user prompt that is plain text (not a `<...>` command
    /// wrapper), joined into one line.
    pub first_prompt: String,
    /// Timestamp of the last message, as written by Claude Code (ISO 8601).
    pub last: String,
}

/// Extract the text of transcript message `v`: `message.content` if it is a
/// string, otherwise the first `text` block of the content array.  Returns
/// `None` if there is no text.
fn msg_text(v: &serde_json::Value) -> Option<String> {
    let c = v.get("message")?.get("content")?;
    if let Some(s) = c.as_str() {
        return Some(s.to_string());
    }
    c.as_array()?.iter().find_map(|x| (x.get("type")?.as_str()? == "text").then(|| x.get("text")?.as_str().map(|s| s.to_string()))?)
}

/// Summarise the Claude Code transcripts captured from the guest: every
/// `.jsonl` file under `<session>/state/.claude/projects/*/`.
///
/// Lines that do not parse are skipped, and transcripts without messages
/// are left out.  `s`: the session.  Returns the summaries, ordered by
/// their last message, oldest first.
pub fn transcripts(s: &Session) -> Vec<Transcript> {
    let root = s.path("state/.claude/projects");
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&root) else { return out };
    for d in rd.filter_map(|e| e.ok()) {
        let Ok(files) = std::fs::read_dir(d.path()) else { continue };
        for f in files.filter_map(|e| e.ok()) {
            let p = f.path();
            if p.extension() != Some(OsStr::new("jsonl")) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            let mut t = Transcript {
                id: p.file_stem().unwrap_or_default().to_string_lossy().into_owned(),
                messages: 0,
                first_prompt: String::new(),
                last: String::new(),
            };
            for line in text.lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
                let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if ty != "user" && ty != "assistant" {
                    continue;
                }
                if v.get("isMeta").and_then(|m| m.as_bool()) == Some(true) {
                    continue;
                }
                t.messages += 1;
                if let Some(ts) = v.get("timestamp").and_then(|t| t.as_str()) {
                    t.last = ts.to_string();
                }
                if ty == "user" && t.first_prompt.is_empty() {
                    if let Some(txt) = msg_text(&v) {
                        let txt = txt.trim();
                        if !txt.starts_with('<') && !txt.is_empty() {
                            t.first_prompt = txt.replace('\n', " ");
                        }
                    }
                }
            }
            if t.messages > 0 {
                out.push(t);
            }
        }
    }
    out.sort_by(|a, b| a.last.cmp(&b.last));
    out
}
