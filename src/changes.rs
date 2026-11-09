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
//!   commits can be imported as a branch ([`crate::gitimport`]);
//! - `ignored` if git on the host would ignore the path (build output, by
//!   the project's `.gitignore` as it is on the host - the agent's edits to
//!   ignore files don't count): hidden from the review and not applied,
//!   unless the user asks for them ([`ChangeSet::include_ignored`]).
//!
//! File contents are never copied out of the stream: a [`Change`] records
//! where its data is in `changes.stream`, and readers seek there.
//!
//! Presentation.  [`print_list`], [`render_diff`] and [`show_diff`] produce
//! the review shown after a session and by `agentcracker diff`.
//!
//! Applying the changes is [`crate::apply`]; importing the agent's
//! commits, [`crate::gitimport`]; its exported state, [`crate::agentstate`].

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::erofs::ManifestEntry;
use crate::proto::{Entry, StreamReader};
use crate::session::{Session, Summary};
use crate::util::{Context, Result, safe_rel_path};

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
    /// git on the host ignores the path (see [`ignored_by_git`]): hidden and
    /// not applied unless [`ChangeSet::include_ignored`] is set.
    pub ignored: bool,
}

impl Change {
    /// Returns the change's path, relative to the project root.
    pub fn path(&self) -> &Path {
        Path::new(OsStr::from_bytes(&self.raw))
    }
    /// Returns true if the change is a deletion.
    fn op_is_delete(&self) -> bool {
        matches!(self.op, Op::Delete)
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
    /// Show, count and apply ignored changes too (`--ignored`).
    pub include_ignored: bool,
}

/// Returns true if path `p` (relative to the project root) names a file the
/// host will later execute, or one that configures tools on the host.
///
/// That covers build files (`Makefile`, `Cargo.toml`, `build.rs`,
/// `package.json`, `setup.py`, ...), environment and shell files
/// (`.envrc`, `.env`, `.bashrc`, ...), git attribute and module files, CI
/// and container configuration, and anything under editor, CI or agent
/// configuration directories such as `.vscode/`, `.github/` or `.claude/`,
/// at any depth, and scripts by extension (`.sh`, `.mk`, ...).  Changes
/// under a `core.hooksPath` inside the project and symlinks pointing
/// outside it are flagged too (see [`ChangeSet::from_stream`]).  Such
/// changes are highlighted in the review, not blocked.
pub fn is_sensitive(p: &[u8]) -> bool {
    let s = String::from_utf8_lossy(p);
    let name = s.rsplit('/').next().unwrap_or(&s);
    const NAMES: &[&str] = &[
        ".envrc", ".env", "Makefile", "makefile", "GNUmakefile", ".gitattributes", ".gitmodules",
        ".pre-commit-config.yaml", ".npmrc", ".yarnrc", ".yarnrc.yml", "package.json", "setup.py",
        "pyproject.toml", "build.rs", "Cargo.toml", ".bashrc", ".zshrc", ".profile", ".bash_profile",
        "Justfile", "justfile", "Taskfile.yml", "Dockerfile", ".editorconfig", ".clang-format", "conftest.py",
        ".gitlab-ci.yml", "Jenkinsfile", "flake.nix", "shell.nix", "direnv.toml",
        // more build systems and package manifests (dependency changes are
        // supply-chain changes)
        "CMakeLists.txt", "meson.build", "meson_options.txt", "configure", "configure.ac", "Makefile.am",
        "Makefile.in", "Kbuild", "Kconfig", "BUILD", "BUILD.bazel", "WORKSPACE", "MODULE.bazel", ".bazelrc",
        "SConstruct", "Rakefile", "Gemfile", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts",
        "settings.gradle", "setup.cfg", "tox.ini", "noxfile.py", "pytest.ini", "Pipfile", "requirements.txt",
        "requirements-dev.txt", "Vagrantfile", ".travis.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml",
        ".gitconfig", ".lfsconfig",
        // instructions every later agent run on this repository will follow
        "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md", "GEMINI.md", ".cursorrules",
        ".windsurfrules", ".clinerules",
    ];
    const EXTS: &[&str] = &[".mk", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".service", ".desktop"];
    const DIRS: &[&str] = &[
        ".vscode/", ".idea/", ".github/", ".husky/", ".devcontainer/", ".circleci/", ".claude/", ".cargo/",
        ".githooks/", ".gitlab/", ".buildkite/", ".gitea/", ".forgejo/", ".config/",
        ".codex/", ".cursor/", ".gemini/", ".windsurf/", ".clinerules/",
    ];
    NAMES.contains(&name)
        || EXTS.iter().any(|e| name.ends_with(e))
        || DIRS.iter().any(|d| s.starts_with(d) || s.contains(&format!("/{d}")))
}

/// Does symlink `path` (relative to the project root) with target `target`
/// point outside the project?  Absolute targets always do; relative ones
/// do when their `..` components climb above the root.  Such a link is
/// harmless to create, but host tools that later follow it (a build that
/// reads or copies it, an editor) reach files outside the project.
pub fn symlink_escapes(path: &[u8], target: &[u8]) -> bool {
    if target.first() == Some(&b'/') {
        return true;
    }
    // depth of the link's directory below the root
    let mut depth = path.iter().filter(|&&b| b == b'/').count() as isize;
    for comp in target.split(|&b| b == b'/') {
        match comp {
            b"" | b"." => {}
            b".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// Where git on the host looks for hooks, if that is inside the project:
/// `core.hooksPath` resolved against the repository's top level, made
/// relative to `cwd`.  Agent changes there are hooks git will run on the
/// host.  Returns `None` when unset, outside the project or not a repo.
fn hooks_path_in(cwd: &Path) -> Option<Vec<u8>> {
    let git = |args: &[&str]| crate::util::git(cwd, args).ok().filter(|s| !s.is_empty());
    let hp = git(&["config", "--get", "core.hooksPath"])?;
    let hp = crate::config::expand(&hp);
    let abs = if hp.is_absolute() { hp } else { PathBuf::from(git(&["rev-parse", "--show-toplevel"])?).join(hp) };
    let rel = abs.strip_prefix(cwd).ok()?;
    let mut v = rel.as_os_str().as_bytes().to_vec();
    if !v.is_empty() {
        v.push(b'/');
    }
    Some(v)
}

/// Which of `changes` git on the host ignores, in the same order.
///
/// Asks `git check-ignore` in `cwd`, so the rules are git's own: the
/// project's `.gitignore` files as they are on the host, `.git/info/exclude`
/// and the user's global excludes; tracked files are never ignored.  The
/// guest's copies of ignore files play no part, so an agent cannot hide its
/// changes by editing them.  Directories are asked about with a trailing `/`
/// (as patterns like `build/` need).  Paths git would refuse - unsafe ones,
/// or ones beneath a symlink on the host, which make it abort - are never
/// ignored.  Outside a git work tree, or if git fails, nothing is - nor
/// when git ignores the project directory itself: its rules are then about
/// an enclosing repository (a home directory under git with `*` ignored),
/// not the project.
fn ignored_by_git(cwd: &Path, changes: &[Change]) -> Vec<bool> {
    let mut out = vec![false; changes.len()];
    let project_ignored = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["check-ignore", "-q", "./"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|st| st.success());
    if project_ignored {
        return out;
    }
    let mut symlinked: HashMap<Vec<u8>, bool> = HashMap::new();
    let mut beneath_symlink = |raw: &[u8]| -> bool {
        let Some(slash) = raw.iter().rposition(|&b| b == b'/') else { return false };
        let parent = &raw[..slash];
        if let Some(&v) = symlinked.get(parent) {
            return v;
        }
        let mut p = cwd.to_path_buf();
        let mut v = false;
        for part in parent.split(|&b| b == b'/') {
            p.push(OsStr::from_bytes(part));
            match p.symlink_metadata() {
                Ok(md) if md.file_type().is_symlink() => {
                    v = true;
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        symlinked.insert(parent.to_vec(), v);
        v
    };
    let mut input = Vec::new();
    let mut asked: HashMap<Vec<u8>, usize> = HashMap::new();
    for (i, c) in changes.iter().enumerate() {
        if c.st == St::Container || safe_rel_path(&c.raw).is_none() || beneath_symlink(&c.raw) {
            continue;
        }
        let mut q = c.raw.clone();
        if matches!(c.op, Op::Dir { .. }) || (c.op_is_delete() && c.nested > 0) {
            q.push(b'/');
        }
        input.extend_from_slice(&q);
        input.push(0);
        asked.insert(q, i);
    }
    if asked.is_empty() {
        return out;
    }
    let child = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["check-ignore", "-z", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return out };
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let Ok(o) = child.wait_with_output() else { return out };
    let _ = writer.join();
    // 0: some are ignored, 1: none are; anything else is an error
    if o.status.code() != Some(0) {
        return out;
    }
    for p in o.stdout.split(|&b| b == 0).filter(|p| !p.is_empty()) {
        if let Some(&i) = asked.get(p) {
            out[i] = true;
        }
    }
    out
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
        let hooks = hooks_path_in(cwd);
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
            let sensitive = is_sensitive(&raw)
                || hooks.as_ref().is_some_and(|h| raw.starts_with(h))
                || matches!(&op, Op::Symlink { target } if symlink_escapes(&raw, target));
            let mut c = Change { raw: raw.clone(), op: op.clone(), st: St::Added, conflict: false, sensitive, mode_only: false, nested: 0, in_place: false, ignored: false };
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
                                ignored: false,
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
        let ignored = ignored_by_git(cwd, &changes);
        for (c, ig) in changes.iter_mut().zip(ignored) {
            c.ignored = ig;
        }
        // a new directory is ignored when everything in it is
        for i in (0..changes.len()).rev() {
            let c = &changes[i];
            if c.ignored || c.st != St::Added || !matches!(c.op, Op::Dir { .. }) {
                continue;
            }
            let dir = &c.raw;
            let mut kids = changes.iter().filter(|k| under(&k.raw, dir)).peekable();
            if kids.peek().is_some() && kids.all(|k| k.ignored) {
                changes[i].ignored = true;
            }
        }
        Ok(ChangeSet { stream: stream.to_path_buf(), changes, git, cwd: cwd.to_path_buf(), include_ignored: false })
    }

    /// Returns true if change `c` is part of the review: not ignored, or
    /// ignored changes were asked for.
    pub(crate) fn wanted(&self, c: &Change) -> bool {
        self.include_ignored || !c.ignored
    }

    /// Returns the number of changes git ignores, counted like
    /// [`ChangeSet::summary`] (new directories are not counted).
    pub fn ignored_count(&self) -> usize {
        self.changes.iter().filter(|c| c.ignored && c.shown() && !matches!((c.st, &c.op), (St::Added, Op::Dir { .. }))).count()
    }

    /// Count the changes for display and for `meta.json`: added files and
    /// symlinks (new directories are not counted), modified and deleted
    /// entries, and `.git/` entries.  Returns the counts.
    pub fn summary(&self) -> Summary {
        let mut s = Summary { git_internal: self.git.len(), ignored: if self.include_ignored { 0 } else { self.ignored_count() }, ..Default::default() };
        for c in self.changes.iter().filter(|c| self.wanted(c)) {
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
        self.changes.iter().filter(|c| c.shown() && self.wanted(c) && !(c.st == St::Added && matches!(c.op, Op::Dir { .. }) && self.has_children(&c.raw)))
    }

    /// Returns true if some change lies strictly beneath directory `dir`.
    fn has_children(&self, dir: &[u8]) -> bool {
        self.changes.iter().any(|c| self.wanted(c) && c.raw.len() > dir.len() && c.raw.starts_with(dir) && c.raw[dir.len()] == b'/')
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
        self.shown().filter(|c| c.conflict).collect()
    }
}

// ---------------------------------------------------------------------------
// presentation
// ---------------------------------------------------------------------------

/// Describe `s` in one line for the review, e.g.
/// `3 files changed: 1 modified, 2 added`, or `no changes`, then how many
/// changes git ignores, if any.  `.git/` entries are not included.
pub fn summary_line(s: &Summary) -> String {
    let n = s.added + s.modified + s.deleted;
    let ig = if s.ignored > 0 { format!(" (+{} ignored by git)", s.ignored) } else { String::new() };
    if n == 0 {
        return format!("no changes{ig}");
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
    format!("{n} file{} changed: {}{ig}", if n == 1 { "" } else { "s" }, parts.join(", "))
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
        let mut p = crate::util::safe_path(c.path());
        match &c.op {
            Op::Dir { .. } => p.push('/'),
            Op::Symlink { target } => p.push_str(&format!(" -> {}", crate::util::safe_text(target, false))),
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
        let escapes = matches!(&c.op, Op::Symlink { target } if symlink_escapes(&c.raw, target));
        if escapes {
            notes.push(format!("{y}points outside the project{z}"));
        } else if c.sensitive {
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
        // file names and contents are the agent's: never let them drive the
        // terminal (raw bytes are kept for `diff > file`)
        let d = colorize(crate::util::safe_text(&d, true).as_bytes());
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
