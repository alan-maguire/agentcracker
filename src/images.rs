//! Building and caching the read-only images the guest boots from, and
//! creating the scratch disk.
//!
//! ```text
//! base.img     tiny root: acinit, mount points, usr-merge symlinks, a
//!              minimal passwd/group and an allowlisted subset of host /etc
//! usr.img      snapshot of host /usr (shared by all sessions)
//! tools.img    snapshot of toolchain dirs found on $PATH outside /usr
//! lower.img    snapshot of the project directory
//! scratch.img  per-session sparse ext4 disk (the only writable one)
//! ```
//!
//! The images are EROFS, written by [`crate::erofs`], and cached under
//! `~/.cache/agentcracker/{base,usr,tools,lower}/` with the cache key in
//! the file name.  Keys are FNV hashes of cheap signals rather than of
//! content:
//!
//! - base: user, group, uid, gid, home and shell; the acinit binary's
//!   mtime; the allowlisted /etc entries' mtimes; the usr-merge symlinks.
//! - usr: package database mtimes, plus directory mtimes two levels into
//!   /usr and three into /usr/local (installs and removals touch them).
//! - tools: the toolchain roots and their directory mtimes.
//! - lower: the full manifest (path, mode, size, mtime, inode) of the
//!   project tree, so any edit gives a new snapshot.
//!
//! A stale /usr snapshot keeps being used while a new one is built in the
//! background (`agentcracker refresh --background`), so a package update
//! never delays a session.  A `lock` file in each cache directory
//! serialises builders, and old images are deleted once a new one is in
//! place (project snapshots are garbage-collected after a week unused).
//!
//! [`find_asset`] locates the files installed by `make install`
//! (`firecracker`, `vmlinux`, `acinit`, `seccomp.bpf`).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::config::{Config, expand};
use crate::erofs::{ManifestEntry, Node, Tree, WalkStats, write_image};
use crate::util::{Context, Excludes, Fnv, Result, cache_dir, home, human_bytes, lock, tilde, try_lock};

/// Mixed into every cache key.  Bump it when the image layout or the rules
/// for what goes into an image change, so old cached images are not reused.
const FORMAT: &str = "agentcracker-images-v1";

/// Print a progress or status message to stderr as `agentcracker: <msg>`,
/// dimmed when stderr is a terminal.
///
/// `msg`: the message, without a trailing newline.
pub fn status(msg: &str) {
    if crate::util::isatty(2) {
        eprintln!("\x1b[2magentcracker: {msg}\x1b[0m");
    } else {
        eprintln!("agentcracker: {msg}");
    }
}

// ---------------------------------------------------------------------------
// assets shipped by `make install`
// ---------------------------------------------------------------------------

/// Locate an installed asset: `firecracker`, `vmlinux`, `acinit` or
/// `seccomp.bpf`.
///
/// Candidates, in order: `$AGENTCRACKER_LIB/<name>`;
/// `<directory of this binary>/../lib/agentcracker/<name>` (the
/// `make install` layout); and, for a binary running from a source checkout
/// (`target/release/agentcracker`), the matching build output in the
/// repository - for `vmlinux`, every `build/vmlinux-*`, highest kernel
/// version first.
///
/// `name`: the asset.  Returns the first candidate that is a regular file,
/// canonicalised; errors, listing every place looked at, if none is.
pub fn find_asset(name: &str) -> Result<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Some(d) = std::env::var_os("AGENTCRACKER_LIB") {
        cands.push(PathBuf::from(d).join(name));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin) = exe.parent() {
            cands.push(bin.join("../lib/agentcracker").join(name));
            // running from a source checkout: target/release/agentcracker
            let repo = bin.join("../..");
            let triple = "x86_64-unknown-linux-gnu";
            match name {
                "firecracker" => cands.push(repo.join(format!("firecracker/build/cargo_target/{triple}/release/firecracker"))),
                "seccomp.bpf" => cands.push(repo.join("build/seccomp.bpf")),
                "acinit" => cands.push(repo.join(format!("build/acinit-target/{triple}/release/agentcracker"))),
                "vmlinux" => {
                    if let Ok(rd) = std::fs::read_dir(repo.join("build")) {
                        let mut v: Vec<PathBuf> = rd
                            .filter_map(|e| e.ok())
                            .map(|e| e.path())
                            .filter(|p| p.file_name().is_some_and(|n| n.as_bytes().starts_with(b"vmlinux-")))
                            .collect();
                        // newest kernel version first (6.18.60 > 6.18.9)
                        v.sort_by_key(|p| std::cmp::Reverse(kernel_version_key(p)));
                        cands.extend(v);
                    }
                }
                _ => {}
            }
        }
    }
    for c in &cands {
        if c.is_file() {
            return Ok(c.canonicalize().unwrap_or_else(|_| c.clone()));
        }
    }
    crate::bail!("cannot find {name} (looked in {}); run `make install`", cands.iter().map(|c| c.display().to_string()).collect::<Vec<_>>().join(", "))
}

/// Sort key for a `vmlinux-<version>` path: the numeric components of the
/// version, so versions compare numerically rather than as text, with the
/// path as tie-breaker so the order is total.
///
/// `p`: the kernel path.  Returns the key; sort with `Reverse` for newest
/// first.
fn kernel_version_key(p: &Path) -> (Vec<u64>, PathBuf) {
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let ver = name.strip_prefix("vmlinux-").unwrap_or(&name);
    let nums = ver
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap_or(u64::MAX))
        .collect();
    (nums, p.to_path_buf())
}

/// Tests for [`kernel_version_key`].
#[cfg(test)]
mod kernel_version_tests {
    use super::kernel_version_key;
    use std::path::{Path, PathBuf};

    /// `6.18.100 > 6.18.60 > 6.18.9 > 6.9.1`, not the text order.
    #[test]
    fn newest_version_first() {
        let mut v: Vec<PathBuf> = ["vmlinux-6.18.60", "vmlinux-6.18.9", "vmlinux-6.9.1", "vmlinux-6.18.100"]
            .iter()
            .map(|s| Path::new("build").join(s))
            .collect();
        v.sort_by_key(|p| std::cmp::Reverse(kernel_version_key(p)));
        let names: Vec<_> = v.iter().map(|p| p.file_name().unwrap().to_str().unwrap()).collect();
        assert_eq!(names, ["vmlinux-6.18.100", "vmlinux-6.18.60", "vmlinux-6.18.9", "vmlinux-6.9.1"]);
    }
}

// ---------------------------------------------------------------------------
// /usr
// ---------------------------------------------------------------------------

/// How [`usr_image`] treats a /usr snapshot that is out of date.
#[derive(PartialEq, Clone, Copy)]
pub enum Refresh {
    /// Normal use: return the current snapshot if there is one; if only an
    /// older one exists, return that and start a background rebuild; build in
    /// the foreground only when there is no snapshot at all.
    Auto,
    /// `agentcracker refresh`: rebuild now, in the foreground, even if a
    /// snapshot for the current key exists.
    Force,
    /// The background rebuild itself (`refresh --background`): build if
    /// missing, without status output.
    Background,
}

/// Mix `p`'s path, mtime (seconds and nanoseconds) and size into `h`: a
/// cheap "has this changed" signal.
///
/// Uses `lstat`, so for a symlink its own metadata counts.  A missing path
/// contributes nothing (so its later appearance changes the hash).
fn mtime_sig(h: &mut Fnv, p: &Path) {
    if let Ok(m) = std::fs::symlink_metadata(p) {
        h.bytes(p.as_os_str().as_bytes()).u64(m.mtime() as u64).u64(m.mtime_nsec() as u64).u64(m.size());
    }
}

/// Mix the mtimes of `root` and of the directories up to `depth` levels
/// below it into `h`, in sorted order.
///
/// Creating or deleting an entry changes its directory's mtime, so this
/// detects installs and removals without reading every file.  `budget`: the
/// maximum number of subdirectories to visit, decremented as they are
/// visited; it bounds the cost on huge trees, at the price of missing
/// changes beyond it.  Symlinked directories are not followed.
fn dir_sig(h: &mut Fnv, root: &Path, depth: usize, budget: &mut usize) {
    mtime_sig(h, root);
    if depth == 0 || *budget == 0 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(root) else { return };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    v.sort();
    for d in v {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        dir_sig(h, &d, depth - 1, budget);
    }
}

/// Compute the cache key of the /usr snapshot.
///
/// It hashes the image [`FORMAT`], the configured /usr excludes, the
/// package database mtimes (rpm, dpkg, pacman, apk), and directory mtimes
/// two levels into /usr and three into /usr/local, which has no package
/// database.  `cfg`: supplies `exclude_usr`.  Returns the key as 16 hex
/// digits.
fn usr_key(cfg: &Config) -> String {
    let mut h = Fnv::new();
    h.str(FORMAT);
    for e in &cfg.exclude_usr {
        h.str(e);
    }
    // package databases
    for p in [
        "/usr/lib/sysimage/rpm/rpmdb.sqlite",
        "/var/lib/rpm/rpmdb.sqlite",
        "/var/lib/rpm/Packages",
        "/var/lib/dpkg/status",
        "/var/lib/pacman/local",
        "/lib/apk/db/installed",
    ] {
        mtime_sig(&mut h, Path::new(p));
    }
    // package installs/removals touch directory mtimes; /usr/local has no db
    let mut budget = 4000;
    dir_sig(&mut h, Path::new("/usr"), 2, &mut budget);
    let mut budget = 2000;
    dir_sig(&mut h, Path::new("/usr/local"), 3, &mut budget);
    h.hex()
}

/// Returns the most recently modified `<prefix>*.img` file in `dir`, or
/// `None` if there is none (or `dir` cannot be read).
fn newest(dir: &Path, prefix: &str) -> Option<PathBuf> {
    let rd = std::fs::read_dir(dir).ok()?;
    rd.filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with(prefix) && n.ends_with(".img")
        })
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .map(|e| e.path())
}

/// Delete every `<prefix>*.img` file and every `<prefix>*` temporary file
/// (`.tmp` in the name) in `dir`, except `keep`.
///
/// Called, with the cache lock held, after a new image is in place.  A VM
/// still running from an old image keeps its open file, so deleting it is
/// safe.  Errors are ignored.
fn remove_others(dir: &Path, prefix: &str, keep: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.filter_map(|e| e.ok()) {
            let n = e.file_name();
            let n = n.to_string_lossy();
            if n.starts_with(prefix) && (n.ends_with(".img") || n.contains(".tmp")) && e.path() != keep {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Return a /usr snapshot to boot from, building one if needed.
///
/// `cfg`: supplies the /usr excludes; `mode`: see [`Refresh`].
///
/// If `usr-<key>.img` for the current key exists it is returned (unless
/// `mode` is `Force`).  In `Auto` mode, if only an older snapshot exists it
/// is returned at once and a background rebuild is started.  Otherwise the
/// snapshot is built under the cache directory's lock (checking again once
/// the lock is held, in case another builder just finished), older
/// snapshots are deleted, and the new one is returned.
///
/// All of /usr is walked except the excluded paths; files the user cannot
/// read are skipped and counted.  Owners are kept, so root-owned files stay
/// root-owned in the guest.
///
/// Returns the image path; errors if /usr cannot be walked or the image
/// cannot be written.
pub fn usr_image(cfg: &Config, mode: Refresh) -> Result<PathBuf> {
    let dir = cache_dir().join("usr");
    crate::util::mkdir_private(&dir)?;
    let key = usr_key(cfg);
    let target = dir.join(format!("usr-{key}.img"));
    if target.exists() && mode != Refresh::Force {
        return Ok(target);
    }
    if mode == Refresh::Auto {
        if let Some(old) = newest(&dir, "usr-") {
            // keep booting the previous snapshot; rebuild behind the user's back
            spawn_background_refresh();
            return Ok(old);
        }
    }
    let _l = lock(&dir.join("lock"))?;
    if target.exists() && mode != Refresh::Force {
        return Ok(target);
    }
    if mode != Refresh::Background {
        status("snapshotting /usr (first run or forced; later rebuilds happen in the background)");
    }
    let t = Instant::now();
    let excl = Excludes::new(&cfg.exclude_usr.iter().map(|e| format!("/{}", e.trim_matches('/'))).collect::<Vec<_>>());
    let mut tree = Tree::new(0o755, 0, 0);
    let mut stats = WalkStats::default();
    tree.walk_into(0, Path::new("/usr"), &excl, None, None, &mut stats)?;
    let size = write_image(&tree, &target)?;
    remove_others(&dir, "usr-", &target);
    if mode != Refresh::Background {
        status(&format!(
            "/usr snapshot: {} files, {} ({} skipped as unreadable) in {:.1}s",
            stats.files,
            human_bytes(size),
            stats.skipped.len(),
            t.elapsed().as_secs_f64()
        ));
    }
    Ok(target)
}

/// Start `agentcracker refresh --background` as a detached process (a new
/// session via `setsid`, stdin from /dev/null, output appended to
/// `~/.cache/agentcracker/refresh.log`) to rebuild the /usr snapshot without
/// delaying the current boot.
///
/// Does nothing if a builder already holds the /usr lock or the path of
/// this executable cannot be found.  The lock is only probed here; the
/// child takes it itself.  Failure to spawn is ignored (the next run tries
/// again).
fn spawn_background_refresh() {
    let dir = cache_dir().join("usr");
    // already running?
    match try_lock(&dir.join("lock")) {
        Ok(Some(_l)) => {}
        _ => return,
    }
    let Ok(exe) = std::env::current_exe() else { return };
    let log = std::fs::File::create(cache_dir().join("refresh.log")).ok();
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("refresh").arg("--background").stdin(std::process::Stdio::null());
    if let Some(l) = log {
        if let Ok(l2) = l.try_clone() {
            cmd.stdout(l).stderr(l2);
        }
    }
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    if cmd.spawn().is_ok() {
        status("host packages changed: refreshing the /usr snapshot in the background");
    }
}

// ---------------------------------------------------------------------------
// toolchains outside /usr
// ---------------------------------------------------------------------------

/// Paths below `$HOME` that are never snapshotted as toolchains, even when
/// they are on `$PATH`: credential stores, cloud and cluster configs,
/// browser profiles and agent state.  A candidate root is rejected if it is
/// inside one of these or contains one.
const NEVER_TOOLS: &[&str] = &[
    ".ssh", ".gnupg", ".aws", ".azure", ".config", ".kube", ".docker", ".password-store",
    ".mozilla", ".netrc", ".git-credentials", ".local/share/keyrings", ".claude", ".codex",
];

/// Left out of the toolchain snapshot: caches and scratch space, and the
/// well-known places toolchains keep registry credentials (cargo's
/// `credentials`/`credentials.toml` at the root of `~/.cargo`, npm, PyPI,
/// netrc and git credential files anywhere), which the agent has no use
/// for and could otherwise read and send out.
const TOOLS_EXCLUDE: &[&str] = &[
    ".cache/", "/downloads/", "/tmp/",
    "/credentials", "/credentials.toml", ".npmrc", ".pypirc", ".netrc", ".git-credentials",
];

/// Map a directory found on `$PATH` (or holding a symlink's target) to the
/// toolchain root to snapshot so that it works in the guest.
///
/// `p`: canonical directory; `h`: the home directory.
///
/// - under `/usr`, or `/bin` / `/sbin`: `None` (already in the guest);
/// - `~/.local/bin`: itself; `~/.local/<x>/<y>/...`: `~/.local/<x>/<y>`
///   (e.g. `~/.local/share/fnm`);
/// - anywhere else in home: its first component (`~/.cargo/bin` gives
///   `~/.cargo`, `~/go/bin` gives `~/go`);
/// - `/opt/<x>/...`: `/opt/<x>`;
/// - anything else: `p` itself.
///
/// Returns the root, or `None` if nothing needs snapshotting (or the path
/// is too short to classify, such as `~/.local` itself).
fn tool_root_for(p: &Path, h: &Path) -> Option<PathBuf> {
    if p.starts_with("/usr") || p == Path::new("/bin") || p == Path::new("/sbin") {
        return None;
    }
    if let Ok(rel) = p.strip_prefix(h) {
        let mut comps = rel.components();
        let first = comps.next()?.as_os_str().to_owned();
        if first == ".local" {
            // ~/.local/bin itself, or ~/.local/share/X, ~/.local/lib/X
            let second = comps.next()?.as_os_str().to_owned();
            if second == "bin" {
                return Some(h.join(".local/bin"));
            }
            let third = comps.next()?.as_os_str().to_owned();
            return Some(h.join(".local").join(second).join(third));
        }
        return Some(h.join(first));
    }
    if let Ok(rel) = p.strip_prefix("/opt") {
        return rel.components().next().map(|c| Path::new("/opt").join(c));
    }
    Some(p.to_path_buf())
}

/// Work out which host directories outside /usr the guest needs, so that
/// the user's tools behave as they do in their shell.
///
/// Candidates are: the toolchain root (see [`tool_root_for`]) of every
/// absolute directory on `$PATH`; the roots of the targets of symlinks in
/// those directories (e.g. `~/.local/bin/claude` pointing into
/// `~/.local/share/claude`); `~/.rustup` when `~/.cargo` is used; and the
/// `tools` entries of the config.  When the project lives inside a root
/// (say `~/go/src/x` inside `~/go`), only the `$PATH` directory itself is
/// taken.
///
/// A candidate is dropped if it is: home itself or an ancestor of it; not a
/// directory; the project or inside it; inside, or containing, a
/// [`NEVER_TOOLS`] path; inside a `no_tools` path; or inside another
/// chosen root (a root that contains roots chosen earlier replaces them).
///
/// `cfg`: the configuration (`tools`, `no_tools`); `cwd`: the project
/// directory.  Returns the roots, as canonical absolute paths.
pub fn detect_tools(cfg: &Config, cwd: &Path) -> Vec<PathBuf> {
    let h = home();
    let mut roots: BTreeSet<PathBuf> = BTreeSet::new();
    let path = std::env::var("PATH").unwrap_or_default();
    for d in path.split(':').filter(|d| d.starts_with('/')) {
        let Ok(canon) = Path::new(d).canonicalize() else { continue };
        let Some(mut root) = tool_root_for(&canon, &h) else { continue };
        if cwd.starts_with(&root) {
            root = canon.clone(); // e.g. ~/go/bin when working in ~/go/src/x
        }
        roots.insert(root);
        // symlinked executables pointing elsewhere (e.g. ~/.local/bin/claude)
        if let Ok(rd) = std::fs::read_dir(&canon) {
            for e in rd.filter_map(|e| e.ok()) {
                if !e.file_type().is_ok_and(|t| t.is_symlink()) {
                    continue;
                }
                let Ok(t) = e.path().canonicalize() else { continue };
                if let Some(r) = t.parent().and_then(|p| tool_root_for(p, &h)) {
                    if !cwd.starts_with(&r) {
                        roots.insert(r);
                    }
                }
            }
        }
    }
    if roots.contains(&h.join(".cargo")) && h.join(".rustup").is_dir() {
        roots.insert(h.join(".rustup"));
    }
    for t in &cfg.tools {
        let p = expand(t);
        if p.exists() {
            roots.insert(p.canonicalize().unwrap_or(p));
        }
    }
    let no: Vec<PathBuf> = cfg.no_tools.iter().map(|t| expand(t)).collect();
    let mut out: Vec<PathBuf> = Vec::new();
    'outer: for r in roots {
        if r == h || h.starts_with(&r) || !r.is_dir() || cwd == r || r.starts_with(cwd) {
            continue;
        }
        for n in NEVER_TOOLS {
            let s = h.join(n);
            if r.starts_with(&s) || s.starts_with(&r) {
                continue 'outer;
            }
        }
        if no.iter().any(|n| r.starts_with(n)) {
            continue;
        }
        if out.iter().any(|o| r.starts_with(o)) {
            continue;
        }
        out.retain(|o| !o.starts_with(&r));
        out.push(r);
    }
    out
}

/// Return an image containing the toolchain directories `tools` at their
/// host paths, building it if needed.
///
/// The cache key covers the image format, each root's path and directory
/// mtimes (two levels deep, bounded), the mtimes of the `$PATH` entries
/// inside it, and `cfg.no_tools`.  Directories leading to a root are
/// root-owned, except those inside `$HOME`, which belong to the user.  Any
/// `.cache/` directory, and `downloads/` and `tmp/` at the top of a root,
/// are left out.  Older tool images are deleted once a new one is written.
/// An empty `tools` still gives a (tiny) image, because the VM always has a
/// tools drive.
///
/// Returns the image path; errors if a root cannot be walked or the image
/// cannot be written.
pub fn tools_image(cfg: &Config, tools: &[PathBuf]) -> Result<PathBuf> {
    let dir = cache_dir().join("tools");
    crate::util::mkdir_private(&dir)?;
    let mut h = Fnv::new();
    h.str(FORMAT);
    for e in TOOLS_EXCLUDE {
        h.str(e); // a changed list must not reuse an image built without it
    }
    let path = std::env::var("PATH").unwrap_or_default();
    for t in tools {
        h.bytes(t.as_os_str().as_bytes());
        let mut budget = 3000;
        dir_sig(&mut h, t, 2, &mut budget);
        for d in path.split(':') {
            if Path::new(d).starts_with(t) {
                mtime_sig(&mut h, Path::new(d));
            }
        }
    }
    for e in &cfg.no_tools {
        h.str(e);
    }
    let target = dir.join(format!("tools-{}.img", h.hex()));
    if target.exists() {
        return Ok(target);
    }
    let _l = lock(&dir.join("lock"))?;
    if target.exists() {
        return Ok(target);
    }
    if !tools.is_empty() {
        status(&format!(
            "snapshotting toolchains: {}",
            tools.iter().map(|t| tilde(t)).collect::<Vec<_>>().join(" ")
        ));
    }
    let t0 = Instant::now();
    let hm = home();
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let excl = Excludes::new(&TOOLS_EXCLUDE.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let mut tree = Tree::new(0o755, 0, 0);
    let mut stats = WalkStats::default();
    for t in tools {
        let rel = t.strip_prefix("/").unwrap_or(t);
        // intermediate dirs inside $HOME belong to the user
        let mut cur = 0;
        let mut acc = PathBuf::from("/");
        for c in rel.components() {
            acc.push(c);
            let name = c.as_os_str().as_bytes();
            cur = match tree.child(cur, name) {
                Some(n) => n,
                None => {
                    let (u, g) = if acc.starts_with(&hm) { (uid, gid) } else { (0, 0) };
                    tree.add(cur, name, Node::dir(0o755, u, g))
                }
            };
        }
        tree.walk_into(cur, t, &excl, None, None, &mut stats)?;
    }
    let size = write_image(&tree, &target)?;
    remove_others(&dir, "tools-", &target);
    if !tools.is_empty() {
        status(&format!("toolchains: {} files, {} in {:.1}s", stats.files, human_bytes(size), t0.elapsed().as_secs_f64()));
    }
    Ok(target)
}

// ---------------------------------------------------------------------------
// base root filesystem
// ---------------------------------------------------------------------------

/// Host /etc entries copied into the guest's base image: dynamic linker
/// configuration, CA certificates and crypto policy, OS identification,
/// locale and timezone, shell startup files and a few tool configs.
/// Never: shadow, sudoers, ssh, machine-id, keytabs, NetworkManager, or
/// anything not named here.  `passwd`, `group`, `hosts`, `hostname` and
/// `resolv.conf` are generated instead (see [`base_image`]).
const ETC_ALLOW: &[&str] = &[
    "ld.so.conf", "ld.so.conf.d", "ld.so.cache", "alternatives",
    "ssl", "pki", "ca-certificates", "ca-certificates.conf", "crypto-policies",
    "os-release", "lsb-release", "debian_version", "fedora-release", "redhat-release", "system-release",
    "localtime", "timezone", "locale.conf", "locale.gen", "default/locale",
    "nsswitch.conf", "profile", "profile.d", "bashrc", "bash.bashrc", "zshrc", "zprofile", "zshenv",
    "inputrc", "shells", "environment", "services", "protocols", "mime.types", "magic",
    "gitconfig", "vimrc", "virc", "nanorc", "man_db.conf", "manpath.config", "terminfo",
    "login.defs", "npmrc", "pip.conf", "xdg/user-dirs.defaults",
];

/// Copy the [`ETC_ALLOW`] entries of host /etc into directory node `etc`.
///
/// Files are read into memory, root-owned and made world-readable
/// (`mode & 0o644 | 0o444`); directories are walked with every node forced
/// to root ownership, leaving out `private/` directories and `*.key` files;
/// symlinks are copied as symlinks.  Entries this host does not have are
/// skipped, and so are files the user cannot read.
///
/// `tree`: the base image tree; `etc`: the index of its `/etc` node;
/// `stats`: receives skipped paths.  Returns an error if a directory cannot
/// be walked at all or a symlink cannot be read.
fn etc_tree(tree: &mut Tree, etc: usize, stats: &mut WalkStats) -> Result<()> {
    let excl = Excludes::new(&["private/".into(), "*.key".into()]);
    for name in ETC_ALLOW {
        let src = Path::new("/etc").join(name);
        let Ok(md) = std::fs::symlink_metadata(&src) else { continue };
        let rel = Path::new(name);
        let parent = match rel.parent() {
            Some(p) if !p.as_os_str().is_empty() => tree.mkdir_p_at(etc, p, 0o755, 0, 0),
            _ => etc,
        };
        let fname = rel.file_name().unwrap().as_bytes();
        let ft = md.file_type();
        if ft.is_symlink() {
            let t = std::fs::read_link(&src)?;
            tree.add(parent, fname, Node::symlink(t.as_os_str().as_bytes(), 0, 0));
        } else if ft.is_dir() {
            let id = tree.add(parent, fname, Node::dir(0o755, 0, 0));
            tree.walk_into(id, &src, &excl, Some((0, 0)), None, stats)?;
        } else if ft.is_file() {
            if let Ok(data) = std::fs::read(&src) {
                tree.add(parent, fname, Node::bytes(data, md.mode() & 0o644 | 0o444, 0, 0));
            }
        }
    }
    Ok(())
}

/// Return the base root filesystem image, building it if needed.
///
/// Contents: `/acinit`, copied from `acinit`; the usual top-level
/// directories plus the mount points acinit uses (`/scratch`,
/// `/lower/{base,usr,tools,proj}`, `/newroot`); the host's usr-merge
/// symlinks (`/bin -> usr/bin` and so on); the allowlisted /etc entries
/// (see [`etc_tree`]); generated `passwd`, `group`, `hosts`, `hostname` and
/// `resolv.conf` that know only root, the invoking user and nobody; and an
/// empty home directory owned by the user.
///
/// The cache key covers the invoking user's identity, acinit's mtime, the
/// allowlisted /etc entries and the usr-merge symlinks, so the image is
/// rebuilt whenever any of them change.  Warns if the host is not
/// usr-merged (programs in a real `/bin` would be missing in the guest).
///
/// `acinit`: path of the static acinit binary.  Returns the image path.
pub fn base_image(acinit: &Path) -> Result<PathBuf> {
    let dir = cache_dir().join("base");
    crate::util::mkdir_private(&dir)?;
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let user = crate::util::user_name(uid);
    let group = crate::util::group_name(gid);
    let hm = home();
    let shell = crate::util::user_shell(uid);

    let mut h = Fnv::new();
    h.str(FORMAT).str(&user).str(&group).u64(uid as u64).u64(gid as u64).bytes(hm.as_os_str().as_bytes()).str(&shell);
    mtime_sig(&mut h, acinit);
    for name in ETC_ALLOW {
        let mut budget = 200;
        dir_sig(&mut h, &Path::new("/etc").join(name), 1, &mut budget);
    }
    for l in ["bin", "sbin", "lib", "lib64", "lib32", "libx32"] {
        if let Ok(t) = std::fs::read_link(Path::new("/").join(l)) {
            h.bytes(t.as_os_str().as_bytes());
        }
    }
    let target = dir.join(format!("base-{}.img", h.hex()));
    if target.exists() {
        return Ok(target);
    }
    let _l = lock(&dir.join("lock"))?;
    if target.exists() {
        return Ok(target);
    }

    let mut t = Tree::new(0o755, 0, 0);
    let acinit_data = std::fs::read(acinit).ctx(format!("read {}", acinit.display()))?;
    t.add(0, b"acinit", Node::bytes(acinit_data, 0o755, 0, 0));
    for (d, mode) in [
        ("proc", 0o555), ("sys", 0o555), ("dev", 0o755), ("run", 0o755), ("tmp", 0o1777),
        ("mnt", 0o755), ("scratch", 0o700), ("lower", 0o700), ("lower/base", 0o755),
        ("lower/usr", 0o755), ("lower/tools", 0o755), ("lower/proj", 0o755), ("lower/projdelta", 0o755), ("newroot", 0o755),
        ("home", 0o755), ("root", 0o700), ("var", 0o755), ("var/tmp", 0o1777), ("var/lib", 0o755),
        ("var/cache", 0o755), ("var/log", 0o755), ("opt", 0o755), ("srv", 0o755), ("usr", 0o755),
        ("etc", 0o755),
    ] {
        let id = t.mkdir_p(Path::new(d), 0o755, 0, 0);
        t.nodes[id].mode = libc::S_IFDIR | mode;
    }
    let mut merged = true;
    for l in ["bin", "sbin", "lib", "lib64", "lib32", "libx32"] {
        match std::fs::read_link(Path::new("/").join(l)) {
            Ok(target) => {
                t.add(0, l.as_bytes(), Node::symlink(target.as_os_str().as_bytes(), 0, 0));
            }
            Err(_) => {
                if Path::new("/").join(l).is_dir() && l != "lib32" && l != "libx32" {
                    merged = false;
                }
            }
        }
    }
    if !merged {
        status("warning: host is not usr-merged; programs outside /usr will be missing in the guest");
    }
    let etc = t.child(0, b"etc").unwrap();
    let mut stats = WalkStats::default();
    etc_tree(&mut t, etc, &mut stats)?;
    let hm_s = hm.display().to_string();
    let files: Vec<(&str, String, u32)> = vec![
        ("passwd", format!("root:x:0:0:root:/root:/bin/sh\n{user}:x:{uid}:{gid}::{hm_s}:{shell}\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n"), 0o644),
        ("group", format!("root:x:0:\n{group}:x:{gid}:{user}\nnobody:x:65534:\n"), 0o644),
        ("hosts", "127.0.0.1 localhost agentcracker\n::1 localhost\n".into(), 0o644),
        ("hostname", "agentcracker\n".into(), 0o644),
        ("resolv.conf", "# no DNS inside agentcracker: use the HTTPS proxy ($HTTPS_PROXY)\nnameserver 127.0.0.1\n".into(), 0o644),
    ];
    for (name, content, mode) in files {
        if let Some(old) = t.child(etc, name.as_bytes()) {
            if let crate::erofs::Kind::Dir(ch) = &mut t.nodes[etc].kind {
                ch.remove(name.as_bytes());
            }
            let _ = old;
        }
        t.add(etc, name.as_bytes(), Node::bytes(content.into_bytes(), mode, 0, 0));
    }
    // the user's home directory (contents live on the scratch disk)
    let rel = hm.strip_prefix("/").unwrap_or(&hm);
    if !rel.as_os_str().is_empty() {
        let id = t.mkdir_p(rel, 0o755, 0, 0);
        t.nodes[id].uid = uid;
        t.nodes[id].gid = gid;
        t.nodes[id].mode = libc::S_IFDIR | 0o700;
    }
    write_image(&t, &target)?;
    remove_others(&dir, "base-", &target);
    Ok(target)
}

// ---------------------------------------------------------------------------
// the project directory
// ---------------------------------------------------------------------------

/// A project snapshot: a base image, optionally a delta layer over it, and
/// the manifest of the tree they add up to.
pub struct Lower {
    /// Path of the cached base image.
    pub image: PathBuf,
    /// A small image of what changed since `image` was taken (changed
    /// entries plus whiteouts for deletions), stacked above it in the guest.
    pub delta: Option<PathBuf>,
    /// The manifest (one entry per file) in binary form, in the cache;
    /// sessions hardlink it for conflict detection.
    pub manifest_file: PathBuf,
}

/// A delta bigger than this (entries changed, as a fraction of all
/// entries; or bytes of file data) is not worth it: write a new base.
const DELTA_MAX_FRACTION: usize = 4;
const DELTA_MAX_BYTES: u64 = 1 << 30;

/// Snapshot the project directory `cwd`.
///
/// Walks the whole tree (minus `cfg.exclude`), recording a manifest, and
/// derives the cache key from the manifest (paths, modes, sizes, mtimes,
/// inode numbers) plus `cwd` and its own mode and owner.  Then, cheapest
/// first:
///
/// - an image with that key exists (nothing changed): reuse it;
/// - a delta for that key over the most recently used base exists: reuse it;
/// - the change since that base is small: write a delta image holding just
///   the changed entries and whiteouts for the deleted ones (a few files to
///   copy instead of the whole tree);
/// - otherwise write a full image, which becomes the new base.
///
/// Cache files: `<dir>-<key>.img` (full), `<dir>-<key>.delta-<base>.img`
/// and `<dir>-<key>.manifest`, where `<dir>` hashes `cwd`.  Old unused
/// files are garbage-collected first (see [`gc_lower`]).
///
/// Returns the images and the manifest; errors if `cwd` cannot be walked or
/// an image cannot be written.
pub fn lower_image(cfg: &Config, cwd: &Path) -> Result<Lower> {
    let dir = cache_dir().join("lower");
    crate::util::mkdir_private(&dir)?;
    gc_lower(&dir);
    let t0 = Instant::now();
    let excl = Excludes::new(&cfg.exclude);
    let mut tree = Tree::new(0o755, 0, 0);
    let mut manifest = Vec::new();
    let mut stats = WalkStats::default();
    tree.walk_into(0, cwd, &excl, None, Some(&mut manifest), &mut stats)?;
    scrub_git_config(&mut tree, cwd);
    let mut hd = Fnv::new();
    hd.str(FORMAT).bytes(cwd.as_os_str().as_bytes());
    if let Ok(md) = std::fs::metadata(cwd) {
        hd.u64(md.mode() as u64).u64(md.uid() as u64);
    }
    let dkey = hd.hex();
    let mut h = Fnv::new();
    // "scrub1": snapshots from before .git/config scrubbing are not reused
    h.str(&dkey).str("scrub1");
    for m in &manifest {
        h.bytes(&m.raw).u64(m.mode as u64).u64(m.size).u64(m.mtime_ns as u64).u64(m.ino);
    }
    let key = h.hex();
    let touch = |p: &Path| {
        let _ = std::fs::File::options().append(true).open(p).and_then(|f| f.set_modified(std::time::SystemTime::now()));
    };
    let manifest_file = dir.join(format!("{dkey}-{key}.manifest"));
    if !manifest_file.exists() {
        crate::erofs::write_manifest(&manifest_file, &manifest).ctx("write manifest")?;
    }
    let done = |image: PathBuf, delta: Option<PathBuf>| Lower { image, delta, manifest_file: manifest_file.clone() };

    // 1. unchanged since a full snapshot
    let full = dir.join(format!("{dkey}-{key}.img"));
    if full.exists() {
        touch(&full);
        return Ok(done(full, None));
    }
    // 2./3. a delta over the most recently used base for this directory
    if let Some((bkey, base)) = latest_base(&dir, &dkey) {
        let delta = dir.join(format!("{dkey}-{key}.delta-{bkey}.img"));
        if delta.exists() {
            touch(&base);
            return Ok(done(base, Some(delta)));
        }
        if let Ok(old) = crate::erofs::read_manifest(&dir.join(format!("{dkey}-{bkey}.manifest"))) {
            let oldm: HashMap<&[u8], &ManifestEntry> = old.iter().map(|m| (m.raw.as_slice(), m)).collect();
            let newp: HashSet<&[u8]> = manifest.iter().map(|m| m.raw.as_slice()).collect();
            let mut keep = HashSet::new();
            let mut bytes = 0u64;
            for m in &manifest {
                let same = oldm.get(m.raw.as_slice()).is_some_and(|o| o.mode == m.mode && o.size == m.size && o.mtime_ns == m.mtime_ns && o.ino == m.ino);
                if !same {
                    if m.mode & libc::S_IFMT == libc::S_IFREG {
                        bytes += m.size;
                    }
                    keep.insert(m.raw.clone());
                }
            }
            // deletions: only the topmost of a deleted subtree needs a whiteout
            let gone: HashSet<&[u8]> = old.iter().map(|m| m.raw.as_slice()).filter(|p| !newp.contains(p)).collect();
            let whiteouts: Vec<Vec<u8>> = gone
                .iter()
                .filter(|p| p.iter().rposition(|&b| b == b'/').is_none_or(|i| !gone.contains(&p[..i])))
                .map(|p| p.to_vec())
                .collect();
            let changed = keep.len() + whiteouts.len();
            if changed * DELTA_MAX_FRACTION <= manifest.len() && bytes <= DELTA_MAX_BYTES {
                let sub = tree.subset(&keep, &whiteouts);
                write_image(&sub, &delta)?;
                touch(&base);
                let el = t0.elapsed().as_secs_f64();
                if el > 1.0 {
                    status(&format!("snapshot of {}: {} changed entries in {:.1}s", tilde(cwd), changed, el));
                }
                return Ok(done(base, Some(delta)));
            }
        }
    }
    // 4. a new full snapshot (the next base)
    let size = write_image(&tree, &full)?;
    let el = t0.elapsed().as_secs_f64();
    if el > 1.0 || !stats.skipped.is_empty() {
        status(&format!(
            "snapshot of {}: {} files, {} in {:.1}s{}",
            tilde(cwd),
            stats.files,
            human_bytes(size),
            el,
            if stats.skipped.is_empty() { String::new() } else { format!(" ({} unreadable entries skipped)", stats.skipped.len()) }
        ));
    }
    Ok(done(full, None))
}

/// Remove credentials from the snapshot's copy of `.git/config` (the host
/// file is untouched): the user:password part of remote URLs (the usual
/// way a token ends up in a repository) and `extraheader` settings (CI
/// style `Authorization:` headers).  The guest's git then asks for
/// credentials it does not have instead of handing the agent a token.
fn scrub_git_config(tree: &mut Tree, cwd: &Path) {
    let Some(git) = tree.child(0, b".git") else { return };
    let Some(cfg) = tree.child(git, b"config") else { return };
    let Ok(text) = std::fs::read_to_string(cwd.join(".git/config")) else { return };
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    for line in text.lines() {
        let l = line.trim_start().to_ascii_lowercase();
        if l.starts_with("extraheader") {
            changed = true;
            continue;
        }
        let scrubbed = strip_url_userinfo(line);
        changed |= scrubbed != line;
        out.push_str(&scrubbed);
        out.push('\n');
    }
    if changed {
        let n = &mut tree.nodes[cfg];
        if matches!(n.kind, crate::erofs::Kind::File(..)) {
            let len = out.len() as u64;
            n.kind = crate::erofs::Kind::File(crate::erofs::Content::Bytes(out.into_bytes()), len);
        }
    }
}

/// `scheme://user:secret@host/...` becomes `scheme://host/...` wherever it
/// appears in `line`.
fn strip_url_userinfo(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail.find(|c: char| c == '/' || c.is_whitespace() || c == '"').unwrap_or(tail.len());
        match tail[..end].rfind('@') {
            Some(at) => rest = &tail[at + 1..],
            None => rest = tail,
        }
    }
    out.push_str(rest);
    out
}

/// Project files that look like credentials: dotenv files, private keys
/// and key stores, and registry/netrc/cloud credential files.  Returns
/// their paths relative to the project (at most `limit`).
pub fn credential_like(manifest_file: &Path, limit: usize) -> Vec<String> {
    let Ok(m) = crate::erofs::read_manifest(manifest_file) else { return vec![] };
    let mut v = Vec::new();
    for e in m.iter().filter(|e| e.mode & libc::S_IFMT == libc::S_IFREG) {
        let name = e.path.rsplit('/').next().unwrap_or(&e.path);
        let lower = name.to_ascii_lowercase();
        let env = lower == ".env" || (lower.starts_with(".env.") && !lower.ends_with(".example") && !lower.ends_with(".sample") && !lower.ends_with(".template"));
        let key = [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk"].iter().any(|x| lower.ends_with(x))
            || lower.starts_with("id_rsa") || lower.starts_with("id_ed25519") || lower.starts_with("id_ecdsa");
        let named = [".npmrc", ".pypirc", ".netrc", ".git-credentials", "credentials.json", "service-account.json", ".htpasswd", "secrets.yaml", "secrets.yml", "secrets.json"]
            .contains(&lower.as_str());
        if (env || key || named) && !e.path.starts_with(".git/") {
            v.push(e.path.clone());
            if v.len() >= limit {
                break;
            }
        }
    }
    v
}

/// The most recently used full snapshot of directory `dkey` in `dir` that
/// still has its manifest.  Returns its key and path.
fn latest_base(dir: &Path, dkey: &str) -> Option<(String, PathBuf)> {
    let prefix = format!("{dkey}-");
    let mut best: Option<(std::time::SystemTime, String, PathBuf)> = None;
    for e in std::fs::read_dir(dir).ok()?.filter_map(|e| e.ok()) {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(key) = name.strip_prefix(&prefix).and_then(|r| r.strip_suffix(".img")) else { continue };
        if key.contains('.') || !dir.join(format!("{dkey}-{key}.manifest")).exists() {
            continue; // a delta, or no manifest to diff against
        }
        let Ok(t) = e.metadata().and_then(|m| m.modified()) else { continue };
        if best.as_ref().is_none_or(|b| t > b.0) {
            best = Some((t, key.to_string(), e.path()));
        }
    }
    best.map(|(_, k, p)| (k, p))
}

/// Drop cached project snapshots that no session references and that have
/// not been used for a week.
///
/// Sessions hold hardlinks to the snapshots they use, so a link count of 1
/// means "unreferenced".  `dir`: the `lower` cache directory.  Errors are
/// ignored.
fn gc_lower(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let week = std::time::Duration::from_secs(7 * 86400);
    for e in rd.filter_map(|e| e.ok()) {
        let Ok(md) = e.metadata() else { continue };
        let old = md.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|a| a > week);
        if md.nlink() == 1 && old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Create a fresh sparse ext4 disk of `size_gib` GiB at `path`, labelled
/// `label`: a session's scratch disk, or a project's build cache.
///
/// It is formatted here with `mkfs.ext4` (no reserved blocks, lazy inode
/// table and journal initialisation, no discard) so the guest never needs
/// mkfs, formatting is quick, and only blocks actually written take space.  The host never mounts or reads
/// the result: the guest's changes come back through the export stream.
///
/// Returns an error if `mkfs.ext4` cannot be run (e2fsprogs missing) or
/// fails.
pub fn create_disk(path: &Path, size_gib: u64, label: &str) -> Result<()> {
    // mkfs.ext4 lives in sbin, which is often not on an ordinary user's PATH
    // (Debian and Ubuntu); and some versions announce "Creating regular
    // file" on stdout even with -q, which must not mix with the command's
    // output, so stdout is discarded and stderr kept for errors
    let mkfs = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .chain(["/usr/sbin", "/sbin"])
        .map(|d| Path::new(d).join("mkfs.ext4"))
        .find(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("mkfs.ext4"));
    let out = std::process::Command::new(&mkfs)
        .args(["-q", "-F", "-m", "0", "-E", "nodiscard,lazy_itable_init=1,lazy_journal_init=1", "-L", label])
        .arg(path)
        .arg(format!("{size_gib}G"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .output()
        .ctx("running mkfs.ext4 (install e2fsprogs)")?;
    if !out.status.success() {
        crate::bail!("mkfs.ext4 failed for {}: {}", path.display(), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
