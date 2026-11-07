//! Build caches: one persistent disk per project directory, mounted as the
//! guest's `~/.cache`.
//!
//! Every session starts from a cold build tree, so an agent that builds
//! the project pays for a full build each time.  The tools that cache
//! compilation already keep their caches in `~/.cache` - ccache,
//! sccache, Go's build cache, pip - and an out-of-tree build
//! (`make O=~/.cache/build`) can go there too.  Giving each project one
//! disk for it, kept across sessions, makes those builds incremental.
//!
//! Layout, under the state directory:
//!
//! ```text
//! caches/<key>/cache.img   sparse ext4 image (the guest's ~/.cache)
//! caches/<key>/dir         the project directory it belongs to
//! caches/<key>/lock        flock()ed by the session using it
//! ```
//!
//! `<key>` is a hash of the project path.  Only guests read and write the
//! image: the host creates it, attaches it and deletes it, and never mounts
//! it.  Its contents are as untrusted as anything else from a guest, and
//! they only ever reach later guests of the same project - a cache an agent
//! poisoned can mislead a later session's builds, never the host
//! (`agentcracker cache --drop` starts it afresh).  One running session
//! uses a cache at a time; another session of the same project meanwhile
//! gets an empty `~/.cache` of its own.

use std::path::{Path, PathBuf};

use crate::util::{Context, Fnv, Result};

/// Size of a new cache image, in GiB (sparse: only what is written uses
/// disk).
const SIZE_GIB: u64 = 64;

/// The directory holding every project's cache.
pub fn root() -> PathBuf {
    crate::util::state_dir().join("caches")
}

/// The cache directory for project `cwd`.
pub fn dir_for(cwd: &Path) -> PathBuf {
    root().join(Fnv::new().str(&cwd.to_string_lossy()).hex())
}

/// A cache attached to a running session: its image, and the lock that
/// keeps other sessions off it until this is dropped.
pub struct Attached {
    pub image: PathBuf,
    _lock: std::fs::File,
}

/// Take the cache for project `cwd`, creating it on first use.
///
/// Returns `Ok(None)` when another running session is using it.  Errors
/// if the cache cannot be created.
pub fn attach(cwd: &Path) -> Result<Option<Attached>> {
    let dir = dir_for(cwd);
    crate::util::mkdir_private(&root())?;
    crate::util::mkdir_private(&dir)?;
    let Some(lock) = crate::util::try_lock(&dir.join("lock"))? else { return Ok(None) };
    std::fs::write(dir.join("dir"), cwd.as_os_str().as_encoded_bytes()).ctx("recording the cache's directory")?;
    let image = dir.join("cache.img");
    if !image.exists() {
        let tmp = dir.join("cache.img.new");
        crate::images::create_disk(&tmp, SIZE_GIB, "accache")?;
        std::fs::rename(&tmp, &image)?;
    }
    Ok(Some(Attached { image, _lock: lock }))
}

/// One project's cache, for `agentcracker cache`.
pub struct Info {
    /// The project directory.
    pub cwd: PathBuf,
    /// Disk space used.
    pub bytes: u64,
    /// When a session last attached it (Unix time), if ever.
    pub used: Option<u64>,
}

/// Every project's cache, most recently used first.
pub fn list() -> Vec<Info> {
    use std::os::unix::fs::MetadataExt;
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir(root()) else { return out };
    for e in rd.filter_map(|e| e.ok()) {
        let path = e.path();
        let Ok(cwd) = std::fs::read(path.join("dir")) else { continue };
        let cwd = PathBuf::from(std::ffi::OsString::from(String::from_utf8_lossy(&cwd).into_owned()));
        let img = std::fs::metadata(path.join("cache.img")).ok();
        let used = std::fs::metadata(path.join("dir")).ok().map(|m| m.mtime().max(0) as u64);
        out.push(Info { cwd, bytes: img.map_or(0, |m| m.blocks() * 512), used });
    }
    out.sort_by_key(|i| std::cmp::Reverse(i.used));
    out
}

/// Delete the cache of project `cwd`.  Returns `Ok(false)` if it has none,
/// and errors if a running session is using it.
pub fn drop_cache(cwd: &Path) -> Result<bool> {
    let dir = dir_for(cwd);
    if !dir.exists() {
        return Ok(false);
    }
    let Some(_lock) = crate::util::try_lock(&dir.join("lock"))? else {
        crate::bail!("the build cache for {} is in use by a running session", cwd.display());
    };
    std::fs::remove_dir_all(&dir).ctx(format!("removing {}", dir.display()))?;
    Ok(true)
}
