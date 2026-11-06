//! Per-session state on the host.
//!
//! Each session is a directory `~/.local/state/agentcracker/sessions/<id>/`
//! (respecting `$XDG_STATE_HOME`), where `<id>` is 8 random hex digits:
//!
//! ```text
//! meta.json       what ran, where, when, how it ended, change summary
//! manifest.json   the project tree as it was snapshotted (conflict detection)
//! lower.img       the project snapshot (a hardlink into the image cache)
//! scratch.img     guest-private writable disk (overlay uppers, $HOME, /tmp)
//! changes.stream  the project's overlay upper layer, as exported by the guest
//! state.stream    agent state exported by the guest
//! state/          state.stream unpacked (e.g. Claude Code transcripts)
//! console.log     guest serial console + Firecracker's log
//! net.log         egress proxy decisions, one line per connection
//! lock            flock()ed while a VM runs on this session
//! tmp/            scratch space for diff rendering and branch import
//! ```
//!
//! A session outlives its VM: it can be booted again (`resume`, `shell`),
//! reviewed, applied, and finally removed.  `meta.json` is rewritten
//! atomically after every state change.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::erofs::ManifestEntry;
use crate::util::{Context, Result, now, state_dir};

/// Counts of user-visible changes, kept in `meta.json` so `agentcracker ls`
/// does not have to re-read the change stream.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Summary {
    /// Files and symlinks created (new directories are not counted).
    pub added: usize,
    /// Entries whose content, type or mode changed.
    pub modified: usize,
    /// Entries removed (a deleted directory counts once).
    pub deleted: usize,
    /// Entries changed inside `.git/` (never applied; see `agentcracker branch`).
    pub git_internal: usize,
}

/// Everything recorded about a session, persisted as `meta.json`.
///
/// Fields added after the first release are `#[serde(default)]`, so older
/// session directories still load.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Meta {
    /// Session id: 8 lowercase hex digits, also the directory name.
    pub id: String,
    /// The project directory on the host (canonical); it has the same path
    /// inside the guest.
    pub cwd: PathBuf,
    /// The command the session was created with; `resume` without a command
    /// runs it again.
    pub cmd: Vec<String>,
    /// Creation time, Unix seconds.
    pub created: u64,
    /// When the most recent boot ended, Unix seconds.
    #[serde(default)]
    pub ended: Option<u64>,
    /// Lifecycle state: `starting` (created, not booted yet), `running`,
    /// `exited` (the command exited and the VM shut down), `crashed` (no exit
    /// status came back), `failed` (the VM could not be started) or `applied`
    /// (the changes were written to the host).  A `running` or `starting`
    /// session that no process holds is displayed as `stopped`.
    pub status: String,
    /// Exit status of the last command (128 + signal number if it was killed),
    /// or `None` if it never reported one.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Number of times a VM has been booted on this session.
    #[serde(default)]
    pub boots: u32,
    /// Total seconds spent running, over all boots.
    #[serde(default)]
    pub runtime: u64,
    /// vCPUs given to the VM.
    #[serde(default)]
    pub vcpus: u32,
    /// Guest memory in MiB.
    #[serde(default)]
    pub mem_mib: u64,
    /// The effective egress allowlist (config plus `--allow`).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Whether the egress proxy is enabled at all.
    #[serde(default)]
    pub net: bool,
    /// `git rev-parse HEAD` in the project when the session was created, if it
    /// is a git repository with commits: the base for `agentcracker branch`.
    #[serde(default)]
    pub git_head: Option<String>,
    /// Change counts from the last complete export.
    #[serde(default)]
    pub summary: Option<Summary>,
    /// When the changes were last applied to the host, Unix seconds.
    #[serde(default)]
    pub applied_at: Option<u64>,
    /// The host branch created by `agentcracker branch`, if any.
    #[serde(default)]
    pub branch: Option<String>,
    /// Hash of `~/.claude/.credentials.json` as last sent to the guest, used to
    /// decide whether a token the guest refreshed can safely be written back.
    #[serde(default)]
    pub cred_seed: Option<String>,
    /// The last error (boot failure, lost guest, ...), shown by `agentcracker
    /// show`.
    #[serde(default)]
    pub error: Option<String>,
}

/// An open session: its directory and its metadata.  Changes to `meta` are
/// only persisted by [`Session::save`].
pub struct Session {
    /// The session directory.
    pub dir: PathBuf,
    /// The session's metadata, in memory.
    pub meta: Meta,
}

/// Returns the directory holding all sessions, `<state dir>/sessions`.  Not
/// created here.
pub fn sessions_dir() -> PathBuf {
    state_dir().join("sessions")
}

impl Session {
    /// Create a new session directory for running `cmd` in `cwd`.
    ///
    /// Picks a random id, retrying until `mkdir` succeeds (so two concurrent
    /// invocations never share a directory), and writes an initial `meta.json`
    /// with status `starting`.  Images and the scratch disk are created by the
    /// caller.
    ///
    /// Returns the new session; errors if the sessions directory or `meta.json`
    /// cannot be written.
    pub fn create(cwd: &Path, cmd: &[String]) -> Result<Session> {
        let root = sessions_dir();
        crate::util::mkdir_private(&root)?;
        loop {
            let id = crate::util::random_hex(4);
            let dir = root.join(&id);
            if std::fs::create_dir(&dir).is_ok() {
                let meta = Meta {
                    id,
                    cwd: cwd.to_path_buf(),
                    cmd: cmd.to_vec(),
                    created: now(),
                    status: "starting".into(),
                    ..Default::default()
                };
                let s = Session { dir, meta };
                s.save()?;
                return Ok(s);
            }
        }
    }

    /// Load the session stored in `dir` by reading its `meta.json`.
    ///
    /// Returns the session; errors if the file is missing or does not parse.
    pub fn load_dir(dir: &Path) -> Result<Session> {
        let text = std::fs::read_to_string(dir.join("meta.json")).ctx(format!("read {}/meta.json", dir.display()))?;
        let meta: Meta = serde_json::from_str(&text).ctx(format!("parse {}/meta.json", dir.display()))?;
        Ok(Session { dir: dir.to_path_buf(), meta })
    }

    /// Persist `meta` to `meta.json` atomically: it is written to
    /// `meta.json.tmp` and renamed over the old file, so a crash never leaves a
    /// truncated file behind.
    ///
    /// Returns an error if writing or renaming fails.
    pub fn save(&self) -> Result<()> {
        let tmp = self.dir.join("meta.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.meta)?)?;
        std::fs::rename(&tmp, self.dir.join("meta.json"))?;
        Ok(())
    }

    /// Returns the session id.
    pub fn id(&self) -> &str {
        &self.meta.id
    }
    /// Returns the path of `name` inside the session directory; whether it
    /// exists is not checked.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Write the project manifest to `manifest.json`.
    ///
    /// The manifest - one [`ManifestEntry`] per entry in the snapshot - is the
    /// baseline used at review time to decide what the agent changed and
    /// whether the host changed the same files meanwhile.
    ///
    /// `m`: the manifest recorded while building `lower.img`.  Returns an
    /// error on I/O or serialisation failure.
    pub fn save_manifest(&self, cached: &Path) -> Result<()> {
        let dst = self.path("manifest.bin");
        if std::fs::hard_link(cached, &dst).is_err() {
            std::fs::copy(cached, &dst).ctx("copy manifest")?;
        }
        Ok(())
    }
    /// Read back the manifest written by [`Session::save_manifest`].
    ///
    /// Returns the entries; errors if the session has none (it never got as far
    /// as taking the snapshot) or the file is corrupt.
    pub fn manifest(&self) -> Result<Vec<ManifestEntry>> {
        let bin = self.path("manifest.bin");
        if bin.exists() {
            return Ok(crate::erofs::read_manifest(&bin)?);
        }
        // sessions from before the binary format
        let f = std::fs::File::open(self.path("manifest.json")).ctx("session has no manifest")?;
        Ok(serde_json::from_reader(std::io::BufReader::new(f))?)
    }

    /// Returns true while a VM runs on this session, i.e. while some process
    /// holds its `lock` file.
    ///
    /// It probes by trying to take the lock (and releasing it at once), so a
    /// crashed agentcracker never leaves a session looking busy.  A lock file
    /// that cannot be opened counts as not running.
    pub fn is_running(&self) -> bool {
        match crate::util::try_lock(&self.path("lock")) {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => false,
        }
    }

    /// Take this session's lock for the duration of a boot.
    ///
    /// Returns the locked file: keep it alive while the VM runs; dropping it
    /// releases the lock.  Errors if the session is already running (or the
    /// lock file cannot be opened).
    pub fn lock(&self) -> Result<std::fs::File> {
        match crate::util::try_lock(&self.path("lock"))? {
            Some(f) => Ok(f),
            None => crate::bail!("session {} is already running", self.id()),
        }
    }

    /// Disk space the session uses, as `(own, shared)` bytes of allocated
    /// blocks (so the sparse 64 GiB scratch disk counts only what was
    /// written).
    ///
    /// `own` is everything only this session holds, subdirectories such as
    /// `state/` included.  `shared` is files hardlinked elsewhere - the
    /// project snapshot and manifest, shared with the image cache and other
    /// sessions - which removing the session does not free while those
    /// links remain.
    pub fn disk_usage(&self) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let (mut own, mut shared) = (0, 0);
        let mut stack = vec![self.dir.clone()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.filter_map(|e| e.ok()) {
                let Ok(m) = e.metadata() else { continue };
                let bytes = m.blocks() * 512;
                if m.is_dir() {
                    own += bytes;
                    stack.push(e.path());
                } else if m.nlink() > 1 {
                    shared += bytes;
                } else {
                    own += bytes;
                }
            }
        }
        (own, shared)
    }

    /// Delete the session directory and everything in it, consuming the session.
    ///
    /// Returns an error if a VM is running on it, or if removal fails.
    pub fn remove(self) -> Result<()> {
        if self.is_running() {
            crate::bail!("session {} is running", self.id());
        }
        std::fs::remove_dir_all(&self.dir).ctx(format!("remove {}", self.dir.display()))
    }
}

/// Returns every loadable session, oldest first.  Directories without a
/// valid `meta.json` are skipped; a missing sessions directory gives an
/// empty list.
pub fn list() -> Vec<Session> {
    let mut v: Vec<Session> = match std::fs::read_dir(sessions_dir()) {
        Ok(rd) => rd.filter_map(|e| e.ok()).filter_map(|e| Session::load_dir(&e.path()).ok()).collect(),
        Err(_) => vec![],
    };
    v.sort_by_key(|s| s.meta.created);
    v
}

/// Resolve the SESSION argument of a subcommand.
///
/// `arg`: `Some(prefix)` selects the one session whose id starts with
/// `prefix`; `None` selects the most recently created session whose project
/// directory is `cwd`.  `cwd`: the current (canonical) directory.
///
/// Returns the session; errors if nothing matches, if the prefix is
/// ambiguous (the error lists the candidates), or if `cwd` has no sessions.
pub fn find(arg: Option<&str>, cwd: &Path) -> Result<Session> {
    let all = list();
    match arg {
        Some(a) => {
            let m: Vec<Session> = all.into_iter().filter(|s| s.meta.id.starts_with(a)).collect();
            match m.len() {
                0 => crate::bail!("no session matching {a:?} (see `agentcracker ls`)"),
                1 => Ok(m.into_iter().next().unwrap()),
                _ => crate::bail!("{a:?} is ambiguous: {}", m.iter().map(|s| s.meta.id.as_str()).collect::<Vec<_>>().join(" ")),
            }
        }
        None => all
            .into_iter()
            .filter(|s| s.meta.cwd == cwd)
            .next_back()
            .ctx(format!("no sessions for {} (see `agentcracker ls`)", crate::util::tilde(cwd))),
    }
}

/// Tell a session id from a command name in
/// `agentcracker resume [SESSION] [command...]`.
///
/// `a`: the first argument.  Returns true if it is 3-8 hex digits and a
/// prefix of at least one existing session id.
pub fn looks_like_id(a: &str) -> bool {
    a.len() >= 3 && a.len() <= 8 && a.bytes().all(|b| b.is_ascii_hexdigit()) && list().iter().any(|s| s.meta.id.starts_with(a))
}
