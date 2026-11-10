//! The agent's git commits, imported into the host repository as a branch
//! ([`import_branch`]).  Only object files are taken from the change
//! stream, into a scratch repository, and fetched from there with
//! `fetch.fsckObjects`: no hooks, config or refs from the guest are used.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::apply::Confined;
use crate::changes::{ChangeSet, Op};
use crate::session::Session;
use crate::util::{Result, git, safe_rel_path};


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

/// The commit the agent's HEAD points to, if it is the agent's work: it
/// differs from `base`, is not an older commit of the host's (see
/// [`checked_out_back`]) and no `git bisect` is left unfinished.
///
/// `cs`: the change set; `base`: the HEAD commit when the session started.
/// Returns `(commit id, branch name or "HEAD")`, or `None` if the project
/// is not a git repository, nothing changed inside `.git/`, HEAD cannot be
/// resolved, or it is not the agent's work as above.
pub fn agent_head(cs: &ChangeSet, base: Option<&str>) -> Option<(String, String)> {
    let (sha, name) = resolve_head(cs)?;
    if Some(sha.as_str()) == base || checked_out_back(cs, base).is_some() {
        return None;
    }
    Some((sha, name))
}

/// Whether the agent's `.git/` was left with `git bisect` unfinished
/// (`BISECT_START`, which `git bisect reset` removes, written in the
/// session).
fn bisecting(cs: &ChangeSet) -> bool {
    cs.git.iter().any(|(p, op)| p.as_slice() == b".git/BISECT_START" && matches!(op, Op::File { .. }))
}

/// Why the agent's work tree is a checkout of an older commit rather than
/// its own work, or `None` if it is not: a `git bisect` it left unfinished,
/// or HEAD moved back to an ancestor of `base` (`git checkout v6.1`).
/// Then its "changes" are that commit's versions of every file that
/// differs from `base`: applying them would revert the host's work tree,
/// and there is nothing new to import as a branch.
///
/// `cs`: the change set; `base`: the HEAD commit when the session started.
/// Returns a sentence for the user.
pub fn checked_out_back(cs: &ChangeSet, base: Option<&str>) -> Option<String> {
    if !cs.cwd.join(".git").is_dir() || cs.git.is_empty() {
        return None;
    }
    let short = |sha: &str| crate::util::safe_text(sha.get(..12).unwrap_or(sha).as_bytes(), false);
    let head = resolve_head(cs);
    if bisecting(cs) {
        let at = head.map(|(sha, _)| format!(" (HEAD is at {})", short(&sha))).unwrap_or_default();
        return Some(format!(
            "the agent left a git bisect unfinished{at}: its work tree is that commit's, not its own work \
             (`agentcracker resume` and `git bisect reset` to end it)"
        ));
    }
    let (sha, _) = head?;
    let base = base?;
    if sha != base && git(&cs.cwd, &["merge-base", "--is-ancestor", &sha, base]).is_ok() {
        return Some(format!(
            "the agent checked out {}, an older commit than {}: its work tree is that commit's, not its own work",
            short(&sha),
            short(base)
        ));
    }
    None
}

/// Resolve `.git/HEAD` as the agent left it: a symbolic ref
/// (`ref: refs/...`, validated) is looked up as a loose ref, then in
/// `packed-refs`; a detached HEAD is used as is.  Returns `(commit id,
/// branch name or "HEAD")`, or `None` if the project is not a git
/// repository, nothing changed inside `.git/` or HEAD cannot be resolved.
fn resolve_head(cs: &ChangeSet) -> Option<(String, String)> {
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
    is_sha(&sha).then_some((sha, name))
}

/// Import the agent's new git objects into the host repository via a
/// scratch repository and `git fetch` (with fsck), creating or updating a
/// branch.
///
/// Only object files are taken from the change stream - loose objects
/// (`objects/xx/<hex>`) and packs (`objects/pack/pack-<hex>.{pack,idx,rev}`),
/// with validated names - and written read-only, through [`Confined`], into
/// a bare scratch repository under the session's `tmp/`.  That repository
/// borrows the host repository's objects through `alternates` and gets a
/// ref for the agent's HEAD; the host repository then fetches from it with
/// `fetch.fsckObjects`, so malformed objects are rejected, and no hooks,
/// config or refs from the guest are ever used.  The branch is the
/// session's `--branch` if it has one, updated only by a fast-forward
/// (git refuses anything else, and a branch checked out on the host);
/// otherwise `agentcracker/<id>`, overwritten if it exists.
///
/// `cs`: the change set; `s`: the session (id and base commit).  Returns
/// the branch name and a description such as `3 commit(s) on main`.  Errors
/// if the agent made no new commits or a git step fails.
pub fn import_branch(cs: &ChangeSet, s: &Session) -> Result<(String, String)> {
    if let Some(why) = checked_out_back(cs, s.meta.git_head.as_deref()) {
        crate::bail!("nothing to import: {why}");
    }
    let Some((sha, from)) = agent_head(cs, s.meta.git_head.as_deref()) else {
        crate::bail!("the agent made no new commits");
    };
    let tmp = s.path("tmp/import.git");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    git(&tmp, &["init", "-q", "--bare", "."])?;
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
    git(&tmp, &["update-ref", "refs/heads/agent", &sha])?;
    // a --branch name only moves forward; agentcracker/<id> is ours to reset
    let (branch, force) = match &s.meta.work_branch {
        Some(b) => (b.clone(), ""),
        None => (format!("agentcracker/{}", s.meta.id), "+"),
    };
    if force.is_empty() {
        // say why git would refuse (it says nothing with -q)
        let r = format!("refs/heads/{branch}");
        if git(&cs.cwd, &["symbolic-ref", "-q", "HEAD"]).is_ok_and(|h| h == r) {
            crate::bail!("{branch} is checked out here: switch to another branch to import into it");
        }
        if let Ok(tip) = git(&cs.cwd, &["rev-parse", "--verify", "-q", &r]) {
            if git(&tmp, &["merge-base", "--is-ancestor", &tip, &sha]).is_err() {
                crate::bail!(
                    "{branch} has commits the agent's does not build on (it rewrote history, or {branch} moved here): \
                     not imported; rename or delete {branch} here and import again"
                );
            }
        }
    }
    let tmp_s = tmp.display().to_string();
    git(&cs.cwd, &["-c", "fetch.fsckObjects=true", "fetch", "-q", "--no-tags", "--no-write-fetch-head", &tmp_s, &format!("{force}refs/heads/agent:refs/heads/{branch}")])?;
    let _ = std::fs::remove_dir_all(&tmp);
    let count = match &s.meta.git_head {
        Some(base) => git(&cs.cwd, &["rev-list", "--count", &format!("{base}..{sha}")]).unwrap_or_default(),
        None => String::new(),
    };
    let from = crate::util::safe_text(from.as_bytes(), false);
    let desc = if count.is_empty() { format!("from {from}") } else { format!("{count} commit(s) on {from}") };
    Ok((branch, desc))
}
