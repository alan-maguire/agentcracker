//! The agent's state as exported from the guest: unpacked into the session
//! ([`extract_state`], as carefully as an apply), refreshed logins noticed
//! but never copied back ([`guest_refreshed_credentials`]), and the
//! transcripts summarised for `agentcracker show` ([`transcripts`]).

use std::ffi::OsStr;
use std::fs::File;
use std::io::BufReader;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::apply::Confined;
use crate::proto::{Entry, StreamReader};
use crate::session::Session;
use crate::util::{Context, Result};


/// Unpack `state.stream` into `<session>/state/`, confined like [`crate::apply::apply`].
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

/// Did the guest change the Claude credentials it was seeded with (i.e.
/// refresh the OAuth token)?
///
/// The guest's copy is never written back to the host: the host cannot
/// tell a refreshed token for the user's account from a token for some
/// other account that a compromised guest planted, and adopting the latter
/// would silently send the user's later host sessions to that account.  So
/// this only reports the refresh, and deletes the exported copy so that no
/// guest-written credentials are kept on the host either.
///
/// `s`: the session.  Returns true if the guest's credentials differ from
/// the seeded ones.
pub fn guest_refreshed_credentials(s: &Session) -> bool {
    let profile = crate::agent::for_session(s.meta.agent.as_deref());
    let guest = s.path("state").join(crate::vm::credential_path(profile));
    let Ok(data) = std::fs::read(&guest) else { return false };
    let _ = std::fs::remove_file(&guest);
    let gh = crate::util::Fnv::new().bytes(&data).hex();
    s.meta.cred_seed.as_deref().is_some_and(|seed| seed != gh)
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
    let profile = crate::agent::for_session(s.meta.agent.as_deref());
    if profile.name == "codex" {
        return codex_transcripts(&s.path("state").join(profile.path(&crate::util::home(), "sessions")));
    }
    let root = s.path("state").join(profile.path(&crate::util::home(), "projects"));
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

/// Summaries of Codex session rollouts (`sessions/YYYY/MM/DD/rollout-*.jsonl`
/// below `root`): each line is `{"timestamp", "type", "payload"}`, and
/// conversation turns are `response_item` lines whose payload is a
/// `message` from the `user` or the `assistant`.  Codex's own context
/// injections (`<environment_context>`, `<user_instructions>`, ...) are not
/// taken as the first prompt.
fn codex_transcripts(root: &Path) -> Vec<Transcript> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(p);
                continue;
            }
            let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
            if !name.starts_with("rollout-") || !name.ends_with(".jsonl") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            // rollout-<YYYY-MM-DDTHH-MM-SS>-<thread id>.jsonl
            let stem = name.trim_end_matches(".jsonl");
            let id = stem.get("rollout-YYYY-MM-DDTHH-MM-SS-".len()..).unwrap_or(stem).to_string();
            let mut t = Transcript { id, messages: 0, first_prompt: String::new(), last: String::new() };
            for line in text.lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
                if v.get("type").and_then(|x| x.as_str()) != Some("response_item") {
                    continue;
                }
                let Some(pl) = v.get("payload") else { continue };
                let role = pl.get("role").and_then(|r| r.as_str()).unwrap_or("");
                if pl.get("type").and_then(|x| x.as_str()) != Some("message") || (role != "user" && role != "assistant") {
                    continue;
                }
                t.messages += 1;
                if let Some(ts) = v.get("timestamp").and_then(|x| x.as_str()) {
                    t.last = ts.to_string();
                }
                if role == "user" && t.first_prompt.is_empty() {
                    let text = pl.get("content").and_then(|c| c.as_array()).and_then(|c| {
                        c.iter().find_map(|b| b.get("text").and_then(|x| x.as_str()))
                    });
                    if let Some(txt) = text.map(str::trim) {
                        if !txt.is_empty() && !txt.starts_with('<') && !txt.starts_with("# AGENTS.md") {
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
