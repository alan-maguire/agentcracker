//! A session's activity as one timeline, for `agentcracker log`.
//!
//! Two sources are merged:
//!
//! - `net.log`, written by the egress proxy: one line per connection
//!   attempt (`<unix time> <verdict> <host:port>`).  Live while the session
//!   runs.
//! - Claude Code's transcripts (`state/.claude/projects/**/*.jsonl`, copied
//!   out when the session ends): every tool call the agent made - shell
//!   commands, file reads and edits, fetches and searches - with its time.
//!
//! Everything here comes from the guest and is untrusted: it is escaped
//! for the terminal when rendered (see [`crate::util::safe_text`]).

use std::path::Path;

use crate::session::Session;

/// One entry of the timeline.
#[derive(Debug, Clone)]
pub struct Event {
    /// Unix time, with fractions of a second when known.
    pub time: f64,
    /// `net`, or the tool's name in lower case (`bash`, `read`, `edit`,
    /// `webfetch`, `websearch`, ...).
    pub kind: String,
    /// The connection target, the command, the file, the URL, the query...
    pub detail: String,
    /// For `net`: the proxy's verdict (`ALLOW`, `DENY`, ...).
    pub verdict: Option<String>,
    /// The call ran on Anthropic's servers, so the proxy never saw it.
    pub server_side: bool,
}

/// Parse `net.log` from byte offset `from`.  Returns the events and the
/// offset after the last complete line (for following a growing file).
pub fn net_events(path: &Path, from: u64) -> (Vec<Event>, u64) {
    use std::io::{Read, Seek};
    let mut out = Vec::new();
    let Ok(mut f) = std::fs::File::open(path) else { return (out, from) };
    if f.seek(std::io::SeekFrom::Start(from)).is_err() {
        return (out, from);
    }
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    let end = buf.iter().rposition(|&b| b == b'\n').map(|i| i + 1).unwrap_or(0);
    for line in String::from_utf8_lossy(&buf[..end]).lines() {
        let mut it = line.splitn(3, ' ');
        let (Some(t), Some(v), Some(target)) = (it.next(), it.next(), it.next()) else { continue };
        let Ok(time) = t.parse::<f64>() else { continue };
        out.push(Event { time, kind: "net".into(), detail: target.to_string(), verdict: Some(v.to_string()), server_side: false });
    }
    (out, from + end as u64)
}

/// The agent's tool calls from the session's Claude Code transcripts
/// (subagents' included), in no particular order.
pub fn tool_events(s: &Session) -> Vec<Event> {
    let mut out = Vec::new();
    let mut stack = vec![s.path("state/.claude/projects")];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() && p.extension().is_some_and(|x| x == "jsonl") {
                transcript_events(&p, &mut out);
            }
        }
    }
    out
}

/// Add the tool calls in one transcript file to `out`.
fn transcript_events(path: &Path, out: &mut Vec<Event>) {
    let Ok(text) = std::fs::read_to_string(path) else { return };
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let Some(time) = v.get("timestamp").and_then(|t| t.as_str()).and_then(parse_iso8601) else { continue };
        let Some(blocks) = v.get("message").and_then(|m| m.get("content")).and_then(|c| c.as_array()) else { continue };
        for b in blocks {
            let ty = b.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if ty != "tool_use" && ty != "server_tool_use" {
                continue;
            }
            let name = b.get("name").and_then(|n| n.as_str()).unwrap_or("tool").to_ascii_lowercase();
            let input = b.get("input");
            let field = |k: &str| input.and_then(|i| i.get(k)).and_then(|x| x.as_str());
            let detail = ["command", "url", "query", "file_path", "notebook_path", "path", "pattern", "description", "prompt"]
                .iter()
                .find_map(|k| field(k))
                .map(|s| s.to_string())
                .unwrap_or_default();
            // WebSearch (and any server tool) runs on Anthropic's servers
            let server_side = ty == "server_tool_use" || name == "websearch";
            out.push(Event { time, kind: name, detail, verdict: None, server_side });
        }
    }
}

/// Parse an RFC 3339 UTC timestamp as Claude Code writes them
/// (`2026-11-06T15:42:01.123Z`) into Unix time.
pub fn parse_iso8601(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut frac = 0.0;
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        let digits: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
        frac = format!("0.{digits}").parse().unwrap_or(0.0);
        rest = &r[digits.len()..];
    }
    let offset = match rest {
        "" | "Z" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) => {
            let secs = (o[1..3].parse::<i64>().ok()? * 60 + o[4..6].parse::<i64>().ok()?) * 60;
            if o.starts_with('+') { secs } else { -secs }
        }
        _ => return None,
    };
    // days since the epoch for a proleptic Gregorian date (Howard Hinnant)
    let (yy, m) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + h * 3600 + mi * 60 + se - offset) as f64 + frac)
}

/// Local wall-clock time of `t` as `HH:MM:SS`, or `YYYY-MM-DD HH:MM:SS`
/// with `with_date`.
pub fn clock(t: f64, with_date: bool) -> String {
    unsafe {
        let tt = t as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&tt, &mut tm);
        let mut buf = [0u8; 64];
        let fmt = if with_date { c"%Y-%m-%d %H:%M:%S" } else { c"%H:%M:%S" };
        let n = libc::strftime(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), &tm);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

/// One line of the human-readable timeline for `e`.
pub fn render(e: &Event, with_date: bool) -> String {
    let mut detail = e.detail.lines().next().unwrap_or("").to_string();
    if e.detail.lines().nth(1).is_some() {
        detail.push_str(" …");
    }
    if detail.chars().count() > 160 {
        detail = detail.chars().take(159).collect::<String>() + "…";
    }
    let detail = crate::util::safe_text(detail.as_bytes(), false);
    let what = match (&e.verdict, e.server_side) {
        (Some(v), _) => format!("{:<6} {detail}", crate::util::safe_text(v.as_bytes(), false)),
        (None, true) => format!("{detail}  (server-side: not seen by the proxy)"),
        (None, false) => detail,
    };
    format!("{}  {:<9} {what}", clock(e.time, with_date), crate::util::safe_text(e.kind.as_bytes(), false))
}

/// `e` as a JSON object for `log --json`.
pub fn json(e: &Event) -> serde_json::Value {
    serde_json::json!({
        "format": 1,
        "time": e.time,
        "kind": e.kind,
        "detail": e.detail,
        "verdict": e.verdict,
        "server_side": e.server_side,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_iso8601;

    #[test]
    fn iso8601() {
        assert_eq!(parse_iso8601("1970-01-01T00:00:00Z"), Some(0.0));
        assert_eq!(parse_iso8601("2026-11-06T15:42:01.500Z"), Some(1793979721.5));
        assert_eq!(parse_iso8601("2026-11-06T16:42:01+01:00"), Some(1793979721.0));
        assert_eq!(parse_iso8601("2000-02-29T12:00:00Z"), Some(951825600.0));
        assert_eq!(parse_iso8601("not a time"), None);
    }
}
