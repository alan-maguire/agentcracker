//! Host-side egress proxy: the only way out of the VM.
//!
//! The guest has no network interface.  When networking is enabled, acinit
//! listens on `127.0.0.1:3128` in the guest and the command's environment
//! points `HTTPS_PROXY` there; each TCP connection to that listener is
//! relayed byte for byte over vsock port
//! [`PORT_PROXY`](crate::proto::PORT_PROXY), which Firecracker delivers here
//! as a connection on the unix socket `v.sock_1025`.
//!
//! For each connection this module:
//!
//! 1. reads one HTTP request head; anything but `CONNECT host:port` is
//!    refused with 405 (plain HTTP is never proxied);
//! 2. checks the host against the session's allowlist with
//!    [`host_allowed`]: port 443 is allowed for any allowed host, other
//!    ports only if `host:port` (or `*`) is listed;
//! 3. resolves the name on the host (the guest has no DNS), connects,
//!    answers `200 Connection Established`, and then copies bytes both ways
//!    without looking at them - TLS runs end to end between the guest and
//!    the server, so the proxy sees names, not content.
//!
//! Every decision is appended to the session's `net.log` as
//! `<unix time> <verdict> <host:port>`; `agentcracker show` summarises it.
//! Each connection is served on its own thread.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::host_allowed;

/// Per-session proxy settings, shared by all connection threads.
pub struct Proxy {
    /// The effective allowlist (see [`host_allowed`]).
    pub allow: Vec<String>,
    /// False with `--no-net`: every request is denied (and logged).
    pub enabled: bool,
    /// `net.log`, or `None` if it could not be opened.  The mutex keeps lines
    /// from different connections from interleaving.
    pub log: Mutex<Option<std::fs::File>>,
}

/// Accept proxy connections on `listener` in a background thread, serving
/// each with [`handle`] on a thread of its own.
///
/// `listener`: the unix socket Firecracker forwards guest vsock port 1025
/// to; `p`: the session's proxy settings.  Returns immediately; the threads
/// run until the process exits.
pub fn serve(listener: UnixListener, p: Arc<Proxy>) {
    std::thread::spawn(move || {
        for c in listener.incoming() {
            let Ok(c) = c else { continue };
            let p = p.clone();
            std::thread::spawn(move || {
                let _ = handle(c, &p);
            });
        }
    });
}

/// Append one decision to `net.log` as `<now> <verdict> <target>`.
///
/// `verdict`: `ALLOW`, `DENY`, `DENY(non-CONNECT)`, `FAIL(dns)` or
/// `FAIL(connect)`; `target`: `host:port` as requested.  Errors are
/// ignored: logging must never break a connection.
fn log(p: &Proxy, verdict: &str, target: &str) {
    // the target is the guest's text; net.log is shown by `agentcracker show`
    let target = &crate::util::safe_text(target.as_bytes(), false).replace(' ', "\\x20");
    if let Ok(mut g) = p.log.lock() {
        if let Some(f) = g.as_mut() {
            let _ = writeln!(f, "{} {verdict} {target}", crate::util::now());
        }
    }
}

/// Serve one proxied connection from the guest.
///
/// Reads the request line and headers (30 s read timeout; a header line
/// over 8 KiB ends the connection), applies the policy described in the
/// module docs, and on success relays bytes in both directions until both
/// sides have closed, half-closing each direction as its source reaches
/// EOF.  Bytes the client sent right after the request head (e.g. an
/// eagerly sent TLS ClientHello) are forwarded first.
///
/// `c`: the connection from the guest; `p`: the proxy settings.
///
/// Returns `Ok(())` when the exchange is over, including after a 403, 405
/// or 502 response; `Err` only for I/O errors on the guest side, which the
/// caller ignores.
fn handle(c: UnixStream, p: &Proxy) -> io::Result<()> {
    c.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut r = BufReader::new(c.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    // drain headers
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if h.len() > 8192 {
            return Ok(());
        }
    }
    let mut w = c;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        let target = parts.get(1).copied().unwrap_or("?");
        log(p, "DENY(non-CONNECT)", target);
        w.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\nagentcracker only proxies HTTPS (CONNECT)\r\n")?;
        return Ok(());
    }
    let target = parts[1].to_string();
    let (host, port) = match target.rsplit_once(':') {
        Some((h, pt)) => (h.trim_matches(|c| c == '[' || c == ']').to_string(), pt.parse::<u16>().unwrap_or(0)),
        None => (target.clone(), 443),
    };
    if !valid_host(&host) || port == 0 {
        log(p, "DENY(bad target)", &target);
        w.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    let port_ok = port == 443 || host_allowed(&p.allow, &format!("{host}:{port}"));
    if !p.enabled || !port_ok || !(host_allowed(&p.allow, &host) || host_allowed(&p.allow, &format!("{host}:{port}"))) {
        log(p, "DENY", &target);
        w.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    let addrs: Vec<_> = match (host.as_str(), port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(_) => {
            log(p, "FAIL(dns)", &target);
            w.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")?;
            return Ok(());
        }
    };
    let mut up = None;
    for a in addrs {
        if let Ok(s) = TcpStream::connect_timeout(&a, Duration::from_secs(10)) {
            up = Some(s);
            break;
        }
    }
    let Some(up) = up else {
        log(p, "FAIL(connect)", &target);
        w.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")?;
        return Ok(());
    };
    log(p, "ALLOW", &target);
    w.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    w.set_read_timeout(None)?;
    // anything the client sent after the headers is already in the BufReader
    let buffered = r.buffer().to_vec();
    let mut up_w = up.try_clone()?;
    if !buffered.is_empty() {
        up_w.write_all(&buffered)?;
    }
    let mut up_r = up;
    let mut w2 = w.try_clone()?;
    let t = std::thread::spawn(move || {
        let _ = io::copy(&mut up_r, &mut w2);
        let _ = w2.shutdown(Shutdown::Write);
    });
    let mut inner = r.into_inner();
    let _ = io::copy(&mut inner, &mut up_w);
    let _ = up_w.shutdown(Shutdown::Write);
    let _ = t.join();
    Ok(())
}

/// A host name (letters, digits, `-`, `.`, `_`) or an IP literal: anything
/// else in a CONNECT target is refused before it is matched or resolved.
fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && (h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
            || h.parse::<std::net::Ipv6Addr>().is_ok())
}

/// Summarise a session's `net.log` for `agentcracker show`.
///
/// `path`: the log file.  Returns one `(target, allowed, denied)` tuple per
/// distinct target, sorted by target.  `target` is the host, with a `:443`
/// suffix dropped (other ports are kept); `denied` counts every verdict
/// other than `ALLOW`, failures included.  A missing or unreadable log
/// gives an empty list.
pub fn summarize(path: &PathBuf) -> Vec<(String, usize, usize)> {
    let Ok(text) = std::fs::read_to_string(path) else { return vec![] };
    let mut m: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    for l in text.lines() {
        let mut it = l.splitn(3, ' ');
        let (_, v, t) = (it.next(), it.next().unwrap_or(""), it.next().unwrap_or("").to_string());
        let host = t.strip_suffix(":443").map(|s| s.to_string()).unwrap_or(t);
        let e = m.entry(host).or_default();
        if v == "ALLOW" {
            e.0 += 1;
        } else {
            e.1 += 1;
        }
    }
    m.into_iter().map(|(k, (a, d))| (k, a, d)).collect()
}
