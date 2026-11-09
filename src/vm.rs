//! Booting a session's microVM and attaching the terminal to it.
//!
//! [`boot`] is one run of the VM.  It gathers the images (base, /usr,
//! toolchains, plus the session's project snapshot and scratch disk),
//! writes a Firecracker config file, listens on the vsock unix sockets,
//! starts Firecracker (`--no-api`, with the compiled seccomp filter when it
//! is installed) and hands over to [`attach`], which drives the control
//! protocol (see `crate::proto`):
//!
//! 1. accept the guest's control connection (waiting up to 30 s);
//! 2. send CONFIG ([`GuestConfig`]) and the home seed - agent config and
//!    credentials - as SEED frames;
//! 3. put the terminal in raw mode and pump stdin and window size changes
//!    to the guest, while copying STDOUT and STDERR frames to the terminal;
//! 4. on EXIT, restore the terminal, then receive the EXPORT stream (saved
//!    as `changes.stream`) and the STATE stream (`state.stream`) until DONE.
//!
//! Firecracker then gets 5 s to exit by itself (the guest powers off)
//! before it is killed.  Failures after the VM has started are returned in
//! [`Outcome::error`], with the tail of the guest console, rather than as
//! `Err`, so the caller can still record what happened.
//!
//! Guest block devices are attached in a fixed order, which is how acinit
//! finds them: vda base (the root), vdb usr, vdc tools, vdd project
//! snapshot, vde scratch.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::agent::Profile;
use crate::config::Config;
use crate::images::{self, Refresh};
use crate::proto::*;
use crate::session::Session;
use crate::util::{Context, Fnv, Result, SpaceGuard, home};

/// What happened during one boot, for the caller to record in the session.
pub struct Outcome {
    /// The command's exit status, if the guest reported one.
    pub exit_code: Option<i32>,
    /// True if a complete change stream arrived and was saved as `changes.stream`.
    pub exported: bool,
    /// Why the boot ended abnormally (setup failure in the guest, lost
    /// connection, ...), with the last console lines appended; `None` for a
    /// clean run.
    pub error: Option<String>,
}

/// Paths below `$HOME` copied into the guest on the first boot of a session.
///
/// These are git's global ignore file (never its configuration, which can
/// hold passwords and tokens: the guest gets only the user's identity, see
/// [`crate::guidance::git_identity`]); the agent profile's seed paths
/// (its settings, instructions and extensions; see [`crate::agent`]); for
/// Claude Code, this project's history directory
/// (`~/.claude/projects/<cwd with every non-alphanumeric character replaced
/// by '-'>`) so `claude --continue` works; and the configured `home`
/// entries.
///
/// `cwd`: the project directory; `cfg`: supplies `home`; `p`: the agent
/// profile.  Returns paths relative to `$HOME` (a leading `~/` is stripped
/// from config entries).  Paths that do not exist are skipped when the seed
/// is built.
fn first_boot_seed(cwd: &Path, cfg: &Config, p: &Profile) -> Vec<String> {
    let h = home();
    let mut v: Vec<String> = vec![".config/git/ignore".to_string()];
    v.extend(p.seed.iter().map(|s| p.path(&h, s)));
    if p.name == "claude" {
        let mangled: String = cwd.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
        v.push(p.path(&h, &format!("projects/{mangled}")));
    }
    v.extend(cfg.home.iter().map(|h| h.trim_start_matches("~/").to_string()));
    v
}

/// Paths below `$HOME` exported from the guest to the session store on exit:
/// the agent profile's state (its transcripts), its credentials file (only
/// to notice a refresh; see [`crate::agentstate::guest_refreshed_credentials`]),
/// the configured `state` entries, and the test kernel boots
/// ([`crate::acrboot::RECORDS`]).
///
/// `cfg`: supplies `state`; `p`: the agent profile.  Returns paths relative
/// to `$HOME`.
pub fn state_paths(cfg: &Config, p: &Profile) -> Vec<String> {
    let h = home();
    let mut v: Vec<String> = p.state.iter().map(|s| p.path(&h, s)).collect();
    v.push(credential_path(p));
    v.extend(cfg.state.iter().map(|h| h.trim_start_matches("~/").to_string()));
    // acrboot's records (kept even if `boot` was turned off since)
    v.push(crate::acrboot::RECORDS.to_string());
    v
}

/// The agent profile's login file, relative to `$HOME`.
pub fn credential_path(p: &Profile) -> String {
    p.path(&home(), p.credential)
}

/// Returns the FNV hash (as hex) of `p`'s contents, or `None` if it cannot
/// be read.  Used to tell whether the credentials file changed.
pub fn hash_file(p: &Path) -> Option<String> {
    std::fs::read(p).ok().map(|d| Fnv::new().bytes(&d).hex())
}

/// Firecracker custom CPU template that hides hardware virtualisation from
/// the guest: CPUID leaf 1 ECX bit 5 (VMX, Intel) and leaf 0x80000001 ECX
/// bit 2 (SVM, AMD) cleared.  Used unless `boot = true`, so that turning
/// acrboot off is enforced by the host's KVM (which refuses VMXON, or
/// setting EFER.SVME, to a guest whose CPUID lacks the feature) rather
/// than by the guest removing `/dev/kvm`: a guest whose kernel the agent
/// took over cannot reach the host's nested virtualisation code.  Both
/// leaves exist on Intel and AMD; the other vendor's bit is already 0.
fn no_nested_virt() -> serde_json::Value {
    let clear = |bit: usize| format!("0b{}0{}", "x".repeat(31 - bit), "x".repeat(bit));
    serde_json::json!({
        "cpuid_modifiers": [
            {"leaf": "0x1", "subleaf": "0x0", "flags": 0,
             "modifiers": [{"register": "ecx", "bitmap": clear(5)}]},
            {"leaf": "0x80000001", "subleaf": "0x0", "flags": 0,
             "modifiers": [{"register": "ecx", "bitmap": clear(2)}]},
        ]
    })
}

/// Build the home seed stream sent to the guest at boot.
///
/// On a session's first boot (`first_boot`) it holds `~/.claude.json`,
/// pruned under `projects` to this project's entry (the file keeps state
/// for every project the user has), and the paths from
/// [`first_boot_seed`].  On every boot it holds the profile's credentials
/// file ([`credential_path`]), since the host copy may have been refreshed since the
/// last boot; otherwise later boots rely on the scratch disk, which still
/// holds the guest's home.
///
/// `cwd`: the project directory; `cfg`: the configuration.  Returns the
/// encoded stream, in memory.
fn build_seed(cwd: &Path, cfg: &Config, first_boot: bool, p: &Profile) -> Result<Vec<u8>> {
    let h = home();
    let mut sw = StreamWriter::new(Vec::new());
    if first_boot && p.name == "claude" {
        // ~/.claude.json carries per-project state for every project; only
        // hand over the entry for this one.
        if let Ok(text) = std::fs::read(h.join(".claude.json")) {
            let data = match serde_json::from_slice::<serde_json::Value>(&text) {
                Ok(mut v) => {
                    if let Some(p) = v.get_mut("projects").and_then(|p| p.as_object_mut()) {
                        let key = cwd.to_string_lossy().to_string();
                        p.retain(|k, _| *k == key);
                    }
                    serde_json::to_vec(&v)?
                }
                Err(_) => text,
            };
            sw.file(b".claude.json", 0o600, data.len() as u64, &mut &data[..])?;
        }
    }
    if first_boot {
        for rel in first_boot_seed(cwd, cfg, p) {
            if crate::util::safe_rel_path(rel.as_bytes()).is_some() {
                stream_tree(&mut sw, &h.join(&rel), rel.as_bytes())?;
            }
        }
    }
    // credentials every boot: the host copy may have been refreshed meanwhile
    let cred = credential_path(p);
    stream_tree(&mut sw, &h.join(&cred), cred.as_bytes())?;
    sw.end()?;
    Ok(sw.w)
}

/// Build the environment the command runs with in the guest.
///
/// Passed through from the host: terminal and locale variables (`TERM`,
/// `LANG`, `LC_*`, ...), editor and pager preferences, `DISABLE_*`, the
/// agent profile's prefixes (`ANTHROPIC_*` and `CLAUDE_CODE_*`, or
/// `OPENAI_*` and `CODEX_*`: API keys and agent settings) and the names
/// listed in `cfg.env`.
/// Set explicitly: `HOME`, `USER`, `LOGNAME`, `SHELL`, the host's `PATH`,
/// `PWD`, `AGENTCRACKER=1`, `AGENTCRACKER_SESSION=<id>`, `TERM` if it was
/// missing, and, when `net` is true, `HTTPS_PROXY` and `HTTP_PROXY` (in
/// both cases) pointing at the guest proxy, with `NO_PROXY` for loopback.
///
/// `s`: the session (directory, id); `cfg`: the configuration; `net`:
/// whether egress is enabled.  Returns `(name, value)` pairs.
fn guest_env(s: &Session, cfg: &Config, net: bool, p: &Profile) -> Vec<(String, String)> {
    let pass_exact = [
        "TERM", "COLORTERM", "LANG", "LANGUAGE", "TZ", "EDITOR", "VISUAL", "PAGER", "LESS", "NO_COLOR",
        "FORCE_COLOR", "CLICOLOR", "TERM_PROGRAM", "TERM_PROGRAM_VERSION",
    ];
    let pass_prefix: Vec<&str> = ["LC_", "DISABLE_"].into_iter().chain(p.env_prefixes.iter().copied()).collect();
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| {
            pass_exact.contains(&k.as_str())
                || pass_prefix.iter().any(|p| k.starts_with(p))
                || cfg.env.iter().any(|e| e == k)
        })
        .collect();
    let uid = unsafe { libc::getuid() };
    let user = crate::util::user_name(uid);
    env.push(("HOME".into(), home().display().to_string()));
    env.push(("USER".into(), user.clone()));
    env.push(("LOGNAME".into(), user));
    env.push(("SHELL".into(), crate::util::user_shell(uid)));
    env.push(("PATH".into(), std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin".into())));
    env.push(("PWD".into(), s.meta.cwd.display().to_string()));
    env.push(("AGENTCRACKER".into(), "1".into()));
    env.push(("AGENTCRACKER_SESSION".into(), s.meta.id.clone()));
    if !env.iter().any(|(k, _)| k == "TERM") {
        env.push(("TERM".into(), "xterm-256color".into()));
    }
    if net {
        let p = format!("http://{GUEST_PROXY_ADDR}");
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            env.push((k.into(), p.clone()));
        }
        env.push(("NO_PROXY".into(), "localhost,127.0.0.1,::1".into()));
        env.push(("no_proxy".into(), "localhost,127.0.0.1,::1".into()));
    }
    env
}

/// Collect the owner, group and mode of every ancestor directory of
/// `paths` (excluding `/` and the paths themselves), without duplicates.
///
/// acinit recreates the same chain in the guest, so the project and
/// toolchain mount points sit in directories with the host's ownership
/// (e.g. `/tmp/claude-1000` stays the user's).  Returns
/// `(path, uid, gid, mode)` tuples; ancestors that cannot be stat()ed are
/// left out.
fn ancestor_dirs<'a>(paths: impl Iterator<Item = &'a Path>) -> Vec<(String, u32, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let mut out: Vec<(String, u32, u32, u32)> = Vec::new();
    for p in paths {
        for a in p.ancestors().skip(1) {
            if a == Path::new("/") || out.iter().any(|o| Path::new(&o.0) == a) {
                continue;
            }
            if let Ok(md) = std::fs::metadata(a) {
                out.push((a.display().to_string(), md.uid(), md.gid(), md.mode() & 0o7777));
            }
        }
    }
    out
}

/// Returns the terminal size as `(rows, cols)`, from the first of stdin,
/// stdout and stderr that is a terminal, or 24x80 if none is.
fn winsize() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        for fd in [0, 1, 2] {
            if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_row > 0 {
                return (ws.ws_row, ws.ws_col);
            }
        }
    }
    (24, 80)
}

/// Guard for raw terminal mode on stdin: the saved settings are restored
/// when it is dropped.
struct RawTerm(libc::termios);
impl RawTerm {
    /// Put stdin in raw mode: no echo, no line editing, and no signal keys, so
    /// Ctrl-C reaches the guest.  Returns the guard, or `None` if stdin is not a
    /// terminal.
    fn enter() -> Option<RawTerm> {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return None;
            }
            let orig = t;
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(0, libc::TCSANOW, &t);
            Some(RawTerm(orig))
        }
    }
}
/// Undo terminal state the guest may have left behind before agentcracker
/// prints anything of its own (the review in particular): leave the
/// alternate screen, soft-reset (attributes, scroll region, origin and
/// insert modes, cursor visibility), select the ASCII character set and
/// turn off mouse reporting, bracketed paste and application cursor keys.
fn reset_terminal() {
    let _ = std::io::stdout().write_all(b"\x1b[?1049l\x1b[!p\x1b(B\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1l\r");
    let _ = std::io::stdout().flush();
}

impl Drop for RawTerm {
    /// Restore the terminal settings saved by [`RawTerm::enter`].
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &self.0) };
    }
}

/// Write end of the self-pipe the SIGWINCH handler signals; -1 while no
/// session is attached.
static WINCH_FD: AtomicI32 = AtomicI32::new(-1);
/// SIGWINCH handler: writes one byte to [`WINCH_FD`] so the stdin pump
/// wakes up and sends the new window size.  Only async-signal-safe
/// operations (an atomic load and `write`).
/// Write end of the self-pipe the SIGTERM handler signals (see
/// [`on_term`]); -1 while no session is attached.
static TERM_FD: AtomicI32 = AtomicI32::new(-1);

/// SIGTERM handler while attached: writes one byte to [`TERM_FD`] so the
/// stdin pump asks the guest to stop the command, which then exits and is
/// exported normally (this is how `agentcracker stop` works).
extern "C" fn on_term(_: libc::c_int) {
    let fd = TERM_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::write(fd, b"t".as_ptr().cast(), 1) };
    }
}

extern "C" fn on_winch(_: libc::c_int) {
    let fd = WINCH_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::write(fd, b"w".as_ptr().cast(), 1) };
    }
}

/// Create a non-blocking, close-on-exec pipe.  Returns
/// `(read end, write end)`; the caller closes both.
fn pipe() -> Result<(RawFd, RawFd)> {
    let mut p = [0; 2];
    if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return crate::util::last_os_error("pipe");
    }
    Ok((p[0], p[1]))
}

/// Forward stdin and window size changes to the guest until told to stop.
///
/// Spawns a thread that polls stdin, `stop_r` and `winch_r`.  Data on stdin
/// is sent as STDIN frames, and its EOF as one STDIN_EOF frame, after which
/// stdin is no longer polled; a byte on `winch_r` sends a RESIZE frame with
/// the current size; anything on `stop_r` ends the thread.  The thread also
/// ends if a frame cannot be sent.
///
/// `ctrl`: the control connection, shared with the receiving side;
/// `stop_r`, `winch_r`: read ends of the stop pipe and the SIGWINCH
/// self-pipe.  Returns the thread's handle.
fn stdin_pump(ctrl: Arc<Mutex<UnixStream>>, stop_r: RawFd, winch_r: RawFd, term_r: RawFd) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut fds = [
            libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: stop_r, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: winch_r, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: term_r, events: libc::POLLIN, revents: 0 },
        ];
        let mut buf = vec![0u8; 16384];
        loop {
            let r = unsafe { libc::poll(fds.as_mut_ptr(), 4, -1) };
            if r < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
            if fds[1].revents != 0 {
                break;
            }
            if fds[3].revents != 0 {
                while unsafe { libc::read(term_r, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
                let _ = write_frame(&mut *ctrl.lock().unwrap(), M_STOP, &[]);
                fds[3].fd = -1; // once is enough
            }
            if fds[2].revents != 0 {
                while unsafe { libc::read(winch_r, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
                let (r, c) = winsize();
                let mut d = r.to_be_bytes().to_vec();
                d.extend_from_slice(&c.to_be_bytes());
                if write_frame(&mut *ctrl.lock().unwrap(), M_RESIZE, &d).is_err() {
                    break;
                }
            }
            if fds[0].revents != 0 {
                let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
                if n <= 0 {
                    let _ = write_frame(&mut *ctrl.lock().unwrap(), M_STDIN_EOF, &[]);
                    fds[0].fd = -1;
                } else if write_frame(&mut *ctrl.lock().unwrap(), M_STDIN, &buf[..n as usize]).is_err() {
                    break;
                }
            }
        }
    })
}

/// Wait for the guest's control connection on `l`.
///
/// Polls every 10 ms so that Firecracker exiting early (bad config, KVM
/// error) is noticed instead of waiting out the timeout.  `fc`: the
/// Firecracker process; `deadline`: how long to wait in total.
///
/// Returns the connection, in blocking mode.  Errors if Firecracker exits
/// first or the deadline passes.
fn accept_guest(l: &UnixListener, fc: &mut Child, deadline: Duration) -> Result<UnixStream> {
    l.set_nonblocking(true)?;
    let t0 = Instant::now();
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false)?;
                return Ok(s);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if let Some(st) = fc.try_wait()? {
            crate::bail!("firecracker exited before the guest came up ({st})");
        }
        if t0.elapsed() > deadline {
            crate::bail!("timed out waiting for the guest to boot");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Returns the last `n` lines of the session's `console.log` (the guest
/// console and Firecracker's own log), or an empty string if there is none.
/// Appended to error messages.
pub fn console_tail(s: &Session, n: usize) -> String {
    // the console carries guest output: never let it drive the terminal
    let text = crate::util::safe_text(&std::fs::read(s.path("console.log")).unwrap_or_default(), true);
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Boot the session's VM, run `cmd` in it, and wait for it to finish.
///
/// `lower.img` and `scratch.img` must already exist in the session (they
/// are created by `agentcracker run`).  Gets the shared images, building or
/// refreshing them as needed; checks access to `/dev/kvm`; starts the
/// egress proxy listener; and runs Firecracker with its output going to
/// `console.log` (or to the terminal, with `console`).  Updates the
/// session's `runtime`, `boots` and `cred_seed`; the caller saves it.
///
/// - `s`: the session; `cfg`: the configuration;
/// - `cmd`: the command to run in the guest;
/// - `console`: show the guest console instead of logging it, and boot the
///   kernel without `quiet`;
/// - `first_boot`: send the full home seed (see [`build_seed`]).
///
/// Returns `Err` if the VM could not be started (an asset missing, no KVM
/// access, an image build failure, ...).  Once Firecracker is running,
/// failures come back as `Ok(Outcome)` with `error` set, so the exit status
/// and partial results are still recorded.
pub fn boot(s: &mut Session, cfg: &Config, cmd: &[String], console: bool, first_boot: bool) -> Result<Outcome> {
    let profile = crate::agent::for_session(s.meta.agent.as_deref());
    let fc_bin = images::find_asset("firecracker")?;
    let vmlinux = images::find_asset("vmlinux")?;
    let acinit = images::find_asset("acinit")?;
    if std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_err() {
        crate::bail!("cannot open /dev/kvm: add yourself to the kvm group (sudo usermod -aG kvm $USER)");
    }

    let base = images::base_image(&acinit, &fc_bin)?;
    crate::util::mark("base image");
    let usr = images::usr_image(cfg, Refresh::Auto)?;
    crate::util::mark("usr image check");
    let tools = images::detect_tools(cfg, &s.meta.cwd);
    let tools_img = images::tools_image(cfg, &tools)?;
    crate::util::mark("tools image check");
    let lower = s.path("lower.img");
    let lower_delta = Some(s.path("lower-delta.img")).filter(|p| p.exists());
    let scratch = s.path("scratch.img");

    let rundir = crate::util::runtime_dir().join(&s.meta.id);
    crate::util::mkdir_private(&rundir)?;
    let uds = rundir.join("v.sock");
    for p in [uds.clone(), rundir.join(format!("v.sock_{PORT_CONTROL}")), rundir.join(format!("v.sock_{PORT_PROXY}"))] {
        let _ = std::fs::remove_file(p);
    }
    let ctrl_l = UnixListener::bind(rundir.join(format!("v.sock_{PORT_CONTROL}"))).ctx("bind control socket")?;
    let proxy_l = UnixListener::bind(rundir.join(format!("v.sock_{PORT_PROXY}"))).ctx("bind proxy socket")?;

    let net = s.meta.net;
    let proxy = Arc::new(crate::proxy::Proxy {
        allow: s.meta.allow.clone(),
        enabled: net,
        log: Mutex::new(std::fs::OpenOptions::new().create(true).append(true).open(s.path("net.log")).ok()),
    });
    crate::proxy::serve(proxy_l, proxy);

    let mut args = String::from(
        "console=ttyS0 reboot=k panic=1 pci=off nomodule i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd \
         random.trust_cpu=on root=/dev/vda ro rootfstype=erofs init=/acinit",
    );
    if !console {
        args.push_str(" quiet loglevel=1");
    }
    if cfg.boot {
        // for acrboot's messages only (see crate::acrboot::BOOT_ARG)
        args.push(' ');
        args.push_str(crate::acrboot::BOOT_ARG);
    }
    let drive =|id: &str, p: &Path, root: bool, ro: bool| {
        serde_json::json!({"drive_id": id, "path_on_host": p, "is_root_device": root, "is_read_only": ro})
    };
    let mut drives = vec![
        drive("base", &base, true, true),
        drive("usr", &usr, false, true),
        drive("tools", &tools_img, false, true),
        drive("lower", &lower, false, true),
        drive("scratch", &scratch, false, false),
    ];
    if let Some(d) = &lower_delta {
        drives.push(drive("lowerdelta", d, false, true)); // /dev/vdf
    }
    // the project's build cache, held (locked) until the VM is gone
    let cache = if cfg.cache {
        match crate::buildcache::attach(&s.meta.cwd) {
            Ok(Some(c)) => Some(c),
            Ok(None) => {
                eprintln!("agentcracker: another session is using this directory's build cache; this one gets an empty ~/.cache");
                None
            }
            Err(e) => {
                eprintln!("agentcracker: no build cache: {e}");
                None
            }
        }
    } else {
        None
    };
    let dev_cache = cache.as_ref().map(|c| {
        // drives appear as vda, vdb, ... in the order given
        let dev = format!("/dev/vd{}", (b'a' + drives.len() as u8) as char);
        drives.push(drive("cache", &c.image, false, false));
        dev
    });
    let mut fc_cfg = serde_json::json!({
        "boot-source": {"kernel_image_path": vmlinux, "boot_args": args},
        "drives": drives,
        "machine-config": {"vcpu_count": s.meta.vcpus, "mem_size_mib": s.meta.mem_mib, "smt": false},
        "vsock": {"guest_cid": 3, "uds_path": uds},
        "entropy": {},
    });
    if !cfg.boot {
        fc_cfg["cpu-config"] = no_nested_virt();
    }
    let cfg_path = rundir.join("firecracker.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&fc_cfg)?)?;

    let tty = crate::util::isatty(0) && crate::util::isatty(1);
    let (rows, cols) = winsize();
    let gcfg = GuestConfig {
        session: s.meta.id.clone(),
        cwd: s.meta.cwd.display().to_string(),
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        user: crate::util::user_name(unsafe { libc::getuid() }),
        home: home().display().to_string(),
        cmd: cmd.to_vec(),
        env: guest_env(s, cfg, net, profile),
        path: std::env::var("PATH").unwrap_or_default(),
        tty,
        rows,
        cols,
        tools: tools.iter().map(|t| t.display().to_string()).collect(),
        dirs: ancestor_dirs(std::iter::once(s.meta.cwd.as_path()).chain(tools.iter().map(|t| t.as_path()))),
        net,
        state_paths: state_paths(cfg, profile),
        time: crate::util::now(),
        dev_usr: "/dev/vdb".into(),
        dev_tools: "/dev/vdc".into(),
        dev_lower: "/dev/vdd".into(),
        dev_scratch: "/dev/vde".into(),
        dev_lower_delta: lower_delta.as_ref().map(|_| "/dev/vdf".into()),
        dev_cache: dev_cache.clone(),
        boot: cfg.boot,
        git_branch: s.meta.work_branch.clone().zip(s.meta.git_head.clone()).filter(|_| first_boot),
        agent_files: crate::guidance::agent_files(
            profile,
            &home(),
            &crate::guidance::Context {
                cwd: &s.meta.cwd,
                net,
                allow: &s.meta.allow,
                cache: dev_cache.is_some(),
                boot: cfg.boot,
                branch: s.meta.work_branch.as_deref(),
                vcpus: s.meta.vcpus,
                mem_mib: s.meta.mem_mib,
            },
        )
        .into_iter()
        .chain(crate::guidance::git_identity())
        .collect(),
    };
    let seed = build_seed(&s.meta.cwd, cfg, first_boot, profile)?;
    crate::util::mark("home seed built");
    s.meta.cred_seed = hash_file(&home().join(credential_path(profile)));

    let mut fc_cmd = Command::new(&fc_bin);
    fc_cmd
        .arg("--no-api")
        .arg("--config-file")
        .arg(&cfg_path)
        .arg("--id")
        .arg(format!("agentcracker-{}", s.meta.id))
        .arg("--level")
        .arg(std::env::var("AGENTCRACKER_FC_LOG").unwrap_or_else(|_| "Error".into()))
        .stdin(Stdio::null());
    // firecracker's own x86_64 policy, compiled at install time (gnu builds
    // otherwise default to an allow-all filter)
    if let Ok(f) = images::find_asset("seccomp.bpf") {
        fc_cmd.arg("--seccomp-filter").arg(f);
    }
    // firecracker writes the console to the file itself (a pipe would
    // stall the guest's console, and its shutdown, if agentcracker died);
    // a thread here keeps the file within bounds
    let console_log = if console {
        fc_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        None
    } else {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(s.path("console.log"))?;
        fc_cmd.stdout(log.try_clone()?).stderr(log.try_clone()?);
        Some(bound_console(log))
    };
    let t0 = Instant::now();
    let mut fc = fc_cmd.spawn().ctx(format!("starting {}", fc_bin.display()))?;

    crate::util::mark("firecracker spawned");
    let res = attach(s, &ctrl_l, &mut fc, &gcfg, &seed, tty);
    if tty {
        reset_terminal();
    }

    // the guest powers off after DONE; give firecracker a moment, then make sure
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if fc.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if fc.try_wait().ok().flatten().is_none() {
        let _ = fc.kill();
        let _ = fc.wait();
    }
    if let Some((stop, t)) = console_log {
        stop.store(true, Ordering::Relaxed);
        let _ = t.join();
    }
    let _ = std::fs::remove_dir_all(&rundir);
    s.meta.runtime += t0.elapsed().as_secs();
    s.meta.boots += 1;
    match res {
        Ok(o) => Ok(o),
        Err(e) => Ok(Outcome { exit_code: None, exported: false, error: Some(e.0) }),
    }
}

/// Most of a boot's console output kept in `console.log`; the rest is
/// dropped (the guest kernel's console is for diagnosis, and only a guest
/// kernel gone wrong says this much).
const CONSOLE_MAX: u64 = 16 << 20;

/// Keep a boot's console output in `console.log` (`log`, which
/// Firecracker appends to) within bounds: a thread checks it twice a second
/// and cuts it back to [`CONSOLE_MAX`] more than it had when the boot
/// started - or to that, if the disk is nearly full
/// ([`crate::util::MIN_FREE`]) - ending it with a note that the rest was
/// dropped.  Returns the flag that stops the thread, and the thread.
fn bound_console(log: std::fs::File) -> (Arc<std::sync::atomic::AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let t = std::thread::spawn(move || {
        const NOTE: &[u8] = b"\n[agentcracker: the rest of this boot's console output was dropped]\n";
        let start = log.metadata().map(|m| m.len()).unwrap_or(0);
        let mut guard = SpaceGuard::default();
        let (mut last, mut cut) = (start, false);
        loop {
            let done = flag.load(Ordering::Relaxed);
            let len = log.metadata().map(|m| m.len()).unwrap_or(0);
            let full = guard.allow(log.as_raw_fd(), len.saturating_sub(last) as usize).is_err();
            let limit = if full { start } else { start + CONSOLE_MAX };
            if len > limit + if cut { NOTE.len() as u64 } else { 0 } {
                cut = true;
                // (the note is appended after the cut, so later output -
                // appended after it - is what the next cut removes)
                let _ = log.set_len(limit);
                let _ = (&log).write_all(NOTE);
            }
            last = log.metadata().map(|m| m.len()).unwrap_or(0);
            if done {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    });
    (stop, t)
}

/// Drive the control protocol for one boot (see the module docs) and copy
/// the command's terminal I/O.
///
/// `s`: the session (where the streams are saved); `l`: the control socket
/// listener; `fc`: the Firecracker process (to notice an early exit); `g`:
/// the guest configuration to send; `seed`: the encoded home seed; `tty`:
/// whether to put the terminal in raw mode.
///
/// EXPORT and STATE data go to `*.stream.tmp` files that are renamed into
/// place only when their end marker arrives, so an interrupted transfer
/// never leaves a truncated `changes.stream`.  The terminal is always
/// restored, and the stdin thread joined, before returning.
///
/// Returns the outcome.  Protocol failures (connection lost before EXIT, an
/// ERROR frame from the guest) are reported in `Outcome::error`, with the
/// console tail appended.  Returns `Err` for a failure before the guest
/// connects (timeout, early Firecracker exit) or a local I/O error writing
/// the streams; [`boot`] turns those into an `Outcome` too.
fn attach(s: &Session, l: &UnixListener, fc: &mut Child, g: &GuestConfig, seed: &[u8], tty: bool) -> Result<Outcome> {
    let conn = accept_guest(l, fc, Duration::from_secs(30))?;
    crate::util::mark("guest connected");
    let mut rd = conn.try_clone()?;
    let ctrl = Arc::new(Mutex::new(conn));
    {
        let mut c = ctrl.lock().unwrap();
        write_frame(&mut *c, M_CONFIG, &serde_json::to_vec(g)?)?;
        for chunk in seed.chunks(1 << 20) {
            write_frame(&mut *c, M_SEED, chunk)?;
        }
        write_frame(&mut *c, M_SEED_END, &[])?;
        crate::util::mark(&format!("config + home seed sent ({} KiB)", seed.len() >> 10));
    }

    let (stop_r, stop_w) = pipe()?;
    let (winch_r, winch_w) = pipe()?;
    let (term_r, term_w) = pipe()?;
    WINCH_FD.store(winch_w, Ordering::Relaxed);
    TERM_FD.store(term_w, Ordering::Relaxed);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_winch as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
        sa.sa_sigaction = on_term as *const () as usize;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
    let mut raw = if tty { RawTerm::enter() } else { None };
    let pump = stdin_pump(ctrl.clone(), stop_r, winch_r, term_r);
    let stop_pump = |raw: &mut Option<RawTerm>| {
        unsafe { libc::write(stop_w, b"x".as_ptr().cast(), 1) };
        raw.take();
    };

    let mut out = io::stdout().lock();
    let mut exit_code = None;
    let mut exported = false;
    let mut changes: Option<std::fs::File> = None;
    let mut state: Option<std::fs::File> = None;
    let mut err = None;
    // what the guest sends stops before it fills the host's disk (see
    // util::MIN_FREE): its output, if that goes to a file, is then
    // dropped; its changes and state end the session with an error
    let (mut out_guard, mut err_guard, mut stream_guard) = <(SpaceGuard, SpaceGuard, SpaceGuard)>::default();
    let mut dropping = [false; 2];
    let full = |what: &str, e: crate::util::Error| {
        format!("{e}: stopped receiving {what}; free some space, then `agentcracker resume` the session to get them")
    };
    loop {
        let (t, d) = match read_frame(&mut rd) {
            Ok(f) => f,
            Err(e) => {
                if exit_code.is_none() {
                    err = Some(format!("lost connection to the guest: {e}"));
                }
                break;
            }
        };
        match t {
            M_STDOUT | M_STDERR => {
                let i = (t == M_STDERR) as usize;
                let g = if i == 0 { &mut out_guard } else { &mut err_guard };
                if !dropping[i] {
                    if let Err(e) = g.allow(1 + i as i32, d.len()) {
                        dropping[i] = true;
                        eprintln!("agentcracker: {e}: the rest of the command's {} is dropped", ["output", "error output"][i]);
                    }
                }
                if !dropping[i] {
                    if i == 0 {
                        let _ = out.write_all(&d);
                        let _ = out.flush();
                    } else {
                        let mut e = std::io::stderr().lock();
                        let _ = e.write_all(&d);
                        let _ = e.flush();
                    }
                }
            }
            M_READY => crate::util::mark("guest command started"),
            M_ERROR => {
                err = Some(format!("guest setup failed: {}", crate::util::safe_text(&d, true)));
                break;
            }
            M_EXIT => {
                crate::util::mark("guest command exited");
                let mut b = [0u8; 4];
                b.copy_from_slice(&d[..4.min(d.len())]);
                exit_code = Some(i32::from_be_bytes(b));
                stop_pump(&mut raw);
            }
            M_EXPORT => {
                if changes.is_none() {
                    changes = Some(std::fs::File::create(s.path("changes.stream.tmp"))?);
                }
                let f = changes.as_mut().unwrap();
                if let Err(e) = stream_guard.allow(f.as_raw_fd(), d.len()) {
                    drop(changes.take());
                    let _ = std::fs::remove_file(s.path("changes.stream.tmp"));
                    err = Some(full("the session's changes", e));
                    break;
                }
                f.write_all(&d)?;
            }
            M_EXPORT_END => {
                if let Some(f) = changes.take() {
                    f.sync_all()?;
                    std::fs::rename(s.path("changes.stream.tmp"), s.path("changes.stream"))?;
                    exported = true;
                }
            }
            M_STATE => {
                if state.is_none() {
                    state = Some(std::fs::File::create(s.path("state.stream.tmp"))?);
                }
                let f = state.as_mut().unwrap();
                if let Err(e) = stream_guard.allow(f.as_raw_fd(), d.len()) {
                    drop(state.take());
                    let _ = std::fs::remove_file(s.path("state.stream.tmp"));
                    err = Some(full("the agent's state", e));
                    break;
                }
                f.write_all(&d)?;
            }
            M_STATE_END => {
                if state.take().is_some() {
                    std::fs::rename(s.path("state.stream.tmp"), s.path("state.stream"))?;
                }
            }
            M_DONE => break,
            _ => {}
        }
    }
    stop_pump(&mut raw);
    let _ = pump.join();
    WINCH_FD.store(-1, Ordering::Relaxed);
    TERM_FD.store(-1, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGWINCH, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        for fd in [stop_r, stop_w, winch_r, winch_w, term_r, term_w] {
            libc::close(fd);
        }
    }
    let _ = ctrl.lock().map(|c| c.shutdown(std::net::Shutdown::Both));
    if err.is_none() && !exported {
        err = Some("lost the connection to the guest after the command exited; the session's changes were not received".into());
    }
    if let Some(e) = err {
        let tail = console_tail(s, 15);
        let msg = if tail.trim().is_empty() { e } else { format!("{e}\n--- guest console (last lines) ---\n{tail}") };
        return Ok(Outcome { exit_code, exported, error: Some(msg) });
    }
    Ok(Outcome { exit_code, exported, error: None })
}

/// Run `cmd` inside the session's running VM (`agentcracker shell` on a
/// running session), attached to this terminal or to these pipes.
///
/// Connects through Firecracker's vsock socket in the session's runtime
/// directory (`CONNECT` to [`PORT_EXEC`]), sends an [`ExecRequest`] and
/// relays input, output and window size until the command exits.  Returns
/// its exit status; errors if the VM cannot be reached or the session ends
/// first.
pub fn exec_running(s: &Session, cmd: &[String]) -> Result<i32> {
    // a session that was just started may not have its VM (or the guest's
    // listener) up yet: keep trying for a while as long as it is running
    let deadline = Instant::now() + Duration::from_secs(15);
    let conn = loop {
        match exec_connect(s) {
            Ok(c) => break c,
            Err(e) => {
                if Instant::now() > deadline || !s.is_running() {
                    crate::bail!("cannot reach session {}'s VM: {e}", s.meta.id);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    let tty = crate::util::isatty(0) && crate::util::isatty(1);
    let (rows, cols) = winsize();
    let req = ExecRequest { cmd: cmd.to_vec(), tty, rows, cols, term: std::env::var("TERM").ok() };
    let mut rd = conn.try_clone()?;
    let ctrl = Arc::new(Mutex::new(conn));
    write_frame(&mut *ctrl.lock().unwrap(), M_EXEC, &serde_json::to_vec(&req)?)?;

    let (stop_r, stop_w) = pipe()?;
    let (winch_r, winch_w) = pipe()?;
    WINCH_FD.store(winch_w, Ordering::Relaxed);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_winch as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
    let mut raw = if tty { RawTerm::enter() } else { None };
    let pump = stdin_pump(ctrl.clone(), stop_r, winch_r, -1);
    let mut out = io::stdout().lock();
    let mut code = None;
    let mut err = None;
    while let Ok((t, d)) = read_frame(&mut rd) {
        match t {
            M_STDOUT => {
                let _ = out.write_all(&d);
                let _ = out.flush();
            }
            M_STDERR => {
                let mut e = io::stderr().lock();
                let _ = e.write_all(&d);
                let _ = e.flush();
            }
            M_ERROR => {
                err = Some(crate::util::safe_text(&d, true));
                break;
            }
            M_EXIT => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&d[..4.min(d.len())]);
                code = Some(i32::from_be_bytes(b));
                break;
            }
            _ => {}
        }
    }
    unsafe { libc::write(stop_w, b"x".as_ptr().cast(), 1) };
    raw.take();
    let _ = ctrl.lock().map(|c| c.shutdown(std::net::Shutdown::Both));
    let _ = pump.join();
    WINCH_FD.store(-1, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGWINCH, libc::SIG_DFL);
        for fd in [stop_r, stop_w, winch_r, winch_w] {
            libc::close(fd);
        }
    }
    if tty {
        reset_terminal();
    }
    if let Some(e) = err {
        crate::bail!("could not start {} in the session: {e}", cmd.first().map(|c| c.as_str()).unwrap_or("?"));
    }
    code.ctx(format!("session {} ended while the command was running", s.meta.id))
}


/// Open a connection to the guest's [`PORT_EXEC`] listener through
/// Firecracker's vsock socket: send `CONNECT <port>` and expect `OK`.
/// Run `cmd` inside the session's running VM without a terminal and
/// return its stdout, at most `limit` bytes (the rest is dropped), or
/// `None` if it exits non-zero.  For reading the guest's files while it
/// runs (`agentcracker log`); the output is the guest's, so untrusted.
/// Errors if the VM cannot be reached or the command cannot be started.
pub fn exec_capture(s: &Session, cmd: &[&str], limit: usize) -> Result<Option<Vec<u8>>> {
    let mut conn = exec_connect(s)?;
    conn.set_read_timeout(Some(Duration::from_secs(30)))?;
    let req = ExecRequest { cmd: cmd.iter().map(|c| c.to_string()).collect(), tty: false, rows: 0, cols: 0, term: None };
    write_frame(&mut conn, M_EXEC, &serde_json::to_vec(&req)?)?;
    write_frame(&mut conn, M_STDIN_EOF, &[])?;
    let mut out = Vec::new();
    loop {
        let (t, d) = read_frame(&mut conn).ctx("reading from the session's VM")?;
        match t {
            M_STDOUT => out.extend_from_slice(&d[..d.len().min(limit.saturating_sub(out.len()))]),
            M_ERROR => crate::bail!("{}", crate::util::safe_text(&d, true)),
            M_EXIT => {
                let code = d.get(..4).map(|b| i32::from_be_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(-1);
                return Ok((code == 0).then_some(out));
            }
            _ => {}
        }
    }
}

fn exec_connect(s: &Session) -> Result<UnixStream> {
    use std::io::Read;
    let uds = crate::util::runtime_dir().join(&s.meta.id).join("v.sock");
    let mut conn = UnixStream::connect(&uds)?;
    conn.write_all(format!("CONNECT {PORT_EXEC}\n").as_bytes())?;
    // read the reply byte by byte so no frame data is consumed with it
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while line.len() < 64 {
        match conn.read(&mut b) {
            Ok(0) => break,
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) => line.push(b[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    if !line.starts_with(b"OK") {
        crate::bail!("the guest is not accepting connections yet");
    }
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_is_cut_at_its_limit() {
        let dir = std::env::temp_dir().join(format!("ac-console-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("console.log");
        std::fs::write(&p, b"earlier boot\n").unwrap();
        let open = || std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        let (stop, t) = bound_console(open());
        // as a guest kernel flooding its console would, in a few bursts
        let mut fc = open();
        for _ in 0..3 {
            fc.write_all(&vec![b'x'; (CONSOLE_MAX / 2 + 1) as usize]).unwrap();
            std::thread::sleep(Duration::from_millis(700));
        }
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
        let got = std::fs::read(&p).unwrap();
        let note = b"[agentcracker: the rest of this boot's console output was dropped]\n";
        assert!(got.starts_with(b"earlier boot\n"), "earlier boots' output is kept");
        assert!(got.ends_with(note), "and the cut is noted");
        assert_eq!(got.len() as u64, 13 + CONSOLE_MAX + 1 + note.len() as u64);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
