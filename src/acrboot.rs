//! `acrboot`: boot a kernel the agent built, in a microVM of its own.
//!
//! Firecracker offers no nested virtualisation, so the agent cannot run a
//! kernel it built inside its own VM.  The host can: inside a session,
//! `acrboot VMLINUX` sends the kernel (and any `--disk` images) to the host
//! over vsock port [`PORT_BOOT`], the host boots them in a separate
//! Firecracker - no network, no vsock, its own seccomp filter, CPUs and
//! memory capped at the session's, a timeout - and streams its serial
//! console back.  `acrboot` exits with the outcome: 0 when the kernel shut
//! the VM down, 1 on a panic, 124 on a timeout, 2 on an error.
//!
//! Two uses: a kernel on its own (built-in KUnit suites with
//! `kunit_shutdown=reboot`, boot smoke tests), and a kernel with a root
//! disk the agent made (`--disk rootfs.img`, mounted as `/dev/vda`).
//!
//! It is opt-in (`boot = true`, in the user's config only), because it
//! hands the agent ring 0 in a VM: the boundary is then KVM and
//! Firecracker's device emulation against a guest kernel the agent
//! controls - Firecracker's own threat model, but more than a session
//! otherwise exposes.  The host does not parse what it is sent: the
//! kernel and disks are written to files (size-capped) and given to
//! Firecracker; only the request, small JSON with clamped values, is read.
//!
//! The conversation, in frames (see [`crate::proto`]):
//!
//! ```text
//! guest: BOOT_REQ (JSON)  then for the kernel and each disk: BLOB* BLOB_END
//! host:  CONSOLE*  then BOOT_RESULT (JSON)
//! ```
//!
//! The client side runs in the guest (`main` dispatches on the program
//! name), the server side in the host's agentcracker for the session.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::proto::{read_frame, write_frame};
use crate::util::{Context, Result};

/// vsock port of boot requests (the host listens on `v.sock_1027` when
/// booting is enabled).
pub const PORT_BOOT: u32 = 1027;

/// guest to host: the [`Request`], as JSON.
const M_BOOT_REQ: u8 = 30;
/// guest to host: a chunk of the current file (the kernel, then each disk).
const M_BLOB: u8 = 31;
/// guest to host: the current file is complete.
const M_BLOB_END: u8 = 32;
/// host to guest: serial console output of the test VM.
const M_CONSOLE: u8 = 33;
/// host to guest: the [`Outcome`], as JSON.  The last frame.
const M_BOOT_RESULT: u8 = 34;

/// Largest kernel accepted (an ELF vmlinux with debug info can be large).
const MAX_KERNEL: u64 = 2 << 30;
/// Largest total size of the disks of one boot.
const MAX_DISKS: u64 = 32 << 30;
/// Most disks per boot.
const MAX_DISK_COUNT: usize = 8;
/// Default and largest timeout, in seconds.
const DEFAULT_TIMEOUT: u64 = 600;
const MAX_TIMEOUT: u64 = 6 * 3600;

/// What the guest asks for.  Every value is clamped by the host.
#[derive(Serialize, Deserialize, Debug, Default)]
struct Request {
    cpus: Option<u32>,
    mem_mib: Option<u64>,
    timeout: Option<u64>,
    /// Extra kernel command line.
    append: String,
    /// Number of disk files that follow the kernel.
    disks: usize,
}

/// How a test boot ended.
#[derive(Serialize, Deserialize, Debug)]
struct Outcome {
    /// `exit` (the kernel reset or powered off the VM), `panic`, `timeout`
    /// or `error`.
    outcome: String,
    /// Wall-clock seconds from start to end.
    secs: f64,
    /// For `error`: what went wrong.
    message: Option<String>,
    /// What the host actually gave the VM, after clamping.
    cpus: u32,
    mem_mib: u64,
}

// ---------------------------------------------------------------------------
// guest side: the acrboot command
// ---------------------------------------------------------------------------

/// The kernel options Firecracker needs, for `acrboot --kconfig`.
const KCONFIG: &str = include_str!("../kernel/acrboot.config");

const USAGE: &str = "usage: acrboot [--cpus N] [--mem SIZE] [--timeout SECS] [--append ARGS] [--disk FILE]... VMLINUX
       acrboot --kconfig    print the kernel options needed to boot under Firecracker

Boot VMLINUX (an uncompressed ELF kernel) in a microVM of its own on the host
and show its serial console.  Each --disk is attached read-write (a copy),
the first as /dev/vda, which becomes the root device unless --append sets
root=.  The VM has no network.  A kernel on its own is useful for built-in
tests: --append \"kunit_shutdown=reboot\" ends the boot after KUnit.

The kernel must be the uncompressed ELF vmlinux, configured for Firecracker:
  acrboot --kconfig > acrboot.config
  scripts/kconfig/merge_config.sh -m .config acrboot.config && make olddefconfig

Exit status: 0 the kernel shut the VM down, 1 kernel panic, 124 timeout,
2 error.  Defaults: 2 CPUs, 1G, 600s (capped at the session's CPUs and memory).
";

/// `acrboot ...` in the guest.  Returns the exit status.
pub fn client(args: &[String]) -> i32 {
    match client_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("acrboot: {e}");
            2
        }
    }
}

fn client_inner(args: &[String]) -> Result<i32> {
    let mut req = Request::default();
    let mut disks: Vec<PathBuf> = vec![];
    let mut kernel = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().cloned().ctx(format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(0);
            }
            "--kconfig" => {
                print!("{KCONFIG}");
                return Ok(0);
            }
            "--cpus" => req.cpus = Some(val("--cpus")?.parse().ok().ctx("--cpus needs a number")?),
            "--mem" => req.mem_mib = Some(crate::util::parse_mem_mib(&val("--mem")?).ctx("bad --mem (e.g. 512M, 2G)")?),
            "--timeout" => req.timeout = Some(val("--timeout")?.parse().ok().ctx("--timeout needs seconds")?),
            "--append" => {
                let v = val("--append")?;
                req.append = if req.append.is_empty() { v } else { format!("{} {v}", req.append) };
            }
            "--disk" => disks.push(PathBuf::from(val("--disk")?)),
            o if o.starts_with('-') => crate::bail!("unknown option {o}\n{USAGE}"),
            o if kernel.is_none() => kernel = Some(PathBuf::from(o)),
            o => crate::bail!("unexpected argument {o}\n{USAGE}"),
        }
    }
    let Some(kernel) = kernel else {
        eprint!("{USAGE}");
        return Ok(2);
    };
    check_kernel(&kernel)?;
    if disks.len() > MAX_DISK_COUNT {
        crate::bail!("at most {MAX_DISK_COUNT} disks");
    }
    req.disks = disks.len();
    let conn = crate::guest::vsock_connect(PORT_BOOT).map_err(|e| {
        crate::util::Error(format!(
            "booting test kernels is not enabled for this session ({e}); \
             it is turned on with `boot = true` in ~/.config/agentcracker/config.toml on the host"
        ))
    })?;
    let mut w = conn.try_clone()?;
    write_frame(&mut w, M_BOOT_REQ, &serde_json::to_vec(&req)?)?;
    for f in std::iter::once(&kernel).chain(disks.iter()) {
        send_file(&mut w, f)?;
    }
    let mut r = conn;
    let mut out = io::stdout();
    loop {
        let (t, d) = read_frame(&mut r).ctx("the host closed the connection")?;
        match t {
            M_CONSOLE => {
                let _ = out.write_all(&d);
                let _ = out.flush();
            }
            M_BOOT_RESULT => {
                let o: Outcome = serde_json::from_slice(&d)?;
                eprintln!(
                    "acrboot: {} after {:.1}s ({} CPU, {}M){}",
                    match o.outcome.as_str() {
                        "exit" => "the kernel shut the VM down",
                        "panic" => "kernel panic",
                        "timeout" => "timed out",
                        _ => "error",
                    },
                    o.secs,
                    o.cpus,
                    o.mem_mib,
                    o.message.map(|m| format!(": {m}")).unwrap_or_default()
                );
                return Ok(match o.outcome.as_str() {
                    "exit" => 0,
                    "panic" => 1,
                    "timeout" => 124,
                    _ => 2,
                });
            }
            _ => {}
        }
    }
}

/// Refuse what Firecracker cannot boot, with a useful message: it needs an
/// uncompressed ELF kernel (`vmlinux`), not a `bzImage`.
fn check_kernel(p: &Path) -> Result<()> {
    let mut f = std::fs::File::open(p).ctx(format!("{}", p.display()))?;
    let mut hdr = [0u8; 0x206];
    let n = f.read(&mut hdr)?;
    if n >= 4 && &hdr[..4] == b"\x7fELF" {
        return Ok(());
    }
    if n >= 0x206 && &hdr[0x202..0x206] == b"HdrS" {
        crate::bail!("{} is a bzImage; Firecracker boots the uncompressed ELF kernel (vmlinux at the top of the build tree)", p.display());
    }
    crate::bail!("{} is not an ELF kernel image (use vmlinux from the top of the build tree)", p.display())
}

/// Send file `p` as BLOB frames and a BLOB_END.
fn send_file(w: &mut impl Write, p: &Path) -> Result<()> {
    let mut f = std::fs::File::open(p).ctx(format!("{}", p.display()))?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        write_frame(w, M_BLOB, &buf[..n]).ctx("sending to the host")?;
    }
    write_frame(w, M_BLOB_END, &[])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// host side
// ---------------------------------------------------------------------------

/// What the server needs from the session.
pub struct Server {
    /// Directory for the uploaded files and per-boot consoles (in the
    /// session directory: these can be large, and the runtime dir is
    /// often a small tmpfs).
    pub dir: PathBuf,
    /// `boot.log`: one line per boot, for `agentcracker log`.
    pub log: PathBuf,
    /// The session's own CPUs and memory: test VMs get at most these.
    pub max_cpus: u32,
    pub max_mem_mib: u64,
    /// The test VM of the moment, so the session can stop it when it ends.
    pub vm: Arc<TestVm>,
}

/// The session's test VM, shared between the boot handler and the session.
#[derive(Default)]
pub struct TestVm {
    /// Its Firecracker's pid while one runs.
    pid: Mutex<Option<u32>>,
    /// Held by the handler for the whole of a request.
    busy: Mutex<()>,
    /// The session is ending: stop, and say so.
    ending: std::sync::atomic::AtomicBool,
}

/// Accept boot requests on `l`, one at a time, until the listener goes
/// away with the session.
pub fn serve(l: UnixListener, srv: Server) {
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            let _ = handle(c, &srv);
            let _ = std::fs::remove_dir_all(srv.dir.join("upload"));
        }
    });
}

/// The session is ending: kill its test VM, if one is running, and wait
/// for the handler to record it.
pub fn stop(vm: &TestVm) {
    vm.ending.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(pid) = vm.pid.lock().unwrap().take() {
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    drop(vm.busy.lock());
}

fn handle(conn: UnixStream, srv: &Server) -> Result<()> {
    let _busy = srv.vm.busy.lock().unwrap();
    if srv.vm.ending.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    let mut r = conn.try_clone()?;
    let w = Arc::new(Mutex::new(conn));
    let (t, d) = read_frame(&mut r)?;
    if t != M_BOOT_REQ || d.len() > 64 << 10 {
        crate::bail!("bad boot request");
    }
    let req: Request = serde_json::from_slice(&d)?;
    let cpus = req.cpus.unwrap_or(2).clamp(1, srv.max_cpus.max(1));
    let mem_mib = req.mem_mib.unwrap_or(1024).clamp(128, srv.max_mem_mib.max(128));
    let timeout = req.timeout.unwrap_or(DEFAULT_TIMEOUT).clamp(1, MAX_TIMEOUT);
    let fail = |msg: String| {
        let o = Outcome { outcome: "error".into(), secs: 0.0, message: Some(msg), cpus, mem_mib };
        let _ = write_frame(&mut *w.lock().unwrap(), M_BOOT_RESULT, &serde_json::to_vec(&o).unwrap_or_default());
    };
    if req.disks > MAX_DISK_COUNT {
        fail(format!("at most {MAX_DISK_COUNT} disks"));
        return Ok(());
    }

    // receive the files, size-capped; their contents are never looked at
    let up = srv.dir.join("upload");
    let _ = std::fs::remove_dir_all(&up);
    crate::util::mkdir_private(&srv.dir)?;
    crate::util::mkdir_private(&up)?;
    let kernel = up.join("vmlinux");
    let disks: Vec<PathBuf> = (0..req.disks).map(|i| up.join(format!("disk{i}"))).collect();
    let mut disk_total = 0;
    for (i, p) in std::iter::once(&kernel).chain(disks.iter()).enumerate() {
        let cap = if i == 0 { MAX_KERNEL } else { MAX_DISKS - disk_total };
        match recv_file(&mut r, p, cap) {
            Ok(n) if i > 0 => disk_total += n,
            Ok(_) => {}
            Err(e) => {
                fail(if i == 0 { format!("kernel: {e}") } else { format!("disk {i}: {e}") });
                return Ok(());
            }
        }
    }

    // the test VM: kernel, disks, serial console; nothing else
    let mut args = String::from("console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd");
    if !disks.is_empty() && !req.append.split_whitespace().any(|a| a.starts_with("root=")) {
        args.push_str(" root=/dev/vda rw");
    }
    if !req.append.is_empty() {
        args.push(' ');
        args.push_str(&req.append);
    }
    let drives: Vec<_> = disks
        .iter()
        .enumerate()
        .map(|(i, p)| serde_json::json!({"drive_id": format!("disk{i}"), "path_on_host": p, "is_root_device": false, "is_read_only": false}))
        .collect();
    let fc_cfg = serde_json::json!({
        "boot-source": {"kernel_image_path": kernel, "boot_args": args},
        "drives": drives,
        "machine-config": {"vcpu_count": cpus, "mem_size_mib": mem_mib, "smt": false},
        "entropy": {},
    });
    let cfg_path = up.join("firecracker.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&fc_cfg)?)?;
    let fc_log = up.join("firecracker.log");
    std::fs::write(&fc_log, b"")?;
    let n = next_boot_number(&srv.dir);
    let console_path = srv.dir.join(format!("{n}.console"));
    let mut console_file = std::fs::File::create(&console_path)?;

    let fc_bin = crate::images::find_asset("firecracker")?;
    let mut cmd = Command::new(&fc_bin);
    cmd.arg("--no-api")
        .arg("--config-file")
        .arg(&cfg_path)
        .arg("--id")
        .arg(format!("acrboot-{n}"))
        .arg("--log-path")
        .arg(&fc_log)
        .arg("--level")
        .arg("Error")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Ok(f) = crate::images::find_asset("seccomp.bpf") {
        cmd.arg("--seccomp-filter").arg(f);
    }
    // the test VM must not outlive this thread (and so the session)
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
    let t0 = Instant::now();
    let mut fc = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            fail(format!("starting firecracker: {e}"));
            return Ok(());
        }
    };
    *srv.vm.pid.lock().unwrap() = Some(fc.id());

    // console -> guest and to the session's copy; watch for a panic
    let mut out = fc.stdout.take().unwrap();
    let w2 = w.clone();
    let panic_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ps = panic_seen.clone();
    let client_left = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cl = client_left.clone();
    let reader = std::thread::spawn(move || {
        let mut buf = vec![0u8; 1 << 16];
        let mut tail: Vec<u8> = vec![];
        let mut panicked = false;
        let mut client_gone = false;
        loop {
            let n = match out.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let _ = console_file.write_all(&buf[..n]);
            tail.extend_from_slice(&buf[..n]);
            if !panicked && contains(&tail, b"Kernel panic - not syncing") {
                panicked = true;
                ps.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            let keep = tail.len().saturating_sub(64);
            tail.drain(..keep);
            if !client_gone && write_frame(&mut *w2.lock().unwrap(), M_CONSOLE, &buf[..n]).is_err() {
                client_gone = true;
                cl.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            if client_gone {
                break; // acrboot was interrupted: stop the VM
            }
        }
        (panicked, client_gone)
    });

    let deadline = t0 + Duration::from_secs(timeout);
    let mut timed_out = false;
    let mut panic_at = None;
    let status = loop {
        if let Ok(Some(st)) = fc.try_wait() {
            break Some(st);
        }
        // a panicked kernel may never reset the VM (panic=0): give it a
        // moment to finish its report, then stop it
        if panic_at.is_none() && panic_seen.load(std::sync::atomic::Ordering::Relaxed) {
            panic_at = Some(Instant::now());
        }
        let panic_done = panic_at.is_some_and(|t| t.elapsed() > Duration::from_secs(3));
        let gone = client_left.load(std::sync::atomic::Ordering::Relaxed);
        if gone || panic_done || Instant::now() >= deadline {
            // acrboot went away, the panic is reported, or out of time
            timed_out = !panic_done && Instant::now() >= deadline;
            let _ = fc.kill();
            break fc.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    *srv.vm.pid.lock().unwrap() = None;
    let (panicked, client_gone) = reader.join().unwrap_or((false, false));
    let secs = t0.elapsed().as_secs_f64();
    let (outcome, message) = if panicked {
        ("panic", None)
    } else if timed_out {
        ("timeout", None)
    } else if srv.vm.ending.load(std::sync::atomic::Ordering::Relaxed) {
        ("error", Some("the session ended".to_string()))
    } else if client_gone {
        ("error", Some("interrupted".to_string()))
    } else if status.is_some_and(|s| s.success()) {
        ("exit", None)
    } else {
        let log = std::fs::read_to_string(&fc_log).unwrap_or_default();
        let last = log.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("firecracker failed").to_string();
        ("error", Some(crate::util::safe_text(last.as_bytes(), false)))
    };
    log_boot(srv, outcome, secs, &kernel, &req.append, req.disks);
    let o = Outcome { outcome: outcome.into(), secs, message, cpus, mem_mib };
    let _ = write_frame(&mut *w.lock().unwrap(), M_BOOT_RESULT, &serde_json::to_vec(&o)?);
    Ok(())
}

/// Receive one file (BLOB* BLOB_END) from `r` into `p`, at most `cap`
/// bytes.  Returns its size.
fn recv_file(r: &mut impl Read, p: &Path, cap: u64) -> Result<u64> {
    let mut f = std::fs::File::create(p)?;
    let mut n = 0u64;
    loop {
        let (t, d) = read_frame(r)?;
        match t {
            M_BLOB => {
                n += d.len() as u64;
                if n > cap {
                    crate::bail!("larger than {}", crate::util::human_bytes(cap));
                }
                f.write_all(&d)?;
            }
            M_BLOB_END => return Ok(n),
            _ => crate::bail!("unexpected frame {t}"),
        }
    }
}

/// The number for the next boot's console file in `dir` (1, 2, ...).
fn next_boot_number(dir: &Path) -> u32 {
    let mut n = 1;
    while dir.join(format!("{n}.console")).exists() {
        n += 1;
    }
    n
}

/// Append a line to `boot.log`: `<time> <outcome> <secs> <kernel size>
/// <disks> <append>` (the append text is the guest's, escaped).
fn log_boot(srv: &Server, outcome: &str, secs: f64, kernel: &Path, append: &str, disks: usize) {
    let size = std::fs::metadata(kernel).map(|m| m.len()).unwrap_or(0);
    let append = crate::util::safe_text(append.as_bytes(), false);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&srv.log) {
        let _ = writeln!(f, "{} {outcome} {secs:.1} {size} {disks} {append}", crate::util::now());
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}
