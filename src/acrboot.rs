//! `acrboot`: boot a kernel the agent built, in a microVM of its own.
//!
//! The session's VM has nested virtualisation: the guest kernel has KVM
//! built in and the host passes VMX/SVM through, so inside a session
//! `acrboot VMLINUX` runs Firecracker itself - a second-level microVM with
//! no network and no vsock, CPUs and memory within the session's, a
//! timeout - and shows its serial console.  It exits with the outcome: 0
//! when the kernel shut the VM down, 1 on a panic, 124 on a timeout, 2 on
//! an error.
//!
//! Two uses: a kernel on its own (built-in KUnit suites with
//! `kunit_shutdown=reboot`, boot smoke tests), and a kernel with a root
//! disk the agent made (`--disk rootfs.img`, mounted as `/dev/vda`).
//!
//! It is opt-in (`boot = true`, in the user's config only): acinit makes
//! `/dev/kvm` usable by the agent only then, and removes it otherwise.
//! Nothing here runs on the host.  The test VM lives inside the session's
//! VM - its memory, CPUs and disk are the session's, and it ends with the
//! session - so a test kernel that escapes its VM lands in the sandbox.
//! What it adds is the host's nested-virtualisation code (KVM handles the
//! test VM's exits first), against a kernel the agent controls.
//!
//! Each boot is recorded in the guest's `~/.local/state/acrboot` (see
//! [`RECORDS`]): a line in `boot.log` and the console, capped, in
//! `N.console`.  That directory is part of the session's exported state, so
//! the user sees the boots (`agentcracker log`) once the VM stops.
//!
//! `main` runs this when the program is called `acrboot`: acinit links
//! `/usr/bin/acrboot` to itself.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::util::{Context, Result};

/// Where the base image has Firecracker and its seccomp filter.
pub const FIRECRACKER: &str = "/acboot/firecracker";
pub const SECCOMP: &str = "/acboot/seccomp.bpf";

/// The guest directory holding boot records, relative to `$HOME`.
pub const RECORDS: &str = ".local/state/acrboot";

/// Most disks per boot.
const MAX_DISK_COUNT: usize = 8;
/// Default and largest timeout, in seconds.
const DEFAULT_TIMEOUT: u64 = 600;
const MAX_TIMEOUT: u64 = 6 * 3600;
/// Most console kept per boot, and most boots' consoles kept.
const MAX_CONSOLE: u64 = 4 << 20;
const KEEP_CONSOLES: u32 = 20;
/// Memory left to the session itself, at least.
pub const RESERVE_MIB: u64 = 512;

/// The kernel options Firecracker needs, for `acrboot --kconfig`.
const KCONFIG: &str = include_str!("../kernel/acrboot.config");

const USAGE: &str = "usage: acrboot [--cpus N] [--mem SIZE] [--timeout SECS] [--append ARGS] [--disk FILE]... VMLINUX
       acrboot --kconfig    print the kernel options needed to boot under Firecracker

Boot VMLINUX (an uncompressed ELF kernel) in a microVM of its own and show
its serial console.  Each --disk is attached read-write, in place (copy it
first to keep the original); the first is /dev/vda, which becomes the root
device unless --append sets root=.  The VM has no network.  A kernel on its
own is useful for built-in tests: --append \"kunit_shutdown=reboot\" ends the
boot after KUnit.

The kernel must be the uncompressed ELF vmlinux, configured for Firecracker:
  acrboot --kconfig > acrboot.config
  scripts/kconfig/merge_config.sh -m .config acrboot.config && make olddefconfig

Exit status: 0 the kernel shut the VM down, 1 kernel panic, 124 timeout,
2 error.  Defaults: 2 CPUs, 1G, 600s (within this VM's CPUs and memory).
";

/// What was asked for.
#[derive(Default)]
struct Request {
    cpus: Option<u32>,
    mem_mib: Option<u64>,
    timeout: Option<u64>,
    /// Extra kernel command line.
    append: String,
    disks: Vec<PathBuf>,
    kernel: Option<PathBuf>,
}

/// Set by SIGINT, SIGTERM or SIGHUP (acrboot interrupted, or the session
/// ending): stop the test VM and record it.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// `acrboot ...` in the guest.  Returns the exit status.
pub fn client(args: &[String]) -> i32 {
    match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("acrboot: {e}");
            2
        }
    }
}

/// The command line; `None` when it asked only for help or `--kconfig`.
fn parse(args: &[String]) -> Result<Option<Request>> {
    let mut req = Request::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().cloned().ctx(format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--kconfig" => {
                print!("{KCONFIG}");
                return Ok(None);
            }
            "--cpus" => req.cpus = Some(val("--cpus")?.parse().ok().ctx("--cpus needs a number")?),
            "--mem" => req.mem_mib = Some(crate::util::parse_mem_mib(&val("--mem")?).ctx("bad --mem (e.g. 512M, 2G)")?),
            "--timeout" => req.timeout = Some(val("--timeout")?.parse().ok().ctx("--timeout needs seconds")?),
            "--append" => {
                let v = val("--append")?;
                req.append = if req.append.is_empty() { v } else { format!("{} {v}", req.append) };
            }
            "--disk" => req.disks.push(PathBuf::from(val("--disk")?)),
            o if o.starts_with('-') => crate::bail!("unknown option {o}\n{USAGE}"),
            o if req.kernel.is_none() => req.kernel = Some(PathBuf::from(o)),
            o => crate::bail!("unexpected argument {o}\n{USAGE}"),
        }
    }
    if req.kernel.is_none() {
        crate::bail!("no kernel given\n{USAGE}");
    }
    Ok(Some(req))
}

fn run(args: &[String]) -> Result<i32> {
    let Some(req) = parse(args)? else { return Ok(0) };
    let kernel = req.kernel.as_deref().unwrap();
    check_kvm()?;
    check_kernel(kernel)?;
    if req.disks.len() > MAX_DISK_COUNT {
        crate::bail!("at most {MAX_DISK_COUNT} disks");
    }
    let abs = |p: &Path| std::fs::canonicalize(p).ctx(format!("{}", p.display()));
    let kernel = abs(kernel)?;
    let disks = req.disks.iter().map(|d| abs(d)).collect::<Result<Vec<_>>>()?;
    for d in &disks {
        if !d.is_file() {
            crate::bail!("{}: not a regular file", d.display());
        }
    }

    // what this VM can give
    let max_cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    let max_mem = mem_total_mib().saturating_sub(RESERVE_MIB).max(128);
    let cpus = req.cpus.unwrap_or(2).clamp(1, max_cpus);
    let mem_mib = req.mem_mib.unwrap_or(1024).clamp(128, max_mem);
    let timeout = req.timeout.unwrap_or(DEFAULT_TIMEOUT).clamp(1, MAX_TIMEOUT);

    // the test VM: kernel, disks, serial console; nothing else
    let mut cmdline = String::from("console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd");
    if !disks.is_empty() && !req.append.split_whitespace().any(|a| a.starts_with("root=")) {
        cmdline.push_str(" root=/dev/vda rw");
    }
    if !req.append.is_empty() {
        cmdline.push(' ');
        cmdline.push_str(&req.append);
    }
    let drives: Vec<_> = disks
        .iter()
        .enumerate()
        .map(|(i, p)| serde_json::json!({"drive_id": format!("disk{i}"), "path_on_host": p, "is_root_device": false, "is_read_only": false}))
        .collect();
    let fc_cfg = serde_json::json!({
        "boot-source": {"kernel_image_path": kernel, "boot_args": cmdline},
        "drives": drives,
        "machine-config": {"vcpu_count": cpus, "mem_size_mib": mem_mib, "smt": false},
    });
    let work = std::env::temp_dir().join(format!("acrboot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    crate::util::mkdir_private(&work)?;
    let _cleanup = RemoveOnDrop(work.clone());
    let cfg_path = work.join("firecracker.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&fc_cfg)?)?;
    let fc_log = work.join("firecracker.log");
    std::fs::write(&fc_log, b"")?;

    let records = records_dir()?;
    let (n, mut console_file) = new_console(&records)?;

    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe { libc::signal(sig, on_signal as *const () as libc::sighandler_t) };
    }
    let mut cmd = Command::new(FIRECRACKER);
    cmd.arg("--no-api")
        .arg("--config-file")
        .arg(&cfg_path)
        .arg("--id")
        .arg(format!("acrboot-{n}"))
        .arg("--log-path")
        .arg(&fc_log)
        .arg("--level")
        .arg("Error")
        .arg("--seccomp-filter")
        .arg(SECCOMP)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // the test VM must not outlive acrboot
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
    let t0 = Instant::now();
    let mut fc = cmd.spawn().ctx(format!("starting {FIRECRACKER}"))?;

    // console -> stdout and the record (capped); watch for a panic
    let mut out = fc.stdout.take().unwrap();
    let panic_seen = Arc::new(AtomicBool::new(false));
    let ps = panic_seen.clone();
    let reader = std::thread::spawn(move || {
        let mut buf = vec![0u8; 1 << 16];
        let mut tail: Vec<u8> = vec![];
        let mut kept = 0u64;
        let mut stdout = io::stdout();
        let mut stdout_ok = true;
        loop {
            let n = match out.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if kept < MAX_CONSOLE {
                let k = (n as u64).min(MAX_CONSOLE - kept) as usize;
                let _ = console_file.write_all(&buf[..k]);
                kept += k as u64;
                if kept == MAX_CONSOLE {
                    let _ = console_file.write_all(b"\n[acrboot: console truncated here]\n");
                }
            }
            tail.extend_from_slice(&buf[..n]);
            if contains(&tail, b"Kernel panic - not syncing") {
                ps.store(true, Ordering::Relaxed);
            }
            let keep = tail.len().saturating_sub(64);
            tail.drain(..keep);
            if stdout_ok && (stdout.write_all(&buf[..n]).is_err() || stdout.flush().is_err()) {
                stdout_ok = false; // nobody is reading; the record goes on
            }
        }
    });

    let deadline = t0 + Duration::from_secs(timeout);
    let mut timed_out = false;
    let mut panic_at = None;
    let mut stopped = false;
    let status = loop {
        if let Ok(Some(st)) = fc.try_wait() {
            break Some(st);
        }
        // a panicked kernel may never reset the VM (panic=0): give it a
        // moment to finish its report, then stop it
        if panic_at.is_none() && panic_seen.load(Ordering::Relaxed) {
            panic_at = Some(Instant::now());
        }
        let panic_done = panic_at.is_some_and(|t| t.elapsed() > Duration::from_secs(3));
        stopped = STOP.load(Ordering::Relaxed);
        if stopped || panic_done || Instant::now() >= deadline {
            timed_out = !stopped && !panic_done;
            let _ = fc.kill();
            break fc.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = reader.join();
    let secs = t0.elapsed().as_secs_f64();
    let (outcome, message) = if panic_seen.load(Ordering::Relaxed) {
        ("panic", None)
    } else if stopped {
        ("error", Some("interrupted".to_string()))
    } else if timed_out {
        ("timeout", None)
    } else if status.is_some_and(|s| s.success()) {
        ("exit", None)
    } else {
        let log = std::fs::read_to_string(&fc_log).unwrap_or_default();
        let last = log.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("firecracker failed").to_string();
        ("error", Some(last))
    };
    // `<time> <outcome> <secs> <kernel bytes> <disks> <append>`
    let size = std::fs::metadata(&kernel).map(|m| m.len()).unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(records.join("boot.log")) {
        let append = req.append.replace('\n', " ");
        let _ = writeln!(f, "{} {outcome} {secs:.1} {size} {} {append}", crate::util::now(), disks.len());
    }
    eprintln!(
        "acrboot: {} after {secs:.1}s ({cpus} CPU, {mem_mib}M){}",
        match outcome {
            "exit" => "the kernel shut the VM down",
            "panic" => "kernel panic",
            "timeout" => "timed out",
            _ => "error",
        },
        message.map(|m| format!(": {m}")).unwrap_or_default()
    );
    Ok(match outcome {
        "exit" => 0,
        "panic" => 1,
        "timeout" => 124,
        _ => 2,
    })
}

/// Error unless this VM can run one: `/dev/kvm` is there only in sessions
/// with `boot = true`, on a host that exposes nested virtualisation.
fn check_kvm() -> Result<()> {
    if std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok() && Path::new(FIRECRACKER).exists() {
        return Ok(());
    }
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let nested = cpuinfo.lines().any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "vmx" || f == "svm"));
    if nested {
        crate::bail!(
            "booting test kernels is not enabled for this session; it is turned on with `boot = true` in \
             ~/.config/agentcracker/config.toml on the host"
        );
    }
    crate::bail!(
        "this VM has no virtualisation support: the host's KVM must allow nested virtualisation \
         (kvm_intel or kvm_amd `nested=1`), and `boot = true` must be set in ~/.config/agentcracker/config.toml on the host"
    )
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

/// This VM's memory, in MiB.
fn mem_total_mib() -> u64 {
    let m = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    m.lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        .map_or(0, |kib| kib / 1024)
}

/// `~/.local/state/acrboot`, created if needed.
fn records_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ctx("HOME is not set")?;
    let d = Path::new(&home).join(RECORDS);
    std::fs::create_dir_all(&d).ctx(format!("creating {}", d.display()))?;
    Ok(d)
}

/// The next boot's console file in `dir` (`1.console`, `2.console`, ...),
/// created; consoles older than the last [`KEEP_CONSOLES`] are removed.
fn new_console(dir: &Path) -> Result<(u32, std::fs::File)> {
    // one past the highest (older ones may have been removed)
    let mut n = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".console")?.parse::<u32>().ok())
        .max()
        .unwrap_or(0)
        + 1;
    loop {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(dir.join(format!("{n}.console"))) {
            Ok(f) => {
                for old in 1..=n.saturating_sub(KEEP_CONSOLES) {
                    let _ = std::fs::remove_file(dir.join(format!("{old}.console")));
                }
                return Ok((n, f));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => n += 1, // another acrboot
            Err(e) => return Err(e.into()),
        }
    }
}

/// Removes its directory when dropped.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}
