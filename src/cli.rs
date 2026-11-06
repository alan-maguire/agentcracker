//! Command line: running sessions, the post-exit review, and session queries.
//!
//! `agentcracker <command>` (or `agentcracker run <command>`) creates a
//! session for the current directory ([`cmd_run`]): it snapshots the
//! project, creates the scratch disk and boots the VM ([`boot_once`], then
//! `vm::boot`).  When the command exits it offers the interactive review
//! ([`review`]): diff, apply, branch, shell, keep or discard.
//!
//! The other subcommands work on existing sessions, chosen by id prefix or
//! defaulting to the latest session for the current directory: `ls`,
//! `show`, `diff`, `apply`, `branch`, `resume`, `shell` and `rm`, plus
//! `refresh` for the shared images.  Two hidden subcommands are build and
//! development aids: `__seccomp-json` adapts Firecracker's seccomp policy
//! to a glibc build (the Makefile uses it), and `__mkimage` snapshots a
//! directory into an EROFS image.
//!
//! Exit status: for `run`, `resume` and `shell`, the guest command's exit
//! status (1 if it never reported one); 2 for usage errors; otherwise 0 on
//! success and 1 on error.

use std::path::{Path, PathBuf};

use crate::changes::{self, ChangeSet};
use crate::config::Config;
use crate::images::{self, Refresh, status};
use crate::session::{self, Session};
use crate::util::{Context, Result, human_age, human_bytes, human_duration, isatty, now, prompt_key, tilde};

/// Help text, printed by `--help` and with usage errors.
const USAGE: &str = "\
agentcracker - run a coding agent in a disposable Firecracker microVM

usage:
  agentcracker [--allow HOST]... [--no-net] [--console] <command> [args...]
        run <command> in a new session for the current directory
  agentcracker ls                       list sessions
  agentcracker show   [SESSION]         details: changes, network, agent transcripts
  agentcracker diff   [SESSION]         show the session's changes
  agentcracker apply  [SESSION]         write the changes into the real directory
  agentcracker branch [SESSION]         turn the agent's git commits into a host branch
  agentcracker resume [SESSION] [command...]   boot again on the same overlay
  agentcracker shell  [SESSION]         open a shell inside the session
  agentcracker rm     SESSION...        discard sessions
  agentcracker refresh                  rebuild the /usr and toolchain snapshots now

SESSION is an id prefix; it defaults to the latest session for this directory.
Use `agentcracker run <command>` for a command that collides with the above.

options:
  --allow HOST   also allow HTTPS to HOST (*.example.com for subdomains)
  --no-net       no network at all
  --console      show the guest kernel console (debugging)

config: ~/.config/agentcracker/config.toml and ./.agentcracker.toml
  vcpus, memory, net, allow, exclude, exclude_usr, tools, no_tools, home, state, env
";

/// Options accepted before the command by `run`, `resume` and `shell`.
struct Opts {
    /// Extra allowlist entries from `--allow HOST` or `--allow=HOST`.
    allow: Vec<String>,
    /// `--no-net`: no network at all.
    no_net: bool,
    /// `--console`: show the guest console.
    console: bool,
    /// The command and its arguments: everything from the first non-option, or
    /// after `--`.
    rest: Vec<String>,
}

/// Parse the leading options in `args` (the arguments after the
/// subcommand).
///
/// Parsing stops at `--` or at the first argument that is not an option;
/// that argument and everything after it form the command, so the
/// command's own options are left alone.  Returns the options; errors for an
/// unknown option or an `--allow` without a value.
fn parse_opts(args: &[String]) -> Result<Opts> {
    let mut o = Opts { allow: vec![], no_net: false, console: false, rest: vec![] };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            o.rest.extend_from_slice(&args[i + 1..]);
            break;
        } else if a == "--allow" {
            i += 1;
            o.allow.push(args.get(i).ctx("--allow needs a host")?.clone());
        } else if let Some(h) = a.strip_prefix("--allow=") {
            o.allow.push(h.to_string());
        } else if a == "--no-net" {
            o.no_net = true;
        } else if a == "--console" {
            o.console = true;
        } else if a.starts_with('-') && o.rest.is_empty() {
            crate::bail!("unknown option {a}\n\n{USAGE}");
        } else {
            o.rest.extend_from_slice(&args[i..]);
            break;
        }
        i += 1;
    }
    Ok(o)
}

/// Returns the current directory, canonicalised (symlinks resolved) so that
/// sessions are keyed by their real path; if that fails, the path as the
/// OS reports it.
fn cwd() -> Result<PathBuf> {
    let c = std::env::current_dir().ctx("current directory")?;
    Ok(c.canonicalize().unwrap_or(c))
}

/// Dispatch the command line.
///
/// `args`: the full argument vector, including the program name.  A known
/// subcommand goes to its `cmd_*` function; anything else is a command to
/// run in a new session, so `agentcracker claude` and
/// `agentcracker run claude` are the same (the latter is needed when the
/// command's name is also a subcommand).
///
/// Returns the process exit status (see the module docs), or an error for
/// `main` to print.
pub fn run(args: Vec<String>) -> Result<i32> {
    let args = &args[1..];
    let Some(first) = args.first() else {
        eprint!("{USAGE}");
        return Ok(2);
    };
    let rest = &args[1..];
    match first.as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(0)
        }
        "-V" | "--version" | "version" => {
            println!("agentcracker {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "ls" | "list" => cmd_ls(),
        "show" | "info" => cmd_show(rest.first().map(|s| s.as_str())),
        "diff" => cmd_diff(rest.first().map(|s| s.as_str())),
        "apply" => cmd_apply(rest.first().map(|s| s.as_str())),
        "branch" => cmd_branch(rest.first().map(|s| s.as_str())),
        "resume" => cmd_resume(rest, false),
        "shell" => cmd_resume(rest, true),
        "rm" | "discard" => cmd_rm(rest),
        "refresh" => cmd_refresh(rest),
        "run" => cmd_run(rest),
        "__seccomp-json" if rest.len() == 2 => {
            // build aid: adapt firecracker's musl seccomp policy to a glibc build
            let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&rest[0])?)?;
            let obj = v.as_object_mut().ctx("seccomp policy is not an object")?;
            obj.remove("blk_worker"); // not accepted for custom filters (firecracker 1.17+)
            for (name, cat) in obj.iter_mut() {
                if let Some(f) = cat.get_mut("filter").and_then(|f| f.as_array_mut()) {
                    if name == "vmm" {
                        // newer glibc implements tcgetattr/tcsetattr with
                        // TCGETS2/TCSETS2 (firecracker restores stdin's
                        // terminal mode on exit)
                        for (req, c) in [(0x802c542au32, "TCGETS2"), (0x402c542b, "TCSETS2")] {
                            f.push(serde_json::json!({
                                "syscall": "ioctl",
                                "args": [{ "index": 1, "type": "dword", "op": "eq", "val": req, "comment": c }],
                                "comment": "glibc (agentcracker)"
                            }));
                        }
                    }
                    // glibc spellings of what musl does differently: epoll_wait
                    // (musl uses epoll_pwait) and tgkill (musl's pthread_kill
                    // uses tkill; firecracker kicks vCPU threads with it on
                    // shutdown, so without it every VM exit is a SIGSYS kill
                    // plus a core dump of guest memory); getpid is what glibc's
                    // raise() calls first
                    for sc in ["epoll_wait", "tgkill", "getpid"] {
                        f.push(serde_json::json!({ "syscall": sc, "comment": "glibc (agentcracker)" }));
                    }
                    // glibc's pthread_join/condvars wait with FUTEX_WAIT_BITSET,
                    // optionally private and/or FUTEX_CLOCK_REALTIME
                    for op in [9u32, 9 | 128, 9 | 256, 9 | 128 | 256, 1 | 128 | 256] {
                        f.push(serde_json::json!({
                            "syscall": "futex",
                            "args": [{ "index": 1, "type": "dword", "op": "eq", "val": op, "comment": "glibc futex op" }],
                            "comment": "glibc (agentcracker)"
                        }));
                    }
                }
            }
            std::fs::write(&rest[1], serde_json::to_vec_pretty(&v)?)?;
            Ok(0)
        }
        "__mkimage" if rest.len() == 2 => {
            // development aid: snapshot a directory into an EROFS image
            let t = std::time::Instant::now();
            let mut tree = crate::erofs::Tree::new(0o755, 0, 0);
            let mut st = crate::erofs::WalkStats::default();
            tree.walk_into(0, Path::new(&rest[0]), &crate::util::Excludes::new(&[]), None, None, &mut st)?;
            let walked = t.elapsed();
            let size = crate::erofs::write_image(&tree, Path::new(&rest[1]))?;
            eprintln!("{} files, {} skipped, {} image; walk {:.2}s, write {:.2}s", st.files, st.skipped.len(), human_bytes(size), walked.as_secs_f64(), (t.elapsed() - walked).as_secs_f64());
            Ok(0)
        }
        _ => cmd_run(args),
    }
}

// ---------------------------------------------------------------------------
// running
// ---------------------------------------------------------------------------

/// Returns the commit `HEAD` points to in `cwd`, if `cwd` is a git
/// repository (it has `.git`) and `git rev-parse HEAD` succeeds; `None`
/// otherwise, including for a repository without commits.
fn git_head(cwd: &Path) -> Option<String> {
    if !cwd.join(".git").exists() {
        return None;
    }
    let o = std::process::Command::new("git").arg("-C").arg(cwd).args(["rev-parse", "HEAD"]).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// `agentcracker [run] [options] <command> [args...]`: run a command in a
/// new session for the current directory.
///
/// Refuses to run in `/` or in a directory that contains the home directory
/// (the snapshot would include everything).  Otherwise creates the session
/// and records its settings (vCPUs, memory, network and allowlist, git
/// HEAD), snapshots the project ([`images::lower_image`]) and hardlinks the
/// image into the session (copying it if the cache is on another
/// filesystem), saves the manifest, creates the 64 GiB sparse scratch disk,
/// and boots.  If the preparation fails, the half-created session is
/// removed.
///
/// `args`: the options and the command.  Returns the command's exit status.
fn cmd_run(args: &[String]) -> Result<i32> {
    let o = parse_opts(args)?;
    if o.rest.is_empty() {
        eprint!("{USAGE}");
        return Ok(2);
    }
    let cwd = cwd()?;
    let h = crate::util::home();
    if cwd == Path::new("/") || h.starts_with(&cwd) {
        crate::bail!("refusing to snapshot {} (it contains your home directory); cd into a project first", cwd.display());
    }
    let cfg = Config::load(&cwd)?;
    crate::util::mark("config loaded");
    let mut s = Session::create(&cwd, &o.rest)?;
    let res = (|| -> Result<()> {
        s.meta.vcpus = cfg.vcpus;
        s.meta.mem_mib = cfg.mem_mib;
        s.meta.net = cfg.net && !o.no_net;
        s.meta.allow = cfg.allow.iter().chain(o.allow.iter()).cloned().collect();
        s.meta.git_head = git_head(&cwd);
        let lower = images::lower_image(&cfg, &cwd)?;
        crate::util::mark("project snapshot");
        let link = |src: &Path, name: &str| -> Result<()> {
            if std::fs::hard_link(src, s.path(name)).is_err() {
                std::fs::copy(src, s.path(name)).ctx("copy project snapshot")?;
            }
            Ok(())
        };
        link(&lower.image, "lower.img")?;
        if let Some(d) = &lower.delta {
            link(d, "lower-delta.img")?;
        }
        s.save_manifest(&lower.manifest_file)?;
        crate::util::mark("session files");
        images::create_scratch(&s.path("scratch.img"), 64)?;
        crate::util::mark("scratch disk");
        Ok(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_dir_all(&s.dir);
        return Err(e);
    }
    let code = boot_and_review(&mut s, &cfg, &o.rest.clone(), o.console, true)?;
    Ok(code)
}

/// Boot the session once ([`boot_once`], which documents the parameters),
/// then run the interactive [`review`] if stdin and stderr are both
/// terminals; otherwise print a one-line summary of the changes and the
/// commands to inspect them.
///
/// Returns the command's exit status.
fn boot_and_review(s: &mut Session, cfg: &Config, cmd: &[String], console: bool, first: bool) -> Result<i32> {
    let code = boot_once(s, cfg, cmd, console, first)?;
    if isatty(0) && isatty(2) {
        review(s, cfg)?;
    } else if let Some(sum) = &s.meta.summary {
        eprintln!("agentcracker: session {}: {} (agentcracker diff|apply {})", s.meta.id, changes::summary_line(sum), s.meta.id);
    }
    Ok(code)
}

/// Boot the session's VM once, running `cmd`, and record the result.
///
/// Holds the session lock throughout (failing if the session is already
/// running), prints a status line and marks the session `running`.  When
/// the VM stops it records the end time, the exit code and the status
/// (`exited`, or `crashed` if no exit status came back) and any error;
/// summarises the changes if a change stream arrived; unpacks the agent
/// state; syncs refreshed credentials back to the host; and saves
/// `meta.json`.
///
/// `s`: the session; `cfg`: the configuration; `cmd`: the command to run;
/// `console`: show the guest console; `first`: whether this is the
/// session's first boot (full home seed).
///
/// Returns the command's exit status (1 if there was none).  Errors, after
/// marking the session `failed`, only if the VM could not be started.
fn boot_once(s: &mut Session, cfg: &Config, cmd: &[String], console: bool, first: bool) -> Result<i32> {
    let _lock = s.lock()?;
    let net = if !s.meta.net {
        "no network".to_string()
    } else {
        let extra: Vec<&String> = s.meta.allow.iter().filter(|a| !crate::config::DEFAULT_ALLOW.contains(&a.as_str())).collect();
        if s.meta.allow.iter().any(|a| a.trim() == "*") {
            "net: ANY HTTPS host (--allow '*')".into()
        } else if extra.is_empty() { "net: Anthropic API only".into() } else { format!("net: Anthropic API + {}", extra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")) }
    };
    status(&format!("session {} · {} vCPU · {} · {}", s.meta.id, s.meta.vcpus, human_bytes(s.meta.mem_mib << 20), net));
    s.meta.status = "running".into();
    s.meta.error = None;
    s.save()?;
    let out = crate::vm::boot(s, cfg, cmd, console, first);
    s.meta.ended = Some(now());
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            s.meta.status = "failed".into();
            s.meta.error = Some(e.0.clone());
            s.save()?;
            return Err(e);
        }
    };
    s.meta.exit_code = out.exit_code;
    s.meta.status = if out.exit_code.is_some() { "exited".into() } else { "crashed".into() };
    if let Some(e) = &out.error {
        s.meta.error = Some(e.clone());
        eprintln!("agentcracker: {e}");
    }
    if out.exported {
        if let Ok(Some(cs)) = ChangeSet::load(s) {
            s.meta.summary = Some(cs.summary());
        }
    }
    crate::util::mark("vm gone");
    if let Err(e) = changes::extract_state(s) {
        eprintln!("agentcracker: could not save agent state: {e}");
    }
    if changes::guest_refreshed_credentials(s) {
        status(
            "Claude refreshed its login inside the VM; agentcracker never copies credentials back to the host. \
             If Claude on the host later says you are logged out, run /login there.",
        );
    }
    s.save()?;
    crate::util::mark("post-processing");
    if out.exit_code.is_none() && !out.exported {
        eprintln!("agentcracker: the session ended abnormally; its disk is kept: agentcracker resume {} | show {}", s.meta.id, s.meta.id);
    }
    Ok(out.exit_code.unwrap_or(1))
}

/// The interactive menu shown after a session ends.
///
/// Shows the change list, the summary, the number of conflicts and any new
/// commit, then offers: `d` (page through the diff), `a` (apply, then keep
/// or discard the session), `b` (import the agent's commits as a branch),
/// `s` (boot the session again with the user's shell, then come back here),
/// `K` (keep - the default, also on Enter or end of input) and `x`
/// (discard, asking first if changes were never applied).  It loops until
/// the session is kept, discarded or applied.
///
/// `s`: the session; `cfg`: the configuration, for the shell boot.  Returns
/// an error if loading the changes, applying or booting fails.
fn review(s: &mut Session, cfg: &Config) -> Result<()> {
    let dim = |t: &str| format!("\x1b[2m{t}\x1b[0m");
    loop {
        let cs = ChangeSet::load(s)?;
        let has_changes = cs.as_ref().is_some_and(|c| !c.is_empty());
        let head = cs.as_ref().and_then(|c| changes::agent_head(c, s.meta.git_head.as_deref()));
        eprintln!();
        if let Some(cs) = &cs {
            if has_changes {
                changes::print_list(cs, 30);
                eprintln!("{}", changes::summary_line(&cs.summary()));
                if !cs.conflicts().is_empty() {
                    eprintln!("{} conflict(s): those files changed on the host while the agent ran", cs.conflicts().len());
                }
            } else {
                eprintln!("No changes to {}.", tilde(&s.meta.cwd));
            }
            if let Some((sha, name)) = &head {
                eprintln!("The agent committed: {} is now {}", crate::util::safe_text(name.as_bytes(), false), crate::util::safe_text(sha.get(..12).unwrap_or(sha).as_bytes(), false));
            }
        } else {
            eprintln!("No change record (the session did not shut down cleanly).");
        }
        let mut opts = vec![];
        if has_changes {
            opts.push("[d]iff");
            opts.push("[a]pply");
        }
        if head.is_some() {
            opts.push("[b]ranch");
        }
        opts.extend(["[s]hell", "[K]eep for later (not applied)", "[x] discard"]);
        let valid = format!("{}{}{}skx\n", if has_changes { "da" } else { "" }, if head.is_some() { "b" } else { "" }, "");
        let Some(k) = prompt_key(&format!("{} ", opts.join(" ")), &valid) else { return Ok(()) };
        match k {
            'd' => {
                if let Some(cs) = &cs {
                    changes::show_diff(cs, &s.path("tmp"))?;
                }
            }
            'a' => {
                let cs = cs.unwrap();
                if apply_interactive(s, &cs)? {
                    let left = prompt_key("Applied. Keep the session? [y/N] ", "yn\n");
                    if left == Some('y') {
                        keep_msg(s);
                    } else {
                        let id = s.meta.id.clone();
                        Session::load_dir(&s.dir)?.remove()?;
                        status(&format!("session {id} discarded"));
                    }
                    return Ok(());
                }
            }
            'b' => {
                let cs = cs.unwrap();
                match changes::import_branch(&cs, s) {
                    Ok((b, desc)) => {
                        status(&format!("created branch {b} ({desc})"));
                        s.meta.branch = Some(b);
                        s.save()?;
                    }
                    Err(e) => eprintln!("agentcracker: {e}"),
                }
            }
            's' => {
                let sh = vec![crate::util::user_shell(unsafe { libc::getuid() })];
                eprintln!("{}", dim("entering the session; exit the shell to come back here"));
                boot_once(s, cfg, &sh, false, false)?;
            }
            'x' => {
                if has_changes && s.meta.applied_at.is_none() && prompt_key("Discard unapplied changes? [y/N] ", "yn\n") != Some('y') {
                    continue;
                }
                let id = s.meta.id.clone();
                Session::load_dir(&s.dir)?.remove()?;
                status(&format!("session {id} discarded"));
                return Ok(());
            }
            _ => {
                keep_msg(s);
                return Ok(());
            }
        }
    }
}

/// Tell the user session `s` was kept without applying its changes, and
/// how to apply, diff, resume or remove it later.
fn keep_msg(s: &Session) {
    let id = &s.meta.id;
    status(&format!("kept session {id}, changes NOT applied: agentcracker apply {id} | diff {id} | resume {id} | rm {id}"));
}

/// Apply change set `cs` of session `s` to the host, asking about conflicts.
///
/// If some changes conflict (the host copy changed since the snapshot), they
/// are listed and the user chooses to skip them, overwrite them, or cancel;
/// without a terminal, conflicts are refused with an error.  Per-path
/// errors are printed, then a summary line, and the session is marked
/// `applied` and saved.
///
/// Returns `Ok(false)` if the user cancelled, or if nothing was written and
/// some paths failed; `Ok(true)` otherwise.  Errors if applying cannot
/// start.
fn apply_interactive(s: &mut Session, cs: &ChangeSet) -> Result<bool> {
    let conflicts = cs.conflicts();
    let mut include = false;
    if !conflicts.is_empty() {
        eprintln!("These files changed on the host since the session started:");
        for c in &conflicts {
            eprintln!("  {}", crate::util::safe_path(c.path()));
        }
        if !isatty(0) {
            crate::bail!("refusing to apply with conflicts (run interactively to choose)");
        }
        match prompt_key("[s]kip them and apply the rest, [o]verwrite them, or [c]ancel? ", "soc") {
            Some('s') => {}
            Some('o') => include = true,
            _ => return Ok(false),
        }
    }
    let r = changes::apply(cs, &s.meta.id, include)?;
    for e in &r.errors {
        eprintln!("agentcracker: apply: {e}");
    }
    status(&format!(
        "applied to {}: {} written, {} deleted{}{}{}",
        tilde(&cs.cwd),
        r.written,
        r.deleted,
        if r.in_place == 0 { String::new() } else { format!(", {} already in place", r.in_place) },
        if r.skipped.is_empty() { String::new() } else { format!(", {} skipped", r.skipped.len()) },
        if r.errors.is_empty() { String::new() } else { format!(", {} errors", r.errors.len()) }
    ));
    if !cs.git.is_empty() {
        status("changes inside .git/ were not applied (use `agentcracker branch` for the agent's commits)");
    }
    s.meta.applied_at = Some(now());
    s.meta.status = "applied".into();
    s.save()?;
    Ok(r.written + r.deleted > 0 || r.errors.is_empty())
}

/// `agentcracker resume [options] [SESSION] [command...]` and
/// `agentcracker shell [options] [SESSION]`: boot an existing session again,
/// on the same scratch disk, so the agent finds its earlier changes and home.
///
/// SESSION is recognised with [`session::looks_like_id`]; without it, the
/// latest session for the current directory is used.  `--allow` adds to
/// the session's allowlist, and `--no-net` disables networking for this and
/// later boots.  The command defaults to the session's original command
/// (`resume`) or the user's login shell (`shell`).  The project is not
/// snapshotted again: host changes made since the session started stay
/// invisible to it.
///
/// `args`: the arguments after the subcommand; `shell`: true for `shell`.
/// Returns the command's exit status; errors if the session cannot be found
/// or its project directory no longer exists.
fn cmd_resume(args: &[String], shell: bool) -> Result<i32> {
    let o = parse_opts(args)?;
    let mut rest = o.rest.clone();
    let id = match rest.first() {
        Some(a) if session::looks_like_id(a) => Some(rest.remove(0)),
        _ => None,
    };
    let mut s = session::find(id.as_deref(), &cwd()?)?;
    if !s.meta.cwd.is_dir() {
        crate::bail!("{} no longer exists", s.meta.cwd.display());
    }
    let cfg = Config::load(&s.meta.cwd)?;
    for a in o.allow {
        if !s.meta.allow.contains(&a) {
            s.meta.allow.push(a);
        }
    }
    if o.no_net {
        s.meta.net = false;
    }
    let cmd = if shell {
        vec![crate::util::user_shell(unsafe { libc::getuid() })]
    } else if rest.is_empty() {
        s.meta.cmd.clone()
    } else {
        rest
    };
    boot_and_review(&mut s, &cfg, &cmd, o.console, false)
}

// ---------------------------------------------------------------------------
// queries
// ---------------------------------------------------------------------------

/// Format Unix time `t` as local time, `YYYY-MM-DD HH:MM`.
fn fmt_time(t: u64) -> String {
    unsafe {
        let tt = t as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&tt, &mut tm);
        let mut buf = [0u8; 64];
        let fmt = c"%Y-%m-%d %H:%M";
        let n = libc::strftime(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), &tm);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

/// Returns the status to display for `s`: `running` while a VM holds its
/// lock; `exit N` after a non-zero exit; `stopped` for a session recorded as
/// `running` or `starting` that no process holds (agentcracker was killed);
/// otherwise the recorded status.
fn status_of(s: &Session) -> String {
    if s.is_running() {
        return "running".into();
    }
    match (s.meta.status.as_str(), s.meta.exit_code) {
        ("exited", Some(c)) if c != 0 => format!("exit {c}"),
        ("running", _) | ("starting", _) => "stopped".into(),
        (st, _) => st.to_string(),
    }
}

/// `agentcracker ls`: print a table of all sessions - id, age, status,
/// change counts, directory and command - oldest first.  Returns 0.
fn cmd_ls() -> Result<i32> {
    let all = session::list();
    if all.is_empty() {
        eprintln!("no sessions");
        return Ok(0);
    }
    let t = now();
    println!("{:<9} {:>4}  {:<8} {:<12} {:<34} COMMAND", "ID", "AGE", "STATUS", "CHANGES", "DIRECTORY");
    for s in &all {
        let ch = s.meta.summary.as_ref().map(changes::short_summary).unwrap_or_else(|| "?".into());
        let mut dir = tilde(&s.meta.cwd);
        if dir.chars().count() > 34 {
            let tail: String = dir.chars().rev().take(33).collect::<Vec<_>>().into_iter().rev().collect();
            dir = format!("…{tail}");
        }
        let mut cmd = crate::util::safe_text(s.meta.cmd.join(" ").as_bytes(), false);
        if cmd.chars().count() > 40 {
            cmd = cmd.chars().take(39).collect::<String>() + "…";
        }
        println!("{:<9} {:>4}  {:<8} {:<12} {:<34} {}", s.meta.id, human_age(t.saturating_sub(s.meta.created)), status_of(s), ch, dir, cmd);
    }
    Ok(0)
}

/// `agentcracker show [SESSION]`: print everything known about a session -
/// metadata, status and run time, VM settings, git base, when it was
/// applied and its branch, the change list, network activity per host (with
/// an `--allow` hint for denied hosts), captured Claude Code transcripts,
/// disk usage and the session directory.
///
/// `arg`: optional session id prefix.  Returns 0; errors if the session
/// cannot be found.
fn cmd_show(arg: Option<&str>) -> Result<i32> {
    let s = session::find(arg, &cwd()?)?;
    let m = &s.meta;
    let t = now();
    let row = |k: &str, v: String| println!("{k:<10} {v}");
    row("session", m.id.clone());
    row("directory", tilde(&m.cwd));
    row("command", crate::util::safe_text(m.cmd.join(" ").as_bytes(), false));
    row("created", format!("{} ({} ago)", fmt_time(m.created), human_age(t.saturating_sub(m.created))));
    let mut st = status_of(&s);
    if let Some(c) = m.exit_code {
        if !st.starts_with("exit") {
            st.push_str(&format!(" (exit {c})"));
        }
    }
    row("status", format!("{st} · {} boot(s) · ran {}", m.boots, human_duration(m.runtime)));
    if let Some(e) = &m.error {
        row("error", crate::util::safe_text(e.lines().next().unwrap_or("").as_bytes(), false));
    }
    row(
        "vm",
        format!("{} vCPU · {} · {}", m.vcpus, human_bytes(m.mem_mib << 20), if m.net { format!("net allowlist: {}", m.allow.join(" ")) } else { "no network".into() }),
    );
    if let Some(h) = &m.git_head {
        row("base", format!("git {}", &h[..h.len().min(12)]));
    }
    if let Some(a) = m.applied_at {
        row("applied", fmt_time(a));
    }
    if let Some(b) = &m.branch {
        row("branch", b.clone());
    }
    match ChangeSet::load(&s) {
        Ok(Some(cs)) => {
            let sum = cs.summary();
            row("changes", format!("{}{}", changes::summary_line(&sum), if sum.git_internal > 0 { format!(" (+{} inside .git/)", sum.git_internal) } else { String::new() }));
            changes::print_list(&cs, 20);
        }
        Ok(None) => row("changes", "none recorded".into()),
        Err(e) => row("changes", format!("unreadable: {e}")),
    }
    let net = crate::proxy::summarize(&s.path("net.log"));
    if !net.is_empty() {
        let mut first = true;
        for (host, a, d) in &net {
            let host = &crate::util::safe_text(host.as_bytes(), false);
            let v = match (a, d) {
                (a, 0) => format!("{a} allowed"),
                (0, d) => format!("{d} denied"),
                (a, d) => format!("{a} allowed, {d} denied"),
            };
            row(if first { "network" } else { "" }, format!("{host:<32} {v}"));
            first = false;
        }
        if net.iter().any(|(_, a, d)| *a == 0 && *d > 0) {
            // the agent chose these names: no ready-made command to paste
            row("", "denied hosts were requested by the agent; allow one with --allow HOST only if you expect this work to need it".into());
        }
    }
    let tr = changes::transcripts(&s);
    if !tr.is_empty() {
        row("agent", format!("{} Claude transcript(s) (resume inside with: agentcracker resume {} claude --resume)", tr.len(), m.id));
        // transcripts are written by the guest: sanitise, and cut by chars
        let clip = |t: &str, n: usize| -> String {
            let t = crate::util::safe_text(t.as_bytes(), false);
            if t.chars().count() > n { t.chars().take(n - 1).collect::<String>() + "…" } else { t }
        };
        for x in tr {
            let id: String = clip(&x.id, 64).chars().take(8).collect();
            let last = clip(&x.last, 64).chars().take(16).collect::<String>().replace('T', " ");
            row("", format!("{id} {:>4} msgs  last {last}  \"{}\"", x.messages, clip(&x.first_prompt, 60)));
        }
        row("", format!("transcripts: {}", tilde(&s.path("state/.claude/projects"))));
    }
    row("disk", human_bytes(s.disk_usage()));
    row("files", tilde(&s.dir));
    Ok(0)
}

/// Load the change set of `s`, turning "no change stream" into an error
/// that suggests resuming the session and exiting cleanly.
fn load_cs(s: &Session) -> Result<ChangeSet> {
    ChangeSet::load(s)?.ctx(format!("session {} has no change record (resume it and exit cleanly)", s.meta.id))
}

/// `agentcracker diff [SESSION]`: show the session's changes as a diff (see
/// [`changes::show_diff`]), or say there are none.  `arg`: optional session
/// id prefix.  Returns 0.
fn cmd_diff(arg: Option<&str>) -> Result<i32> {
    let s = session::find(arg, &cwd()?)?;
    let cs = load_cs(&s)?;
    if cs.is_empty() {
        eprintln!("no changes");
        if !cs.git.is_empty() {
            eprintln!("({} changes inside .git/; see `agentcracker branch`)", cs.git.len());
        }
        return Ok(0);
    }
    changes::show_diff(&cs, &s.path("tmp"))?;
    Ok(0)
}

/// `agentcracker apply [SESSION]`: list the session's changes and apply
/// them to the project directory (see [`apply_interactive`]), asking first
/// if they were applied before.  Refuses while the session is running.
///
/// `arg`: optional session id prefix.  Returns 0, or 1 if the user declined
/// to apply again.
fn cmd_apply(arg: Option<&str>) -> Result<i32> {
    let mut s = session::find(arg, &cwd()?)?;
    if s.is_running() {
        crate::bail!("session {} is still running", s.meta.id);
    }
    let cs = load_cs(&s)?;
    if cs.is_empty() {
        eprintln!("no changes to apply");
        return Ok(0);
    }
    changes::print_list(&cs, 30);
    if cs.all_in_place() {
        eprintln!("all of these are already on the host; nothing to do");
        return Ok(0);
    }
    if s.meta.applied_at.is_some() && isatty(0) && prompt_key("This session was already applied once. Apply again? [y/N] ", "yn\n") != Some('y') {
        return Ok(1);
    }
    apply_interactive(&mut s, &cs)?;
    Ok(0)
}

/// `agentcracker branch [SESSION]`: import the agent's commits as the
/// branch `agentcracker/<id>` (see [`changes::import_branch`]) and record it
/// in the session.  `arg`: optional session id prefix.  Returns 0.
fn cmd_branch(arg: Option<&str>) -> Result<i32> {
    let mut s = session::find(arg, &cwd()?)?;
    let cs = load_cs(&s)?;
    let (b, desc) = changes::import_branch(&cs, &s)?;
    status(&format!("created branch {b} ({desc})"));
    s.meta.branch = Some(b);
    s.save()?;
    Ok(0)
}

/// `agentcracker rm SESSION...`: remove each named session (by id prefix),
/// stopping at the first that cannot be found or is still running.
/// Returns 0.
fn cmd_rm(args: &[String]) -> Result<i32> {
    if args.is_empty() {
        crate::bail!("usage: agentcracker rm SESSION...");
    }
    let cwd = cwd()?;
    for a in args {
        let s = session::find(Some(a), &cwd)?;
        let id = s.meta.id.clone();
        s.remove()?;
        println!("removed {id}");
    }
    Ok(0)
}

/// `agentcracker refresh [--background]`: rebuild the /usr snapshot now;
/// in the foreground, also rebuild (if stale) the toolchain image for the
/// current directory and the base image.
///
/// `--background` is what [`images::usr_image`] starts when it finds the
/// snapshot stale: it builds only the /usr image, quietly.  `args`: the
/// arguments after `refresh`.  Returns 0.
fn cmd_refresh(args: &[String]) -> Result<i32> {
    let bg = args.iter().any(|a| a == "--background");
    let cwd = cwd()?;
    let cfg = Config::load(&cwd)?;
    images::usr_image(&cfg, if bg { Refresh::Background } else { Refresh::Force })?;
    if !bg {
        let tools = images::detect_tools(&cfg, &cwd);
        images::tools_image(&cfg, &tools)?;
        if let Ok(a) = images::find_asset("acinit") {
            images::base_image(&a)?;
        }
    }
    Ok(0)
}
