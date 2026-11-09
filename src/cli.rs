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

/// `println!` that ends the program quietly (status 141, as if killed by
/// SIGPIPE) when stdout has gone away, e.g. `agentcracker ls | head -1`.
/// SIGPIPE itself stays ignored: a proxied connection closing must never
/// kill a session.
macro_rules! out {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        if writeln!(std::io::stdout(), $($t)*).is_err() {
            std::process::exit(141);
        }
    }};
}

use crate::changes::{self, ChangeSet};
use crate::{agentstate, apply, gitimport};
use crate::config::Config;
use crate::images::{self, Refresh, status};
use crate::session::{self, Session};
use crate::util::{Context, Result, human_age, human_bytes, human_duration, isatty, now, prompt_key, tilde};

/// Help text, printed by `--help` and with usage errors.
const USAGE: &str = "\
agentcracker - run a coding agent in a disposable Firecracker microVM

usage:
  agentcracker [--allow HOST]... [--no-net] [--console] [--detach] [--branch NAME] <command> [args...]
        run <command> in a new session for the current directory
  agentcracker ls     [--json]          list sessions
  agentcracker show   [--json] [SESSION]   details: changes, network, agent transcripts
  agentcracker diff   [--ignored] [SESSION]   show the session's changes
  agentcracker apply  [--ignored] [SESSION]   write them into the real directory
                                        (--ignored: also what git ignores)
  agentcracker branch [SESSION]         turn the agent's git commits into a host branch
  agentcracker resume [SESSION] [command...]   boot again on the same overlay
  agentcracker shell  [SESSION]         open a shell inside the session (also while it runs)
  agentcracker log    [--json] [-f] [SESSION]  timeline: network requests, agent tool calls
  agentcracker wait   [--json] [SESSION...]   wait for running sessions to end
  agentcracker stop   [SESSION...]      end running sessions (changes are kept)
  agentcracker rm     SESSION...        discard sessions
  agentcracker refresh                  rebuild the /usr and toolchain snapshots now
  agentcracker cache  [--drop [DIR]]    list build caches (each project's ~/.cache);
                                        --drop deletes this directory's (or DIR's)

SESSION is an id prefix; it defaults to the latest session for this directory.
Use `agentcracker run <command>` for a command that collides with the above.

options:
  --allow HOST   also allow HTTPS to HOST (*.example.com for subdomains)
  --no-net       no network at all
  --console      show the guest kernel console (debugging)
  --branch NAME  the agent works on a new git branch NAME (from HEAD), which
                 `branch` imports into the repository as NAME
  --detach       run in the background: print the session id and return;
                 output goes to the session's stdout/stderr files

config: ~/.config/agentcracker/config.toml and ./.agentcracker.toml
  vcpus, memory, net, allow, exclude, exclude_usr, tools, no_tools, home, state, env, agent
";

/// Options accepted before the command by `run`, `resume` and `shell`.
struct Opts {
    /// Extra allowlist entries from `--allow HOST` or `--allow=HOST`.
    allow: Vec<String>,
    /// `--no-net`: no network at all.
    no_net: bool,
    /// `--console`: show the guest console.
    console: bool,
    /// `--detach`: run the session in the background.
    detach: bool,
    /// `--json`: machine-readable output.
    json: bool,
    /// `--branch NAME`: the git branch the agent works on (new sessions).
    branch: Option<String>,
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
    let mut o = Opts { allow: vec![], no_net: false, console: false, detach: false, json: false, branch: None, rest: vec![] };
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
        } else if a == "--detach" {
            o.detach = true;
        } else if a == "--json" {
            o.json = true;
        } else if a == "--branch" {
            i += 1;
            o.branch = Some(args.get(i).ctx("--branch needs a name")?.clone());
        } else if let Some(b) = a.strip_prefix("--branch=") {
            o.branch = Some(b.to_string());
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

/// A subcommand's parsed arguments (see [`parse_args`]).
struct Args {
    /// The options given, each by its last spelling (`--follow` for `-f`).
    flags: Vec<&'static str>,
    /// The other arguments, in order.
    pos: Vec<String>,
}

impl Args {
    /// Whether option `f` (its last spelling) was given.
    fn has(&self, f: &str) -> bool {
        self.flags.contains(&f)
    }

    /// The first other argument: a session id prefix, for most commands.
    fn first(&self) -> Option<&str> {
        self.pos.first().map(|s| s.as_str())
    }
}

/// Parse the arguments of subcommand `cmd` (everything after its name),
/// for subcommands other than `run`, `resume` and `shell` (which stop at
/// the command to run: [`parse_opts`]).
///
/// `flags`: the options it takes, each with its spellings separated by
/// `|` (`"-f|--follow"`); `max`: how many other arguments it takes, in any
/// position.  Errors, naming `cmd`, for any other option or for too many
/// arguments.
fn parse_args(cmd: &str, args: &[String], flags: &[&'static str], max: usize) -> Result<Args> {
    let mut a = Args { flags: vec![], pos: vec![] };
    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 {
            let Some(f) = flags.iter().find(|f| f.split('|').any(|s| s == arg)) else {
                crate::bail!("{cmd}: unknown option {arg} (see agentcracker --help)");
            };
            a.flags.push(f.rsplit('|').next().unwrap_or(f));
        } else if a.pos.len() < max {
            a.pos.push(arg.clone());
        } else {
            crate::bail!("{cmd}: unexpected argument {arg} (see agentcracker --help)");
        }
    }
    Ok(a)
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
            out!("agentcracker {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "ls" | "list" => cmd_ls(rest),
        "show" | "info" => cmd_show(rest),
        "wait" => cmd_wait(rest),
        "log" => cmd_log(rest),
        "stop" => cmd_stop(rest),
        "diff" => cmd_diff(rest),
        "apply" => cmd_apply(rest),
        "branch" => cmd_branch(rest),
        "resume" => cmd_resume(rest, false),
        "shell" => cmd_resume(rest, true),
        "rm" | "discard" => cmd_rm(rest),
        "refresh" => cmd_refresh(rest),
        "cache" => cmd_cache(rest),
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
    crate::util::git(cwd, &["rev-parse", "HEAD"]).ok()
}

/// Check `name` for `--branch`: `cwd` must be a git repository (not a
/// worktree) with commits (`has_head`), `name` a valid branch name, and no
/// such branch may exist there yet - it is created by importing the
/// agent's commits, never overwritten.  Returns the name.
fn check_new_branch(cwd: &Path, has_head: bool, name: &str) -> Result<String> {
    if !cwd.join(".git").is_dir() || !has_head {
        crate::bail!("--branch needs a git repository with commits (and not a worktree)");
    }
    let git = |args: &[&str]| crate::util::git(cwd, args).is_ok();
    if name.starts_with('-') || !git(&["check-ref-format", &format!("refs/heads/{name}")]) {
        crate::bail!("--branch {name}: not a valid branch name");
    }
    if git(&["rev-parse", "--verify", "-q", &format!("refs/heads/{name}")]) {
        crate::bail!("--branch {name}: the branch already exists (the agent's commits go on a new branch)");
    }
    Ok(name.to_string())
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
        // the agent profile: from the command, else the config, else Claude Code
        let profile = crate::agent::detect(&o.rest).or(cfg.agent).unwrap_or(&crate::agent::CLAUDE);
        s.meta.agent = Some(profile.name.to_string());
        s.meta.allow = profile.allow.iter().map(|a| a.to_string()).chain(cfg.allow.iter().cloned()).chain(o.allow.iter().cloned()).collect();
        s.meta.git_head = git_head(&cwd);
        if let Some(b) = &o.branch {
            s.meta.work_branch = Some(check_new_branch(&cwd, s.meta.git_head.is_some(), b)?);
        }
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
        let creds = images::credential_like(&lower.manifest_file, 6);
        if !creds.is_empty() {
            let mut list: Vec<String> = creds.iter().take(5).map(|p| crate::util::safe_text(p.as_bytes(), false)).collect();
            if creds.len() > 5 {
                list.push("...".into());
            }
            eprintln!(
                "agentcracker: warning: the agent can read files that look like credentials: {}\n  \
                 (if it doesn't need them, leave them out with exclude = [...] in .agentcracker.toml)",
                list.join(", ")
            );
        }
        crate::util::mark("session files");
        images::create_disk(&s.path("scratch.img"), 64, "acscratch")?;
        crate::util::mark("scratch disk");
        Ok(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_dir_all(&s.dir);
        return Err(e);
    }
    if o.detach {
        return run_detached(&mut s, &cfg, &o.rest.clone(), true, o.json);
    }
    let code = boot_and_review(&mut s, &cfg, &o.rest.clone(), o.console, true, None)?;
    Ok(code)
}

/// Boot the session once ([`boot_once`], which documents the parameters),
/// then run the interactive [`review`] if stdin and stderr are both
/// terminals; otherwise print a one-line summary of the changes and the
/// commands to inspect them.
///
/// Returns the command's exit status.
fn boot_and_review(s: &mut Session, cfg: &Config, cmd: &[String], console: bool, first: bool, lock: Option<std::fs::File>) -> Result<i32> {
    let code = boot_once(s, cfg, cmd, console, first, lock)?;
    if isatty(0) && isatty(2) {
        review(s, cfg)?;
    } else if let Some(sum) = &s.meta.summary {
        eprintln!("agentcracker: session {}: {} (agentcracker diff|apply {})", s.meta.id, changes::summary_line(sum), s.meta.id);
    }
    Ok(code)
}

/// Warn when the disk holding agentcracker's state (sessions, build caches)
/// is getting full: sessions and caches are kept until removed, and each
/// can grow to tens of GB.  `s`: the session just run.
fn low_space_warning(s: &Session) {
    let Ok(f) = std::fs::File::open(s.path("meta.json")) else { return };
    use std::os::fd::AsRawFd;
    if let Some(free) = crate::util::free_space(f.as_raw_fd()).filter(|&b| b < 10 << 30) {
        let (own, _) = s.disk_usage();
        eprintln!(
            "agentcracker: only {} free on the disk holding sessions and build caches (this session uses {}); \
             `agentcracker ls` and `rm`, and `agentcracker cache --drop`, free space",
            human_bytes(free),
            human_bytes(own)
        );
    }
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
fn boot_once(s: &mut Session, cfg: &Config, cmd: &[String], console: bool, first: bool, lock: Option<std::fs::File>) -> Result<i32> {
    let _lock = match lock {
        Some(l) => l,
        None => s.lock()?,
    };
    let net = if !s.meta.net {
        "no network".to_string()
    } else {
        let profile = crate::agent::for_session(s.meta.agent.as_deref());
        let extra: Vec<&String> = s.meta.allow.iter().filter(|a| !profile.allow.contains(&a.as_str())).collect();
        if s.meta.allow.iter().any(|a| a.trim() == "*") {
            "net: ANY HTTPS host (--allow '*')".into()
        } else if extra.is_empty() {
            format!("net: {} only", profile.api)
        } else {
            format!("net: {} + {}", profile.api, extra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))
        }
    };
    // its disks grow on the host's as the guest writes (see vm::watch_space)
    if let Some(free) = std::fs::File::open(s.path("meta.json")).ok().and_then(|f| {
        use std::os::fd::AsRawFd;
        crate::util::free_space(f.as_raw_fd())
    }) {
        if free < crate::util::min_free_session() {
            crate::bail!(
                "only {} free on the disk holding sessions; free some space first \
                 (`agentcracker ls` and `rm`, `agentcracker cache --drop`)",
                human_bytes(free)
            );
        }
    }
    low_space_warning(s);
    status(&format!("session {} · {} vCPU · {} · {}", s.meta.id, s.meta.vcpus, human_bytes(s.meta.mem_mib << 20), net));
    s.meta.status = "running".into();
    s.meta.error = None;
    s.meta.pid = Some(std::process::id());
    s.save()?;
    let out = crate::vm::boot(s, cfg, cmd, console, first);
    s.meta.ended = Some(now());
    s.meta.pid = None;
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
    if let Err(e) = agentstate::extract_state(s) {
        eprintln!("agentcracker: could not save agent state: {e}");
    }
    if agentstate::guest_refreshed_credentials(s) {
        let a = crate::agent::for_session(s.meta.agent.as_deref()).display;
        status(&format!(
            "{a} refreshed its login inside the VM; agentcracker never copies credentials back to the host. \
             If {a} on the host later says you are logged out, log in again there."
        ));
    }
    s.save()?;
    low_space_warning(s);
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
    let mut with_ignored = false;
    loop {
        let mut cs = ChangeSet::load(s)?;
        if let Some(c) = &mut cs {
            c.include_ignored = with_ignored;
        }
        let ignored = cs.as_ref().map_or(0, |c| c.ignored_count());
        let has_changes = cs.as_ref().is_some_and(|c| !c.is_empty());
        let head = cs.as_ref().and_then(|c| gitimport::agent_head(c, s.meta.git_head.as_deref()));
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
            if ignored > 0 && with_ignored {
                eprintln!("{}", dim(&format!("including {ignored} file(s) git ignores; [i] to leave them out")));
            } else if ignored > 0 {
                eprintln!("{}", dim(&format!("{ignored} more file(s) git ignores (build output) are hidden and not applied; [i] to include them")));
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
        if ignored > 0 {
            opts.push("[i]gnored");
        }
        opts.extend(["[s]hell", "[K]eep for later (not applied)", "[x] discard"]);
        let valid = format!("{}{}{}skx\n", if has_changes { "da" } else { "" }, if head.is_some() { "b" } else { "" }, if ignored > 0 { "i" } else { "" });
        let Some(k) = prompt_key(&format!("{} ", opts.join(" ")), &valid) else { return Ok(()) };
        match k {
            'i' => with_ignored = !with_ignored,
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
                match gitimport::import_branch(&cs, s) {
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
                boot_once(s, cfg, &sh, false, false, None)?;
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
    let r = apply::apply(cs, &s.meta.id, include)?;
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
    if o.branch.is_some() {
        crate::bail!("--branch is for new sessions (a session keeps the branch it started with)");
    }
    let mut rest = o.rest.clone();
    let id = match rest.first() {
        Some(a) if session::looks_like_id(a) => Some(rest.remove(0)),
        _ => None,
    };
    let mut s = session::find(id.as_deref(), &cwd()?)?;
    if shell && s.is_running() {
        // another terminal in the running VM, beside the session's command
        let sh = vec![crate::util::user_shell(unsafe { libc::getuid() })];
        return crate::vm::exec_running(&s, &sh);
    }
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
    if o.detach {
        return run_detached(&mut s, &cfg, &cmd, false, o.json);
    }
    boot_and_review(&mut s, &cfg, &cmd, o.console, false, None)
}

/// `--detach`: boot the session in a background process and return at once.
///
/// The session lock is taken here, before forking, so the session shows as
/// running (and `wait` works) as soon as this returns; the child inherits
/// it.  The child leaves the terminal (new session, stdin from /dev/null),
/// writes the command's output and its own messages to the session's
/// `stdout` and `stderr` files, and runs the VM without a review.  Prints
/// the session id (or `{"id", "dir"}` with `json`) and returns 0.
fn run_detached(s: &mut Session, cfg: &Config, cmd: &[String], first: bool, json: bool) -> Result<i32> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    let lock = s.lock()?;
    let append = |name: &str| std::fs::OpenOptions::new().create(true).append(true).open(s.path(name));
    let (out, err) = (append("stdout")?, append("stderr")?);
    let null = std::fs::File::open("/dev/null")?;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    match unsafe { libc::fork() } {
        -1 => crate::bail!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            unsafe {
                libc::setsid();
                libc::dup2(null.as_raw_fd(), 0);
                libc::dup2(out.as_raw_fd(), 1);
                libc::dup2(err.as_raw_fd(), 2);
            }
            drop((null, out, err));
            let code = match boot_and_review(s, cfg, cmd, false, first, Some(lock)) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("agentcracker: {e}");
                    1
                }
            };
            std::process::exit(code);
        }
        _ => {
            drop(lock); // the child holds the same lock until the VM is gone
            if json {
                out!("{}", serde_json::json!({ "id": s.meta.id, "dir": s.meta.cwd }));
            } else {
                out!("{}", s.meta.id);
            }
            Ok(0)
        }
    }
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
fn cmd_ls(args: &[String]) -> Result<i32> {
    let json = parse_args("ls", args, &["--json"], 0)?.has("--json");
    let all = session::list();
    if json {
        out!("{}", serde_json::to_string_pretty(&all.iter().map(session_brief).collect::<Vec<_>>())?);
        return Ok(0);
    }
    if all.is_empty() {
        eprintln!("no sessions");
        return Ok(0);
    }
    let t = now();
    out!("{:<9} {:>4}  {:<8} {:<12} {:<34} COMMAND", "ID", "AGE", "STATUS", "CHANGES", "DIRECTORY");
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
        out!("{:<9} {:>4}  {:<8} {:<12} {:<34} {}", s.meta.id, human_age(t.saturating_sub(s.meta.created)), status_of(s), ch, dir, cmd);
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
fn cmd_show(args: &[String]) -> Result<i32> {
    let a = parse_args("show", args, &["--json"], 1)?;
    let json = a.has("--json");
    let s = session::find(a.first(), &cwd()?)?;
    if json {
        out!("{}", serde_json::to_string_pretty(&session_json(&s))?);
        return Ok(0);
    }
    let m = &s.meta;
    let t = now();
    let row = |k: &str, v: String| out!("{k:<10} {v}");
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
    row("agent", crate::agent::for_session(m.agent.as_deref()).display.to_string());
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
    } else if let Some(b) = &m.work_branch {
        row("branch", format!("{b} (the agent's; not imported yet)"));
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
    let tr = agentstate::transcripts(&s);
    if !tr.is_empty() {
        let p = crate::agent::for_session(m.agent.as_deref());
        row("history", format!("{} {} transcript(s) (resume inside with: agentcracker resume {} {})", tr.len(), p.display, m.id, p.resume));
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
        row("", format!("transcripts: {}", tilde(&s.path("state").join(p.path(&crate::util::home(), p.state[0])))));
    }
    let (own, shared) = s.disk_usage();
    row(
        "disk",
        if shared > 0 { format!("{} (plus {} of project snapshot shared with the image cache)", human_bytes(own), human_bytes(shared)) } else { human_bytes(own) },
    );
    row("files", tilde(&s.dir));
    let cache = crate::buildcache::dir_for(&m.cwd).join("cache.img");
    if let Ok(md) = std::fs::metadata(&cache) {
        use std::os::unix::fs::MetadataExt;
        row("cache", format!("{} build cache for {}, shared by its sessions (agentcracker cache)", human_bytes(md.blocks() * 512), tilde(&m.cwd)));
    }
    Ok(0)
}

/// Load the change set of `s`, turning "no change stream" into an error
/// that suggests resuming the session and exiting cleanly.
fn load_cs(s: &Session) -> Result<ChangeSet> {
    ChangeSet::load(s)?.ctx(format!("session {} has no change record (resume it and exit cleanly)", s.meta.id))
}

/// Say how many ignored changes `cs` leaves out, if any, and how to get them.
fn ignored_note(cs: &ChangeSet, cmd: &str) {
    let n = cs.ignored_count();
    if n > 0 && !cs.include_ignored {
        eprintln!("({n} more file(s) git ignores are left out; agentcracker {cmd} --ignored includes them)");
    }
}

/// `agentcracker diff [--ignored] [SESSION]`: show the session's changes as
/// a diff (see [`changes::show_diff`]), or say there are none.  `args`:
/// `--ignored` (include changes git ignores) and an optional session id
/// prefix.  Returns 0.
fn cmd_diff(args: &[String]) -> Result<i32> {
    let a = parse_args("diff", args, &["--ignored"], 1)?;
    let (ig, s) = (a.has("--ignored"), session::find(a.first(), &cwd()?)?);
    let mut cs = load_cs(&s)?;
    cs.include_ignored = ig;
    if cs.is_empty() {
        eprintln!("no changes");
        ignored_note(&cs, "diff");
        if !cs.git.is_empty() {
            eprintln!("({} changes inside .git/; see `agentcracker branch`)", cs.git.len());
        }
        return Ok(0);
    }
    ignored_note(&cs, "diff");
    changes::show_diff(&cs, &s.path("tmp"))?;
    Ok(0)
}

/// `agentcracker apply [--ignored] [SESSION]`: list the session's changes
/// and apply them to the project directory (see [`apply_interactive`]),
/// asking first if they were applied before.  Refuses while the session is
/// running.
///
/// `args`: `--ignored` (apply changes git ignores too) and an optional
/// session id prefix.  Returns 0, or 1 if the user declined to apply again.
fn cmd_apply(args: &[String]) -> Result<i32> {
    let a = parse_args("apply", args, &["--ignored"], 1)?;
    let (ig, mut s) = (a.has("--ignored"), session::find(a.first(), &cwd()?)?);
    if s.is_running() {
        crate::bail!("session {} is still running", s.meta.id);
    }
    let mut cs = load_cs(&s)?;
    cs.include_ignored = ig;
    if cs.is_empty() {
        eprintln!("no changes to apply");
        ignored_note(&cs, "apply");
        return Ok(0);
    }
    changes::print_list(&cs, 30);
    ignored_note(&cs, "apply");
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
/// branch `agentcracker/<id>` (see [`gitimport::import_branch`]) and record it
/// in the session.  `arg`: optional session id prefix.  Returns 0.
fn cmd_branch(args: &[String]) -> Result<i32> {
    let a = parse_args("branch", args, &[], 1)?;
    let mut s = session::find(a.first(), &cwd()?)?;
    let cs = load_cs(&s)?;
    let (b, desc) = gitimport::import_branch(&cs, &s)?;
    status(&format!("created branch {b} ({desc})"));
    s.meta.branch = Some(b);
    s.save()?;
    Ok(0)
}

/// `agentcracker rm SESSION...`: remove each named session (by id prefix),
/// stopping at the first that cannot be found or is still running.
/// Returns 0.
fn cmd_rm(args: &[String]) -> Result<i32> {
    let args = parse_args("rm", args, &[], usize::MAX)?.pos;
    if args.is_empty() {
        crate::bail!("usage: agentcracker rm SESSION...");
    }
    let cwd = cwd()?;
    for a in &args {
        let s = session::find(Some(a), &cwd)?;
        let id = s.meta.id.clone();
        s.remove()?;
        out!("removed {id}");
    }
    Ok(0)
}

/// `agentcracker cache [--drop [DIR]]`: list every project's build cache
/// (size, last use, directory), or delete the one for DIR (default: the
/// current directory).  Returns 0, or 1 if there was no cache to drop.
fn cmd_cache(args: &[String]) -> Result<i32> {
    let a = parse_args("cache", args, &["--drop"], 1)?;
    match (a.has("--drop"), a.first()) {
        (false, None) => {
            let all = crate::buildcache::list();
            if all.is_empty() {
                eprintln!("no build caches yet (a session's ~/.cache becomes its directory's build cache)");
                return Ok(0);
            }
            let now = now();
            for i in all {
                let used = i.used.map_or("-".into(), |t| format!("{} ago", crate::util::human_age(now.saturating_sub(t))));
                let gone = if i.cwd.is_dir() { "" } else { "  (directory gone)" };
                out!("{:>8}  {:>9}  {}{gone}", human_bytes(i.bytes), used, tilde(&i.cwd));
            }
            Ok(0)
        }
        (true, dir) => {
            let dir = match dir {
                Some(p) => std::fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p)),
                None => cwd()?,
            };
            if crate::buildcache::drop_cache(&dir)? {
                status(&format!("dropped the build cache for {}", tilde(&dir)));
                Ok(0)
            } else {
                eprintln!("agentcracker: {} has no build cache", tilde(&dir));
                Ok(1)
            }
        }
        (false, Some(_)) => crate::bail!("usage: agentcracker cache [--drop [DIR]]"),
    }
}

/// `agentcracker refresh [--background]`: rebuild the /usr snapshot now;
/// in the foreground, also rebuild (if stale) the toolchain image for the
/// current directory and the base image.
///
/// `--background` is what [`images::usr_image`] starts when it finds the
/// snapshot stale: it builds only the /usr image, quietly.  `args`: the
/// arguments after `refresh`.  Returns 0.
fn cmd_refresh(args: &[String]) -> Result<i32> {
    // (--background: the detached rebuild a session starts)
    let bg = parse_args("refresh", args, &["--background"], 0)?.has("--background");
    let cwd = cwd()?;
    let cfg = Config::load(&cwd)?;
    images::usr_image(&cfg, if bg { Refresh::Background } else { Refresh::Force })?;
    if !bg {
        let tools = images::detect_tools(&cfg, &cwd);
        images::tools_image(&cfg, &tools)?;
        if let (Ok(a), Ok(f)) = (images::find_asset("acinit"), images::find_asset("firecracker")) {
            images::base_image(&a, &f)?;
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// scripting: --json, wait, stop
// ---------------------------------------------------------------------------

/// Version of the `--json` output.  Adding fields keeps it; removing or
/// changing the meaning of one bumps it.
const JSON_FORMAT: u32 = 1;

/// The status word `ls` shows, plus whether a VM is running.
fn status_json(s: &Session) -> (String, bool) {
    let running = s.is_running();
    let st = if running {
        "running".to_string()
    } else {
        match s.meta.status.as_str() {
            "running" | "starting" => "stopped".into(),
            st => st.to_string(),
        }
    };
    (st, running)
}

/// One session in brief, as `ls --json` and `wait --json` print it.
fn session_brief(s: &Session) -> serde_json::Value {
    let (status, running) = status_json(s);
    let m = &s.meta;
    serde_json::json!({
        "format": JSON_FORMAT,
        "id": m.id,
        "dir": m.cwd,
        "command": m.cmd,
        "agent": crate::agent::for_session(m.agent.as_deref()).name,
        "status": status,
        "exit_code": m.exit_code,
        "running": running,
        "created": m.created,
        "ended": m.ended,
        "changes": m.summary.as_ref().map(|x| serde_json::json!({
            "added": x.added, "modified": x.modified, "deleted": x.deleted, "inside_git": x.git_internal, "ignored": x.ignored,
        })),
    })
}

/// Everything `show` reports, as `show --json` prints it.  Strings are the
/// agent's where they come from the guest: JSON escaping makes them safe
/// to carry, not safe to act on.
fn session_json(s: &Session) -> serde_json::Value {
    let m = &s.meta;
    let mut v = session_brief(s);
    let cs = ChangeSet::load(s).ok().flatten();
    let files: Vec<serde_json::Value> = cs
        .iter()
        .flat_map(|cs| cs.shown())
        .map(|c| {
            let status = match c.st {
                changes::St::Added => "added",
                changes::St::Modified => "modified",
                changes::St::Deleted => "deleted",
                changes::St::Container => "unchanged",
            };
            let (ty, mode, target) = match &c.op {
                changes::Op::File { mode, .. } => ("file", Some(format!("{:o}", mode & 0o777)), None),
                changes::Op::Symlink { target } => ("symlink", None, Some(String::from_utf8_lossy(target).into_owned())),
                changes::Op::Dir { mode } => ("dir", Some(format!("{:o}", mode & 0o777)), None),
                changes::Op::Delete => ("deleted", None, None),
            };
            let mut f = serde_json::json!({
                "path": String::from_utf8_lossy(&c.raw),
                "status": status,
                "type": ty,
                "conflict": c.conflict,
                "runs_on_host": c.sensitive,
                "already_on_host": c.in_place,
            });
            if let Some(mode) = mode {
                f["mode"] = mode.into();
            }
            if let Some(t) = target {
                f["points_outside"] = changes::symlink_escapes(&c.raw, t.as_bytes()).into();
                f["target"] = t.into();
            }
            if c.nested > 0 {
                f["entries"] = c.nested.into();
            }
            f
        })
        .collect();
    let agent_head = cs.as_ref().and_then(|cs| gitimport::agent_head(cs, m.git_head.as_deref()));
    let (own, shared) = s.disk_usage();
    let o = v.as_object_mut().unwrap();
    o.insert("boots".into(), m.boots.into());
    o.insert("runtime_secs".into(), m.runtime.into());
    o.insert("error".into(), m.error.clone().into());
    o.insert("vm".into(), serde_json::json!({ "vcpus": m.vcpus, "memory_mib": m.mem_mib, "net": m.net, "allow": m.allow }));
    o.insert(
        "git".into(),
        serde_json::json!({
            "base": m.git_head,
            "agent_head": agent_head.map(|(sha, branch)| serde_json::json!({ "branch": branch, "commit": sha })),
            "imported_branch": m.branch,
        }),
    );
    o.insert("applied_at".into(), m.applied_at.into());
    if let Some(c) = o.get_mut("changes").and_then(|c| c.as_object_mut()) {
        c.insert("files".into(), files.into());
    }
    o.insert(
        "network".into(),
        crate::proxy::summarize(&s.path("net.log"))
            .into_iter()
            .map(|(host, a, d)| serde_json::json!({ "host": host, "allowed": a, "denied": d }))
            .collect::<Vec<_>>()
            .into(),
    );
    o.insert(
        "transcripts".into(),
        agentstate::transcripts(s)
            .into_iter()
            .map(|t| serde_json::json!({ "id": t.id, "messages": t.messages, "last": t.last, "first_prompt": t.first_prompt }))
            .collect::<Vec<_>>()
            .into(),
    );
    o.insert("disk".into(), serde_json::json!({ "own": own, "shared": shared }));
    let opt = |name: &str| Some(s.path(name)).filter(|p| p.exists());
    o.insert(
        "paths".into(),
        serde_json::json!({
            "session": s.dir,
            "stdout": opt("stdout"),
            "stderr": opt("stderr"),
            "transcripts": opt(&format!("state/{}", {
                let p = crate::agent::for_session(m.agent.as_deref());
                p.path(&crate::util::home(), p.state[0])
            })),
        }),
    );
    v
}

/// Resolve the session arguments of `wait` and `stop`: id prefixes, or the
/// latest session for the current directory when there are none.
fn sessions_from(args: &[String]) -> Result<Vec<Session>> {
    let cwd = cwd()?;
    if args.is_empty() {
        return Ok(vec![session::find(None, &cwd)?]);
    }
    args.iter().map(|a| session::find(Some(a), &cwd)).collect()
}

/// `agentcracker wait [--json] [SESSION...]`: block until each session's VM
/// has gone, printing `ID STATUS` (or a JSON object) as each one ends.
///
/// Returns the command's exit status for a single session; for several, 0
/// if every one exited 0 and 1 otherwise.
fn cmd_wait(args: &[String]) -> Result<i32> {
    let a = parse_args("wait", args, &["--json"], usize::MAX)?;
    let json = a.has("--json");
    let all = sessions_from(&a.pos)?;
    let (tx, rx) = std::sync::mpsc::channel();
    for s in &all {
        let (lock, dir) = (s.path("lock"), s.dir.clone());
        let tx = tx.clone();
        // the running VM's process holds the lock; getting it means it is done
        std::thread::spawn(move || {
            let _ = crate::util::lock(&lock);
            let _ = tx.send(dir);
        });
    }
    drop(tx);
    let mut codes = Vec::new();
    for dir in rx {
        let s = Session::load_dir(&dir)?;
        if json {
            out!("{}", serde_json::to_string(&session_brief(&s))?);
        } else {
            let (st, _) = status_json(&s);
            let st = match (st.as_str(), s.meta.exit_code) {
                ("exited", Some(c)) => format!("exit {c}"),
                _ => st,
            };
            out!("{} {st}", s.meta.id);
        }
        codes.push(s.meta.exit_code);
    }
    Ok(match codes.as_slice() {
        [c] => c.unwrap_or(1),
        cs => i32::from(!cs.iter().all(|c| *c == Some(0))),
    })
}

/// `agentcracker stop [SESSION...]`: end running sessions cleanly.
///
/// Sends SIGTERM to each session's agentcracker process, which asks the
/// guest to stop the command (SIGTERM, then SIGKILL 5 s later); the
/// session then exports its changes and ends as usual.  Waits up to 30 s
/// for each.  Returns 0 if every session is stopped (or was not running).
fn cmd_stop(args: &[String]) -> Result<i32> {
    let all = sessions_from(&parse_args("stop", args, &[], usize::MAX)?.pos)?;
    let mut ok = true;
    for s in &all {
        let id = &s.meta.id;
        if !s.is_running() {
            out!("{id} is not running");
            continue;
        }
        // the pid is recorded just after the lock is taken; allow for that
        let mut pid = None;
        for _ in 0..50 {
            pid = Session::load_dir(&s.dir).ok().and_then(|x| x.meta.pid);
            if pid.is_some() || !s.is_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if let Some(pid) = pid {
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while s.is_running() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if s.is_running() {
            eprintln!("agentcracker: {id} is still running");
            ok = false;
        } else {
            out!("stopped {id}");
        }
    }
    Ok(i32::from(!ok))
}

/// `agentcracker log [--json] [-f] [SESSION]`: the session's activity as
/// one timeline - every connection attempt through the proxy, every tool
/// call in the agent's transcripts and every test kernel boot (see
/// [`crate::activity`]).
///
/// On a running session the agent's tool calls and boots are read out of
/// the VM ([`activity::Live`]); they reach the session's state only when
/// it ends.  With `-f`, new events are printed as they happen: network
/// events at once, the agent's within a couple of seconds.  Returns 0.
fn cmd_log(args: &[String]) -> Result<i32> {
    use crate::activity::{self, Event};
    use std::time::{Duration, Instant};
    let a = parse_args("log", args, &["--json", "-f|--follow"], 1)?;
    let (json, follow) = (a.has("--json"), a.has("--follow"));
    let s = session::find(a.first(), &cwd()?)?;
    let net = s.path("net.log");
    let (mut events, mut off) = activity::net_events(&net, 0);
    // the agent's tool calls and its test kernel boots, as exported with
    // the session's state
    let late_events = |s: &Session| {
        let mut v = activity::tool_events(s);
        v.extend(activity::boot_events(&s.path("state").join(crate::acrboot::RECORDS).join("boot.log")));
        v
    };
    // what an earlier run exported, then (while it runs) what the VM has
    // now: the guest's files hold both, so drop what is already listed
    let key = |e: &Event| (e.time.to_bits(), e.kind.clone(), e.detail.clone());
    let mut seen = std::collections::HashSet::new();
    let mut fresh = |v: Vec<Event>| -> Vec<Event> { v.into_iter().filter(|e| seen.insert(key(e))).collect() };
    events.extend(fresh(late_events(&s)));
    let mut live = s.is_running().then(activity::Live::default);
    if let Some(l) = live.as_mut() {
        match l.poll(&s) {
            Ok(v) => events.extend(fresh(v)),
            Err(e) => eprintln!("agentcracker: the agent's tool calls and test boots so far are not shown: {e}"),
        }
    }
    events.sort_by(|a, b| a.time.total_cmp(&b.time));
    // dates only when the timeline spans more than one day
    let first = events.first().map(|e| e.time).unwrap_or(s.meta.created as f64);
    let last = if follow { now() as f64 } else { events.last().map(|e| e.time).unwrap_or(first) };
    let with_date = activity::clock(first, true)[..10] != activity::clock(last, true)[..10];
    let emit = |e: &Event| {
        if json {
            out!("{}", activity::json(e));
        } else {
            out!("{}", activity::render(e, with_date));
        }
    };
    for e in &events {
        emit(e);
    }
    if follow && s.is_running() {
        let mut polled = Instant::now();
        loop {
            let running = s.is_running();
            let (mut new, o) = activity::net_events(&net, off);
            off = o;
            // the agent's, read out of the VM every couple of seconds (a
            // VM that cannot be reached for a moment is tried again later)
            if let Some(l) = live.as_mut().filter(|_| running && polled.elapsed() >= Duration::from_secs(2)) {
                polled = Instant::now();
                new.extend(fresh(l.poll(&s).unwrap_or_default()));
            }
            new.sort_by(|a, b| a.time.total_cmp(&b.time));
            new.iter().for_each(emit);
            if !running {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        // and whatever came after the last look, once the state is out
        let mut late = fresh(late_events(&s));
        late.sort_by(|a, b| a.time.total_cmp(&b.time));
        late.iter().for_each(emit);
    } else if events.is_empty() && !json {
        eprintln!("no activity recorded for session {}", s.meta.id);
    }
    Ok(0)
}
