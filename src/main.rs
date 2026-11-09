//! agentcracker: disposable Firecracker microVMs for coding agents.
//!
//! One program, four roles, chosen at run time - so host and guest can
//! never disagree about the protocol or the stream formats they share:
//!
//! 1. on the host, the `agentcracker` CLI;
//! 2. in the session's VM, as PID 1, acinit, its init ([`guest::main`]).
//!    The build makes a statically linked copy for this, which goes into
//!    the base image as `/acinit`;
//! 3. in the session's VM, run as `acrboot` (a symlink to `/acinit`), the
//!    command that boots test kernels ([`acrboot::main`]);
//! 4. in an `acrboot --run` test VM, as PID 1 with `acrboot_run` on the
//!    kernel command line, that VM's init ([`acrboot::init`]).
//!
//! Module map (IMPLEMENTATION.md has the full walkthrough):
//!
//! - `cli`: command-line parsing, the run/review loop and session queries
//! - `config`: config files and the egress allowlist matcher
//! - `session`: the per-session state directory and metadata on the host
//! - `images`: building and caching the read-only EROFS images (base,
//!   /usr, toolchains, project) and creating the scratch disk
//! - `erofs`: the EROFS image writer the images are built with
//! - `vm`: launching Firecracker, the vsock control channel, terminal attach
//! - `proxy`: the host-side HTTPS CONNECT proxy enforcing the allowlist
//! - `proto`: the vsock frame protocol and the file stream format
//! - `guest`: acinit, PID 1 inside the VM
//! - `changes`: interpreting and reviewing the guest's changes
//! - `apply`: applying them to the host, through confined writes
//! - `gitimport`: importing the agent's commits as a host branch
//! - `agentstate`: the agent's exported state and transcripts
//! - `activity`: the `log` timeline
//! - `agent`: agent profiles (Claude Code, Codex)
//! - `guidance`: what the agent is told, and its git identity
//! - `buildcache`: per-project build caches
//! - `acrboot`: booting test kernels in nested microVMs
//! - `util`: errors, paths, hashing, locking, git and formatting helpers

mod acrboot;
mod activity;
mod agent;
mod agentstate;
mod apply;
mod buildcache;
mod changes;
mod cli;
mod config;
mod erofs;
mod gitimport;
mod guidance;
mod guest;
mod images;
mod jail;
mod proto;
mod proxy;
mod session;
mod util;
mod vm;

/// Entry point for every role (see the module docs).
///
/// As PID 1 (inside the guest) control passes to [`guest::main`], which
/// never returns: it powers the VM off when it is done.  Otherwise this is
/// the host CLI: [`cli::run`] gets the full argument vector, and its result
/// becomes the process exit status - the command's own status on success,
/// or 1 after printing `agentcracker: <error>` to stderr.
fn main() {
    if std::process::id() == 1 {
        // a test VM's init (acrboot --run), chosen on its kernel command line
        if std::env::var_os("acrboot_run").is_some() {
            acrboot::init();
        }
        guest::main();
    }
    let args: Vec<String> = std::env::args().collect();
    // inside a session, acinit is also the acrboot command
    if args.first().is_some_and(|a| a.rsplit('/').next() == Some("acrboot")) {
        std::process::exit(acrboot::main(&args[1..]));
    }
    util::mark("start");
    let code = match cli::run(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agentcracker: {e}");
            1
        }
    };
    std::process::exit(code);
}
