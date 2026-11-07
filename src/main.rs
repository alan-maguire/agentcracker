//! agentcracker: disposable Firecracker microVMs for coding agents.
//!
//! One program, two roles.  On the host it is the `agentcracker` CLI.  The
//! build also produces a statically linked copy that goes into the base
//! image as `/acinit`; when the guest kernel starts it as PID 1 it acts as
//! the guest's init instead.  The role is chosen at run time from
//! `getpid() == 1`, so host and guest can never disagree about the protocol
//! or the stream formats they share.
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
//! - `changes`: interpreting, reviewing and safely applying the guest's changes
//! - `util`: errors, paths, hashing, locking and formatting helpers

mod acrboot;
mod activity;
mod agent;
mod buildcache;
mod changes;
mod cli;
mod config;
mod erofs;
mod guest;
mod images;
mod proto;
mod proxy;
mod session;
mod util;
mod vm;

/// Entry point for both roles.
///
/// As PID 1 (inside the guest) control passes to [`guest::main`], which
/// never returns: it powers the VM off when it is done.  Otherwise this is
/// the host CLI: [`cli::run`] gets the full argument vector, and its result
/// becomes the process exit status - the command's own status on success,
/// or 1 after printing `agentcracker: <error>` to stderr.
fn main() {
    if std::process::id() == 1 {
        guest::main();
    }
    let args: Vec<String> = std::env::args().collect();
    // inside a session, acinit is also the acrboot command
    if args.first().is_some_and(|a| a.rsplit('/').next() == Some("acrboot")) {
        std::process::exit(acrboot::client(&args[1..]));
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
