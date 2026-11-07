//! Configuration.
//!
//! Two optional TOML files are read, in this order:
//!
//! 1. `~/.config/agentcracker/config.toml` (respecting `$XDG_CONFIG_HOME`)
//! 2. `.agentcracker.toml` in the project directory
//!
//! Scalars (`vcpus`, `memory`, `net`, `agent`, `cache`, `boot`) in a later file override earlier
//! ones.  Lists (`allow`, `exclude`, `exclude_usr`, `tools`, `no_tools`,
//! `home`, `state`, `env`) are appended, so a project can add to the user's
//! settings but not take anything away.  Unknown keys are an error, so a
//! typo is reported instead of being silently ignored.
//!
//! The project file is read from the host directory, never from the
//! session's overlay: edits the agent makes to it only take effect once
//! they have been reviewed and applied.

use serde::Deserialize;
use std::path::Path;

use crate::util::{Context, Result, parse_mem_mib};

/// The on-disk shape of one config file.  Every key is optional, so a file
/// only mentions what it changes; `deny_unknown_fields` turns typos into
/// errors.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
struct File {
    vcpus: Option<u32>,
    memory: Option<toml::Value>,
    net: Option<bool>,
    allow: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    exclude_usr: Option<Vec<String>>,
    tools: Option<Vec<String>>,
    no_tools: Option<Vec<String>>,
    home: Option<Vec<String>>,
    state: Option<Vec<String>>,
    env: Option<Vec<String>>,
    agent: Option<String>,
    cache: Option<bool>,
    boot: Option<bool>,
}

/// The effective configuration: built-in defaults with both config files
/// merged in (see [`Config::load`]).
#[derive(Debug, Clone)]
pub struct Config {
    /// Number of guest vCPUs.  Default: the host's CPU count clamped to 1..=8;
    /// values from a config file are clamped to 1..=32.
    pub vcpus: u32,
    /// Guest memory in MiB.  Default: half of host RAM, clamped to 1-8 GiB.
    pub mem_mib: u64,
    /// Whether the guest gets the HTTPS egress proxy at all (`--no-net` turns
    /// it off for a session).
    pub net: bool,
    /// Egress allowlist: host names, `*.domain` wildcards, `host:port` entries
    /// or `*` (see [`host_allowed`]), in addition to the agent profile's own
    /// (see [`crate::agent`]).
    pub allow: Vec<String>,
    /// Patterns ([`Excludes`](crate::util::Excludes) syntax) left out of the
    /// project snapshot.
    pub exclude: Vec<String>,
    /// Paths relative to `/usr` left out of the /usr snapshot.  Starts as
    /// [`DEFAULT_EXCLUDE_USR`].
    pub exclude_usr: Vec<String>,
    /// Extra toolchain directories to snapshot into the guest, in addition to
    /// those found through `$PATH`.
    pub tools: Vec<String>,
    /// Toolchain directories (with everything beneath them) never to snapshot.
    pub no_tools: Vec<String>,
    /// Extra `$HOME` paths copied into the guest on a session's first boot.
    pub home: Vec<String>,
    /// Extra `$HOME` paths exported back into the session store on exit.
    pub state: Vec<String>,
    /// Extra environment variable names passed through to the guest command.
    pub env: Vec<String>,
    /// The agent profile for commands that are not recognisably an agent
    /// (a shell, `make`, ...); `None` means Claude Code.
    pub agent: Option<&'static crate::agent::Profile>,
    /// Give sessions the project's persistent build cache as `~/.cache`
    /// (see [`crate::buildcache`]).  Default: on.
    pub cache: bool,
    /// Let the agent boot kernels it built in a microVM of their own
    /// (`acrboot`, see [`crate::acrboot`]).  Default: off; settable only in
    /// the user's config, never by a project.
    pub boot: bool,
}

/// Always excluded from the /usr snapshot: useless in a guest (kernel
/// modules, firmware, debug info, kernel sources) or large and private
/// (container storage, local model weights).
pub const DEFAULT_EXCLUDE_USR: &[&str] = &[
    "lib/modules",
    "lib/firmware",
    "lib/debug",
    "src/kernels",
    "src/debug",
    "lib/containers/storage",
    "share/ollama",
];

impl Config {
    /// Load the effective configuration for a session in `cwd`.
    ///
    /// Starts from the built-in defaults - vCPUs: host CPUs clamped to 1..=8;
    /// memory: half of host RAM clamped to 1-8 GiB; network on (the agent
    /// profile supplies the default allowlist); /usr excludes from
    /// [`DEFAULT_EXCLUDE_USR`] - then
    /// merges the user config file and `cwd/.agentcracker.toml`, in that order.
    /// Missing files are skipped.
    ///
    /// `cwd`: the project directory.  Returns the merged configuration, or an
    /// error naming the file that failed to parse or held a bad value.
    pub fn load(cwd: &Path) -> Result<Config> {
        let ncpu = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(2);
        let mem_total_mib = unsafe {
            let mut si: libc::sysinfo = std::mem::zeroed();
            libc::sysinfo(&mut si);
            si.totalram as u64 * si.mem_unit as u64 / (1024 * 1024)
        };
        let mut c = Config {
            vcpus: ncpu.clamp(1, 8),
            mem_mib: (mem_total_mib / 2).clamp(1024, 8192),
            net: true,
            allow: vec![],
            exclude: vec![],
            exclude_usr: DEFAULT_EXCLUDE_USR.iter().map(|s| s.to_string()).collect(),
            tools: vec![],
            no_tools: vec![],
            home: vec![],
            state: vec![],
            env: vec![],
            agent: None,
            cache: true,
            boot: false,
        };
        for (i, p) in [crate::util::config_dir().join("config.toml"), cwd.join(".agentcracker.toml")].into_iter().enumerate() {
            if let Ok(text) = std::fs::read_to_string(&p) {
                let f: File = toml::from_str(&text).ctx(format!("{}", p.display()))?;
                if i == 1 && f.boot.is_some() {
                    // a cloned repository must not hand its agents ring 0
                    crate::bail!("{}: `boot` can only be set in {}", p.display(), crate::util::config_dir().join("config.toml").display());
                }
                c.merge(f).ctx(format!("{}", p.display()))?;
            }
        }
        Ok(c)
    }

    /// Merge one parsed config file into `self`.
    ///
    /// Scalars present in `f` replace the current value (`vcpus` clamped to
    /// 1..=32; `memory` either an integer number of MiB or a string accepted by
    /// [`parse_mem_mib`]).  Lists present in `f` are appended.
    ///
    /// Returns an error only for an invalid `memory` value.
    fn merge(&mut self, f: File) -> Result<()> {
        if let Some(v) = f.vcpus {
            self.vcpus = v.clamp(1, 32);
        }
        if let Some(m) = f.memory {
            self.mem_mib = match m {
                toml::Value::Integer(i) if i > 0 => i as u64,
                toml::Value::String(s) => parse_mem_mib(&s).ctx(format!("bad memory value {s:?}"))?,
                v => crate::bail!("bad memory value {v}"),
            };
        }
        if let Some(n) = f.net {
            self.net = n;
        }
        if let Some(c) = f.cache {
            self.cache = c;
        }
        if let Some(b) = f.boot {
            self.boot = b;
        }
        if let Some(a) = f.agent {
            let names: Vec<&str> = crate::agent::PROFILES.iter().map(|p| p.name).collect();
            self.agent = Some(crate::agent::by_name(&a).ctx(format!("unknown agent {a:?} (known: {})", names.join(", ")))?);
        }
        let app = |dst: &mut Vec<String>, src: Option<Vec<String>>| dst.extend(src.unwrap_or_default());
        app(&mut self.allow, f.allow);
        app(&mut self.exclude, f.exclude);
        app(&mut self.exclude_usr, f.exclude_usr);
        app(&mut self.tools, f.tools);
        app(&mut self.no_tools, f.no_tools);
        app(&mut self.home, f.home);
        app(&mut self.state, f.state);
        app(&mut self.env, f.env);
        Ok(())
    }
}

/// Check a host name (or `host:port`) against the egress allowlist.
///
/// `allow`: the allowlist.  Each entry is compared case-insensitively,
/// after trimming whitespace: `*` allows everything; `*.example.com` allows
/// any subdomain of `example.com` but not `example.com` itself (list both
/// if needed); any other entry must equal `host` exactly.  `host`: the
/// name the guest asked for; a trailing dot is ignored.
///
/// Returns true if any entry matches.  Ports are not interpreted here: the
/// proxy calls this with both `host` and `host:port`, which is how
/// `host:port` entries work.
pub fn host_allowed(allow: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allow.iter().any(|a| {
        let a = a.trim().to_ascii_lowercase();
        if a == "*" {
            true
        } else if let Some(suffix) = a.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == a
        }
    })
}

/// Expand a leading `~` in a path from a config file.
///
/// `p`: the path as written.  `~` and `~/rest` are resolved against
/// `$HOME`; anything else, including `~user` forms (not supported), is
/// returned unchanged.  Returns the expanded path.
pub fn expand(p: &str) -> std::path::PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        crate::util::home().join(rest)
    } else if p == "~" {
        crate::util::home()
    } else {
        std::path::PathBuf::from(p)
    }
}
