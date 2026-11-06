//! Agent profiles: what agentcracker needs to know about each coding agent
//! it runs.
//!
//! A profile says which hosts the agent needs by default, which of its
//! files to copy into the guest (configuration on a session's first boot,
//! the login on every boot - never back out), which of its files to keep
//! when the session ends, which environment variables to pass through, and
//! how to resume it.  Each session gets one profile, chosen from the command
//! (`claude ...`, `codex ...`), else from the `agent` config key, else
//! Claude Code; it is recorded in the session so `resume` and `show` use
//! the same one.

use std::path::{Path, PathBuf};

/// What agentcracker knows about one agent.
#[derive(Debug)]
pub struct Profile {
    /// Name as used in config (`agent = "codex"`) and session metadata.
    pub name: &'static str,
    /// Human-readable name.
    pub display: &'static str,
    /// What the default allowlist reaches, for the session banner.
    pub api: &'static str,
    /// Hosts allowed by default (as for `--allow`).
    pub allow: &'static [&'static str],
    /// The agent's directory under `$HOME`.
    pub dir: &'static str,
    /// Environment variable that moves the agent's directory, if any.
    pub dir_env: Option<&'static str>,
    /// Paths inside the agent's directory copied in on a session's first
    /// boot: configuration, instructions, extensions.  Never credentials or
    /// other projects' data.
    pub seed: &'static [&'static str],
    /// The login file inside the agent's directory: copied in on every boot
    /// (the host copy may have been refreshed), never copied back out.
    pub credential: &'static str,
    /// Paths inside the agent's directory kept when the session ends (its
    /// transcripts).
    pub state: &'static [&'static str],
    /// Environment variable prefixes passed through to the guest.
    pub env_prefixes: &'static [&'static str],
    /// How to continue the agent's last conversation inside the session.
    pub resume: &'static str,
}

/// Claude Code.
pub static CLAUDE: Profile = Profile {
    name: "claude",
    display: "Claude",
    api: "Anthropic API",
    allow: &["anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai", "claude.com", "*.claude.com"],
    dir: ".claude",
    dir_env: None,
    seed: &["settings.json", "CLAUDE.md", "commands", "agents", "skills", "plugins", "output-styles"],
    credential: ".credentials.json",
    state: &["projects"],
    env_prefixes: &["ANTHROPIC_", "CLAUDE_CODE_"],
    resume: "claude --resume",
};

/// OpenAI Codex CLI.  Per its source: `$CODEX_HOME` (default `~/.codex`)
/// holds `config.toml`, the global `AGENTS.md`, skills, agents and rules,
/// the login in `auth.json`, and session rollouts under `sessions/`.  Not
/// copied: `secrets/`, `gateway_oauth.json` and `.credentials.json` (other
/// credentials), `memories/` and `history.jsonl` (cross-project data).
pub static CODEX: Profile = Profile {
    name: "codex",
    display: "Codex",
    api: "OpenAI API",
    allow: &["openai.com", "*.openai.com", "chatgpt.com", "*.chatgpt.com"],
    dir: ".codex",
    dir_env: Some("CODEX_HOME"),
    seed: &["config.toml", "AGENTS.md", "AGENTS.override.md", "skills", "agents", "rules", "themes"],
    credential: "auth.json",
    state: &["sessions"],
    env_prefixes: &["OPENAI_", "CODEX_"],
    resume: "codex resume",
};

/// Every profile, the default first.
pub static PROFILES: &[&Profile] = &[&CLAUDE, &CODEX];

/// The profile called `name`, if there is one.
pub fn by_name(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().copied().find(|p| p.name == name)
}

/// The profile for a session: the one it recorded (sessions from before
/// profiles were Claude Code's).
pub fn for_session(agent: Option<&str>) -> &'static Profile {
    agent.and_then(by_name).unwrap_or(&CLAUDE)
}

/// Recognise the agent a command starts.  Looks at the program, past the
/// usual wrappers: `env [VAR=value]...`, `npx`/`bunx`/`pnpx`, `npm exec`,
/// `pnpm dlx`, `nice`, and `sh -c '...'` (whose script's first word is
/// examined in turn).  Matches the agent's command by file name, or its
/// npm package (`@openai/codex`, `@anthropic-ai/claude-code`).
pub fn detect(cmd: &[String]) -> Option<&'static Profile> {
    let mut words: Vec<String> = cmd.to_vec();
    let mut i = 0;
    for _ in 0..8 {
        let word = words.get(i)?.clone();
        let base = word.rsplit('/').next().unwrap_or(&word).to_string();
        let skip_opts = |mut j: usize, w: &[String]| {
            while w.get(j).is_some_and(|a| a.starts_with('-')) {
                j += 1;
            }
            j
        };
        match base.as_str() {
            "env" => {
                i += 1;
                while words.get(i).is_some_and(|a| a.starts_with('-') || a.contains('=')) {
                    i += 1;
                }
            }
            "nice" | "npx" | "bunx" | "pnpx" => i = skip_opts(i + 1, &words),
            "npm" | "pnpm" | "yarn" | "bun" if matches!(words.get(i + 1).map(|s| s.as_str()), Some("exec" | "dlx" | "x")) => {
                i = skip_opts(i + 2, &words)
            }
            "sh" | "bash" | "dash" | "zsh" => {
                let j = skip_opts(i + 1, &words);
                let script = if words[i + 1..j].iter().any(|o| o.contains('c')) { words.get(j) } else { None };
                words = script?.split_whitespace().map(|s| s.to_string()).collect();
                i = 0;
            }
            _ => {
                let pkg = base.split('@').next().filter(|b| !b.is_empty()).unwrap_or(&base);
                return if pkg == "codex" || word.starts_with("@openai/codex") {
                    Some(&CODEX)
                } else if pkg == "claude" || pkg == "claude-code" || word.starts_with("@anthropic-ai/claude-code") {
                    Some(&CLAUDE)
                } else {
                    None
                };
            }
        }
    }
    None
}

impl Profile {
    /// The agent's directory relative to `$HOME`: its default, or where its
    /// environment variable points when that is inside `home`.
    pub fn dir_in(&self, home: &Path) -> PathBuf {
        if let Some(var) = self.dir_env {
            if let Some(v) = std::env::var_os(var) {
                if let Ok(rel) = Path::new(&v).strip_prefix(home) {
                    if !rel.as_os_str().is_empty() {
                        return rel.to_path_buf();
                    }
                }
            }
        }
        PathBuf::from(self.dir)
    }

    /// `rel` inside the agent's directory, relative to `$HOME`, as a string.
    pub fn path(&self, home: &Path, rel: &str) -> String {
        self.dir_in(home).join(rel).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(cmd: &[&str]) -> Option<&'static str> {
        detect(&cmd.iter().map(|s| s.to_string()).collect::<Vec<_>>()).map(|p| p.name)
    }

    #[test]
    fn detects_agents() {
        assert_eq!(d(&["claude"]), Some("claude"));
        assert_eq!(d(&["/home/u/.local/bin/claude", "-p", "hi"]), Some("claude"));
        assert_eq!(d(&["codex", "exec", "fix it"]), Some("codex"));
        assert_eq!(d(&["env", "FOO=1", "codex"]), Some("codex"));
        assert_eq!(d(&["npx", "@openai/codex"]), Some("codex"));
        assert_eq!(d(&["npx", "-y", "@anthropic-ai/claude-code"]), Some("claude"));
        assert_eq!(d(&["sh", "-c", "codex exec 'x'"]), Some("codex"));
        assert_eq!(d(&["./codex"]), Some("codex"));
        assert_eq!(d(&["bash"]), None);
        assert_eq!(d(&["make", "test"]), None);
        assert_eq!(d(&["grep", "-r", "codex"]), None);
        assert_eq!(d(&["sh", "-c", "grep codex x"]), None);
        assert_eq!(d(&["bash", "-lc", "claude -p hi"]), Some("claude"));
        assert_eq!(d(&["npm", "exec", "--", "@openai/codex@latest"]), Some("codex"));
        assert_eq!(d(&["env"]), None);
    }
}
