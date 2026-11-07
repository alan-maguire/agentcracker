#!/bin/bash
# Agent profiles: a session gets the profile of the agent it runs (Claude
# Code by default, Codex here): its hosts, its configuration and login (and
# nothing else of its), its environment, its transcripts in show and log.
# Runs with a throwaway $HOME and image cache, like t10, so a regression
# can never touch the real logins or cached images.
. "$(dirname "$0")/lib.sh"
require_vm

fake=$WORK/home
mkdir -p "$fake/.codex/skills/demo" "$fake/.codex/secrets" "$fake/.codex/memories" "$fake/.codex/sessions/2026/01/01" "$fake/.claude"
printf 'model = "gpt-test"\n' >"$fake/.codex/config.toml"
printf 'Always run the tests.\n' >"$fake/.codex/AGENTS.md"
printf 'demo skill\n' >"$fake/.codex/skills/demo/SKILL.md"
printf '{"OPENAI_API_KEY":null,"tokens":{"access_token":"host-token"}}\n' >"$fake/.codex/auth.json"
echo secret >"$fake/.codex/secrets/store"
echo '{}' >"$fake/.codex/gateway_oauth.json"
echo '{}' >"$fake/.codex/.credentials.json"
echo '{}' >"$fake/.codex/history.jsonl"
echo mem >"$fake/.codex/memories/m.md"
echo '{}' >"$fake/.codex/sessions/2026/01/01/rollout-old.jsonl"
printf '{"theme":"x"}\n' >"$fake/.claude/settings.json"
chmod 600 "$fake/.codex/auth.json"
auth_before=$(sha256sum <"$fake/.codex/auth.json")
real_cache=${XDG_CACHE_HOME:-$REAL_HOME/.cache}/agentcracker
mkdir -p "$WORK/cache/agentcracker"
[ -d "$real_cache/usr" ] && ln -s "$real_cache/usr" "$WORK/cache/agentcracker/usr"
fakeenv() { HOME=$fake XDG_CACHE_HOME=$WORK/cache PATH=/usr/bin:/bin "$@"; }

mkdir -p "$fake/proj" && cd "$fake/proj" && echo hi >f
# stands in for codex: reports what it finds, then acts like a Codex session
cat >codex <<'SH'
#!/bin/sh
c=$HOME/.codex
for f in config.toml AGENTS.md skills/demo/SKILL.md auth.json; do test -e "$c/$f" && echo "has $f"; done
for f in secrets gateway_oauth.json .credentials.json history.jsonl memories sessions/2026/01/01; do test -e "$c/$f" && echo "LEAKED $f"; done
test -e "$HOME/.claude/settings.json" && echo "LEAKED claude settings"
echo "key=${OPENAI_API_KEY:-none} codexvar=${CODEX_TEST_VAR:-none} anthropic=${ANTHROPIC_TEST_VAR:-none}"
curl -s -o /dev/null --max-time 5 https://example.com
d=$c/sessions/2026/11/06; mkdir -p "$d"
cat >"$d/rollout-2026-11-06T15-42-00-0199a1b2-c3d4.jsonl" <<'JSON'
{"timestamp":"2026-11-06T15:42:00.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>cwd</environment_context>"}]}}
{"timestamp":"2026-11-06T15:42:01.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"port the parser"}]}}
{"timestamp":"2026-11-06T15:42:02.000Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"cargo test\"}","call_id":"c1"}}
{"timestamp":"2026-11-06T15:42:03.000Z","type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","input":"*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-a\n+b\n*** Add File: src/new.rs\n+x\n*** End Patch","call_id":"c2"}}
{"timestamp":"2026-11-06T15:42:04.000Z","type":"response_item","payload":{"type":"web_search_call","status":"completed","action":{"type":"search","query":"erofs layout"}}}
{"timestamp":"2026-11-06T15:42:05.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]}}
JSON
printf '{"tokens":{"access_token":"REFRESHED-IN-GUEST"}}\n' >"$c/auth.json"
echo "Read the docs first." > AGENTS.md
SH
chmod +x codex

step "a codex session gets the Codex profile"
OPENAI_API_KEY=sk-test CODEX_TEST_VAR=yes ANTHROPIC_TEST_VAR=no fakeenv ac_run ./codex
assert_rc 0 "the session ran"
assert_contains "$AC_ERR" "net: OpenAI API only" "the banner shows OpenAI's default allowlist"
assert_eq "$(meta agent)" "codex" "the profile is recorded in the session"
assert_contains "$(meta allow)" "chatgpt.com" "ChatGPT's hosts are allowed by default"
assert_not_contains "$(meta allow)" "anthropic.com" "Anthropic's are not"
for f in config.toml AGENTS.md skills/demo/SKILL.md auth.json; do
    assert_contains "$AC_OUT" "has $f" "~/.codex/$f is seeded"
done
assert_not_contains "$AC_OUT" "LEAKED" "credential stores, memories, history and other sessions are not seeded"
assert_contains "$AC_OUT" "key=sk-test codexvar=yes anthropic=none" "OPENAI_* and CODEX_* pass through, ANTHROPIC_* does not"

step "its login is never copied back"
assert_eq "$(sha256sum <"$fake/.codex/auth.json")" "$auth_before" "the host's auth.json is untouched"
assert_contains "$AC_ERR" "Codex refreshed its login inside the VM" "the refresh is reported"
assert_no_file "$(session_dir "$SID")/state/.codex/auth.json" "the guest's auth.json is not kept"

step "show and log read Codex's transcripts"
fakeenv ac show "$SID"
assert_contains "$AC_OUT" "agent      Codex" "show names the agent"
assert_contains "$AC_OUT" "1 Codex transcript(s) (resume inside with: agentcracker resume $SID codex resume)" "show counts Codex transcripts"
assert_contains "$AC_OUT" '"port the parser"' "the first real prompt, not Codex's context, is shown"
assert_contains "$AC_ERR" "A AGENTS.md  (runs or configures tools on the host" "an agent instruction file is flagged at review"
fakeenv ac log "$SID"
assert_match "$AC_OUT" '  shell +cargo test' "shell commands are in the log"
assert_match "$AC_OUT" '  edit +src/lib\.rs' "patched files are in the log"
assert_match "$AC_OUT" '  write +src/new\.rs' "added files are in the log"
assert_match "$AC_OUT" '  websearch +erofs layout  \(server-side' "web searches are marked server-side"
assert_match "$AC_OUT" 'net +DENY +example\.com:443' "and the network requests"

step "choosing the profile"
fakeenv ac_run sh -c 'test -e $HOME/.claude/settings.json && echo claude-seeded; test -e $HOME/.codex/auth.json && echo codex-seeded'
assert_eq "$(meta agent)" "claude" "a command that is no agent gets Claude Code by default"
assert_eq "$AC_OUT" "claude-seeded" "...with Claude's files and none of Codex's"
set_config 'agent = "codex"'
fakeenv ac_run sh -c 'test -e $HOME/.codex/auth.json && echo codex-seeded'
assert_eq "$(meta agent)" "codex" "the agent config key picks the profile for other commands"
assert_eq "$AC_OUT" "codex-seeded" "...with that profile's files"
fakeenv ac_run sh -c 'cat $HOME/.codex/AGENTS.md'
assert_contains "$AC_OUT" "Always run the tests." "Codex's global AGENTS.md keeps the user's text"
assert_contains "$AC_OUT" "## agentcracker sandbox" "...and gains the sandbox section"
fakeenv ac resume "$SID" true
assert_contains "$AC_ERR" "net: OpenAI API only" "resume keeps the session's profile"
set_config 'agent = "nosuch"'
fakeenv ac_run true
assert_rc 1 "an unknown agent in the config is an error"
assert_contains "$AC_ERR" 'unknown agent "nosuch"' "naming the problem"
set_config

step "CODEX_HOME"
mkdir -p "$fake/.config/codex-alt"
printf 'model = "alt"\n' >"$fake/.config/codex-alt/config.toml"
echo '{}' >"$fake/.config/codex-alt/auth.json"
set_config 'agent = "codex"'
CODEX_HOME=$fake/.config/codex-alt fakeenv ac_run sh -c 'cat "$CODEX_HOME/config.toml"; test -e "$CODEX_HOME/auth.json" && echo auth-ok'
assert_eq "$AC_OUT" "$(printf 'model = "alt"\nauth-ok')" "a relocated CODEX_HOME inside \$HOME is seeded where Codex will look"
set_config

finish
