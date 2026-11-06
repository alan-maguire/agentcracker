#!/bin/bash
# `agentcracker log`: one timeline of network requests and the agent's
# tool calls, followed live with -f, as JSON with --json, and escaped.
. "$(dirname "$0")/lib.sh"
require_vm
require_cmd curl
new_project

# a transcript like Claude Code's, as if the agent had made these calls
key=$(printf '%s' "$PWD" | sed 's/[^A-Za-z0-9]/-/g')
mkdir -p fixture
cat >fixture/t.jsonl <<'JSON'
{"type":"user","message":{"content":"fix the build"},"timestamp":"2026-11-06T15:42:00.000Z"}
{"type":"assistant","timestamp":"2026-11-06T15:42:01.000Z","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"make -j8\necho done"}}]}}
{"type":"assistant","timestamp":"2026-11-06T15:42:02.000Z","message":{"content":[{"type":"tool_use","name":"Edit","input":{"file_path":"/p/src/main.rs","old_string":"a","new_string":"b"}}]}}
{"type":"assistant","timestamp":"2026-11-06T15:42:03.000Z","message":{"content":[{"type":"tool_use","name":"WebFetch","input":{"url":"https://docs.rs/erofs","prompt":"summarise"}}]}}
{"type":"assistant","timestamp":"2026-11-06T15:42:04.000Z","message":{"content":[{"type":"tool_use","name":"WebSearch","input":{"query":"erofs \u001b]0;pwned\u0007 layout"}}]}}
JSON
mkdir -p fixture/sub/subagents
cat >fixture/sub/subagents/a.jsonl <<'JSON'
{"type":"assistant","isSidechain":true,"timestamp":"2026-11-06T15:42:05.000Z","message":{"content":[{"type":"tool_use","name":"Read","input":{"file_path":"/p/README.md"}}]}}
JSON

step "timeline of a finished session"
ac_run sh -c 'curl -s -o /dev/null --max-time 5 https://example.com; d=$HOME/.claude/projects/'"$key"'; mkdir -p $d/s && cp fixture/t.jsonl $d/ && cp -r fixture/sub/subagents $d/s/'
ac log "$SID"
assert_rc 0 "log exits 0"
# (the fixture's date differs from today's on most days, which adds dates)
assert_match "$AC_OUT" '^([0-9-]{10} )?[0-9:]{8}  net +DENY +example\.com:443' "network requests are listed with the proxy's verdict"
assert_match "$AC_OUT" '  bash +make -j8 …' "shell commands are listed (first line)"
assert_match "$AC_OUT" '  edit +/p/src/main\.rs' "file edits are listed"
assert_match "$AC_OUT" '  webfetch +https://docs\.rs/erofs' "fetched URLs are listed"
assert_contains "$AC_OUT" "(server-side: not seen by the proxy)" "web searches are marked as invisible to the proxy"
assert_match "$AC_OUT" '  read +/p/README\.md' "subagents' tool calls are included"
assert_contains "$AC_OUT" 'erofs \x1b]0;pwned\x07 layout' "agent-controlled text is escaped"
[[ "$AC_OUT" == *$'\e'* ]] && fail "raw escape in log output" || pass "no raw escapes reach the terminal"
order=$("$AC" log --json "$SID" | python3 -I -c 'import json,sys; print(" ".join(json.loads(l)["kind"] for l in sys.stdin))')
assert_eq "$order" "bash edit webfetch websearch read net" "events are in time order"

step "--json"
ac log --json "$SID"
n=$(echo "$AC_OUT" | python3 -I -c 'import json,sys; print(sum(1 for l in sys.stdin if json.loads(l)["format"] == 1))')
assert_eq "$n" "6" "one JSON object per event"
assert_contains "$AC_OUT" '"verdict":"DENY"' "network verdicts in JSON"
assert_contains "$AC_OUT" '"server_side":true' "server-side flag in JSON"

step "-f follows a running session"
id=$("$AC" --detach sh -c 'sleep 2; curl -s -o /dev/null --max-time 5 https://example.org; sleep 1' </dev/null)
timeout 30 "$AC" log -f "$id" >"$WORK/follow.out" 2>&1
rc=$?
assert_eq "$rc" "0" "log -f ends by itself when the session does"
assert_match "$(cat "$WORK/follow.out")" 'net +DENY +example\.org:443' "requests made while following are shown"

step "an empty timeline"
ac_run true
ac log "$SID"
assert_contains "$AC_ERR" "no activity recorded" "says so when there is nothing"

finish
