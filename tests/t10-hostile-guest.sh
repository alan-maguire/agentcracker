#!/bin/bash
# A hostile guest: it must not be able to plant credentials on the host or
# drive the user's terminal through anything agentcracker prints.
. "$(dirname "$0")/lib.sh"
require_vm

ESC=$'\e'
has_esc() { [[ "$1" == *"$ESC"* ]]; }

step "credentials are never copied back to the host"
# a throwaway $HOME with fake credentials, so that a regression here can
# never overwrite the real login
fake=$WORK/home
mkdir -p "$fake/.claude"
printf '{"claudeAiOauth":{"accessToken":"host-token","refreshToken":"host-refresh"}}\n' >"$fake/.claude/.credentials.json"
chmod 600 "$fake/.claude/.credentials.json"
before=$(sha256sum <"$fake/.claude/.credentials.json")
mkdir -p "$fake/proj" && cd "$fake/proj" && echo hi >f
# its own image cache too, since images keyed on $HOME (base, toolchains)
# would otherwise replace the real ones; only the /usr snapshot, which does
# not depend on $HOME, is borrowed from the real cache
real_cache=${XDG_CACHE_HOME:-$REAL_HOME/.cache}/agentcracker
mkdir -p "$WORK/cache/agentcracker"
[ -d "$real_cache/usr" ] && ln -s "$real_cache/usr" "$WORK/cache/agentcracker/usr"
fakeenv() { HOME=$fake XDG_CACHE_HOME=$WORK/cache PATH=/usr/bin:/bin "$@"; }
fakeenv ac_run sh -c 'cat $HOME/.claude/.credentials.json >/dev/null && echo seeded; printf "{\"claudeAiOauth\":{\"accessToken\":\"ATTACKER\",\"refreshToken\":\"ATTACKER\"}}\n" > $HOME/.claude/.credentials.json'
assert_contains "$AC_OUT" "seeded" "the guest was given the credentials"
assert_eq "$(sha256sum <"$fake/.claude/.credentials.json")" "$before" "guest-written credentials do not reach the host"
assert_contains "$AC_ERR" "never copies credentials back" "the refresh is reported instead"
assert_no_file "$(session_dir "$SID")/state/.claude/.credentials.json" "guest credentials are not kept in the session"
fakeenv ac_run true
assert_not_contains "$AC_ERR" "refreshed its login" "no report when the guest left them alone"

step "escape sequences in file names and contents"
new_project escapes
ac_run sh -c '
printf "line1\n\033[1A\033[2Kinnocent\n\033]52;c;cHduZWQ=\007\n" > payload.txt
touch "$(printf "evil\033]0;pwned\007.txt")"
ln -s "$(printf "tgt\033[2J")" link
'
ac show "$SID"
has_esc "$AC_OUT$AC_ERR" && fail "show passes raw escapes through" || pass "show prints no raw escapes"
assert_contains "$AC_ERR" 'evil\x1b]0;pwned\x07.txt' "a hostile file name is shown escaped"
assert_contains "$AC_ERR" 'link -> tgt\x1b[2J' "a hostile symlink target is shown escaped"
ac diff "$SID"
has_esc "$AC_OUT" && pass "diff to a file or pipe keeps the raw bytes" || fail "diff output was altered for a non-terminal"
ac_pty 'expect payload' diff "$SID"
assert_contains "$AC_OUT" '+\x1b[1A\x1b[2Kinnocent' "diff on a terminal shows cursor movement as text"
assert_contains "$AC_OUT" '\x1b]52;c;' "diff on a terminal shows a clipboard write as text"

step "escape sequences in transcripts"
# Claude Code keeps a project's transcripts under its path with every
# non-alphanumeric character replaced by '-'
key=$(printf '%s' "$PWD" | sed 's/[^A-Za-z0-9]/-/g')
cat >transcript.jsonl <<'JSON'
{"type":"user","message":{"content":"hi \u001b]0;owned\u0007 there"},"timestamp":"2026-01-01T00:00:00Z"}
JSON
ac_run sh -c 'd=$HOME/.claude/projects/'"$key"'; mkdir -p $d && cp transcript.jsonl $d/t.jsonl'
ac show "$SID"
has_esc "$AC_OUT" && fail "transcript text reaches the terminal raw" || pass "transcript text is escaped"
assert_contains "$AC_OUT" 'hi \x1b]0;owned\x07 there' "the escaped prompt is still readable"

step "proxy refuses malformed CONNECT targets"
ac_run bash -c '
port=${HTTPS_PROXY##*:}
exec 3<>/dev/tcp/127.0.0.1/$port
printf "CONNECT ev\033il.example:443 HTTP/1.1\r\n\r\n" >&3
head -1 <&3'
assert_contains "$AC_OUT" "400" "a CONNECT target with control characters is rejected"
has_esc "$(cat "$(session_dir "$SID")/net.log")" && fail "net.log holds raw escapes" || pass "net.log is sanitised"
ac show "$SID"
has_esc "$AC_OUT" && fail "show prints a raw escape from net.log" || pass "show prints the bad target escaped"

finish
