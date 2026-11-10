#!/bin/bash
# A hostile guest: it must not be able to plant credentials on the host,
# drive the user's terminal through anything agentcracker prints, fill
# the host's disk, or find much of the host if it escaped into Firecracker.
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

step "registry credentials stay out of the toolchain snapshot"
mkdir -p "$fake/.cargo/bin"
printf '#!/bin/sh\necho tool-ok\n' >"$fake/.cargo/bin/mytool" && chmod +x "$fake/.cargo/bin/mytool"
printf '[registry]\ntoken = "SECRET"\n' >"$fake/.cargo/credentials.toml"
HOME=$fake XDG_CACHE_HOME=$WORK/cache PATH=$fake/.cargo/bin:/usr/bin:/bin ac_run sh -c 'mytool; test -e $HOME/.cargo/credentials.toml && echo CREDS-VISIBLE || echo creds-hidden'
assert_contains "$AC_OUT" "tool-ok" "the toolchain itself is available"
assert_contains "$AC_OUT" "creds-hidden" "cargo's credentials.toml is not in the guest"

step "secrets in the project's git config"
new_project gitcreds
git init -q . && git remote add origin https://someone:ghp_SECRET123@github.com/o/r.git
git config http.https://github.com/.extraheader "AUTHORIZATION: basic SECRET456"
host_cfg=$(cat .git/config)
ac_run sh -c 'cat .git/config; git remote get-url origin'
assert_not_contains "$AC_OUT" "SECRET" "no token from .git/config reaches the guest"
assert_contains "$AC_OUT" "https://github.com/o/r.git" "the remote itself is still there"
assert_eq "$(cat .git/config)" "$host_cfg" "the host's .git/config is untouched"
echo changed >hello.txt
ac_run sh -c 'cat .git/config'
assert_not_contains "$AC_OUT" "SECRET" "still scrubbed in a delta snapshot"

step "warning about credential-like files"
new_project credfiles
echo "API_KEY=x" >.env; echo x >.env.example; mkdir -p certs && echo x >certs/server.key
ac_run true
assert_contains "$AC_ERR" "warning: the agent can read files that look like credentials" "a warning is printed"
assert_contains "$AC_ERR" ".env" "the dotenv file is named"
assert_contains "$AC_ERR" "certs/server.key" "the private key is named"
assert_not_contains "$AC_ERR" ".env.example" "example files are not"
new_project nocreds
ac_run true
assert_not_contains "$AC_ERR" "look like credentials" "no warning for a project without such files"

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

step "the guest cannot fill the host's disk"
# (a free-space floor no disk meets, so the guard trips at its first check)
export AGENTCRACKER_MIN_FREE=$((1 << 62))
ac_run sh -c 'yes | head -c 100M; echo done >&2'
assert_contains "$AC_ERR" "the rest of the command's output is dropped" "output to a file stops"
[ "$(stat -c %s "$WORK/last.out")" -lt $((100 << 20)) ] && pass "short of all 100M" || fail "all of the output was written"
ac_run sh -c 'head -c 100M /dev/urandom > big'
assert_contains "$AC_ERR" "stopped receiving the session's changes" "a change stream stops too"
assert_no_file "$(session_dir "$SID")/changes.stream.tmp" "and what was received is removed"
unset AGENTCRACKER_MIN_FREE
ac resume "$SID" true
assert_contains "$AC_ERR" "1 file changed: 1 added" "resumed with room, the session's changes come through"
export AGENTCRACKER_MIN_FREE_SESSION=$((1 << 62))
ac_run true
assert_rc 1 "a session does not start on a nearly full disk"
assert_contains "$AC_ERR" "free on the disk holding sessions" "saying why"
unset AGENTCRACKER_MIN_FREE_SESSION
# (stopping a running session that gets there: a unit test, vm.rs)

step "the proxy bounds what a guest can make the host hold"
ac_run bash -c '
port=${HTTPS_PROXY##*:}
exec 3<>/dev/tcp/127.0.0.1/$port
head -c 1000000 /dev/zero | tr "\0" A >&3
timeout 5 head -c 12 <&3; echo
for i in $(seq 200); do exec {fd}<>/dev/tcp/127.0.0.1/$port || break; done
sleep 1'
assert_contains "$AC_OUT" "HTTP/1.1 400" "a request line without an end is refused"
assert_contains "$(cat "$(session_dir "$SID")/net.log")" "DENY(too many)" "connections beyond the limit are refused"

step "Firecracker runs in a sandbox of its own"
if ! unshare --user --map-current-user --mount true 2>/dev/null; then
    # this host refuses unprivileged user namespaces: Firecracker runs
    # without them, says so, and keeps its limits
    ac_run true
    assert_contains "$AC_ERR" "running Firecracker without its sandbox" "without user namespaces, the user is told"
    sandbox=0
else
    sandbox=1
fi
id=$("$AC" --detach sh -c 'sleep 30' </dev/null)
pid=
for _ in $(seq 100); do
    pid=$(pgrep -f -- "--id agentcracker-$id" | head -1)
    [ -n "$pid" ] && break   # (the command line is Firecracker's only after exec)
    sleep 0.1
done
[ -n "$pid" ] || die "no firecracker process for $id"
root=/proc/$pid/root
if [ "$sandbox" = 1 ]; then
    assert_ne "$(readlink /proc/$pid/ns/user)" "$(readlink /proc/self/ns/user)" "in a user namespace of its own"
    assert_ne "$(readlink /proc/$pid/ns/net)" "$(readlink /proc/self/ns/net)" "with no network"
    [ -e "$root$PWD" ] && fail "the project is visible to Firecracker" || pass "the project is not visible"
    # only what is mounted there, the directories on the way to it, and the
    # /lib links into /usr
    mounts=$(awk '{print $5}' /proc/$pid/mountinfo)
    extra=
    for d in / "$HOME/"; do
        for e in $(ls -A "$root$d"); do
            [ -L "$root$d$e" ] || grep -q "^$d$e\(/\|\$\)" <<<"$mounts" || extra+="$d$e "
        done
    done
    assert_eq "$extra" "" "nothing else of the host's tree is visible"
    [ -c "$root/dev/kvm" ] && pass "/dev/kvm is there" || fail "/dev/kvm is missing"
    assert_match "$(grep ' ro[ ,]' /proc/$pid/mountinfo)" "$(session_dir "$id")/lower.img" "the project snapshot is read-only"
    assert_match "$(grep -E ' rw[ ,]' /proc/$pid/mountinfo)" "$(session_dir "$id")/scratch.img" "the scratch disk is writable"
fi
assert_match "$(grep '^Max core file size' /proc/$pid/limits)" ' 0 +0 ' "no core dumps"
assert_match "$(grep NoNewPrivs /proc/$pid/status)" '1$' "no_new_privs is set"
"$AC" stop "$id" >/dev/null 2>&1

step "Firecracker never runs without its seccomp filter"
# an install with every asset but the filter: a gnu Firecracker would
# otherwise run with an allow-all filter
t=$(uname -m)-unknown-linux-gnu
fc=$REPO/firecracker/build/cargo_target/$t/release/firecracker
init=$REPO/build/acinit-target/$t/release/agentcracker
kern=$(ls "$REPO"/build/vmlinux-* 2>/dev/null | tail -1)
if [ -x "$fc" ] && [ -x "$init" ] && [ -n "$kern" ]; then
    mkdir -p "$WORK/inst/bin" "$WORK/inst/lib/agentcracker"
    cp "$AC" "$WORK/inst/bin/agentcracker"
    ln -s "$fc" "$WORK/inst/lib/agentcracker/firecracker"
    ln -s "$init" "$WORK/inst/lib/agentcracker/acinit"
    ln -s "$kern" "$WORK/inst/lib/agentcracker/vmlinux"
    "$WORK/inst/bin/agentcracker" true </dev/null >"$WORK/last.out" 2>"$WORK/last.err"
    assert_ne "$?" "0" "a session does not start"
    assert_contains "$(cat "$WORK/last.err")" "cannot find seccomp.bpf" "saying the filter is missing"
else
    info "(skipped: needs the build tree)"
fi

finish
