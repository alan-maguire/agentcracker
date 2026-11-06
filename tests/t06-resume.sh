#!/bin/bash
# Session save/restore: resume and shell boot again on the same disk, the
# guest $HOME and project overlay persist, agent state is exported, and a
# session survives its host process being killed.
. "$(dirname "$0")/lib.sh"
require_vm
new_project

step "state persists across resume"
ac_run sh -c 'echo one > a.txt; echo run >> runs.txt; echo home-state > $HOME/.ac-marker; mkdir -p $HOME/.cache/ac && echo cached > $HOME/.cache/ac/x'
sid=$SID
ac resume "$sid" sh -c 'cat a.txt; cat $HOME/.ac-marker; cat $HOME/.cache/ac/x'
assert_rc 0 "resume with a command exits 0"
mapfile -t L <<<"$AC_OUT"
assert_eq "${L[0]:-}" "one" "project changes persist"
assert_eq "${L[1]:-}" "home-state" "guest \$HOME persists"
assert_eq "${L[2]:-}" "cached" "nested \$HOME directories persist"
assert_eq "$(meta boots "$sid")" "2" "boot count incremented"
assert_contains "$AC_ERR" "session $sid ·" "resume reuses the session"
assert_eq "$(session_count)" "1" "no new session created"

step "resume without a command reruns the original"
ac resume "$sid"
assert_rc 0 "resume exits 0"
assert_eq "$(meta boots "$sid")" "3" "third boot"
ac resume "$sid" cat runs.txt
assert_eq "$AC_OUT" "$(printf 'run\nrun')" "original command ran twice"

step "changes accumulate across boots"
ac resume "$sid" sh -c 'echo two > b.txt; rm keep.txt'
ac show "$sid"
assert_contains "$AC_ERR" "A a.txt" "first boot's change still listed"
assert_contains "$AC_ERR" "A b.txt" "second boot's change listed"
assert_contains "$AC_ERR" "D keep.txt" "later deletion listed"
ac resume sh -c 'test -e keep.txt && echo present || echo absent'
assert_eq "$AC_OUT" "absent" "resume without an id picks this directory's latest session"

step "apply, then keep working"
ac apply "$sid"
assert_file a.txt "one" "applied after several boots"
assert_no_file keep.txt "deletion applied"
ac resume "$sid" sh -c 'echo three > c.txt'
ac apply "$sid"
assert_rc 0 "second apply exits 0"
assert_file c.txt "three" "post-apply change applied"
assert_contains "$AC_ERR" "already in place" "earlier changes are recognised as applied"

step "shell"
out=$(printf 'cat a.txt\necho in-shell > d.txt\n' | "$AC" shell "$sid" 2>/dev/null)
assert_eq "$out" "one" "shell reads commands from a pipe and sees the session"
ac resume "$sid" cat d.txt
assert_eq "$AC_OUT" "in-shell" "shell changes persist"

step "agent state is exported"
ac_run sh -c 'mkdir -p $HOME/.claude/projects/p && printf "{\"type\":\"user\"}\n" > $HOME/.claude/projects/p/t.jsonl; echo guest > $HOME/.claude/ac-test-file'
st=$(session_dir "$SID")/state/.claude/projects/p/t.jsonl
assert_file "$st" '{"type":"user"}' "~/.claude/projects is copied into the session"
assert_no_file "$HOME/.claude/ac-test-file" "guest writes to ~/.claude do not reach the host"

step "host process killed mid-session"
"$AC" sh -c 'echo before > killed.txt; sync; echo READY; sleep 60' </dev/null >"$WORK/killed.out" 2>"$WORK/killed.err" &
pid=$!
for _ in $(seq 1 100); do grep -q READY "$WORK/killed.out" && break; sleep 0.1; done
grep -q READY "$WORK/killed.out" || fail "session never started"
ksid=$(session_from_output "$(cat "$WORK/killed.err")")
fc=$(pgrep -f "agentcracker-$ksid" | head -1)
kill -KILL "$pid"
wait "$pid" 2>/dev/null
gone=no
for _ in $(seq 1 100); do
    if [ -z "$fc" ] || ! kill -0 "$fc" 2>/dev/null; then gone=yes; break; fi
    sleep 0.1
done
assert_eq "$gone" "yes" "the VM shuts down when its host process dies"
ac ls
assert_match "$AC_OUT" "^$ksid .* stopped " "session shows as stopped"
ac resume "$ksid" cat killed.txt
assert_rc 0 "a killed session can be resumed"
assert_eq "$AC_OUT" "before" "writes made before the kill survive"

step "resume refuses a running session"
"$AC" sh -c 'echo READY; sleep 5' </dev/null >"$WORK/busy.out" 2>"$WORK/busy.err" &
pid=$!
for _ in $(seq 1 100); do grep -q READY "$WORK/busy.out" && break; sleep 0.1; done
bsid=$(session_from_output "$(cat "$WORK/busy.err")")
ac ls
assert_match "$AC_OUT" "^$bsid .* running " "ls shows the session as running"
ac resume "$bsid" true
assert_ne "$AC_RC" "0" "a running session cannot be booted twice"
ac apply "$bsid"
assert_contains "$AC_ERR" "still running" "apply refuses a running session"
kill -TERM "$pid" 2>/dev/null
wait "$pid" 2>/dev/null

step "project directory removed"
new_project doomed
ac_run sh -c 'echo x > y'
dsid=$SID
cd "$WORK" && mv doomed doomed.moved
ac resume "$dsid" true
assert_rc 1 "resume fails when the project directory is gone"
assert_contains "$AC_ERR" "no longer exists" "the reason is given"

finish
