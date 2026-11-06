#!/bin/bash
# Driving agentcracker from scripts and orchestrators: background sessions,
# wait, stop, JSON output, and extra shells in a running session.
. "$(dirname "$0")/lib.sh"
require_vm
new_project

json() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

step "--detach"
t0=$(date +%s.%N)
id=$("$AC" --detach sh -c 'echo to-out; echo to-err >&2; echo work > out.txt; sleep 2; exit 4' </dev/null)
t=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.2f", b - a }')
assert_match "$id" '^[0-9a-f]{8}$' "--detach prints the session id"
assert_le "$t" 1.5 "--detach returns without waiting for the session (${t}s)"
ac ls
assert_match "$AC_OUT" "^$id .* running " "the session shows as running at once"
ac rm "$id"
assert_rc 1 "a running session cannot be removed"
assert_no_file out.txt "nothing reaches the host while it runs"

step "wait"
ac wait "$id"
assert_rc 4 "wait returns the command's exit status"
assert_eq "$AC_OUT" "$id exit 4" "wait reports the outcome"
d=$(session_dir "$id")
assert_file "$d/stdout" "to-out" "the command's stdout is kept in the session"
assert_contains "$(cat "$d/stderr")" "to-err" "its stderr too"
assert_contains "$(cat "$d/stderr")" "1 file changed: 1 added" "with agentcracker's summary"
ac show "$id"
assert_contains "$AC_ERR" "A out.txt" "the changes are recorded as usual"
ac wait "$id"
assert_rc 4 "waiting for a finished session returns at once"

step "wait for several"
a=$("$AC" --detach sh -c 'sleep 1' </dev/null)
b=$("$AC" --detach sh -c 'sleep 2; exit 1' </dev/null)
ac wait "$a" "$b"
assert_rc 1 "several: non-zero when any failed"
assert_eq "$(echo "$AC_OUT" | head -1)" "$a exit 0" "sessions are reported as they finish"
assert_eq "$(echo "$AC_OUT" | tail -1)" "$b exit 1" "...in order of finishing"

step "stop"
id=$("$AC" --detach sh -c 'echo before > s.txt; trap "echo got-term; exit 9" TERM; sleep 60 & wait' </dev/null)
sleep 1.5
t0=$(date +%s.%N)
ac stop "$id"
t=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.2f", b - a }')
assert_rc 0 "stop exits 0"
assert_contains "$AC_OUT" "stopped $id" "stop reports it"
assert_le "$t" 5 "the command got SIGTERM and the session ended (${t}s)"
assert_eq "$(meta exit_code "$id")" "9" "the command saw SIGTERM"
assert_contains "$(cat "$(session_dir "$id")/stdout")" "got-term" "and could clean up"
ac show "$id"
assert_contains "$AC_ERR" "A s.txt" "a stopped session keeps its changes"
id=$("$AC" --detach sh -c 'trap "" TERM; sleep 60' </dev/null)
sleep 1.5
ac stop "$id"
assert_rc 0 "a command ignoring SIGTERM is killed after the grace period"
ac stop "$id"
assert_contains "$AC_OUT" "is not running" "stopping a finished session says so"

step "--json"
id=$("$AC" --detach --json sh -c 'echo x > j.txt; ln -s /etc/passwd jl' </dev/null | json 'd["id"]')
ac wait --json "$id"
assert_eq "$(echo "$AC_OUT" | json 'd["format"], d["id"] == "'"$id"'", d["status"], d["exit_code"], d["running"]')" "1 True exited 0 False" "wait --json"
ac show --json "$id"
assert_eq "$(echo "$AC_OUT" | json 'sorted((f["path"], f["status"], f["type"]) for f in d["changes"]["files"])')" \
    "[('j.txt', 'added', 'file'), ('jl', 'added', 'symlink')]" "show --json lists the changes"
assert_eq "$(echo "$AC_OUT" | json '[f.get("points_outside") for f in d["changes"]["files"] if f["path"] == "jl"]')" "[True]" "...with the review flags"
# fields may be added within a format, never removed: check they are all there
assert_eq "$(echo "$AC_OUT" | json 'sorted(set(["agent", "applied_at", "boots", "changes", "command", "created", "dir", "disk", "ended", "error", "exit_code", "format", "git", "id", "network", "paths", "running", "runtime_secs", "status", "transcripts", "vm"]) - set(d))')" \
    "[]" "show --json has the documented fields"
ac ls --json
assert_eq "$(echo "$AC_OUT" | json 'any(s["id"] == "'"$id"'" for s in d)')" "True" "ls --json lists sessions"
# stdout is a pipe whose reader is already gone (`| head` would race:
# small output fits in the pipe before head exits)
rc=$(python3 -I -c 'import os, subprocess, sys
r, w = os.pipe(); os.close(r)
print(subprocess.run([sys.argv[1], "ls"], stdout=w, stderr=subprocess.DEVNULL).returncode)' "$AC")
assert_eq "$rc" "141" "a closed stdout ends the output quietly"

step "a shell in a running session"
export SHELL=/bin/sh
id=$("$AC" --detach sh -c 'echo agent > agent.txt; sleep 8' </dev/null)
out=$(printf 'cat agent.txt; echo from-shell > shell.txt; echo "in $AGENTCRACKER_SESSION"; exit 3\n' | "$AC" shell "$id" 2>/dev/null)
rc=$?
assert_eq "$out" "$(printf 'agent\nin %s' "$id")" "the shell sees the agent's work in the same VM"
assert_eq "$rc" "3" "the shell's exit status is returned"
ac_pty 'sleep 1
send echo TTY-$((6*7)); stty size\r
expect TTY-42
send exit\r' shell "$id"
assert_contains "$AC_OUT" "40 120" "on a terminal it gets a terminal of its own"
ac ls
assert_match "$AC_OUT" "^$id .* running " "leaving the shell leaves the session running"
ac wait "$id"
ac show "$id"
assert_contains "$AC_ERR" "A shell.txt" "the shell's changes are part of the session"

finish
