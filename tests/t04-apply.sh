#!/bin/bash
# `agentcracker apply` (non-interactive): results on the host, idempotence,
# conflict refusal, and what is never applied.
. "$(dirname "$0")/lib.sh"
require_vm
new_project

step "apply a session"
ac_run sh -c "$AGENT_EDITS"
edits=$SID
ac apply
assert_rc 0 "apply exits 0"
assert_contains "$AC_ERR" "8 written, 2 deleted" "apply reports what it did"
assert_edits_applied
assert_eq "$(meta status "$edits")" "applied" "session status becomes applied"
assert_ne "$(meta applied_at "$edits")" "" "apply time recorded"
ac ls
assert_match "$AC_OUT" "^$edits .* applied " "ls shows the session as applied"
leftovers=$(find . -name '.agentcracker-*' -o -name '*.ac-tmp*' | head -3)
assert_eq "$leftovers" "" "no temporary files left behind"

step "apply again"
ac apply "$edits"
assert_rc 0 "re-applying exits 0"
assert_contains "$AC_ERR" "already on the host; nothing to do" "re-applying is a no-op"
assert_edits_applied

step "conflicts"
new_project conflicts
ac_run sh -c 'echo agent > hello.txt; echo agent > keep.txt; echo agent-new > new.txt'
c=$SID
echo "host edit" >hello.txt
ac apply "$c"
assert_rc 1 "apply refuses when the host changed a file (no tty to ask)"
assert_contains "$AC_ERR" "conflict: changed on the host" "conflict is flagged in the list"
assert_contains "$AC_ERR" "refusing to apply with conflicts" "refusal is explained"
assert_file hello.txt "host edit" "host edit preserved"
assert_file keep.txt "keep me" "nothing else applied either"
assert_no_file new.txt "no new files applied"
ac diff "$c"
assert_contains "$AC_OUT" "# CONFLICT" "diff marks the conflict"
assert_contains "$AC_OUT" "$(printf -- '-host edit\n+agent')" "conflict diff is against the current host file"

step "same edit made on both sides is not a conflict"
echo agent >hello.txt
ac apply "$c"
assert_rc 0 "apply succeeds once the host matches the agent's version"
assert_contains "$AC_ERR" "already on the host" "the matching file is recognised"
assert_file keep.txt "agent" "the rest was applied"
assert_file new.txt "agent-new" "new file applied"

step "deleted host file the agent modified"
new_project vanished
ac_run sh -c 'echo agent > hello.txt'
rm hello.txt
ac apply "$SID"
assert_rc 1 "apply refuses: the file the agent edited is gone on the host"
assert_no_file hello.txt "file not resurrected"

step "never applied"
new_project gitrepo
git init -q . && git add -A && git -c user.name=t -c user.email=t@t commit -qm init
head_before=$(git rev-parse HEAD)
ac_run sh -c 'echo x > .git/agent-was-here; git config user.name agent; echo y > tracked.txt'
ac apply "$SID"
assert_rc 0 "apply exits 0"
assert_no_file .git/agent-was-here "writes inside .git/ are not applied"
assert_eq "$(git config --local user.name || true)" "" "git config edits are not applied"
assert_file tracked.txt "y" "the work tree change is applied"
assert_eq "$(git rev-parse HEAD)" "$head_before" "HEAD unchanged"
assert_contains "$AC_ERR" "inside .git/ were not applied" "apply says .git changes were skipped"

step "apply by id from another directory"
new_project elsewhere
ac_run sh -c 'echo remote > from-elsewhere.txt'
id=$SID
cd "$WORK"
ac apply "$id"
assert_rc 0 "apply by id works from any directory"
assert_file "$WORK/elsewhere/from-elsewhere.txt" "remote" "changes land in the session's own directory"

finish
