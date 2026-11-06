#!/bin/bash
# Git: the agent's commits become a host branch (objects verified on import);
# the host repository is otherwise untouched.
. "$(dirname "$0")/lib.sh"
require_vm
require_cmd git
new_project
G="git -c user.name=test -c user.email=test@example.com"
git init -q -b main . && git add -A && $G commit -qm "initial"
base=$(git rev-parse HEAD)

step "agent commits"
ac_run sh -c '
G="git -c user.name=agent -c user.email=agent@example.com"
echo feature > feature.txt && git add feature.txt && $G commit -qm "add feature"
echo more >> feature.txt && $G commit -qam "extend feature"
'
assert_rc 0 "agent committed inside the VM"
assert_eq "$(git rev-parse HEAD)" "$base" "host HEAD unchanged"
assert_no_file feature.txt "work tree unchanged"
ac show "$SID"
assert_contains "$AC_OUT" "(+" "show counts changes inside .git/"

step "branch"
ac branch "$SID"
assert_rc 0 "branch exits 0"
b="agentcracker/$SID"
assert_contains "$AC_ERR" "created branch $b" "branch is named after the session"
assert_eq "$(git rev-list --count "$base..$b")" "2" "both commits imported"
assert_eq "$(git log -1 --format=%s "$b")" "extend feature" "commit messages kept"
assert_eq "$(git log -1 --format=%an "$b")" "agent" "commit authors kept"
assert_eq "$(git show "$b:feature.txt")" "$(printf 'feature\nmore')" "commit contents imported"
assert_eq "$(git rev-parse HEAD)" "$base" "HEAD still unchanged"
assert_eq "$(git symbolic-ref --short HEAD)" "main" "still on the original branch"
assert_eq "$(git status --porcelain)" "" "work tree still clean"
git fsck --no-dangling >/dev/null 2>&1 && pass "repository passes fsck" || fail "fsck reports problems"
assert_eq "$(meta branch "$SID")" "$b" "branch recorded in the session"
ac show "$SID"
assert_contains "$AC_OUT" "branch     $b" "show lists the branch"

step "the review menu offers [b]ranch only with commits"
ac_pty 'expect \[x\] discard
key k' sh -c 'git -c user.name=a -c user.email=a@a commit -q --allow-empty -m empty'
assert_rc 0 "session with a commit kept"
assert_contains "$AC_OUT" "The agent committed" "menu mentions the agent's commit"
assert_contains "$AC_OUT" "[b]ranch" "menu offers [b]ranch"
ac_pty 'expect \[x\] discard
key x
expect Discard unapplied changes
key y' sh -c 'echo x > untracked.txt'
assert_rc 0 "session without commits discarded"
assert_not_contains "$AC_OUT" "[b]ranch" "no [b]ranch without commits"

step "branch without commits"
ac_run sh -c 'echo x > y.txt'
ac branch "$SID"
assert_rc 1 "branch fails when the agent made no commits"

step "not a git repository"
new_project plain
ac_run sh -c 'echo x > y.txt'
ac branch "$SID"
assert_rc 1 "branch fails outside a git repository"

finish
