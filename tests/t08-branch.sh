#!/bin/bash
# Git: the agent's commits become a host branch (objects verified on import),
# named after the session or by --branch; the host repository is otherwise
# untouched.
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

step "a bisect left unfinished, or an older commit checked out"
echo two > two.txt && git add two.txt && $G commit -qm "two"
echo three > three.txt && git add three.txt && $G commit -qm "three"
ac_pty 'expect \[x\] discard
key a
expect Apply anyway
key n
expect \[x\] discard
key k' sh -c 'git bisect start HEAD HEAD~2 >/dev/null'
assert_rc 0 "session kept"
sid=$(latest_session)
assert_contains "$AC_OUT" "left a git bisect unfinished (HEAD is at $(git rev-parse --short=12 HEAD~1))" \
    "the menu says the agent left a bisect, and where"
assert_contains "$AC_OUT" "three.txt" "(whose work tree lacks three.txt)"
assert_not_contains "$AC_OUT" "The agent committed" "it is not taken for a commit"
assert_not_contains "$AC_OUT" "[b]ranch" "nor offered as a branch"
assert_file three.txt "three" "declining to apply leaves the work tree alone"
ac branch "$sid"
assert_rc 1 "branch refuses it"
assert_contains "$AC_ERR" "nothing to import: the agent left a git bisect unfinished" "and says why"
ac apply "$sid" < /dev/null
assert_ne "$AC_RC" 0 "apply without a terminal refuses it"
assert_file three.txt "three" "the work tree is untouched"
ac show --json "$sid"
assert_contains "$AC_OUT" '"checked_out_back": "the agent left a git bisect' "show --json says so"
ac_run sh -c 'git checkout -q HEAD~2'
ac branch "$SID"
assert_contains "$AC_ERR" "checked out $(git rev-parse --short=12 HEAD~2), an older commit" "a checkout of an older commit too"
ac_run sh -c 'git bisect start HEAD HEAD~2 >/dev/null; git bisect reset >/dev/null 2>&1; git -c user.name=a -c user.email=a@a commit -q --allow-empty -m after'
ac branch "$SID"
assert_rc 0 "a bisect that was reset is no obstacle"
base=$(git rev-parse HEAD)   # this step moved main on

step "--branch: the agent works on a branch of that name"
ac_run --branch feature/x sh -c '
G="git -c user.name=agent -c user.email=agent@example.com"
git symbolic-ref --short HEAD; grep -c "branch .feature/x." ~/.claude/CLAUDE.md
echo one > x.txt && git add x.txt && $G commit -qm "x one"
'
assert_rc 0 "the session runs"
assert_eq "$AC_OUT" "$(printf 'feature/x\n1')" "it starts on the branch, and is told"
sid=$SID
ac show "$sid"
assert_contains "$AC_OUT" "feature/x (the agent's; not imported yet)" "show names it before the import"
ac branch "$sid"
assert_contains "$AC_ERR" "created branch feature/x" "branch imports into it"
assert_eq "$(git log -1 --format=%s feature/x)" "x one" "with the agent's commit"
assert_eq "$(git rev-parse feature/x~1)" "$base" "on top of the session's base"
assert_eq "$(git symbolic-ref --short HEAD)" "main" "the host stays on its branch"
ac resume "$sid" sh -c 'git -c user.name=agent -c user.email=agent@example.com commit -q --allow-empty -m "x two"; git symbolic-ref --short HEAD'
assert_eq "$AC_OUT" "feature/x" "a resumed session is still on it"
ac branch "$sid"
assert_eq "$(git log -1 --format=%s feature/x)" "x two" "a later import fast-forwards it"
ac resume "$sid" sh -c 'git -c user.name=agent -c user.email=agent@example.com commit -q --amend --allow-empty -m "x rewritten"'
ac branch "$sid"
assert_rc 1 "an import that is not a fast-forward is refused"
assert_contains "$AC_ERR" "does not build on" "saying why"
assert_eq "$(git log -1 --format=%s feature/x)" "x two" "and the branch is left as it was"
ac --branch feature/x true
assert_rc 1 "a branch that exists already is refused"
assert_contains "$AC_ERR" "already exists" "naming the problem"
ac --branch 'bad..name' true
assert_rc 1 "an invalid name is refused"
ac resume --branch y "$sid" true
assert_rc 1 "--branch is for new sessions only"

step "the guest gets the user's git identity, and nothing else of their config"
cat >"$WORK/gitconfig" <<'CFG'
[user]
	name = Test \"Q\" User
	email = test@example.com
[sendemail]
	smtppass = SECRET-smtp
[url "https://x:SECRET-token@example.com/"]
	insteadOf = https://example.com/
CFG
GIT_CONFIG_GLOBAL=$WORK/gitconfig ac_run sh -c '
git config --global user.name; git config --global user.email
cat ~/.gitconfig ~/.config/git/config 2>/dev/null
git commit -q --allow-empty -m mine && git log -1 --format="%an <%ae>"'
assert_contains "$AC_OUT" "$(printf 'Test "Q" User\ntest@example.com')" "name and email are there"
assert_not_contains "$AC_OUT" "SECRET" "no other setting is"
assert_contains "$AC_OUT" 'Test "Q" User <test@example.com>' "and the agent's commits are the user's"

step "a hostile .git: only objects are imported, and git checks them"
marker=$WORK/pwned
hooks_before=$(ls .git/hooks | sort | md5sum)
ac_run sh -c "
git -c user.name=a -c user.email=a@a commit -q --allow-empty -m 'with hostile config'
git config core.fsmonitor 'touch $marker.fsmonitor'
git config core.hooksPath /tmp
for h in post-checkout post-merge reference-transaction pre-auto-gc; do
  printf '#!/bin/sh\\ntouch $marker.%s\\n' \$h > .git/hooks/\$h; chmod +x .git/hooks/\$h
done
echo / > .git/objects/info/alternates
echo 'ref: refs/heads/main' > .git/refs/heads/evil
"
ac branch "$SID"
assert_rc 0 "the commit is imported"
assert_eq "$(git log -1 --format=%s "agentcracker/$SID")" "with hostile config" "as the agent made it"
git status >/dev/null 2>&1; git log -1 "agentcracker/$SID" >/dev/null 2>&1
assert_eq "$(ls "$WORK" | grep -c pwned)" "0" "no hook or fsmonitor of the guest's ran on the host"
assert_eq "$(git config --get core.fsmonitor; git config --get core.hooksPath)" "" "its git config is not taken"
assert_eq "$(ls .git/hooks | sort | md5sum)" "$hooks_before" "nor its hooks"
assert_eq "$(cat .git/objects/info/alternates 2>/dev/null)" "" "nor its alternates"
assert_eq "$(git for-each-ref --format=%\(refname\) refs/heads/evil)" "" "nor its refs"
ac_run sh -c '
bad=$(printf "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor nobody\n\nbad\n" | git hash-object -t commit --literally -w --stdin)
git update-ref refs/heads/main $bad'
ac branch "$SID"
assert_rc 1 "a malformed commit is refused"
assert_contains "$AC_ERR" "fsck" "by git's fsck"
assert_eq "$(git for-each-ref --format=%\(refname\) "refs/heads/agentcracker/$SID")" "" "and no branch is made"
git fsck --no-dangling >/dev/null 2>&1 && pass "the repository still passes fsck" || fail "fsck reports problems"

step "not a git repository"
new_project plain
ac_run sh -c 'echo x > y.txt'
ac branch "$SID"
assert_rc 1 "branch fails outside a git repository"

finish
