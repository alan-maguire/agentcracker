#!/bin/bash
# Change tracking: what the agent did is captured, summarised, listed and
# diffed - and nothing reaches the host until it is applied.
. "$(dirname "$0")/lib.sh"
require_vm
new_project

step "a session with a representative set of edits"
ac_run sh -c "$AGENT_EDITS"
assert_rc 0 "agent edits ran"
assert_contains "$AC_ERR" "$EDITS_SUMMARY" "exit summary counts the changes"
assert_edits_not_applied

step "show"
ac show "$SID"
assert_rc 0 "show exits 0"
assert_contains "$AC_OUT" "changes    $EDITS_SUMMARY" "show has the summary"
for line in "${EDITS_EXPECT[@]}"; do
    assert_contains "$AC_ERR" "  $line" "show lists: $line"
done
assert_not_contains "$AC_ERR" "src/main.rs" "a file touched but not changed is not listed"
ac show
assert_contains "$AC_OUT" "session    $SID" "show without an id picks this directory's latest session"

step "ls"
ac ls
assert_match "$AC_OUT" "^$SID +[0-9]+[smhd] +exited +\+5 ~3 -2 " "ls row has status and change counts"

step "diff"
ac diff "$SID"
assert_rc 0 "diff exits 0"
d=$AC_OUT
assert_contains "$d" "$(printf -- '-hello\n+changed')" "diff shows a modified file"
assert_contains "$d" "$(printf -- '--- a/added.txt\n+++ b/added.txt')" "diff shows an added file"
assert_contains "$d" "$(printf -- '-delete me')" "diff shows a deleted file's content"
assert_contains "$d" "deleted directory docs/old/ (2 entries)" "diff summarises a deleted directory"
assert_contains "$d" "$(printf 'old mode 644\nnew mode 600')" "diff shows a mode change"
assert_contains "$d" "+symlink -> hello.txt" "diff shows a symlink"
assert_contains "$d" "$(printf ' one\n-two\n+TWO\n three')" "diff has context lines"
assert_contains "$d" "diff agentcracker a/suid b/suid
new file mode 755" "diff shows the setuid file without the setuid bit"

step "no changes"
ac_run sh -c 'cat hello.txt >/dev/null; touch keep.txt'
assert_contains "$AC_ERR" "no changes" "a read-only session reports no changes"
ac diff "$SID"
assert_rc 0 "diff of an unchanged session exits 0"
assert_contains "$AC_ERR" "no changes" "diff says there are no changes"
ac apply "$SID"
assert_contains "$AC_ERR" "no changes to apply" "apply says there is nothing to apply"

step "host edits between sessions (delta snapshot layer)"
# a delta is only used when a small part of the tree changed
mkdir -p filler && for i in $(seq 1 60); do echo "$i" >"filler/$i.txt"; done
ac_run true
echo "host edit" >hello.txt
rm keep.txt
rm -r docs
mkdir -p brand/new && echo fresh >brand/new/file.txt
chmod 700 run.sh
ac_run sh -c 'cat hello.txt; test -e keep.txt && echo keep-present; test -e docs && echo docs-present; cat brand/new/file.txt; stat -c %a run.sh'
assert_eq "$AC_OUT" "$(printf 'host edit\nfresh\n700')" "a new session sees edits, deletions and new files made since the last one"
[ -e "$(session_dir "$SID")/lower-delta.img" ] && pass "small host changes use a delta layer" || fail "no delta layer for a small change"
ac show "$SID"
assert_contains "$AC_OUT" "no changes" "the delta is not mistaken for agent changes"

step "excluded paths"
mkdir -p node_modules/pkg && echo dep >node_modules/pkg/index.js
set_config 'exclude = ["node_modules", "/secret.txt"]'
echo top-secret >secret.txt
ac_run sh -c 'test -e node_modules && echo nm-visible; test -e secret.txt && echo secret-visible; echo x > visible.txt'
assert_not_contains "$AC_OUT" "nm-visible" "excluded directory is not in the guest"
assert_not_contains "$AC_OUT" "secret-visible" "anchored exclude hides a top-level file"
set_config

finish
