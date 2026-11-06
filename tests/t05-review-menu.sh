#!/bin/bash
# The interactive review after a session ends (needs a terminal, so these
# run under tests/pty.py): apply, keep, discard, diff, shell, and resolving
# conflicts interactively.
. "$(dirname "$0")/lib.sh"
require_vm

MENU='\[x\] discard'

step "[a]pply, then drop the session"
new_project apply
ac_pty "expect $MENU
key a
expect Keep the session\?
key n" sh -c "$AGENT_EDITS"
assert_rc 0 "session exits 0"
assert_contains "$AC_OUT" "[d]iff [a]pply [s]hell [K]eep for later (not applied) [x] discard" "menu offers the expected choices"
assert_contains "$AC_OUT" "8 written, 2 deleted" "apply reported"
assert_edits_applied
sid=$(session_from_output "$AC_OUT")
assert_contains "$AC_OUT" "session $sid discarded" "session dropped after applying"
session_exists "$sid" && fail "session directory still exists" || pass "session directory removed"

step "[a]pply and keep the session"
new_project apply-keep
ac_pty "expect $MENU
key a
expect Keep the session\?
key y" sh -c 'echo kept > kept.txt'
sid=$(session_from_output "$AC_OUT")
assert_file kept.txt "kept" "change applied"
session_exists "$sid" && pass "session kept after applying" || fail "session was removed"
assert_eq "$(meta status "$sid")" "applied" "kept session is marked applied"

step "[K]eep for later"
new_project keep
ac_pty "expect $MENU
key k" sh -c "$AGENT_EDITS"
sid=$(session_from_output "$AC_OUT")
assert_contains "$AC_OUT" "kept session $sid, changes NOT applied" "keep says nothing was applied"
assert_edits_not_applied
session_exists "$sid" && pass "kept session exists" || fail "kept session missing"
ac apply "$sid"
assert_rc 0 "a kept session can be applied later"
assert_edits_applied

step "Enter keeps"
new_project enter
ac_pty "expect $MENU
key " sh -c 'echo x > enter.txt'
sid=$(session_from_output "$AC_OUT")
assert_contains "$AC_OUT" "kept session $sid" "Enter defaults to keep"
assert_no_file enter.txt "nothing applied"

step "[x] discard"
new_project discard
ac_pty "expect $MENU
key x
expect Discard unapplied changes\?
key n
expect $MENU
key x
expect Discard unapplied changes\?
key y" sh -c "$AGENT_EDITS"
sid=$(session_from_output "$AC_OUT")
assert_contains "$AC_OUT" "session $sid discarded" "discard confirmed"
assert_edits_not_applied
session_exists "$sid" && fail "discarded session still exists" || pass "discarded session removed"

step "[d]iff, then keep"
new_project diff
ac_pty "expect $MENU
key d
expect $MENU
key k" sh -c 'echo changed > hello.txt'
assert_contains "$AC_OUT" "+changed" "diff shown from the menu (PAGER=cat)"
assert_contains "$AC_OUT" "kept session" "menu returns after the diff"

step "[s]hell into the session, then apply"
new_project shell
export SHELL=/bin/sh
ac_pty "expect $MENU
key s
expect entering the session
sleep 1
send echo from-shell > shell.txt; echo SHELL-\$((6*7))\\r
expect SHELL-42
send exit\\r
expect $MENU
key a
expect Keep the session\?
key n" sh -c 'echo first > first.txt'
assert_contains "$AC_OUT" "SHELL-42" "shell runs inside the session"
assert_file first.txt "first" "the command's change applied"
assert_file shell.txt "from-shell" "the shell's change applied too"

step "interactive conflict resolution"
new_project conflict
ac_run sh -c 'echo agent > hello.txt; echo agent > keep.txt'
c=$SID
echo "host edit" >hello.txt
ac_pty 'expect \[c\]ancel\?
key c' apply "$c"
assert_file keep.txt "keep me" "[c]ancel applies nothing"
ac_pty 'expect \[c\]ancel\?
key s' apply "$c"
assert_contains "$AC_OUT" "1 skipped" "[s]kip reports the skipped file"
assert_file hello.txt "host edit" "[s]kip keeps the host's version"
assert_file keep.txt "agent" "[s]kip applies the rest"
# the skip above marked the session applied, so apply first asks to go again
ac_pty 'expect Apply again\?
key y
expect \[c\]ancel\?
key o' apply "$c"
assert_file hello.txt "agent" "[o]verwrite takes the agent's version"

step "terminal control"
new_project tty
ac_pty "expect READY
send \\x03
expect $MENU
key x" sh -c 'echo READY; sleep 30; echo NOT-INTERRUPTED'
assert_not_contains "$AC_OUT" "NOT-INTERRUPTED" "Ctrl-C reaches the guest command"
session_exists "$(session_from_output "$AC_OUT")" && fail "session still exists" || pass "session discarded from the menu"

finish
