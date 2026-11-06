#!/bin/bash
# Past sessions: listing, lookup by id prefix and directory, show, removal.
. "$(dirname "$0")/lib.sh"
require_vm
new_project one

step "several sessions in several directories"
ac_run sh -c 'echo 1 > a.txt'
s1=$SID
ac_run sh -c 'exit 3'
s2=$SID
new_project two
ac_run sh -c 'echo 2 > b.txt; echo 2 > c.txt'
s3=$SID
assert_eq "$(session_count)" "3" "three sessions stored"

step "ls"
ac ls
assert_rc 0 "ls exits 0"
assert_match "$AC_OUT" "^ID +AGE +STATUS +CHANGES +DIRECTORY +COMMAND" "ls has a header"
assert_match "$AC_OUT" "^$s1 .* exited +\+1 ~0 -0 .*one +sh -c echo 1 > a.txt" "ls row for the first session"
assert_match "$AC_OUT" "^$s2 .* exit 3 +- " "ls shows a non-zero exit status"
assert_match "$AC_OUT" "^$s3 .* \+2 ~0 -0 .*two " "ls row for the other directory"
order=$(echo "$AC_OUT" | awk 'NR > 1 { print $1 }' | tr '\n' ' ')
assert_eq "$order" "$s1 $s2 $s3 " "ls lists oldest first"

step "lookup"
cd "$WORK/one"
ac show
assert_contains "$AC_OUT" "session    $s2" "no id: latest session for this directory"
cd "$WORK/two"
ac show
assert_contains "$AC_OUT" "session    $s3" "no id: follows the current directory"
ac show "${s1:0:4}"
assert_contains "$AC_OUT" "session    $s1" "a unique id prefix works from anywhere"
ac show "$s1"
assert_contains "$AC_OUT" "command    sh -c echo 1 > a.txt" "show has the command"
assert_contains "$AC_OUT" "directory  " "show has the directory"
assert_match "$AC_OUT" "status +exited · 1 boot\(s\) · ran [0-9]+s" "show has status, boots and run time"
assert_match "$AC_OUT" "vm +[0-9]+ vCPU · [0-9.]+[GM] · net allowlist: " "show has the VM shape and network policy"
assert_match "$AC_OUT" "disk +[0-9.]+[KMG]" "show has disk usage"
ac show "$s2"
assert_contains "$AC_OUT" "exit 3" "show has a non-zero exit status"
for f in meta.json manifest.bin lower.img scratch.img changes.stream console.log; do
    [ -e "$(session_dir "$s1")/$f" ] && pass "session keeps $f" || fail "session is missing $f"
done
ac show nosuch
assert_rc 1 "an unknown session id fails"

step "session disk usage stays small"
kib=$(du -sk "$(session_dir "$s1")" | cut -f1)
info "session directory: ${kib}K on disk"
assert_le "$kib" "102400" "a small session uses under 100M on disk"

step "the project snapshot is shared, not copied"
lower=$(session_dir "$s1")/lower.img
assert_ne "$(stat -c %h "$lower")" "1" "lower.img is a hardlink into the cache"

step "rm"
ac rm "$s1" "${s2:0:5}"
assert_rc 0 "rm exits 0"
assert_contains "$AC_OUT" "removed $s1" "rm reports each session"
assert_contains "$AC_OUT" "removed $s2" "rm accepts prefixes"
session_exists "$s1" && fail "$s1 still on disk" || pass "removed session's files are gone"
assert_eq "$(session_count)" "1" "one session left"
ac rm "$s1"
assert_rc 1 "removing a removed session fails"
assert_file "$WORK/two/hello.txt" "hello" "rm never touches the project"

finish
