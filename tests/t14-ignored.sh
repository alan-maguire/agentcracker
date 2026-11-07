#!/bin/bash
# Changes git ignores (build output): hidden from the review, counted, and
# not applied unless asked for - by the host's ignore rules, never the
# guest's.
. "$(dirname "$0")/lib.sh"
require_vm
require_cmd git

# a git project with a kernel-like .gitignore, a tracked file that matches
# it, and an ignored file that exists on the host
ignored_project() {
    new_project "$1"
    printf '*.o\nbuild/\n.*\n!.gitignore\n' >.gitignore
    echo old >tracked.o
    echo CONFIG_OLD=y >.config
    git init -q && git add -f .gitignore tracked.o hello.txt &&
        git -c user.name=t -c user.email=t@t commit -qm init || die "git setup"
}

EDITS='
echo code > main.c
echo obj > main.o
mkdir -p build/sub && echo out > build/sub/out
echo new > tracked.o
echo CONFIG_NEW=y > .config
echo "export X=1" > .envrc
echo "*.c" >> .gitignore
echo c > hidden.c
'

step "ignored changes are hidden and counted"
ignored_project ig
ac_run sh -c "$EDITS"
assert_rc 0 "the session ran"
assert_contains "$AC_ERR" "4 files changed: 2 modified, 2 added (+4 ignored by git)" "the summary counts what git ignores separately"
assert_eq "$(meta summary | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["ignored"])')" "4" "and records it"
ac show "$SID"
assert_contains "$AC_OUT$AC_ERR" "A main.c" "new source files are listed"
assert_contains "$AC_OUT$AC_ERR" "M tracked.o" "tracked files are never ignored"
assert_contains "$AC_OUT$AC_ERR" "A hidden.c" "the agent's own .gitignore edits hide nothing"
assert_not_contains "$AC_OUT$AC_ERR" "A main.o" "build output is not listed"
assert_not_contains "$AC_OUT$AC_ERR" "A build/" "nor ignored directories"

step "diff"
ac diff "$SID"
assert_contains "$AC_OUT" "b/main.c" "diff shows the reviewed changes"
assert_not_contains "$AC_OUT" "main.o" "but not ignored ones"
assert_contains "$AC_ERR" "4 more file(s) git ignores are left out" "and says what it left out"
ac diff --ignored "$SID"
assert_contains "$AC_OUT" "b/main.o" "--ignored includes them"
assert_contains "$AC_OUT" "b/build/sub/out" "...in ignored directories too"

step "apply"
ac apply "$SID"
assert_rc 0 "apply exits 0"
assert_contains "$AC_ERR" "4 written" "only the reviewed changes are written"
assert_file main.c "code" "a reviewed change is applied"
assert_no_file main.o "build output is not applied"
assert_no_file build "nor ignored directories"
assert_no_file .envrc "nor ignored dotfiles"
assert_file .config "CONFIG_OLD=y" "an ignored file on the host is left alone"
ac apply --ignored "$SID"
assert_rc 0 "apply --ignored exits 0"
assert_file main.o "obj" "--ignored applies build output"
assert_file build/sub/out "out" "...and ignored directories"
assert_file .config "CONFIG_NEW=y" "...and ignored files"

step "the review's [i] toggle"
ignored_project ig-review
ac_pty 'expect \[i\]gnored
key i
expect including 4 file\(s\) git ignores
key a
expect Keep the session\?
key n' sh -c "$EDITS"
assert_contains "$AC_OUT" "4 more file(s) git ignores (build output) are hidden" "the review says what it hides"
assert_file build/sub/out "out" "ignored changes are applied once included"
assert_file main.c "code" "...with the rest"

step "outside a git work tree nothing is ignored"
new_project plain
printf '*.o\n' >.gitignore
# (the test's work directory is itself inside a git checkout)
GIT_CEILING_DIRECTORIES=$WORK ac_run sh -c 'echo obj > main.o'
assert_contains "$AC_ERR" "1 file changed: 1 added" "a .gitignore without git hides nothing"
assert_not_contains "$AC_ERR" "ignored by git" "and nothing is counted as ignored"

step "a project its enclosing repository ignores"
# (like a home directory under git that ignores everything)
outer=$WORK/outer
mkdir -p "$outer" && (cd "$outer" && git init -q && printf '*\n' >.gitignore) || die "outer repo"
mkdir -p "$outer/proj" && cd "$outer/proj" && echo hi >f
GIT_CEILING_DIRECTORIES=$WORK ac_run sh -c 'echo new > g'
assert_contains "$AC_ERR" "1 file changed: 1 added" "the enclosing repository's rules hide nothing"

finish
