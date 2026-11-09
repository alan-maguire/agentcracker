#!/bin/bash
# Command line handling that needs no VM: usage, errors, empty session store.
. "$(dirname "$0")/lib.sh"

[ -x "$AC" ] || skip_test "$AC is not built (run make)"

step "usage and version"
ac --help
assert_rc 0 "--help exits 0"
assert_contains "$AC_OUT" "usage:" "--help prints usage"
ac
assert_rc 2 "no arguments exits 2"
assert_contains "$AC_ERR" "usage:" "no arguments prints usage to stderr"
ac --version
assert_rc 0 "--version exits 0"
assert_match "$AC_OUT" '^agentcracker [0-9]+\.[0-9]+' "--version prints a version"

step "bad options"
ac --bogus true
assert_rc 1 "unknown option fails"
assert_contains "$AC_ERR" "unknown option --bogus" "unknown option is named"
ac --allow
assert_rc 1 "--allow without a host fails"
ac rm
assert_rc 1 "rm without a session fails"

step "subcommands check their arguments"
ac branch deadbeef extra
assert_rc 1 "an extra argument fails"
assert_contains "$AC_ERR" "branch: unexpected argument extra" "naming the subcommand and the argument"
ac log --bogus
assert_rc 1 "an unknown option fails"
assert_contains "$AC_ERR" "log: unknown option --bogus" "naming the subcommand and the option"

step "every subcommand is documented"
# the names cli::run dispatches to a cmd_ function
cmds=$(sed -n '/^pub fn run(/,/^}/p' "$REPO/src/cli.rs" | grep -E '=> cmd_' | grep -oE '^ +"[a-z][a-z-]*"' | tr -d ' "')
[ -n "$cmds" ] && pass "found the subcommands in cli.rs: $(echo $cmds)" || fail "no subcommands found in cli.rs"
ac --help
undocumented=
for c in $cmds; do
    grep -qE "agentcracker $c( |$)" <<<"$AC_OUT" || undocumented+=" $c(--help)"
    grep -qE "^\.BR? $c( |$)" "$REPO/man/agentcracker.1" || undocumented+=" $c(man)"
    grep -qE "agentcracker $c( |$)" "$REPO/README.md" || undocumented+=" $c(README)"
done
assert_eq "$undocumented" "" "each is in --help, the man page and the README"

step "empty session store"
mkdir -p "$WORK/empty" && cd "$WORK/empty"
ac ls
assert_rc 0 "ls with no sessions exits 0"
assert_contains "$AC_ERR" "no sessions" "ls says there are no sessions"
ac show
assert_rc 1 "show with no sessions fails"
assert_contains "$AC_ERR" "no sessions for" "show explains there is no session here"
ac apply
assert_rc 1 "apply with no sessions fails"
ac diff deadbeef
assert_rc 1 "diff of an unknown id fails"
assert_contains "$AC_ERR" "no session matching" "unknown id is reported"

step "refuses to snapshot home or /"
cd "$HOME" && ac true
assert_rc 1 "running in \$HOME is refused"
assert_contains "$AC_ERR" "refusing to snapshot" "refusal is explained"
cd / && ac true
assert_rc 1 "running in / is refused"
assert_eq "$(latest_session)" "" "no session was created by refused runs"

finish
