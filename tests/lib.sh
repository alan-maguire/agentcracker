# Common library for agentcracker tests.  Source it from a test script:
#
#   . "$(dirname "$0")/lib.sh"
#   require_vm
#   new_project
#   ac_run sh -c 'echo hi > f'
#   assert_no_file f "not applied yet"
#   finish
#
# Environment:
#   AGENTCRACKER     binary under test (default: the in-tree target/release build;
#                    its assets - firecracker, kernel, acinit - are found
#                    relative to it, so in-tree builds test in-tree assets)
#   AC_TEST_DIR      where per-test work dirs go (default:
#                    ~/.cache/agentcracker-tests: outside the repository, which
#                    sessions snapshot, and on the same filesystem as
#                    ~/.cache so snapshots hardlink)
#   AC_KEEP=1        keep work dirs and sessions even when the test passes
#   AC_TEST_CONFIG   a config.toml every test starts from (and set_config
#                    adds to), e.g. CI's exclude_usr to keep the /usr
#                    snapshot small; tests otherwise see no user config
#   AC_VERBOSE=1     echo every agentcracker invocation and its output
#
# Isolation: each test gets its own XDG_STATE_HOME and XDG_CONFIG_HOME, so it
# sees only its own sessions and no user config.  XDG_CACHE_HOME is shared on
# purpose: the /usr snapshot takes ~30s to build and is identical for all tests.
#
# Exit status: 0 pass, 1 fail, 77 skip (automake convention).

set -u
set -o pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(dirname "$TESTS_DIR")
AC=${AGENTCRACKER:-$REPO/target/release/agentcracker}
TEST_NAME=$(basename "$0" .sh)
REAL_HOME=$HOME

_PASS=0
_FAIL=0
_FAILED=()

if [ -t 1 ]; then
    _G=$'\e[32m' _R=$'\e[31m' _Y=$'\e[33m' _D=$'\e[2m' _B=$'\e[1m' _Z=$'\e[0m'
else
    _G= _R= _Y= _D= _B= _Z=
fi

# --- logging ------------------------------------------------------------------

log()   { printf '%s[%s]%s %s\n' "$_D" "$TEST_NAME" "$_Z" "$*"; }
info()  { log "$*"; }
debug() { [ "${AC_VERBOSE:-0}" = 1 ] && log "${_D}$*${_Z}"; return 0; }
step()  { printf '%s[%s]%s %s== %s%s\n' "$_D" "$TEST_NAME" "$_Z" "$_B" "$*" "$_Z"; }

pass() {
    _PASS=$((_PASS + 1))
    printf '%s[%s]%s %sPASS%s %s\n' "$_D" "$TEST_NAME" "$_Z" "$_G" "$_Z" "$*"
}

fail() {
    _FAIL=$((_FAIL + 1))
    _FAILED+=("$*")
    printf '%s[%s]%s %sFAIL%s %s\n' "$_D" "$TEST_NAME" "$_Z" "$_R" "$_Z" "$*"
}

# Show the last agentcracker invocation's output (for failure context).
show_last() {
    [ -n "${AC_OUT:-}" ] && printf '%s    stdout: %s%s\n' "$_D" "$(head -c 2000 "$WORK/last.out" | sed '2,$s/^/            /')" "$_Z"
    [ -s "$WORK/last.err" ] && printf '%s    stderr: %s%s\n' "$_D" "$(head -c 2000 "$WORK/last.err" | sed '2,$s/^/            /')" "$_Z"
    return 0
}

# Skip the whole test (exit 77).
skip_test() {
    printf '%s[%s]%s %sSKIP%s %s\n' "$_D" "$TEST_NAME" "$_Z" "$_Y" "$_Z" "$*"
    _SKIPPED=1
    exit 77
}

die() {
    fail "$*"
    exit 1
}

# --- assertions ---------------------------------------------------------------

assert_eq() { # actual expected description
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (got '$1', expected '$2')"; show_last; fi
}

assert_ne() { # actual unexpected description
    if [ "$1" != "$2" ]; then pass "$3"; else fail "$3 (got '$1')"; show_last; fi
}

assert_contains() { # haystack needle description
    if [[ "$1" == *"$2"* ]]; then pass "$3"; else fail "$3 (no '$2' in output)"; printf '%s    %s%s\n' "$_D" "$(printf '%s' "$1" | head -c 1500 | sed '2,$s/^/    /')" "$_Z"; fi
}

assert_not_contains() { # haystack needle description
    if [[ "$1" != *"$2"* ]]; then pass "$3"; else fail "$3 (unexpected '$2' in output)"; fi
}

assert_match() { # haystack regex description
    if printf '%s' "$1" | grep -Eq -- "$2"; then pass "$3"; else fail "$3 (no match for /$2/)"; printf '%s    %s%s\n' "$_D" "$(printf '%s' "$1" | head -c 1500 | sed '2,$s/^/    /')" "$_Z"; fi
}

assert_file() { # path [expected-content] description
    local p=$1
    if [ $# -eq 3 ]; then
        if [ -f "$p" ] && [ "$(cat "$p")" = "$2" ]; then pass "$3"; else fail "$3 ($p: $( [ -f "$p" ] && printf "'%s'" "$(head -c 200 "$p")" || echo missing))"; fi
    else
        if [ -f "$p" ]; then pass "$2"; else fail "$2 ($p missing)"; fi
    fi
}

assert_no_file() { # path description
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then pass "$2"; else fail "$2 ($1 exists)"; fi
}

assert_dir() { # path description
    if [ -d "$1" ]; then pass "$2"; else fail "$2 ($1 is not a directory)"; fi
}

assert_rc() { # expected description   (checks AC_RC from the last ac call)
    if [ "$AC_RC" = "$1" ]; then pass "$2"; else fail "$2 (exit $AC_RC, expected $1)"; show_last; fi
}

assert_le() { # actual max description   (numbers, may be decimal)
    if awk -v a="$1" -v b="$2" 'BEGIN { exit !(a <= b) }'; then pass "$3"; else fail "$3 ($1 > $2)"; fi
}

# --- running agentcracker -------------------------------------------------------

# ac ARGS...: run agentcracker with stdin from /dev/null (non-interactive).
# Sets AC_RC, AC_OUT (stdout) and AC_ERR (stderr).  Never fails the script.
ac() {
    debug "\$ agentcracker $*"
    "$AC" "$@" </dev/null >"$WORK/last.out" 2>"$WORK/last.err"
    AC_RC=$?
    AC_OUT=$(cat "$WORK/last.out")
    AC_ERR=$(cat "$WORK/last.err")
    { echo "\$ agentcracker $* (cwd $PWD) -> $AC_RC"; cat "$WORK/last.out" "$WORK/last.err"; } >>"$WORK/ac.log"
    if [ "${AC_VERBOSE:-0}" = 1 ]; then
        sed 's/^/    | /' "$WORK/last.out" "$WORK/last.err"
    fi
    return 0
}

# ac_pty SCRIPT ARGS...: run agentcracker on a pseudo-terminal, driven by an
# expect-like SCRIPT (see pty.py).  Sets AC_RC and AC_OUT (the transcript).
ac_pty() {
    local script=$1
    shift
    debug "\$ agentcracker $* (pty)"
    printf '%s\n' "$script" | python3 -I "$TESTS_DIR/pty.py" --timeout "${AC_PTY_TIMEOUT:-60}" -- "$AC" "$@" >"$WORK/last.out" 2>"$WORK/last.err"
    AC_RC=$?
    AC_OUT=$(cat "$WORK/last.out")
    AC_ERR=$(cat "$WORK/last.err")
    { echo "\$ agentcracker $* (pty, cwd $PWD) -> $AC_RC"; cat "$WORK/last.out" "$WORK/last.err"; } >>"$WORK/ac.log"
    if [ "${AC_VERBOSE:-0}" = 1 ]; then
        sed 's/^/    | /' "$WORK/last.out" "$WORK/last.err"
    fi
    # a stuck prompt or a hung session is always a failure, whatever the
    # test goes on to check
    case $AC_RC in
        124 | 125) fail "pty: $(grep -o '\[pty.py: .*\]' "$WORK/last.out" | tail -1) running: agentcracker $*"
                   tail -5 "$WORK/last.out" | sed 's/^/    /' ;;
    esac
    return 0
}

# ac_run CMD...: run CMD in a new session for the current directory.  Also sets
# SID to the new session's id.
ac_run() {
    ac "$@"
    SID=$(session_from_output "$AC_ERR")
}

# The session id from agentcracker's "session XXXXXXXX · ..." status line.
session_from_output() {
    printf '%s\n' "$1" | sed -n 's/^agentcracker: session \([0-9a-f]\{8\}\) .*/\1/p' | head -1
}

# Id of the most recently modified session (empty if none).
latest_session() {
    local d=$XDG_STATE_HOME/agentcracker/sessions
    [ -d "$d" ] || return 0
    ls -t "$d" 2>/dev/null | head -1
}

# Number of sessions in this test's store.
session_count() {
    local d=$XDG_STATE_HOME/agentcracker/sessions
    [ -d "$d" ] || { echo 0; return; }
    ls "$d" | wc -l
}

session_dir() { echo "$XDG_STATE_HOME/agentcracker/sessions/$1"; }

# meta FIELD [SESSION]: one field of a session's meta.json (null -> empty).
meta() {
    local s=${2:-$SID}
    python3 -I -c 'import json,sys
v=json.load(open(sys.argv[1])).get(sys.argv[2])
print("" if v is None else (json.dumps(v) if isinstance(v,(dict,list)) else v))' "$(session_dir "$s")/meta.json" "$1"
}

session_exists() { [ -d "$(session_dir "$1")" ]; }

# --- fixtures -------------------------------------------------------------------

# new_project [NAME]: create a small project directory and cd into it.
new_project() {
    PROJ=$WORK/${1:-proj}
    mkdir -p "$PROJ/src" "$PROJ/docs/old"
    printf 'hello\n' >"$PROJ/hello.txt"
    printf 'keep me\n' >"$PROJ/keep.txt"
    printf 'delete me\n' >"$PROJ/remove.txt"
    printf 'fn main() {}\n' >"$PROJ/src/main.rs"
    printf 'one\ntwo\nthree\n' >"$PROJ/src/lines.txt"
    printf 'old docs\n' >"$PROJ/docs/old/a.md"
    printf 'old docs\n' >"$PROJ/docs/old/b.md"
    printf '#!/bin/sh\necho run\n' >"$PROJ/run.sh"
    chmod 755 "$PROJ/run.sh"
    cd "$PROJ" || die "cd $PROJ"
}

# A representative set of agent edits against new_project's files (a guest
# shell script).  EDITS_EXPECT lists the resulting change list lines.
AGENT_EDITS='
echo changed > hello.txt
echo new > added.txt
rm remove.txt
mkdir -p newdir/sub && echo nested > newdir/sub/f.txt
rm -rf docs/old
ln -s hello.txt link
chmod 600 keep.txt
printf "one\nTWO\nthree\n" > src/lines.txt
touch src/main.rs
echo "all:" > Makefile
echo setuid > suid && chmod 4755 suid
'
EDITS_EXPECT=(
    "A added.txt"
    "D docs/old/ (2 entries)"
    "M hello.txt"
    "M keep.txt  (mode only)"
    "A link -> hello.txt"
    "A newdir/sub/f.txt"
    "D remove.txt"
    "M src/lines.txt"
    "A Makefile  (runs or configures tools on the host"
    "A suid  (runs or configures tools on the host"
)
EDITS_SUMMARY="10 files changed: 3 modified, 5 added, 2 deleted"

# Check the host tree looks like AGENT_EDITS were applied.
assert_edits_applied() {
    assert_file hello.txt "changed" "modified file applied"
    assert_file added.txt "new" "added file applied"
    assert_no_file remove.txt "deleted file removed"
    assert_file newdir/sub/f.txt "nested" "file in new nested directories applied"
    assert_no_file docs/old "deleted directory removed"
    assert_dir docs "parent of a deleted directory kept"
    assert_eq "$(readlink link 2>/dev/null)" "hello.txt" "symlink applied"
    assert_eq "$(stat -c %a keep.txt)" "600" "mode change applied"
    assert_file keep.txt "keep me" "mode-only change kept the content"
    assert_file src/lines.txt "$(printf 'one\nTWO\nthree')" "multi-line edit applied"
    assert_file src/main.rs "fn main() {}" "touched-only file unchanged"
    assert_file Makefile "all:" "sensitive file applied"
    assert_eq "$(stat -c %a suid 2>/dev/null)" "755" "setuid bit stripped on apply"
}

# Check the host tree is exactly new_project's original state.
assert_edits_not_applied() {
    assert_file hello.txt "hello" "host file not modified"
    assert_no_file added.txt "added file not on the host"
    assert_file remove.txt "delete me" "deleted file still on the host"
    assert_no_file newdir "new directory not on the host"
    assert_file docs/old/a.md "old docs" "deleted directory still on the host"
    assert_no_file link "symlink not on the host"
    assert_eq "$(stat -c %a keep.txt)" "644" "mode not changed on the host"
    assert_no_file Makefile "sensitive file not on the host"
}

# Write a config file for this test (replaces any previous one).
set_config() {
    mkdir -p "$XDG_CONFIG_HOME/agentcracker"
    {
        if [ -n "${AC_TEST_CONFIG:-}" ]; then cat "$AC_TEST_CONFIG"; fi
        printf '%s\n' "$@"
    } >"$XDG_CONFIG_HOME/agentcracker/config.toml"
}

# --- prerequisites ----------------------------------------------------------------

require_cmd() {
    local c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || skip_test "needs $c"
    done
}

# Skip unless microVMs can run: built tool + assets, /dev/kvm access.
require_vm() {
    [ -x "$AC" ] || skip_test "$AC is not built (run make)"
    [ -r /dev/kvm ] && [ -w /dev/kvm ] || skip_test "/dev/kvm is not accessible"
    if [ -z "${AGENTCRACKER:-}" ]; then
        local f
        for f in "$REPO/build/acinit-target/x86_64-unknown-linux-gnu/release/agentcracker" \
                 "$REPO/firecracker/build/cargo_target/x86_64-unknown-linux-gnu/release/firecracker"; do
            [ -x "$f" ] || skip_test "missing $f (run make)"
        done
        ls "$REPO"/build/vmlinux-* >/dev/null 2>&1 || skip_test "no guest kernel in build/ (run make)"
    fi
    require_cmd python3
}

# Wall-clock seconds of a command, to 2 decimals (output discarded).
time_cmd() {
    local t0 t1
    t0=$(date +%s.%N)
    "$@" </dev/null >/dev/null 2>&1
    t1=$(date +%s.%N)
    awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }'
}

# --- setup / teardown --------------------------------------------------------------

_cleanup() {
    local rc=$?
    cd /
    local keep=${AC_KEEP:-0}
    [ "$_FAIL" -gt 0 ] && keep=1
    if [ "$keep" = 1 ] && [ -z "${_SKIPPED:-}" ]; then
        log "kept work dir: $WORK (agentcracker log: $WORK/ac.log)"
        log "inspect with: XDG_STATE_HOME=$WORK/state $AC ls"
    else
        # remove sessions through the tool (it knows about locks and runtime
        # dirs), then the work dir
        local d=$XDG_STATE_HOME/agentcracker/sessions s
        if [ -d "$d" ]; then
            for s in $(ls "$d"); do "$AC" rm "$s" >/dev/null 2>&1; done
        fi
        rm -rf -- "$WORK"
    fi
    exit $rc
}

# finish: print the result line and exit with the test's status.
finish() {
    if [ "$_FAIL" -gt 0 ]; then
        printf '%s[%s]%s %s%d passed, %d FAILED%s\n' "$_D" "$TEST_NAME" "$_Z" "$_R" "$_PASS" "$_FAIL" "$_Z"
        local f
        for f in "${_FAILED[@]}"; do printf '    - %s\n' "$f"; done
        exit 1
    fi
    printf '%s[%s]%s %s%d passed%s\n' "$_D" "$TEST_NAME" "$_Z" "$_G" "$_PASS" "$_Z"
    exit 0
}

_TEST_ROOT=${AC_TEST_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/agentcracker-tests}
mkdir -p "$_TEST_ROOT"
# kept work dirs hold sessions with 64G sparse disks: say when they pile up
_kept=$(find "$_TEST_ROOT" -mindepth 1 -maxdepth 1 -type d | wc -l)
[ "$_kept" -gt 10 ] && log "note: $_kept kept work dirs in $_TEST_ROOT (failed or AC_KEEP runs); remove them when done"
WORK=$(mktemp -d "$_TEST_ROOT/$TEST_NAME.XXXX")
export XDG_STATE_HOME=$WORK/state
export XDG_CONFIG_HOME=$WORK/config
export PAGER=cat
unset LESS
mkdir -p "$XDG_STATE_HOME" "$XDG_CONFIG_HOME"
if [ -n "${AC_TEST_CONFIG:-}" ]; then
    [ -r "$AC_TEST_CONFIG" ] || { echo "AC_TEST_CONFIG: cannot read $AC_TEST_CONFIG" >&2; exit 1; }
    set_config
fi
: >"$WORK/ac.log"
trap _cleanup EXIT
trap 'exit 130' INT TERM
debug "work dir $WORK, binary $AC"
