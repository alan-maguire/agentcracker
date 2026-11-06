#!/bin/bash
# The guest environment: command output and exit status, identity, paths,
# the project and host toolchain visible, and isolation from the host.
. "$(dirname "$0")/lib.sh"
require_vm
new_project

step "exit status and output"
ac_run sh -c 'echo to-stdout; echo to-stderr >&2; exit 7'
assert_rc 7 "guest exit status is propagated"
assert_contains "$AC_OUT" "to-stdout" "guest stdout reaches host stdout"
assert_contains "$AC_ERR" "to-stderr" "guest stderr reaches host stderr"
assert_not_contains "$AC_OUT" "to-stderr" "stderr is not mixed into stdout"
assert_eq "$(meta exit_code)" "7" "exit code recorded in the session"
assert_eq "$(meta status)" "exited" "session status is exited"
assert_eq "$(meta boots)" "1" "one boot recorded"

ac_run sh -c 'kill -TERM $$'
assert_rc 143 "death by signal is reported as 128+signal"

ac_run /no/such/program
assert_ne "$AC_RC" "0" "a missing command fails"

step "identity and paths"
ac_run sh -c 'id -u; id -g; pwd; echo "$HOME"; echo "$USER"'
mapfile -t L <<<"$AC_OUT"
assert_eq "${L[0]:-}" "$(id -u)" "runs as the invoking uid"
assert_eq "${L[1]:-}" "$(id -g)" "runs as the invoking gid"
assert_eq "${L[2]:-}" "$PROJ" "starts in the project directory, same path"
assert_eq "${L[3]:-}" "$HOME" "HOME is the same path as on the host"
assert_eq "${L[4]:-}" "${USER:-$(id -un)}" "USER is set"

step "project and host tools are visible"
ac_run sh -c 'cat hello.txt; test -x run.sh && ./run.sh; ls docs/old | wc -l'
mapfile -t L <<<"$AC_OUT"
assert_eq "${L[0]:-}" "hello" "project files are readable"
assert_eq "${L[1]:-}" "run" "project executables run"
assert_eq "${L[2]:-}" "2" "project directories are listed"
ac_run sh -c 'command -v bash && command -v git && test -d /usr/lib && echo ok'
assert_contains "$AC_OUT" "ok" "host /usr toolchain is available"
ac_run sh -c 'cat /proc/cmdline; uname -r'
assert_contains "$AC_OUT" "init=/acinit" "really running inside the microVM"
assert_ne "$(echo "$AC_OUT" | tail -1)" "$(uname -r)" "guest kernel differs from the host kernel"

step "isolation from the host"
outside=$WORK/outside.txt
echo host >"$outside"
ac_run sh -c "echo guest > '$outside'; echo changed > hello.txt; touch new.txt; rm remove.txt; touch \$HOME/.ac-test-\$\$"
assert_rc 0 "guest wrote files"
assert_file "$outside" "host" "a file outside the project is not touched on the host"
assert_file hello.txt "hello" "project file unchanged until applied"
assert_no_file new.txt "new file not on the host until applied"
assert_file remove.txt "delete me" "deleted file still on the host until applied"
assert_eq "$(ls -a "$HOME" | grep -c '^\.ac-test-')" "0" "guest \$HOME writes do not reach the host"

ac_run sh -c 'id -u 0 >/dev/null; touch /etc/ac-test 2>/dev/null && echo wrote || echo denied'
assert_eq "$AC_OUT" "denied" "the agent is not root inside the guest"

step "on a terminal"
# with a host tty the command gets a pty of its own, sized like the host's;
# with no changes the review menu offers [x] discard, which needs no confirm
before=$(session_count)
ac_pty 'expect READY
resize 50 132
expect \[x\] discard
key x' sh -c 'test -t 0 && test -t 1 && echo IS-TTY; stty size; echo READY; sleep 1; stty size'
assert_rc 0 "terminal session exits 0"
assert_contains "$AC_OUT" "IS-TTY" "stdin and stdout are a terminal"
assert_contains "$AC_OUT" "40 120" "guest terminal has the host's size"
assert_contains "$AC_OUT" "50 132" "host resize reaches the guest"
assert_eq "$(session_count)" "$before" "discarding from the menu removes the session"

step "pipes when not on a terminal"
ac_run sh -c 'test -t 0 || echo stdin-pipe; test -t 1 || echo stdout-pipe'
assert_contains "$AC_OUT" "stdin-pipe" "stdin is not a terminal"
assert_contains "$AC_OUT" "stdout-pipe" "stdout is not a terminal"
out=$(printf 'one\ntwo\n' | "$AC" sh -c 'cat; echo done' 2>/dev/null)
assert_eq "$out" "$(printf 'one\ntwo\ndone')" "host stdin is forwarded and reaches EOF"

finish
