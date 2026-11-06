#!/bin/bash
# Startup and teardown timing.  Thresholds are generous defaults; tighten or
# loosen them with the environment:
#   AC_MAX_WARM      whole `agentcracker true` with warm caches (default 3s)
#   AC_MAX_FIRST     first output from the guest command (default 1.5s)
#   AC_MAX_TEARDOWN  guest command exit -> agentcracker exit (default 1.5s)
#   AC_MAX_NEWPROJ   first session in a fresh project, i.e. including the
#                    project snapshot (default 5s)
#   AC_TIMING_RUNS   samples per measurement; the median is used (default 3)
. "$(dirname "$0")/lib.sh"
require_vm

MAX_WARM=${AC_MAX_WARM:-3}
MAX_FIRST=${AC_MAX_FIRST:-1.5}
MAX_TEARDOWN=${AC_MAX_TEARDOWN:-1.5}
MAX_NEWPROJ=${AC_MAX_NEWPROJ:-5}
RUNS=${AC_TIMING_RUNS:-3}

median() { tr ' ' '\n' | sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }

step "warm-up (builds any missing snapshot; not timed)"
new_project
ac_run true
assert_rc 0 "warm-up session ran"

step "first session in a fresh project (includes the project snapshot)"
new_project fresh
for i in $(seq 1 40); do printf 'file %s\n' "$i" >"f$i.txt"; done
t=$(time_cmd "$AC" true)
info "fresh project: ${t}s"
assert_le "$t" "$MAX_NEWPROJ" "fresh project session within ${MAX_NEWPROJ}s"

step "warm session: whole run of \`true\`"
samples=()
for i in $(seq 1 "$RUNS"); do samples+=("$(time_cmd "$AC" true)"); done
m=$(echo "${samples[@]}" | median)
info "warm runs: ${samples[*]} (median ${m}s)"
assert_le "$m" "$MAX_WARM" "warm session within ${MAX_WARM}s"

step "time to first output and teardown"
# timestamps from a helper so the guest command's own output marks the point
# where it ran; teardown is everything after it (export, poweroff, VMM exit)
read -r first teardown < <(python3 -I - "$AC" "$RUNS" <<'EOF'
import subprocess, sys, time
firsts, tears = [], []
for _ in range(int(sys.argv[2])):
    t0 = time.time()
    p = subprocess.Popen([sys.argv[1], "echo", "MARK"], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    seen = None
    for line in p.stdout:
        if b"MARK" in line and seen is None:
            seen = time.time()
    p.wait()
    end = time.time()
    if seen is None:
        print("99 99"); sys.exit()
    firsts.append(seen - t0); tears.append(end - seen)
firsts.sort(); tears.sort()
print(f"{firsts[len(firsts)//2]:.2f} {tears[len(tears)//2]:.2f}")
EOF
)
info "first output after ${first}s, teardown ${teardown}s (medians)"
assert_le "$first" "$MAX_FIRST" "guest command starts within ${MAX_FIRST}s"
assert_le "$teardown" "$MAX_TEARDOWN" "VM is gone within ${MAX_TEARDOWN}s of the command exiting"

step "firecracker exits cleanly"
# a seccomp violation at VMM shutdown shows up as a "bad syscall" line in the
# console log (and costs seconds while the kernel dumps core)
ac_run true
log_file=$(session_dir "$SID")/console.log
if grep -q "bad syscall" "$log_file"; then
    fail "firecracker hit a seccomp violation: $(grep 'bad syscall' "$log_file" | tail -1)"
else
    pass "no seccomp violation at VM exit"
fi

finish
