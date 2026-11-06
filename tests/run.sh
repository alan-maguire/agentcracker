#!/bin/bash
# Run agentcracker tests and summarise.
#
#   tests/run.sh                 # every tests/t*.sh
#   tests/run.sh resume apply    # tests whose names contain these words
#   AGENTCRACKER=/usr/local/bin/agentcracker tests/run.sh    # test an install
#
# Each test is a standalone script and can also be run directly:
#   tests/t05-review-menu.sh

set -u
cd "$(dirname "$0")" || exit 1

tests=()
if [ $# -eq 0 ]; then
    tests=(t*.sh)
else
    for t in t*.sh; do
        for w in "$@"; do
            [[ $t == *"$w"* ]] && { tests+=("$t"); break; }
        done
    done
fi
[ ${#tests[@]} -gt 0 ] || { echo "no tests match: $*"; exit 2; }

if [ -t 1 ]; then G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' B=$'\e[1m' Z=$'\e[0m'; else G= R= Y= B= Z=; fi

echo "${B}agentcracker tests${Z}: ${AGENTCRACKER:-$(cd .. && pwd)/target/release/agentcracker}"
passed=() failed=() skipped=()
start=$(date +%s)
for t in "${tests[@]}"; do
    echo
    t0=$(date +%s)
    bash "./$t"
    rc=$?
    secs=$(( $(date +%s) - t0 ))
    case $rc in
        0)  passed+=("$t (${secs}s)") ;;
        77) skipped+=("$t") ;;
        *)  failed+=("$t") ;;
    esac
done

echo
echo "${B}summary${Z} ($(( $(date +%s) - start ))s)"
for t in "${passed[@]}";  do echo "  ${G}PASS${Z} $t"; done
for t in "${skipped[@]}"; do echo "  ${Y}SKIP${Z} $t"; done
for t in "${failed[@]}";  do echo "  ${R}FAIL${Z} $t"; done
echo "${#passed[@]} passed, ${#failed[@]} failed, ${#skipped[@]} skipped"
[ ${#failed[@]} -eq 0 ]
