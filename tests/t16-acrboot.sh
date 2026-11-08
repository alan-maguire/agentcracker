#!/bin/bash
# acrboot: the agent boots a kernel it built in a microVM of its own,
# nested in the session's.  Off by default (no /dev/kvm), enabled only by
# the user's config; outcomes (exit, panic, timeout, error), root disks,
# limits, the records the user gets, and cleanup.
# agentcracker's own guest kernel stands in for one the agent built.
. "$(dirname "$0")/lib.sh"
require_vm

kernel=$(ls "$REPO"/build/vmlinux-* 2>/dev/null | head -1)
[ -n "$kernel" ] || skip_test "no in-tree guest kernel (run make)"
new_project
cp "$kernel" vmlinux

step "off by default"
ac_run sh -c 'acrboot vmlinux; echo rc=$?; test -e /dev/kvm && echo kvm'
assert_contains "$AC_OUT" "rc=2" "acrboot fails"
assert_not_contains "$AC_OUT" "kvm" "the guest has no /dev/kvm"
assert_contains "$AC_ERR$AC_OUT" "boot = true" "and says how to turn it on"
ac_run sh -c 'test -e ~/.claude/skills/agentcracker-acrboot && echo skill; grep -c "agentcracker sandbox" ~/.claude/CLAUDE.md; grep -c "acrboot. boots" ~/.claude/CLAUDE.md'
assert_eq "$AC_OUT" "$(printf '1\n0')" "the agent is told about its sandbox, but not about acrboot"

step "a project cannot turn it on"
echo 'boot = true' >.agentcracker.toml
ac_run true
assert_rc 1 "the session is refused"
assert_contains "$AC_ERR" "can only be set in" "naming the problem"
rm .agentcracker.toml

set_config 'boot = true' 'vcpus = 2' 'memory = "2G"'

step "the agent is told"
host_md=$(sha256sum "$REAL_HOME/.claude/CLAUDE.md" 2>/dev/null)
ac_run sh -c 'sed -n 1,3p ~/.claude/skills/agentcracker-acrboot/SKILL.md; grep -c "agentcracker: begin" ~/.claude/CLAUDE.md; grep -c "acrboot. boots" ~/.claude/CLAUDE.md'
assert_contains "$AC_OUT" "name: agentcracker-acrboot" "an acrboot skill is installed in the guest"
assert_match "$AC_OUT" $'\n1\n1$' "and the instructions file mentions acrboot, once"
first=$SID
ac resume "$first" sh -c 'grep -c "agentcracker: begin" ~/.claude/CLAUDE.md'
assert_eq "$AC_OUT" "1" "a later boot replaces the section instead of adding another"
assert_eq "$(sha256sum "$REAL_HOME/.claude/CLAUDE.md" 2>/dev/null)" "$host_md" "the host's CLAUDE.md is untouched"
ac_run sh -c 'acrboot --kconfig'
assert_contains "$AC_OUT" "CONFIG_VIRTIO_BLK=y" "acrboot --kconfig prints the Firecracker kernel options"

step "a kernel on its own"
ac_run sh -c 'acrboot --cpus 0 nonexistent 2>&1'
if echo "$AC_OUT" | grep -q "no virtualisation support"; then
    info "the host does not expose nested virtualisation: boots not tested"
    finish
fi
ac_run sh -c 'acrboot vmlinux > console.txt; echo rc=$?; grep -c "Kernel panic - not syncing" console.txt'
assert_eq "$AC_OUT" "$(printf 'rc=1\n1')" "no root: a panic, exit status 1, with the console"
assert_contains "$AC_ERR" "kernel panic after" "the outcome is reported"
ac log "$SID"
assert_match "$AC_OUT" 'boot +PANIC +[0-9.]+M kernel' "the boot is in the log"
records=$(session_dir "$SID")/state/.local/state/acrboot
[ -s "$records/1.console" ] && pass "the console is kept in the session" || fail "no console in the session"

step "with a root disk"
# (looked up now: the sessions above rebuild it if acinit changed)
base=$(ls -t "${XDG_CACHE_HOME:-$REAL_HOME/.cache}"/agentcracker/base/base-*.img 2>/dev/null | head -1)
if [ -n "$base" ]; then
    cp "$base" root.img || die "copying $base"
    ac_run sh -c 'acrboot --disk root.img --append init=/acinit vmlinux; echo rc=$?'
    assert_contains "$AC_OUT" "Run /acinit as init process" "the disk is the root device"
    assert_contains "$AC_OUT" "rc=0" "a VM the kernel shuts down exits 0"
    ac log "$SID"
    assert_match "$AC_OUT" 'boot +EXIT +[0-9.]+M kernel, 1 disk' "the log counts its disk"
else
    info "no base image in the cache: root disk not tested"
fi

step "timeouts and limits"
ac_run sh -c 'acrboot --timeout 3 --cpus 99 --mem 64G --append "root=/dev/vdz rootwait" vmlinux >/dev/null; echo rc=$?'
assert_eq "$AC_OUT" "rc=124" "a kernel that never finishes times out with 124"
assert_match "$AC_ERR" '\(2 CPU, 1[0-9]{3}M\)' "CPUs and memory are capped within the session's"

step "what Firecracker cannot boot"
ac_run sh -c 'head -c 514 /dev/zero > bz; printf HdrS >> bz; acrboot bz; echo rc=$?'
assert_contains "$AC_ERR$AC_OUT" "is a bzImage" "a bzImage is refused with a hint"
assert_contains "$AC_OUT" "rc=2" "with exit status 2"

step "the test VM ends with the session"
ac_run sh -c 'acrboot --timeout 600 --append "root=/dev/vdz rootwait" vmlinux >/dev/null 2>&1 & sleep 2'
assert_rc 0 "the session ends when its command does"
assert_match "$(cat "$(session_dir "$SID")/state/.local/state/acrboot/boot.log" 2>/dev/null)" ' error ' "the boot it cut short is recorded"

finish
