#!/bin/bash
# Build caches: each project's ~/.cache persists across its sessions, one
# running session at a time; listed, shown, dropped, and off with
# `cache = false`.
. "$(dirname "$0")/lib.sh"
require_vm
require_cmd flock

cache_root=$XDG_STATE_HOME/agentcracker/caches

step "~/.cache persists across a project's sessions"
new_project
ac_run sh -c 'echo one >> ~/.cache/n; cat ~/.cache/n'
assert_eq "$AC_OUT" "one" "the first session starts with an empty cache"
first=$SID
ac_run sh -c 'echo two >> ~/.cache/n; cat ~/.cache/n; stat -c %U ~/.cache'
assert_eq "$AC_OUT" "$(printf 'one\ntwo\n%s' "$(id -un)")" "the next session sees it, owned by the user"
ac resume "$first" sh -c 'cat ~/.cache/n'
assert_eq "$AC_OUT" "$(printf 'one\ntwo')" "so does a resumed one"
ac show "$SID"
assert_match "$AC_OUT" '^cache +[0-9.]+[KMG] build cache for ' "show reports the cache"
ac_run sh -c 'echo build > ~/.cache/out.o'
assert_contains "$AC_ERR" "no changes" "the cache is not part of the project's changes"

step "another project has its own"
new_project other
ac_run sh -c 'cat ~/.cache/n 2>/dev/null || echo empty'
assert_eq "$AC_OUT" "empty" "caches are per project"
ac cache
assert_eq "$(echo "$AC_OUT" | wc -l)" "2" "cache lists both"
assert_match "$AC_OUT" "/other$" "with their directories"

step "one running session at a time"
cd "$WORK/proj"
id=$("$AC" --detach sh -c 'echo held > ~/.cache/held; sleep 4' </dev/null)
# wait for it to take the cache
lock=$(dirname "$(grep -lx "$WORK/proj" "$cache_root"/*/dir)")/lock
for _ in $(seq 150); do
    flock -n "$lock" true 2>/dev/null || break
    sleep 0.1
done
ac_run sh -c 'cat ~/.cache/n 2>/dev/null || echo empty'
assert_eq "$AC_OUT" "empty" "a concurrent session gets an empty ~/.cache"
assert_contains "$AC_ERR" "another session is using this directory's build cache" "and is told why"
ac cache --drop
assert_rc 1 "a cache in use cannot be dropped"
assert_contains "$AC_ERR" "in use by a running session" "naming the problem"
"$AC" wait "$id" >/dev/null 2>&1
ac_run sh -c 'cat ~/.cache/held'
assert_eq "$AC_OUT" "held" "the detached session's writes are kept"

step "--drop"
ac cache --drop
assert_rc 0 "drop exits 0"
ac_run sh -c 'cat ~/.cache/n 2>/dev/null || echo empty'
assert_eq "$AC_OUT" "empty" "a dropped cache starts afresh"
ac cache --drop "$WORK/other"
assert_rc 0 "another directory's cache can be dropped by name"
ac cache --drop "$WORK/other"
assert_rc 1 "dropping a missing cache is an error"

step "cache = false"
new_project nocache
set_config 'cache = false'
ac_run sh -c 'echo x > ~/.cache/n 2>/dev/null; echo ok'
ac_run sh -c 'cat ~/.cache/n 2>/dev/null || echo empty'
assert_eq "$AC_OUT" "empty" "nothing persists"
ac cache
assert_not_contains "$AC_OUT" "nocache" "and no cache is created"
set_config

finish
