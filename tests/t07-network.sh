#!/bin/bash
# Network policy: HTTPS egress only through the host proxy, only to allowed
# hosts; --no-net; decisions logged and shown.  Steps that need the internet
# are skipped (not failed) when the host itself is offline.
. "$(dirname "$0")/lib.sh"
require_vm
require_cmd curl
new_project

# which hosts can the host itself reach? (sandboxes often allow only some)
reach() { curl -s -o /dev/null --max-time 5 "https://$1" && echo yes || echo no; }
online_api=$(reach api.anthropic.com)
online_example=$(reach example.com)
info "host reaches api.anthropic.com: $online_api, example.com: $online_example"

# in-guest probe: print the HTTP status, or ERR<curl exit code>
probe() { echo "code=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 $1) || code=ERR\$?; echo \"\$code\""; }

step "default policy"
ac_run sh -c 'echo "proxy=$HTTPS_PROXY"'
assert_match "$AC_OUT" '^proxy=http://127\.0\.0\.1:[0-9]+' "HTTPS_PROXY points at the in-guest relay"
ac_run sh -c "$(probe https://example.com)"
assert_match "$AC_OUT" '^(ERR[0-9]+|403)$' "a host outside the allowlist is refused"
ac show "$SID"
assert_match "$AC_OUT" 'example\.com +1 denied' "show lists the denial"
assert_contains "$AC_OUT" "requested by the agent" "show warns that denied hosts are the agent's choice"
assert_not_contains "$AC_OUT" "--allow example.com" "show does not hand over a command allowing the agent's host"
grep -q "example.com" "$(session_dir "$SID")/net.log" && pass "denial is in net.log" || fail "net.log has no entry for example.com"
ac_run sh -c "curl -s -o /dev/null --max-time 5 --noproxy '*' https://example.com && echo direct-ok || echo direct-blocked"
assert_eq "$AC_OUT" "direct-blocked" "bypassing the proxy gets nowhere"

if [ "$online_api" = yes ]; then
    ac_run sh -c "$(probe https://api.anthropic.com)"
    assert_match "$AC_OUT" '^[1-5][0-9][0-9]$' "the Anthropic API is reachable by default"
    assert_ne "$AC_OUT" "403" "the Anthropic API is not refused"
else
    info "host cannot reach api.anthropic.com: skipping"
fi

step "--allow"
if [ "$online_example" = yes ]; then
    ac_run --allow example.com sh -c "$(probe https://example.com)"
    assert_eq "$AC_OUT" "200" "--allow admits the host"
    ac show "$SID"
    assert_match "$AC_OUT" 'example\.com +1 allowed' "show lists the allowed connection"
    ac resume "$SID" sh -c "$(probe https://example.com)"
    assert_eq "$AC_OUT" "200" "--allow is remembered on resume"
    ac_run --allow '*.example.com' sh -c "$(probe https://example.com)"
    assert_match "$AC_OUT" '^(ERR[0-9]+|403)$' "a *.domain pattern does not match the bare domain"
else
    info "host cannot reach example.com: checking --allow bookkeeping only"
    ac_run --allow example.com true
    assert_contains "$AC_ERR" "net: Anthropic API + example.com" "--allow is shown in the session banner"
fi
assert_contains "$(meta allow "$SID")" "example.com" "--allow is recorded in the session"

step "allow from the project config"
printf 'allow = ["example.org"]\n' >.agentcracker.toml
ac_run true
assert_contains "$AC_ERR" "example.org" "project config adds to the allowlist"
rm .agentcracker.toml

step "--no-net"
ac_run --no-net sh -c 'echo "proxy=${HTTPS_PROXY:-none}"; '"$(probe https://api.anthropic.com)"
assert_contains "$AC_ERR" "no network" "banner says there is no network"
assert_contains "$AC_OUT" "proxy=none" "no proxy configured"
assert_match "$AC_OUT" 'ERR[0-9]+' "nothing is reachable"
assert_eq "$(meta net "$SID")" "False" "session recorded without network"

finish
