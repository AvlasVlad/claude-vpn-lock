#!/bin/bash
# claude-vpn-lock: check the installed lock and prove it with pf packet counters.
#
#   sudo bash check.sh                # all safe checks (P0-P9)
#   sudo bash check.sh --short        # main checks only (P0-P3 and P5)
#   sudo bash check.sh --heal-tests   # also P10-P11 (for maintainers, see below)
#
# What it checks: the daemon and the pf rule are in place; a packet that leaves outside the
# tunnel is dropped by the kernel (the rule's counter goes up); traffic through the tunnel is
# not touched; Claude still works through the tunnel; other services are not affected.
# --heal-tests also removes the rule and the table and waits for the daemon to put them back
# (P10), and reloads /etc/pf.conf (P11). For those ~10 s Anthropic is NOT blocked outside the
# tunnel, so they are off by default and meant for maintainers (tests/acceptance.sh).
#
# Safety rule: this script never sends a request to Anthropic outside the tunnel until it has
# proven on the control address 203.0.113.7 (TEST-NET-3, not routed on the internet) that
# such a packet is dropped.
#
# Exit code: the number of failed checks; 100 = no check failed, but some are NOT MEASURED.

set -uo pipefail
export LC_ALL=C

SRC="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "${SRC}/lib/common.sh"
[ "$(id -u)" = 0 ] || die "must run as root: sudo bash $0"
[ -x "${CVL_DAEMON}" ] || die "the lock is not installed (${CVL_DAEMON} is missing)"
CVL_LIB=1 CVL_NO_NOTIFY=1 . "${CVL_DAEMON}"

SHORT=0
HEAL=0
for arg in "$@"; do
  case "${arg}" in
    --short) SHORT=1 ;;
    --heal-tests) HEAL=1 ;;
    *) die "unknown argument: ${arg}" ;;
  esac
done
FAILS=0
pass() { printf '  OK    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
UNTESTED=0
untested() { printf '  NOT MEASURED  %s\n' "$*"; UNTESTED=$((UNTESTED + 1)); }
info() { printf '        %s\n' "$*"; }

test_packets() { pfctl -a "${CVL_TEST_ANCHOR}" -v -s rules 2>/dev/null | awk -v want="$1" '
  index($0, want) { on = 1; next }
  on && /Packets:/ { for (i = 1; i <= NF; i++) if ($i == "Packets:") { print $(i + 1); exit } }'; }
cleanup_test_anchor() { remove_anchor "${CVL_TEST_ANCHOR}" >/dev/null; }
trap cleanup_test_anchor EXIT

MODE_NOW=$(cat "${CVL_VAR}/mode" 2>/dev/null)
PIN_NOW=$(cat "${CVL_VAR}/pinned" 2>/dev/null)
TUN_IF=${PIN_NOW%% *}
# DIRECT_POLICY=country with a verified plain network: the pinned interface is the physical one.
DIRECT_NOW=0
[ "${MODE_NOW}" = open ] && is_link_id "${PIN_NOW}" && DIRECT_NOW=1
TUN_ADDR=$(first_addr "${PIN_NOW}")
REAL=$(direct_addr) || REAL=""

step "P0. How pf looks right now (for diagnosis, not a check)"
info "main ruleset: $(pfctl -s rules 2>/dev/null | tr '\n' ';')"
info "main nat/rdr: $(pfctl -s nat 2>/dev/null | tr '\n' ';')"
info "all anchors: $(pfctl -v -s Anchors 2>/dev/null | tr -s ' \n' ' ')"
for a in $(pfctl -v -s Anchors 2>/dev/null | grep -v ClaudeVPNLock); do
  r=$(pfctl -a "${a}" -s rules 2>/dev/null | grep -c .)
  [ "${r}" -gt 0 ] && info "  ${a}: ${r} rules; $(pfctl -a "${a}" -s rules 2>/dev/null | grep -c 'pass.*quick') with pass quick"
done
info "references that keep pf enabled: $(pfctl -s References 2>/dev/null | tail -n +2 | tr -s ' \n' ' ')"

step "P1. Daemon and rule are in place"
launchctl print "system/${CVL_LABEL}" 2>/dev/null | grep -q 'state = running' && pass "daemon is running (launchd)" || fail "daemon is not running"
pf_enabled && pass "pf is enabled" || fail "pf is disabled"
main_has_apple_anchor && pass "main pf ruleset contains the \"com.apple/*\" anchor" || fail "main pf ruleset has no \"com.apple/*\" anchor"
if [ "${DIRECT_NOW}" = 1 ]; then pass "mode is open on a direct network (DIRECT_POLICY=country), ${PIN_NOW}"
elif [ "${MODE_NOW}" = open ]; then pass "mode is open, tunnel ${PIN_NOW}"
else fail "mode is ${MODE_NOW} (expected open while the VPN is on)"; fi
case "$(anchor_rule)" in
  *"on ! ${TUN_IF} "*) pass "rule: $(anchor_rule)" ;;
  *) fail "rule is not bound to ${TUN_IF}: $(anchor_rule)" ;;
esac
[ "$(route_iface)" = "${TUN_IF}" ] && pass "route to Anthropic goes through ${TUN_IF}" || fail "route to Anthropic goes through $(route_iface), but the rule is bound to ${TUN_IF}"
info "networks in the table: $(pfctl -a "${CVL_ANCHOR}" -t claude_nets -T show 2>/dev/null | tr -s ' \n' ' ')"

if [ "${DIRECT_NOW}" = 1 ]; then
step "D2. The rule leaves the verified direct network alone (control address ${CANARY_NET})"
if [ -z "${REAL}" ]; then
  fail "could not find the address of the physical interface"
else
  b=$(rule_packets)
  curl -s -o /dev/null -m 3 --interface "${REAL}" "http://${CANARY_NET}/"; rc=$?
  a=$(rule_packets)
  info "curl --interface ${REAL} http://${CANARY_NET}/ -> curl code ${rc}; rule counter ${b} -> ${a}"
  [ "${a}" = "${b}" ] && pass "the rule did not fire for the network it is pinned to" || fail "the rule fired on the pinned network"
fi

step "D3. The network's own exit country is allowed"
check_exit "$(first_addr "${PIN_NOW}")"; crc=$?
case "${crc}" in
  0) pass "${VERDICT} (blocked: ${BLOCKED_COUNTRIES})" ;;
  1) fail "${VERDICT} is a blocked country (${BLOCKED_COUNTRIES}); the daemon should close the lock within seconds" ;;
  *) untested "the network's country could not be obtained now" ;;
esac

step "D4. Claude reaches Anthropic directly; the rule does not fire"
if [ "${crc}" != 0 ] || [ -z "${REAL}" ]; then
  untested "no request to Anthropic: the network's country is not confirmed as allowed (D3) or there is no physical address"
else
  b=$(rule_counter) || b=""
  resp=$(curl -4 -s -m 12 -o /dev/null -w '%{http_code} %{local_ip}' --interface "${REAL}" https://api.anthropic.com/ 2>/dev/null)
  a=$(rule_counter) || a=""
  code=${resp%% *}
  info "https://api.anthropic.com/ from ${REAL} -> HTTP ${code:-none}; rule counter ${b:-?} -> ${a:-?}"
  if [ -n "${code}" ] && [ "${code}" != 000 ] && [ -n "${b}" ] && [ "${a}" = "${b}" ]; then pass "Anthropic answered (HTTP ${code}) from the verified direct network"
  elif [ -z "${b}" ] || [ -z "${a}" ]; then untested "counter not obtained"
  elif [ "${a}" -gt "${b}" ] 2>/dev/null; then fail "the rule dropped packets to Anthropic on the pinned network"
  else untested "Anthropic did not answer (HTTP ${code:-none}) and the rule dropped nothing: the network, not the lock"; fi
fi
info "P2-P11 prove the tunnel mode and do not apply while a direct network is allowed."
info "To see the lock close on a blocked country, run tests/acceptance-direct.sh (maintainers)."

step "Summary"
[ "${UNTESTED}" = 0 ] || say "  NOT MEASURED: ${UNTESTED} (neither a failure nor a success; see above)"
[ "${FAILS}" = 0 ] && say "  NO FAILURES" || say "  FAILED CHECKS: ${FAILS}"
[ "${FAILS}" = 0 ] && [ "${UNTESTED}" -gt 0 ] && exit 100
exit "${FAILS}"
fi

step "P2. A packet outside the tunnel is dropped by the kernel (control address ${CANARY_NET})"
P2_OK=0
if [ -z "${REAL}" ]; then
  fail "could not find the address of the physical interface"
else
  b=$(rule_packets); t0=$(date +%s)
  curl -s -o /dev/null -m 3 --interface "${REAL}" "http://${CANARY_NET}/"; rc=$?
  a=$(rule_packets); t1=$(date +%s)
  info "curl --interface ${REAL} http://${CANARY_NET}/ -> curl code ${rc} in $((t1 - t0)) s; rule counter ${b} -> ${a}"
  if [ "${a}" -gt "${b}" ] 2>/dev/null; then pass "packet from ${REAL} was dropped (counter +$((a - b)))"; P2_OK=1
  else fail "counter did not go up; the packet did not hit the rule"; fi
  [ "${rc}" = 7 ] && info "code 7 = connection refused at once (block return): the program does not wait for a timeout"
fi

step "P3. The rule does not touch the same control address through the tunnel"
b=$(rule_packets)
curl -s -o /dev/null -m 3 "http://${CANARY_NET}/"; rc=$?
a=$(rule_packets)
info "curl http://${CANARY_NET}/ (default route, through ${TUN_IF}) -> curl code ${rc}; counter ${b} -> ${a}"
[ "${a}" = "${b}" ] && pass "the rule did not fire for traffic through the tunnel" || fail "the rule fired on a packet that went through the tunnel"

if [ "${SHORT}" = 0 ]; then
step "P4. A real Anthropic address (160.79.104.10) from the physical interface"
if [ "${P2_OK}" = 1 ]; then
  b=$(rule_packets)
  curl -s -o /dev/null -k -m 3 --interface "${REAL}" https://160.79.104.10/; rc=$?
  a=$(rule_packets)
  info "curl --interface ${REAL} https://160.79.104.10/ -> curl code ${rc}; counter ${b} -> ${a}"
  [ "${a}" -gt "${b}" ] 2>/dev/null && [ "${rc}" != 0 ] && pass "dropped by the kernel, did not reach Anthropic" || fail "NOT dropped"
else
  info "skipped: P2 did not prove the drop, so nothing is sent to Anthropic from the real address"
fi
fi

step "P5. Claude works through the tunnel"
if [ "${P2_OK}" != 1 ]; then
  untested "the drop is not proven (P2); no request sent to Anthropic"
else
  probe=$(claude_tunnel_probe); prc=$?
  printf '%s\n' "${probe}" | sed '$d' | sed 's/^/        /'
  verdict=$(printf '%s\n' "${probe}" | tail -1)
  case "${prc}" in
    0) pass "${verdict#OK: }" ;;
    4) untested "${verdict#NOT MEASURED: }" ;;
    *) fail "${verdict}" ;;
  esac
fi
claude_conns=$(lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'tolower($1) ~ /^claude/ && $9 ~ /->160\.79\./ { split($9, s, "->"); sub(/:[0-9]+$/, "", s[1]); print s[1] }' | sort | uniq -c | tr -s ' \n' ' ')
info "live connections of Claude processes to 160.79.x, by source address: ${claude_conns:-none}"

if [ "${SHORT}" = 0 ]; then
step "P6. Traffic that the VPN itself sends directly is also dropped (three states)"
# Many VPN clients with split-tunnel rules send some addresses "direct": the VPN app opens the
# socket on the physical interface. 77.88.44.55 (a Yandex address) is an example of such an
# address; your VPN may route it differently, so it can be overridden with CVL_DIRECT_TEST_IP.
# A test rule of the same shape as the real one shows whether pf sees and blocks that direct
# egress of the VPN app. If your VPN sends the address through the tunnel there is nothing to
# demonstrate, and the result is NOT MEASURED, not a failure.
DIRECT_IP=${CVL_DIRECT_TEST_IP:-77.88.44.55}
c1=$(curl -s -m 6 -o /dev/null -w '%{http_code}' "http://${DIRECT_IP}/")
printf 'table <cvl_direct> persist { %s }\nblock return out quick on ! %s to <cvl_direct> label "cvl-vpn-direct"\n' "${DIRECT_IP}" "${TUN_IF}" \
  | pfctl -a "${CVL_TEST_ANCHOR}" -f - >/dev/null 2>&1
c2=$(curl -s -m 6 -o /dev/null -w '%{http_code}' "http://${DIRECT_IP}/")
n2=$(test_packets cvl-vpn-direct)
cleanup_test_anchor
c3=$(curl -s -m 6 -o /dev/null -w '%{http_code}' "http://${DIRECT_IP}/")
info "test address ${DIRECT_IP}; without the rule: HTTP ${c1}; with the rule: HTTP ${c2}, counter ${n2:-?}; rule removed: HTTP ${c3}"
if [ "${c1}" = 000 ] || [ "${c3}" = 000 ]; then
  untested "no answer from the test address; cannot demonstrate"
elif [ "${c2}" = 000 ] && [ "${n2:-0}" -gt 0 ] 2>/dev/null; then
  pass "pf sees and blocks the direct egress of the VPN app"
elif [ "${c2}" != 000 ] && [ "${n2:-}" = 0 ]; then
  untested "your VPN sends this address through the tunnel, so there is no direct flow to demonstrate on"
else
  fail "direct egress of the VPN is not proven (expected: a code, 000 with counter > 0, a code)"
fi

step "P7. Other services are not affected by the rule"
for url in https://api.github.com/ https://registry.npmjs.org/ https://pypi.org/simple/ \
           https://www.cloudflare.com/cdn-cgi/trace; do
  b=$(rule_packets)
  code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "${url}")
  a=$(rule_packets)
  if [ "${a}" != "${b}" ]; then fail "${url} -> HTTP ${code}, rule counter ${b} -> ${a}"
  elif [ "${code}" = 000 ]; then untested "${url} -> no answer; the rule was not involved"
  else pass "${url} -> HTTP ${code}"; fi
done

step "P8. pf states for connections to Anthropic"
st=$(pfctl -s states 2>/dev/null | grep -c '160\.79\.10[4-9]\|160\.79\.11[01]')
info "pf state entries with Anthropic addresses: ${st} (0 = other pass rules create no bypass states)"
fi

if [ "${SHORT}" = 0 ]; then
step "P9. Addresses that Claude processes connect to now but that are not in the table"
# The instrument prints every address with pfctl's own verdict ("1/1 addresses match"),
# so an exit-code quirk cannot turn "not covered" into "nothing".
lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null \
  | awk 'tolower($1) ~ /^claude/ { split($9, s, "->"); r = s[2]; sub(/:[0-9]+$/, "", r); gsub(/[][]/, "", r); print $1, r }' \
  | sort | uniq -c | while read -r n proc ip; do
      m=$(pfctl -a "${CVL_ANCHOR}" -t claude_nets -T test "${ip}" 2>&1 | grep -o '[0-9]*/[0-9]* addresses match')
      case "${m}" in "1/1 addresses match") v="in the table" ;; "0/1 addresses match") v="NOT in the table" ;; *) v="not obtained (${m})" ;; esac
      info "${proc} -> ${ip} x${n}: ${v}"
    done
info "(not necessarily Anthropic: MCP servers, GitHub, Google fonts; shared CDNs cannot be covered by address)"

if [ "${HEAL}" = 1 ]; then
step "P10. Self-healing on the real pf (VPN on; Anthropic unblocked outside the tunnel for up to ~1 tick)"
pfctl -a "${CVL_ANCHOR}" -t claude_nets -T flush >/dev/null 2>&1
t0=$(date +%s); ok=0
for _ in $(seq 1 15); do
  sleep 1
  [ "$(pfctl -a "${CVL_ANCHOR}" -t claude_nets -T show 2>/dev/null | grep -c .)" -gt 2 ] && { ok=1; break; }
done
[ "${ok}" = 1 ] && pass "the daemon refilled the flushed table in $(( $(date +%s) - t0 )) s" || fail "table was not restored within 15 s"
pfctl -a "${CVL_ANCHOR}" -F rules >/dev/null 2>&1
t0=$(date +%s); ok=0
for _ in $(seq 1 15); do
  sleep 1
  case "$(anchor_rule)" in *"on ! ${TUN_IF} "*) ok=1; break ;; esac
done
[ "${ok}" = 1 ] && pass "the daemon restored the removed rule in $(( $(date +%s) - t0 )) s" || fail "rule was not restored within 15 s"

step "P11. System reload of /etc/pf.conf: our rule and other anchors"
extra=$( { pfctl -s rules; pfctl -s nat; } 2>/dev/null | grep -v -E '^(scrub-anchor|nat-anchor|rdr-anchor|binat-anchor|dummynet-anchor|anchor) "com\.apple/\*"' | grep -c .)
if [ "${extra}" != 0 ]; then
  info "skipped: the main ruleset has lines beyond the stock ones (${extra}); a reload would erase them"
else
  list_counts() { for a in $(pfctl -v -s Anchors 2>/dev/null); do printf '%s=%s ' "${a}" "$(pfctl -a "${a}" -s rules 2>/dev/null | grep -c .)"; done; }
  before=$(list_counts | sed 's/com.apple\/000.ClaudeVPNLock=[0-9]* //')
  pfctl -f /etc/pf.conf >/dev/null 2>&1; rc=$?
  sleep 1
  r1=$(anchor_rule)
  t0=$(date +%s); ok=0
  for _ in $(seq 1 12); do case "$(anchor_rule)" in *"on ! ${TUN_IF} "*) ok=1; break ;; esac; sleep 1; done
  after=$(list_counts | sed 's/com.apple\/000.ClaudeVPNLock=[0-9]* //')
  info "pfctl -f /etc/pf.conf -> code ${rc}; rule right after: ${r1:-none}"
  [ "${ok}" = 1 ] && pass "our rule is in place ($( [ -n "${r1}" ] && printf 'survived the reload' || printf "restored by the daemon in $(( $(date +%s) - t0 )) s"))" \
    || fail "our rule did not come back within 12 s"
  info "other anchors before: ${before}"
  info "other anchors after:  ${after}"
  [ "${before}" = "${after}" ] && pass "other anchors and their rule counts are unchanged" || fail "other anchors changed"
fi
else
  step "P10-P11. Self-healing and pf reload"
  info "skipped: they remove the rule for a few seconds; run with --heal-tests if you want them"
fi

fi

step "Summary"
[ "${UNTESTED}" = 0 ] || say "  NOT MEASURED: ${UNTESTED} (neither a failure nor a success; see above)"
[ "${FAILS}" = 0 ] && say "  NO FAILURES" || say "  FAILED CHECKS: ${FAILS}"
[ "${FAILS}" = 0 ] && [ "${UNTESTED}" -gt 0 ] && exit 100
exit "${FAILS}"
