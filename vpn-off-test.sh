#!/bin/bash
# claude-vpn-lock: live test "VPN off -> Claude is blocked, VPN on -> Claude works".
#
#   sudo bash vpn-off-test.sh
#
# You turn the VPN off in your VPN app, wait ~10 s and turn it back on. The script itself sends
# nothing to Anthropic. Once a second it records: which interface the route to Anthropic uses,
# the daemon mode, the fate of the control packet (203.0.113.7, not routed on the internet) and
# the number of ESTABLISHED connections from Claude processes to Anthropic that start from the
# physical interface's address; that number must stay 0. Exit code: the number of failed
# conditions.

set -uo pipefail
export LC_ALL=C

SRC="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "${SRC}/lib/common.sh"
[ "$(id -u)" = 0 ] || die "must run as root: sudo bash $0"
[ -x "${CVL_DAEMON}" ] || die "the lock is not installed"
CVL_LIB=1 CVL_NO_NOTIFY=1 . "${CVL_DAEMON}"

REAL=$(direct_addr) || REAL=""
[ -n "${REAL}" ] || die "could not find the address of the physical interface"
is_vpn_name "$(route_iface)" || die "the VPN is off right now; turn it on and run this again"

log_from=$(( $(stat -f %z "${CVL_LOG}" 2>/dev/null || printf 0) + 1 ))
claude_from_real() {   # established TCP of Claude processes from the physical address to Anthropic
  lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk -v r="${REAL}:" '
    tolower($1) ~ /^claude/ && index($9, r) == 1 && $9 ~ /->(160\.79\.|\[2607:6bc0)/ { n++ } END { print n + 0 }'
}

say ""
say "  >>> Turn OFF the VPN in your VPN app now. Wait ~10 seconds. Turn it back ON. <<<"
say "  (Waiting up to 240 s. Claude will lose its connection while the VPN is off - that is by design.)"
say ""

t0=$(date +%s)
off_at=""; on_at=""; open_at=""; closed_seen=0
leaks=0; canary_off=0; canary_blocked=0
while :; do
  now=$(date +%s); el=$((now - t0))
  ifc=$(route_iface); mode=$(cat "${CVL_VAR}/mode" 2>/dev/null)
  est=$(claude_from_real); leaks=$((leaks + est))
  note=""
  if ! is_vpn_name "${ifc}"; then
    [ -z "${off_at}" ] && off_at=${el}
    curl -s -o /dev/null -m 1 "http://${CANARY_NET}/"; rc=$?
    canary_off=$((canary_off + 1))
    [ "${rc}" = 7 ] && canary_blocked=$((canary_blocked + 1))
    note="control packet: curl ${rc}"
  elif [ -n "${off_at}" ] && [ -z "${on_at}" ]; then
    on_at=${el}
  fi
  [ "${mode}" = closed ] && [ -n "${off_at}" ] && closed_seen=1
  [ -n "${on_at}" ] && [ -z "${open_at}" ] && [ "${mode}" = open ] && open_at=${el}
  printf '  %3d s  route=%-8s mode=%-8s Claude connections from %s to Anthropic: %s  %s\n' \
    "${el}" "${ifc}" "${mode}" "${REAL}" "${est}" "${note}"
  [ -n "${open_at}" ] && [ $((el - open_at)) -ge 5 ] && break
  [ "${el}" -ge 240 ] && break
  [ -z "${off_at}" ] && [ $((el % 30)) -eq 29 ] && say "  ...waiting for the VPN to be turned off"
  sleep 1
done

step "Daemon log during the test"
tail -c +"${log_from}" "${CVL_LOG}" 2>/dev/null | grep -E 'STATE|blocked|WARN|ERROR' | sed 's/^/  /'
blocked=$(tail -c +"${log_from}" "${CVL_LOG}" 2>/dev/null | sed -n 's/.*had blocked \([0-9]*\) packets.*/\1/p' | awk '{ s += $1 } END { print s + 0 }')

step "Summary"
fails=0
if [ -z "${off_at}" ]; then
  say "  FAIL  the VPN was never turned off; the test did not take place"; fails=$((fails + 1))
else
  say "  VPN went off at ${off_at} s and came back at ${on_at:-?} s; the daemon opened Claude at ${open_at:-?} s"
  [ "${leaks}" = 0 ] && say "  OK    no established connection from Claude to Anthropic from address ${REAL}" \
    || { say "  FAIL  Claude connections from ${REAL} to Anthropic: ${leaks} (sum over the seconds)"; fails=$((fails + 1)); }
  [ "${closed_seen}" = 1 ] && say "  OK    the daemon switched to 'closed' while the VPN was off" \
    || { say "  FAIL  mode 'closed' was never observed"; fails=$((fails + 1)); }
  [ "${canary_off}" -gt 0 ] && [ "${canary_blocked}" = "${canary_off}" ] \
    && say "  OK    the control packet was dropped ${canary_blocked} of ${canary_off} times with the VPN off (at once, code 7)" \
    || { say "  FAIL  the control packet was dropped ${canary_blocked} of ${canary_off} times"; fails=$((fails + 1)); }
  say "        packets to Anthropic dropped by the kernel during the test (from the daemon log): ${blocked}"
  [ -n "${open_at}" ] && say "  OK    Claude was open $((open_at - on_at)) s after the VPN came back" \
    || { say "  FAIL  mode open did not return after the VPN came back"; fails=$((fails + 1)); }
fi
exit "${fails}"
