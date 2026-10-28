#!/bin/bash
# claude-vpn-lock: maintainer acceptance of DIRECT_POLICY=country on a real machine.
#
#   sudo bash tests/acceptance-direct.sh
#
# Needs the lock installed with DIRECT_POLICY=country in the config and a network whose own exit
# country is NOT blocked. It never sends anything to Anthropic outside a state the daemon has
# verified; the "blocked" proof uses the kernel's own drop of a packet that never leaves.
#
# 1. You turn the VPN off: the daemon verifies the network and opens the rule on the plain
#    interface (mode open, pinned en*).                                    -> proof: mode, rule
# 2. check.sh --short runs its direct-network checks (D2-D4).
# 3. The config gets this network's own country added to BLOCKED_COUNTRIES (the daemon is
#    restarted): the lock must close and the kernel must drop packets to Anthropic and to the
#    control address, from the physical address.                           -> proof: pf counters
#    The original config is put back, also when this script is interrupted.
# 4. You turn the VPN on again: the lock follows the tunnel, and Claude processes keep 0
#    connections from the physical address.
# Full log: ~/Library/Logs/claude-vpn-lock/acceptance-direct-<time>.log

set -uo pipefail
export LC_ALL=C

SRC="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${SRC}/lib/common.sh"
[ "$(id -u)" = 0 ] || die "must run as root: sudo bash $0"
[ -x "${CVL_DAEMON}" ] || die "the lock is not installed"
CVL_LIB=1 CVL_NO_NOTIFY=1 . "${CVL_DAEMON}"
[ "${DIRECT_POLICY}" = country ] || die "DIRECT_POLICY=country is not set in ${CVL_CONF}"

LOGS=$(cvl_user_logs) || die "could not find the user's log folder"
OUT="${LOGS}/acceptance-direct-$(date +%Y%m%d-%H%M%S).log"
touch "${OUT}" && chown "$(cvl_user)" "${OUT}"
exec > >(tee -a "${OUT}") 2>&1

RESULTS=""
note() { RESULTS="${RESULTS}$(printf '%-52s %s' "$1" "$2")"$'\n'; }
FAILS=0
verdict() { if [ "$2" = 1 ]; then note "$1" OK; else note "$1" FAIL; FAILS=$((FAILS + 1)); fi; }
mode_now() { cat "${CVL_VAR}/mode" 2>/dev/null; }
pin_now() { cat "${CVL_VAR}/pinned" 2>/dev/null; }
wait_for() { local i; for i in $(seq 1 "$2"); do eval "$1" && return 0; sleep 1; done; return 1; }
restart_daemon() { launchctl kickstart -k "system/${CVL_LABEL}" >/dev/null 2>&1; sleep 2; }

CONF_BACKUP=$(mktemp "${LOGS}/.conf-backup.XXXXXX")
cat "${CVL_CONF}" >"${CONF_BACKUP}"
restore_conf() {
  if [ -s "${CONF_BACKUP}" ] && ! cmp -s "${CONF_BACKUP}" "${CVL_CONF}"; then
    cat "${CONF_BACKUP}" >"${CVL_CONF}"
    say "  config restored from ${CONF_BACKUP}"
    restart_daemon
  fi
}
# Closing the terminal kills tee first; after that every write to the pipe would kill this script
# (SIGPIPE) before the config is back. So the handler first moves its output to the log file.
cleanup() {
  trap '' PIPE
  exec >>"${OUT}" 2>&1
  restore_conf
  rm -f "${CONF_BACKUP}"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

say "claude-vpn-lock direct acceptance, $(date '+%Y-%m-%d %H:%M:%S'), log ${OUT}"

step "1. Turn the VPN OFF"
if is_vpn_name "$(route_iface)"; then
  say "  >>> Turn OFF the VPN in your VPN app now. Waiting up to 180 s. <<<"
  wait_for '! is_vpn_name "$(route_iface)"' 180 || die "the VPN is still on"
fi
say "  route to Anthropic: $(route_iface)"
wait_for '[ "$(mode_now)" = open ] && is_link_id "$(pin_now)"' 25
M=$(mode_now); P=$(pin_now)
say "  mode=${M} pinned=${P}"
say "  rule: $(anchor_rule)"
CC=$(sed -n 's/^cc=//p' "${CVL_VAR}/country" 2>/dev/null); say "  network exit: ${CC:-?} $(sed -n 's/^ip=//p' "${CVL_VAR}/country" 2>/dev/null)"
case "$(anchor_rule)" in *"on ! ${P%% *} "*) R=1 ;; *) R=0 ;; esac
[ "${M}" = open ] && is_link_id "${P}" && [ "${R}" = 1 ]; verdict "VPN off: opened on the verified direct network" $((! $? ))
[ -n "${CC}" ] && [ "${CC}" != "?" ] || die "the network's country is unknown; cannot go on"

step "2. check.sh --short (direct-network checks)"
bash "${SRC}/check.sh" --short; rc=$?
case "${rc}" in 0) note "check.sh --short D2-D4" OK ;; 100) note "check.sh --short D2-D4" "no failures; some NOT MEASURED" ;; *) note "check.sh --short D2-D4" "FAIL (${rc})"; FAILS=$((FAILS + 1)) ;; esac
REAL=$(direct_addr) || REAL=""
say "  Claude connections to 160.79.x by source address now: $(lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'tolower($1) ~ /^claude/ && $9 ~ /->160\.79\./ { split($9, s, "->"); sub(/:[0-9]+$/, "", s[1]); print s[1] }' | sort | uniq -c | tr -s ' \n' ' ')"

step "3. This network's country (${CC}) is added to BLOCKED_COUNTRIES: the lock must close"
printf '\nBLOCKED_COUNTRIES="%s %s"\n' "${BLOCKED_COUNTRIES}" "${CC}" >>"${CVL_CONF}"
restart_daemon
ok=0
if wait_for '[ "$(mode_now)" = country ]' 25; then
  say "  mode=$(mode_now); rule: $(anchor_rule)"
  b=$(rule_counter) || b=""
  curl -s -o /dev/null -m 3 --interface "${REAL}" "http://${CANARY_NET}/"; rc1=$?
  curl -s -o /dev/null -k -m 3 --interface "${REAL}" https://160.79.104.10/; rc2=$?
  a=$(rule_counter) || a=""
  say "  control packet: curl ${rc1}; Anthropic address 160.79.104.10: curl ${rc2}; rule counter ${b:-?} -> ${a:-?}"
  [ "$(mode_now)" = country ] && [ -n "${b}" ] && [ -n "${a}" ] && [ "${a}" -ge $((b + 2)) ] && [ "${rc1}" = 7 ] && [ "${rc2}" != 0 ] && ok=1
else
  say "  the lock did not close within 25 s (mode=$(mode_now)): nothing is sent to Anthropic"
fi
verdict "blocked country: kernel dropped 2 of 2 packets (counter +$(( ${a:-0} - ${b:-0} )))" "${ok}"
restore_conf
wait_for '[ "$(mode_now)" = open ] && is_link_id "$(pin_now)"' 25
say "  mode=$(mode_now) pinned=$(pin_now)"
[ "$(mode_now)" = open ]; verdict "config restored: open again on the direct network" $((! $? ))

step "4. Turn the VPN ON"
say "  >>> Turn ON the VPN in your VPN app now. Waiting up to 180 s. <<<"
wait_for 'is_vpn_name "$(route_iface)"' 180
wait_for '[ "$(mode_now)" = open ] || [ "$(mode_now)" = country ]' 30
say "  route=$(route_iface) mode=$(mode_now) pinned=$(pin_now)"
say "  exit: $(grep -v '^at=' "${CVL_VAR}/country" 2>/dev/null | tr '\n' ' ')"
claude_from_real=$(lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk -v r="${REAL}:" 'tolower($1) ~ /^claude/ && index($9, r) == 1 && $9 ~ /->(160\.79\.|\[2607:6bc0)/ { n++ } END { print n + 0 }')
say "  Claude connections from ${REAL} to Anthropic after the VPN came on: ${claude_from_real}"
ok=0
{ [ "$(mode_now)" = open ] && ! is_link_id "$(pin_now)" || [ "$(mode_now)" = country ]; } && [ "${claude_from_real}" = 0 ] && ok=1
verdict "VPN on: the lock follows the tunnel, 0 Claude connections past it" "${ok}"

step "Acceptance summary"
printf '%s' "${RESULTS}" | sed 's/^/  /'
say ""
say "  failed: ${FAILS}; log: ${OUT}"
exit "${FAILS}"
