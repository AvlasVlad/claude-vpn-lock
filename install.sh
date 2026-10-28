#!/bin/bash
# claude-vpn-lock: install.
#
#   bash install.sh --dry-run       # plan and checks; changes nothing (sudo not needed)
#   sudo bash install.sh            # install
#   sudo bash install.sh --check    # install, then run the full check (check.sh)
#   --enable-pf-anyway              # see "pf is off but other rules are loaded" below
#
# Installs the daemon, its settings and state under /opt/claude-vpn-lock (owned by root) and a
# LaunchDaemon (start at boot, restart on crash). In pf: one anchor, com.apple/000.ClaudeVPNLock,
# under the stock "com.apple/*" hook, plus our own reference that keeps pf enabled.
# /etc/pf.conf and /etc/hosts are NOT edited. pf is off by default on macOS; if it is off and
# other rules are loaded, switching it on would make them work too, so the installer stops and
# lists them (--enable-pf-anyway goes ahead).
#
# After starting: a test packet sent past the tunnel must be dropped by the kernel (otherwise
# everything is rolled back), then one request to Anthropic through the tunnel. A failure of
# that request does not remove the lock.
# Exit: 0 all verified; 3 something sends Anthropic traffic outside the VPN (dropped);
# 4 Claude through the tunnel not measured; 5 answer not from the tunnel address;
# anything else: the install failed and was rolled back.

set -uo pipefail
export LC_ALL=C

SRC="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "${SRC}/lib/common.sh"

DRY=0
CHECK=0
PF_ANYWAY=0
for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY=1 ;;
    --check) CHECK=1 ;;
    --enable-pf-anyway) PF_ANYWAY=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) die "unknown argument: ${arg}" ;;
  esac
done

DAEMON_SRC="${SRC}/lib/claude-vpn-lock-daemon.sh"
PLIST_SRC="${SRC}/lib/claude-vpn-lock.plist"
[ -f "${DAEMON_SRC}" ] || die "missing ${DAEMON_SRC}"
[ -f "${PLIST_SRC}" ] || die "missing ${PLIST_SRC}"

# The daemon's own functions (route, tunnel identity, rule text) are the single source of truth.
# Their scratch state goes to a temp folder: the dry run must not write anything on the machine.
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/claude-vpn-lock-install.XXXXXX") || die "mktemp failed"
trap 'rm -rf "${SCRATCH}"' EXIT
CONF_FOR_CHECKS=/dev/null
[ -f "${CVL_CONF}" ] && CONF_FOR_CHECKS="${CVL_CONF}"
CVL_LIB=1 CVL_CONFIG="${CONF_FOR_CHECKS}" CVL_STATE_DIR="${SCRATCH}" CVL_LOG=/dev/null CVL_NO_NOTIFY=1 . "${DAEMON_SRC}"

step "What will be done"
cat <<PLAN
  1. ${CVL_DAEMON}
     the daemon: keeps the pf rule pinned to the verified VPN tunnel
  2. ${CVL_CONF}
     settings (countries, intervals)
  3. ${CVL_PLIST}
     start at boot, restart on crash
  4. pf: anchor ${CVL_ANCHOR} (stock hook "com.apple/*") with the rule
       block return out quick on ! <tunnel> to <Anthropic networks>
     A packet to Anthropic that does NOT leave through the verified tunnel is dropped by the
     kernel at once - from any program, including the VPN app itself.
  5. ${CVL_VAR}  - state, counters, snapshot of the machine before install
  pf is switched on if it is off (other loaded rules: see the checks below).
  NOT changed: /etc/pf.conf, /etc/hosts, VPN settings, apps, other pf rules.
  Remove everything: sudo bash '${SRC}/uninstall.sh'
PLAN

step "Checks"
bash -n "${DAEMON_SRC}" || die "daemon syntax check failed"
say "  daemon: syntax ok"
plutil -lint "${PLIST_SRC}" >/dev/null || die "LaunchDaemon plist is invalid"
say "  LaunchDaemon plist: ok"
for target in closed utun99; do
  if out=$(anchor_text "${target}" | pfctl -n -a "${CVL_ANCHOR}" -f - 2>&1); then
    say "  pf rule (${target}): syntax ok (pfctl -n)"
  else
    die "pf rule (${target}) does not parse: $(printf '%s' "${out}" | grep -i error)"
  fi
done

TUNNEL=$(tunnel_identity) || TUNNEL=""
if [ -z "${TUNNEL}" ]; then
  msg="the route to Anthropic does not go through a VPN (interface $(route_iface)). Turn the VPN on and retry."
  [ "${DRY}" = 1 ] && say "  WARNING: ${msg}" || die "${msg}"
else
  say "  tunnel: ${TUNNEL}"
  COUNTRY_WAIT_MAX=8
  check_exit "$(first_addr "${TUNNEL}")"
  rc=$?
  say "  exit through the tunnel: ${VERDICT}"
  if [ "${rc}" = 1 ]; then
    msg="the VPN exits in a blocked country. Pick another server and retry."
    [ "${DRY}" = 1 ] && say "  WARNING: ${msg}" || die "${msg}"
  fi
fi

step "Current state"
installed_version=$(grep -oE '^VERSION=[0-9.]+' "${CVL_DAEMON}" 2>/dev/null | head -1 | cut -d= -f2)
say "  installed daemon: ${installed_version:-none}, LaunchDaemon: $(launchctl print "system/${CVL_LABEL}" >/dev/null 2>&1 && printf loaded || printf 'not loaded (or not visible without root)')"
if [ "$(id -u)" = 0 ]; then
  say "  pf: $(pfctl -s info 2>/dev/null | awk '/^Status:/ {print $2}'), hook \"com.apple/*\": $(main_has_apple_anchor && printf present || printf MISSING)"
  if ! pf_enabled; then
    FOREIGN=$(foreign_pf_rules)
    if [ -n "${FOREIGN}" ]; then
      say "  WARNING: pf is off, but these rules are loaded and would start working once it is on:"
      printf '%s\n' "${FOREIGN}" | sed 's/^/    /'
    fi
  fi
else
  say "  pf: not visible without root"
fi
if grep -qE '^[0-9].*(anthropic|claude\.(ai|com))' /etc/hosts 2>/dev/null; then
  say "  WARNING: /etc/hosts has active lines that send Claude to another address:"
  grep -nE '^[0-9].*(anthropic|claude\.(ai|com))' /etc/hosts | sed 's/^/    /'
fi

if [ "${DRY}" = 1 ]; then
  say ""
  say "Dry run finished, nothing changed. To install: sudo bash $0"
  exit 0
fi

[ "$(id -u)" = 0 ] || die "root is required. Run: sudo bash $0"
main_has_apple_anchor || die "the main pf ruleset has no \"com.apple/*\" hook - pf is customised here, not installing"
if ! pf_enabled && [ -n "$(foreign_pf_rules)" ] && [ "${PF_ANYWAY}" != 1 ]; then
  die "pf is off, but other rules are loaded (listed above) and would start working once pf is on. If they are meant to be active, rerun with --enable-pf-anyway."
fi

# Root runs what is installed here, so nobody else may be able to change it.
parent=$(dirname "${CVL_DEST_DIR}")
[ -d "${parent}" ] || { mkdir "${parent}" && chown root:wheel "${parent}" && chmod 755 "${parent}"; }
path_trusted "${parent}" || die "${parent} or a folder above it can be changed by a non-root user; not installing"

rollback() {
  say "  ROLLBACK: $*"
  bash "${SRC}/uninstall.sh" --rollback | sed 's/^/    /'
  die "install cancelled; the lock is removed (a previous install too, if there was one); settings and the snapshot were saved to ~/Library/Logs/claude-vpn-lock"
}

step "Snapshot of the machine before install"
mkdir -p "${CVL_DEST_DIR}" "${CVL_VAR}" && chown root:wheel "${CVL_DEST_DIR}" "${CVL_VAR}" && chmod 755 "${CVL_DEST_DIR}" "${CVL_VAR}"
if [ ! -d "${CVL_SNAP}" ]; then
  mkdir -p "${CVL_SNAP}"
  cp -p /etc/hosts "${CVL_SNAP}/hosts"
  cp -p /etc/pf.conf "${CVL_SNAP}/pf.conf"
  fingerprint >"${CVL_SNAP}/fingerprint"
  pfctl -s References >"${CVL_SNAP}/references" 2>/dev/null
  pfctl -s rules >"${CVL_SNAP}/main-rules" 2>/dev/null
  date '+%Y-%m-%dT%H:%M:%S%z' >"${CVL_SNAP}/taken_at"
  say "  ${CVL_SNAP}:"
  sed 's/^/    /' "${CVL_SNAP}/fingerprint"
else
  say "  snapshot already exists (taken $(cat "${CVL_SNAP}/taken_at")), keeping it"
fi

step "Install files (the old daemon, if any, is stopped for a few seconds; the VPN was checked above)"
stop_daemon
case $? in
  0) say "  previous daemon stopped" ;;
  1) say "  no previous daemon running" ;;
  *) say "  WARNING: previous daemon unloaded, but its process is alive after 25 s" ;;
esac
install -o root -g wheel -m 755 "${DAEMON_SRC}" "${CVL_DAEMON}" && say "  ${CVL_DAEMON}"
if [ ! -f "${CVL_CONF}" ]; then
  cat >"${CVL_CONF}" <<'CONF'
# claude-vpn-lock settings. After editing: sudo launchctl kickstart -k system/io.github.avlasvlad.claude-vpn-lock
# Exit countries in which Claude must not be used (two-letter codes, checked through the tunnel).
BLOCKED_COUNTRIES="RU BY"
# Seconds between exit checks while open.
COUNTRY_INTERVAL=30
# A new tunnel whose exit country cannot be checked: open (noted in the log) or closed.
COUNTRY_FAIL=open
# block   - Claude only through a verified VPN tunnel (default).
# country - also allowed WITHOUT a VPN while this network's own exit country is not in
#           BLOCKED_COUNTRIES (checked through the network itself; unknown = closed).
DIRECT_POLICY=block
CONF
  chown root:wheel "${CVL_CONF}"
  chmod 644 "${CVL_CONF}"
fi
say "  ${CVL_CONF}"
install -o root -g wheel -m 644 "${PLIST_SRC}" "${CVL_PLIST}" && say "  ${CVL_PLIST}"
out=$("${CVL_DAEMON}" once 2>&1) || rollback "initial rule load failed: ${out}"
say "  pf rule: ${out}"
case "${out}" in *mode=open*) ;; *) rollback "the tunnel did not pass the check: ${out}" ;; esac

step "Start the daemon"
log_size=$(stat -f %z "${CVL_LOG}" 2>/dev/null || printf 0)
started() { tail -c +"$((log_size + 1))" "${CVL_LOG}" 2>/dev/null | grep 'START claude-vpn-lock ' | tail -1; }
launchctl bootstrap system "${CVL_PLIST}" >/dev/null 2>&1 || launchctl load -w "${CVL_PLIST}" >/dev/null 2>&1 \
  || rollback "launchd did not accept the daemon"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -n "$(started)" ] && break
  sleep 1
done
[ -n "$(started)" ] || rollback "the daemon did not log START within 10 s"
sleep 2
say "  $(started)"
tail -c +"$((log_size + 1))" "${CVL_LOG}" | grep -E 'RESTORE|STATE' | sed 's/^/  /'

step "Verify: a packet past the tunnel is dropped, Claude works through the tunnel"
# The test packet first. A request to Anthropic is sent only after the kernel rule is proven.
"${CVL_DAEMON}" verify | sed 's/^/  /'
"${CVL_DAEMON}" verify >/dev/null 2>&1
vrc=$?
case "${vrc}" in
  0) ;;
  2) say "  WARNING: the test packet could not prove the blocking (no physical interface address, or a direct network is allowed by DIRECT_POLICY=country) - blocking NOT verified" ;;
  *) rollback "the test packet past the tunnel was not dropped" ;;
esac
# One request to Anthropic, never repeated; see claude_tunnel_probe in lib/common.sh. Its
# failure never rolls back: the counter tells "the VPN was silent" from "something sends
# Anthropic past the tunnel", and removing the lock fixes neither.
CLAUDE_RC=0
if [ "${vrc}" = 0 ]; then
  probe=$(claude_tunnel_probe)
  CLAUDE_RC=$?
  printf '%s\n' "${probe}" | sed 's/^/  /'
  case "${CLAUDE_RC}" in
    3)
      say "  So something on this Mac sends Anthropic traffic outside the tunnel, and the rule stops it:"
      say "  usually the VPN app's own direct / bypass / split-tunnel rules, or IPv6 traffic when the VPN"
      say "  carries only IPv4. The lock stays. If Claude does not work through this VPN, route Anthropic"
      say "  through the VPN's proxy in the VPN app."
      say "  Remove the lock: sudo bash '${SRC}/uninstall.sh'" ;;
    4) say "  The lock stays; not retrying. Check later: sudo bash '${SRC}/check.sh' --short" ;;
    5) say "  The lock is in place, but the rule let this answer through. Investigate: sudo bash '${SRC}/check.sh'" ;;
  esac
else
  CLAUDE_RC=4
  say "  NOT MEASURED: no request to Anthropic sent - blocking was not proven by the test packet"
fi

if [ "${CHECK}" = 1 ]; then
  step "Full check"
  bash "${SRC}/check.sh" || say "  the check found problems - see above"
fi

step "Done"
"${CVL_DAEMON}" status | sed 's/^/  /'
say ""
say "  daemon log:    ${CVL_LOG}"
say "  status:        sudo ${CVL_DAEMON} status"
say "  check:         sudo bash '${SRC}/check.sh'"
say "  remove:        sudo bash '${SRC}/uninstall.sh'"
exit "${CLAUDE_RC}"
