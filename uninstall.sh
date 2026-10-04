#!/bin/bash
# claude-vpn-lock: remove everything.
#
#   bash uninstall.sh --dry-run     # what would be removed; changes nothing
#   sudo bash uninstall.sh          # remove
#
# Afterwards the machine is compared with the snapshot the installer took before installing
# (/etc/hosts, /etc/pf.conf, whether pf is enabled, pf anchors, the main ruleset).

set -uo pipefail
export LC_ALL=C

SRC="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "${SRC}/lib/common.sh"

DRY=0
QUIET=0
for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY=1 ;;
    --rollback) QUIET=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) die "unknown argument: ${arg}" ;;
  esac
done

if [ "${DRY}" = 1 ]; then
  step "Dry run: what would be done"
  cat <<PLAN
  - stop and unload the daemon ${CVL_LABEL}, delete ${CVL_PLIST}
  - empty the pf anchor ${CVL_ANCHOR} (and the test anchor ${CVL_TEST_ANCHOR})
  - release our reference that keeps pf enabled (pfctl -X <token>): pf switches off only if
    nothing else holds it
  - delete ${CVL_DEST_DIR} (daemon, settings, state) and ${CVL_LOG}
    (the log, the settings and the snapshot are copied to ~/Library/Logs/claude-vpn-lock first)
  - compare the machine with the snapshot taken before install
PLAN
  step "Current state"
  say "  installed daemon: $(grep -oE '^VERSION=[0-9.]+' "${CVL_DAEMON}" 2>/dev/null | head -1 | cut -d= -f2 | grep . || printf none)"
  say "  LaunchDaemon:     $([ -f "${CVL_PLIST}" ] && printf present || printf none)"
  say "  snapshot:         $(cat "${CVL_SNAP}/taken_at" 2>/dev/null || printf 'none (or not visible without root)')"
  [ "$(id -u)" = 0 ] && say "  pf rule:          $(pfctl -a "${CVL_ANCHOR}" -s rules 2>/dev/null | head -1)"
  say ""
  say "Dry run finished, nothing changed."
  exit 0
fi

[ "$(id -u)" = 0 ] || die "root is required. Run: sudo bash $0"

step "Stop the daemon"
stop_daemon
case $? in
  0) say "  daemon stopped (process exited)" ;;
  1) say "  daemon was not running" ;;
  *) say "  WARNING: daemon unloaded, but its process is alive after 25 s" ;;
esac
[ -f "${CVL_PLIST}" ] && rm -f "${CVL_PLIST}" && say "  deleted ${CVL_PLIST}"

step "pf rules"
for a in "${CVL_ANCHOR}" "${CVL_TEST_ANCHOR}"; do
  r=$(remove_anchor "${a}")
  case "${r}" in
    absent) ;;
    LEFT) say "  anchor ${a}: emptied; the kernel keeps an empty node (0 rules, 0 tables) until reboot" ;;
    *) say "  anchor ${a}: removed (${r})" ;;
  esac
done
token=$(cat "${CVL_VAR}/pf_token" 2>/dev/null)
if [ -n "${token}" ]; then
  pfctl -X "${token}" >/dev/null 2>&1 && say "  released our pf reference (token ${token})" \
    || say "  token ${token} is no longer valid (normal after a reboot)"
fi

step "Compare with the snapshot taken before install"
now_fp=$(fingerprint)
if [ -f "${CVL_SNAP}/fingerprint" ]; then
  diffs=0
  while IFS= read -r line; do
    key=${line%% *}
    case "${key}" in
      launchd_job|lock_files) continue ;;   # expected to differ until the files are removed below
      pf_empty_nodes) say "  note        empty pf nodes: ${line#* } (0 rules, 0 tables; gone after reboot)"; continue ;;
    esac
    was=$(grep "^${key} " "${CVL_SNAP}/fingerprint" | head -1)
    if [ "${was}" = "${line}" ]; then
      say "  same        ${key}"
    else
      diffs=$((diffs + 1))
      say "  DIFFERENT   ${key}"
      say "      before: ${was#* }"
      say "      now:    ${line#* }"
    fi
  done <<<"${now_fp}"
  if ! cmp -s /etc/hosts "${CVL_SNAP}/hosts"; then
    say "  /etc/hosts differs from the snapshot (changed by something else since install?):"
    diff "${CVL_SNAP}/hosts" /etc/hosts | sed 's/^/      /' | head -20
  fi
  [ "${diffs}" = 0 ] && say "  RESULT: the machine matches the snapshot" \
    || say "  RESULT: ${diffs} differences. pf_status may differ if something else enabled pf (AirDrop, the firewall)."
else
  say "  no snapshot - nothing to compare with"
fi

step "Delete files"
LOGS=$(cvl_user_logs) || LOGS=""
if [ -n "${LOGS}" ] && [ -s "${CVL_LOG}" ]; then
  dest="${LOGS}/daemon-$(date +%Y%m%d-%H%M%S).log"
  cp "${CVL_LOG}" "${dest}" && chown "$(cvl_user)" "${dest}" && say "  log saved: ${dest}"
fi
if [ -n "${LOGS}" ] && { [ -d "${CVL_SNAP}" ] || [ -f "${CVL_CONF}" ]; }; then
  keep="${LOGS}/snapshot-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "${keep}"
  cp -p "${CVL_SNAP}"/* "${keep}/" 2>/dev/null
  cp -p "${CVL_CONF}" "${keep}/" 2>/dev/null
  chown -R "$(cvl_user)" "${keep}" 2>/dev/null
  say "  snapshot and settings saved: ${keep}"
fi
for f in "${CVL_DEST_DIR}" "${CVL_LOG}" "${CVL_LOG}.1" /var/log/claude-vpn-lock.out.log /var/log/claude-vpn-lock.err.log; do
  [ -e "${f}" ] && rm -rf "${f}" && say "  deleted ${f}"
done

step "Result"
say "  launchd: $(launchctl print "system/${CVL_LABEL}" >/dev/null 2>&1 && printf 'daemon STILL VISIBLE' || printf 'no daemon')"
say "  files:   $(ls -d "${CVL_DEST_DIR}" "${CVL_CONF}" "${CVL_VAR}" "${CVL_PLIST}" 2>/dev/null | tr '\n' ' ' | sed 's/^$/none/')"
[ "${QUIET}" = 1 ] || say "  Done. Claude now works without the lock."
exit 0
