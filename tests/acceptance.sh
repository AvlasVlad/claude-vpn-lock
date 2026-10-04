#!/bin/bash
# claude-vpn-lock: maintainer acceptance run, the whole cycle in one command.
#
#   sudo bash tests/acceptance.sh [--with-vpn-off]
#
# This is a script for maintainers, not for normal use. It installs and removes the lock on this
# machine, so run it only on a machine you can afford to change.
#
# 1. Fingerprint of the machine -> dry runs of install and uninstall -> fingerprint (must match).
# 2. Install, then the full check.sh.
# 3. Uninstall and compare with the snapshot taken before the install.
# 4. Install again and run the short check; the lock stays installed.
# --with-vpn-off: after the full check you turn the VPN off and on again (vpn-off-test.sh).
# Full log: ~/Library/Logs/claude-vpn-lock/acceptance-<time>.log

set -uo pipefail
export LC_ALL=C

SRC="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${SRC}/lib/common.sh"
[ "$(id -u)" = 0 ] || die "must run as root: sudo bash $0"

LOGS=$(cvl_user_logs) || die "could not find the user's log folder"
OUT="${LOGS}/acceptance-$(date +%Y%m%d-%H%M%S).log"
touch "${OUT}" && chown "$(cvl_user)" "${OUT}"
exec > >(tee -a "${OUT}") 2>&1

RESULTS=""
note() { RESULTS="${RESULTS}$(printf '%-48s %s' "$1" "$2")"$'\n'; }
# Installer exit codes (install.sh header): the protection stands in 0, 3, 4 and 5.
note_install() {
  case "$2" in
    0) note "$1" "OK (Claude answers through the tunnel)" ;;
    3) note "$1" "installed; WARNING: something sends to Anthropic outside the VPN (blocked)" ;;
    4) note "$1" "installed; Claude through the tunnel NOT MEASURED" ;;
    5) note "$1" "installed; FAIL: the answer did not come from the tunnel address" ;;
    *) note "$1" "FAIL (${2})"; return 1 ;;
  esac
}
# check.sh: number of failures; 100 = none failed, some not measured.
check_result() {
  case "$1" in
    0) printf OK ;;
    100) printf 'no failures; some NOT MEASURED (see above)' ;;
    *) printf 'FAIL (%s)' "$1" ;;
  esac
}
t_start=$(date +%s)
VPN_OFF=0
[ "${1:-}" = "--with-vpn-off" ] && VPN_OFF=1
say "claude-vpn-lock: acceptance, $(date '+%Y-%m-%d %H:%M:%S'), log ${OUT}"

if [ -x "${CVL_DAEMON}" ]; then
  step "Preparation: the lock is already installed; removing it to start from a clean machine"
  # Keeps only the lines of uninstall.sh that describe anchors, references and the final result.
  bash "${SRC}/uninstall.sh" | grep -E 'anchor|reference|RESULT|deleted /usr' | sed 's/^/  /'
  say "  pf anchors after preparation: $(pfctl -v -s Anchors 2>/dev/null | tr -s ' \n' ' ')"
fi

step "0. Dry runs change nothing (even as root)"
fp0=$(fingerprint)
bash "${SRC}/install.sh" --dry-run >"${LOGS}/.dry-install.txt" 2>&1; rc_i=$?
bash "${SRC}/uninstall.sh" --dry-run >"${LOGS}/.dry-uninstall.txt" 2>&1; rc_u=$?
fp1=$(fingerprint)
sed 's/^/  | /' "${LOGS}/.dry-install.txt"
sed 's/^/  | /' "${LOGS}/.dry-uninstall.txt"
rm -f "${LOGS}/.dry-install.txt" "${LOGS}/.dry-uninstall.txt"
if [ "${fp0}" = "${fp1}" ]; then
  say "  fingerprint is the same before and after the dry runs (${rc_i}/${rc_u} are the exit codes)"
  note "dry runs change nothing" "OK"
else
  say "  FINGERPRINT CHANGED:"; diff <(printf '%s\n' "${fp0}") <(printf '%s\n' "${fp1}") | sed 's/^/    /'
  note "dry runs change nothing" "FAIL"
fi
printf '%s\n' "${fp0}" | sed 's/^/  before: /'

step "1. Install"
bash "${SRC}/install.sh"; irc=$?
note_install "install" "${irc}" || { say "install failed; not going on"; printf '\n%s' "${RESULTS}"; exit 1; }

step "2. Full check"
bash "${SRC}/check.sh" --heal-tests; rc=$?
note "full check (P0-P11)" "$(check_result "${rc}")"

if [ "${VPN_OFF}" = 1 ]; then
  step "2b. You turn the VPN off: Claude does not connect outside the tunnel"
  bash "${SRC}/vpn-off-test.sh"; rc=$?
  note "VPN off -> blocked, VPN on -> open" "$([ "${rc}" = 0 ] && printf OK || printf 'FAIL (%s)' "${rc}")"
fi

step "3. Uninstall and compare with the snapshot"
snap_fp=$(cat "${CVL_SNAP}/fingerprint" 2>/dev/null)
bash "${SRC}/uninstall.sh"
fp2=$(fingerprint)
diffs=$(diff <(printf '%s\n' "${snap_fp}" | grep -v -e '^launchd_job' -e '^lock_files' -e '^pf_empty_nodes') \
             <(printf '%s\n' "${fp2}"     | grep -v -e '^launchd_job' -e '^lock_files' -e '^pf_empty_nodes'))
say "  empty pf nodes (no rules, no tables) before the install: $(printf '%s\n' "${snap_fp}" | sed -n 's/^pf_empty_nodes *//p')"
say "  empty pf nodes after the uninstall:                      $(printf '%s\n' "${fp2}" | sed -n 's/^pf_empty_nodes *//p')"
leftovers=$(printf '%s\n' "${fp2}" | grep -e '^launchd_job' -e '^lock_files')
say "  after the uninstall:"; printf '%s\n' "${fp2}" | sed 's/^/    /'
if [ -z "${diffs}" ] && printf '%s' "${leftovers}" | grep -q 'launchd_job *absent' \
   && [ -z "$(printf '%s\n' "${leftovers}" | sed -n 's/^lock_files *//p' | tr -d ' ')" ]; then
  note "uninstall returns the machine to the snapshot" "OK"
else
  say "  differences from the snapshot:"; printf '%s\n' "${diffs}" | sed 's/^/    /'
  note "uninstall returns the machine to the snapshot" "FAIL"
fi

step "4. Install again and the short check"
bash "${SRC}/install.sh"; irc=$?
if note_install "second install" "${irc}"; then
  bash "${SRC}/check.sh" --short; rc=$?
  note "short check after it" "$(check_result "${rc}")"
fi

step "Acceptance summary ($(( $(date +%s) - t_start )) s)"
printf '%s' "${RESULTS}" | sed 's/^/  /'
say ""
say "  log: ${OUT}"
