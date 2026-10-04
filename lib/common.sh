# Shared constants and helpers for the claude-vpn-lock scripts. Sourced, never executed.
# shellcheck shell=bash

CVL_LABEL=io.github.avlasvlad.claude-vpn-lock
# Root-owned on every Mac. Not /usr/local: with Homebrew on Intel it belongs to the user.
CVL_DEST_DIR=/opt/claude-vpn-lock
CVL_DAEMON="${CVL_DEST_DIR}/claude-vpn-lock-daemon.sh"
CVL_CONF="${CVL_DEST_DIR}/claude-vpn-lock.conf"
CVL_VAR="${CVL_DEST_DIR}/state"
CVL_SNAP="${CVL_VAR}/snapshot"
CVL_PLIST=/Library/LaunchDaemons/io.github.avlasvlad.claude-vpn-lock.plist
CVL_LOG=/var/log/claude-vpn-lock.log
CVL_ANCHOR=com.apple/000.ClaudeVPNLock
CVL_TEST_ANCHOR=com.apple/001.ClaudeVPNLockTest

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# The person who ran sudo, and a log folder they can open.
cvl_user() { printf '%s' "${SUDO_USER:-$(stat -f %Su /dev/console 2>/dev/null)}"; }
cvl_user_logs() {
  local u home dir
  u=$(cvl_user)
  home=$(dscl . -read "/Users/${u}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
  [ -n "${home}" ] || return 1
  dir="${home}/Library/Logs/claude-vpn-lock"
  mkdir -p "${dir}" 2>/dev/null && chown "${u}" "${dir}" 2>/dev/null
  printf '%s' "${dir}"
}

# Stops the launchd job and waits until its process is gone. bootout returns before the daemon
# exits, and its TERM trap still writes "STOP" to the log: a log removed in that window is
# created again. Exit: 0 stopped, 1 was not running, 2 still alive after 25 s.
stop_daemon() {
  local pid
  launchctl print "system/${CVL_LABEL}" >/dev/null 2>&1 || return 1
  pid=$(launchctl print "system/${CVL_LABEL}" 2>/dev/null | awk '$1 == "pid" && $2 == "=" { print $3; exit }')
  # A failed bootout is judged by what follows, not by its exit code.
  launchctl bootout "system/${CVL_LABEL}" >/dev/null 2>&1
  # 25 s: the TERM trap waits for a running exit check (COUNTRY_WAIT_MAX, 8 s), and launchd
  # itself sends SIGKILL after 20 s.
  for _ in $(seq 1 50); do
    if ! launchctl print "system/${CVL_LABEL}" >/dev/null 2>&1 \
       && { [ -z "${pid}" ] || ! kill -0 "${pid}" 2>/dev/null; }; then
      return 0
    fi
    sleep 0.5
  done
  return 2
}

# Packets matched by our anchor's rule; fails when pfctl does not answer.
rule_counter() {
  local out
  out=$(pfctl -a "${CVL_ANCHOR}" -v -s rules 2>/dev/null) || return 1
  [ -n "${out}" ] || return 1
  printf '%s\n' "${out}" | awk '
    /Packets:/ { for (i = 1; i <= NF; i++) if ($i == "Packets:") s += $(i + 1) }
    END { print s + 0 }'
}

# The one request to Anthropic made by install.sh and by check.sh (P5); never repeated.
# Sent only while the route goes through the pinned tunnel. A failure is attributed by our
# rule's counter over the request, and the counter is trusted only if pfctl answered, the rule
# text did not change, the counter did not go down and the daemon log shows no reload that
# dropped counted packets ("PF rule being replaced had blocked N" is logged whenever N > 0).
# Needs the daemon's functions (route_iface, first_addr). Prints evidence and a verdict.
# IPv4 only (-4): the pinned tunnel address is IPv4, and on an IPv6 network curl would first try
# IPv6 past an IPv4-only tunnel, which the rule drops as it should.
# Exit: 0 answered through the tunnel (packets the rule dropped meanwhile from other programs are
# reported, not counted against it); 3 no answer and the rule dropped Anthropic packets outside
# the tunnel meanwhile; 4 not measured; 5 answered from an address other than the tunnel's.
claude_tunnel_probe() {
  local pin tun_if tun_addr ifc log_from rule_b rule_a b a resp crc code src valid=1
  pin=$(cat "${CVL_VAR}/pinned" 2>/dev/null)
  tun_if=${pin%% *}
  tun_addr=$(first_addr "${pin}")
  ifc=$(route_iface)
  if [ -z "${tun_if}" ] || [ "${ifc}" != "${tun_if}" ]; then
    printf 'NOT MEASURED: the route to Anthropic goes via %s, the rule is pinned to %s; no request sent\n' \
      "${ifc:-?}" "${tun_if:-?}"
    return 4
  fi
  log_from=$(( $(stat -f %z "${CVL_LOG}" 2>/dev/null || printf 0) + 1 ))
  rule_b=$(pfctl -a "${CVL_ANCHOR}" -s rules 2>/dev/null | head -1)
  b=$(rule_counter) || b=""
  resp=$(curl -4 -s -m 12 -o /dev/null -w '%{http_code} %{local_ip}' https://api.anthropic.com/ 2>/dev/null)
  crc=$?
  a=$(rule_counter) || a=""
  rule_a=$(pfctl -a "${CVL_ANCHOR}" -s rules 2>/dev/null | head -1)
  code=${resp%% *}
  src=${resp#* }
  [ "${src}" = "${resp}" ] && src=""
  { [ -n "${b}" ] && [ -n "${a}" ] && [ -n "${rule_b}" ] && [ "${rule_b}" = "${rule_a}" ] \
    && [ "${a}" -ge "${b}" ]; } 2>/dev/null || valid=0
  tail -c +"${log_from}" "${CVL_LOG}" 2>/dev/null \
    | grep -qE 'PF rule being replaced|lost its rule|ERROR loading' && valid=0
  printf 'https://api.anthropic.com/ -> HTTP %s from %s (curl %s); rule counter %s -> %s%s\n' \
    "${code:-none}" "${src:-none}" "${crc}" "${b:-?}" "${a:-?}" \
    "$([ "${valid}" = 1 ] || printf '; counter NOT OBTAINED (pfctl did not answer or the rule was reloaded)')"
  if [ -n "${code}" ] && [ "${code}" != 000 ]; then
    if [ "${src}" = "${tun_addr}" ]; then
      if [ "${valid}" != 1 ]; then
        printf 'OK: Claude answers through the tunnel (%s), but the counter was not obtained\n' "${tun_addr}"
      elif [ "${a}" -gt "${b}" ]; then
        printf 'OK: Claude answers through the tunnel (%s); meanwhile the rule dropped %s packets to Anthropic from other programs outside the tunnel\n' \
          "${tun_addr}" "$((a - b))"
      else
        printf 'OK: Claude answers through the tunnel (%s), the rule did not fire\n' "${tun_addr}"
      fi
      return 0
    fi
    printf 'ERROR: the answer came from %s, not from the tunnel address %s\n' "${src:-none}" "${tun_addr:-?}"
    return 5
  fi
  if [ "${valid}" = 1 ] && [ "${a}" -gt "${b}" ]; then
    printf 'LEAK BLOCKED: no answer, and meanwhile the rule dropped %s packets to Anthropic outside tunnel %s\n' \
      "$((a - b))" "${tun_if}"
    return 3
  fi
  if [ "${valid}" = 1 ]; then
    printf 'NOT MEASURED: Anthropic did not answer (curl %s) and the rule dropped nothing: the VPN was silent, not the lock\n' "${crc}"
  else
    printf 'NOT MEASURED: Anthropic did not answer (curl %s) and the counter was not obtained: cause unknown\n' "${crc}"
  fi
  return 4
}

# What the machine looks like from the lock's point of view. Two fingerprints taken around
# a step that must change nothing have to be identical line for line.
fingerprint() {
  printf 'hosts_sha      %s\n' "$(shasum -a 256 </etc/hosts | cut -c1-16)"
  printf 'pf.conf_sha    %s\n' "$(shasum -a 256 </etc/pf.conf | cut -c1-16)"
  printf 'pf.anchors_dir %s\n' "$(ls /etc/pf.anchors 2>/dev/null | tr '\n' ' ')"
  printf 'pf_status      %s\n' "$(pfctl -s info 2>/dev/null | awk '/^Status:/ {print $2}')"
  # anchors that hold rules or tables; empty nodes are listed apart (pf keeps them until reboot)
  printf 'pf_anchors     %s\n' "$(pf_anchor_census active)"
  printf 'pf_empty_nodes %s\n' "$(pf_anchor_census empty)"
  printf 'pf_main_rules  %s\n' "$(pfctl -s rules 2>/dev/null | shasum -a 256 | cut -c1-16)"
  printf 'launchd_job    %s\n' "$(launchctl print "system/${CVL_LABEL}" >/dev/null 2>&1 && printf present || printf absent)"
  printf 'lock_files     %s\n' "$(ls -d "${CVL_DEST_DIR}" "${CVL_CONF}" "${CVL_VAR}" "${CVL_PLIST}" "${CVL_LOG}" 2>/dev/null | tr '\n' ' ')"
}

pf_anchor_census() {
  local a r t
  for a in $(pfctl -v -s Anchors 2>/dev/null); do
    r=$(pfctl -a "${a}" -s rules 2>/dev/null | grep -c .)
    t=$(pfctl -a "${a}" -s Tables 2>/dev/null | grep -c .)
    if [ $((r + t)) -gt 0 ]; then
      [ "$1" = active ] && printf '%s(r%s,t%s) ' "${a}" "${r}" "${t}"
    else
      [ "$1" = empty ] && printf '%s ' "${a}"
    fi
  done
}

# Rules that are loaded but would only start working once pf is switched on: anything in the main
# ruleset besides the stock "com.apple/*" hooks, and any anchor with rules besides the stock
# com.apple one and ours. Empty output: nothing would change when pf is enabled.
foreign_pf_rules() {
  local a n
  { pfctl -s rules; pfctl -s nat; } 2>/dev/null \
    | grep -v -E '^(scrub-anchor|nat-anchor|rdr-anchor|binat-anchor|dummynet-anchor|anchor) "com\.apple/\*"' \
    | sed 's/^/main ruleset: /'
  for a in $(pfctl -v -s Anchors 2>/dev/null); do
    case "${a}" in com.apple|"${CVL_ANCHOR}"|"${CVL_TEST_ANCHOR}") continue ;; esac
    n=$(pfctl -a "${a}" -s rules 2>/dev/null | grep -c .)
    [ "${n}" -gt 0 ] && printf 'anchor %s: %s rules\n' "${a}" "${n}"
  done
  return 0
}

# pf keeps an emptied anchor in its tree; flushing an anchor that does not exist creates one.
anchor_listed() { pfctl -v -s Anchors 2>/dev/null | awk '{ print $1 }' | grep -qxF "$1"; }

# Empties an anchor and makes the kernel drop the node. Prints how it went: absent | tables+rules
# | all | LEFT. Tables go first: an anchor that still owns a table is not removed when its rules go.
# `-a <anchor> -F all` touches only that anchor's tables and rules (states are global and are
# flushed by -F all only without -a); it is still used only when pf holds no states at all.
# The macOS kernel may keep the empty node until reboot whatever is done ("LEFT"); harmless.
remove_anchor() {
  local a="$1"
  anchor_listed "${a}" || { printf 'absent'; return 0; }
  pfctl -a "${a}" -F Tables >/dev/null 2>&1
  pfctl -a "${a}" -F rules >/dev/null 2>&1
  anchor_listed "${a}" || { printf 'tables+rules'; return 0; }
  if [ "$(pfctl -s states 2>/dev/null | grep -c .)" = 0 ]; then
    pfctl -a "${a}" -F all >/dev/null 2>&1
    anchor_listed "${a}" || { printf 'all'; return 0; }
  fi
  printf 'LEFT'
  return 1
}
