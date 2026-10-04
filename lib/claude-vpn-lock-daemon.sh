#!/bin/bash
# claude-vpn-lock: traffic to Anthropic may leave this Mac only through a verified VPN tunnel.
#
# THE GUARANTEE is one pf rule in the anchor com.apple/000.ClaudeVPNLock:
#
#     block return out quick on ! utunN to <claude_nets>      (a verified tunnel exists)
#     block return out quick to <claude_nets>                 (no verified tunnel)
#
# The kernel applies it to every packet of every process: Claude.app, the CLI, the VS Code
# extension, and the VPN extension itself when it sends a flow "direct" past its own tunnel.
# The rule names the one interface that was verified, so a tunnel that disappears, or comes
# back under another name, is blocked with no reaction time at all; the daemon is not on the
# packet path. The anchor hangs off the stock `anchor "com.apple/*"` in /etc/pf.conf, so
# /etc/pf.conf is never edited.
#
# THE DAEMON keeps that rule correct:
#   - pins it to the VPN interface that carries the route to Anthropic, after checking through
#     that interface that the exit country is not blocked (RU, BY by default);
#   - re-checks the exit every COUNTRY_INTERVAL seconds and blocks while it is RU/BY;
#   - re-pins on interface events (route monitor) and every TICK seconds;
#   - holds its own pf enable reference and re-loads the anchor if something flushed it;
#   - learns addresses of Anthropic hosts that live outside Anthropic's own network.
#
# Commands: run | once | status | verify | version
# Sourced with CVL_LIB=1 it only defines functions (used by check.sh and the tests).
# CVL_* environment variables replace paths and binaries for the unprivileged simulation.

set -uo pipefail
export LC_ALL=C

VERSION=1.0.0

# Everything lives under /opt/claude-vpn-lock, owned by root. Not /usr/local: on an Intel Mac
# with Homebrew /usr/local/* belongs to the user, who could then swap what root runs.
CONFIG="${CVL_CONFIG:-/opt/claude-vpn-lock/claude-vpn-lock.conf}"
STATE_DIR="${CVL_STATE_DIR:-/opt/claude-vpn-lock/state}"
LOG="${CVL_LOG:-/var/log/claude-vpn-lock.log}"
ETC_HOSTS="${CVL_HOSTS:-/etc/hosts}"
ANCHOR="${CVL_ANCHOR:-com.apple/000.ClaudeVPNLock}"
PFCTL="${CVL_PFCTL:-/sbin/pfctl}"
ROUTE="${CVL_ROUTE:-/sbin/route}"
IFCONFIG="${CVL_IFCONFIG:-/sbin/ifconfig}"
NETSTAT="${CVL_NETSTAT:-/usr/sbin/netstat}"
CURL="${CVL_CURL:-/usr/bin/curl}"
DSCACHEUTIL="${CVL_DSCACHEUTIL:-/usr/bin/dscacheutil}"

# Defaults; the config file may override any of them.
PINNED_NETS="160.79.104.0/21 2607:6bc0::/32"   # Anthropic, PBC (whois AP-2440)
CANARY_NET="203.0.113.7"                       # TEST-NET-3: lets verify prove the real rule
ROUTE_PROBE="160.79.104.10"                    # only asked of the routing table, never sent to
# Hosts Claude talks to (strings of Claude Code and Claude.app, ~/Library/Logs/Claude). Most sit in
# PINNED_NETS; the rest are dedicated Google Cloud load balancers (s-cdn, a-cdn.anthropic.com,
# assets, downloads) and the telemetry/crash intakes. Deliberately NOT here: names on shared CDNs
# (a-cdn.claude.ai on CloudFront, *.mcp.claude.com on Google front ends, status.claude.com):
# their addresses serve thousands of other sites, so they cannot be told apart by address.
LEARN_DOMAINS="api.anthropic.com claude.ai platform.claude.com console.anthropic.com mcp-proxy.anthropic.com code.claude.com a.claude.ai a-api.anthropic.com assets-proxy.anthropic.com www.anthropic.com releases.claude.com downloads.claude.ai a-cdn.anthropic.com s-cdn.anthropic.com assets.claude.ai statsig.anthropic.com http-intake.logs.us5.datadoghq.com o1158394.ingest.us.sentry.io"
LEARN_INTERVAL=1800
LEARN_MAX_AGE=2592000
BLOCKED_COUNTRIES="RU BY"
COUNTRY_URLS="https://1.1.1.1/cdn-cgi/trace https://www.cloudflare.com/cdn-cgi/trace https://ipinfo.io/json"
COUNTRY_INTERVAL=30
COUNTRY_RETRY=5
COUNTRY_WAIT_MAX=8
COUNTRY_FAIL=open
TICK=5
LOG_MAX_BYTES=5000000

# The config is sourced as code by root, so it is read only if nobody else can change it: the
# file and every folder above it are owned by root (or by the current user, in the simulation)
# and not writable by group or others.
path_trusted() {
  local p="$1" me owner perm
  me=$(id -u)
  while :; do
    owner=$(stat -f %u "${p}" 2>/dev/null) || return 1
    perm=$(stat -f %Lp "${p}" 2>/dev/null) || return 1
    [ "${owner}" = 0 ] || [ "${owner}" = "${me}" ] || return 1
    [ $(( 8#${perm} & 022 )) = 0 ] || return 1
    [ "${p}" = / ] && return 0
    p=$(dirname "${p}")
  done
}
CONFIG_IGNORED=""
if [ -r "${CONFIG}" ]; then
  if path_trusted "${CONFIG}"; then
    # shellcheck disable=SC1090
    . "${CONFIG}"
  else
    CONFIG_IGNORED=1
  fi
fi

MODE_FILE="${STATE_DIR}/mode"
PIN_FILE="${STATE_DIR}/pinned"
COUNTRY_FILE="${STATE_DIR}/country"
COUNTER_FILE="${STATE_DIR}/counters"
LEARNED_FILE="${STATE_DIR}/learned"
NETS_FILE="${STATE_DIR}/nets"
TOKEN_FILE="${STATE_DIR}/pf_token"
NOTIFY_DIR="${STATE_DIR}/notified"

MODE=closed        # open | closed | country
PINNED_ID=""       # "<iface> <index> <generation> <addrs>" of the verified tunnel
PINNED_IF=""
LAST_COUNTRY=0
UNKNOWN_STREAK=0
VERDICT=""

# ------------------------------------------------------------------ plumbing

log() {
  local line
  line="$(date '+%Y-%m-%dT%H:%M:%S%z') $*"
  printf '%s\n' "${line}" >>"${LOG}" 2>/dev/null
  [ -n "${CVL_VERBOSE:-}" ] && printf '%s\n' "${line}" >&2
  return 0
}

rotate_log() {
  local size
  size=$(stat -f %z "${LOG}" 2>/dev/null || printf 0)
  [ "${size}" -gt "${LOG_MAX_BYTES}" ] 2>/dev/null && mv -f "${LOG}" "${LOG}.1"
  return 0
}

# The background learner writes counters too. Without the lock two read-modify-write cycles
# overlap and one update is lost (about half of 400 increments were lost; tests/sim.sh scenario 26).
# mkdir is atomic; bash 3.2 has no flock. Counters are diagnostics: after 1 s of waiting the lock
# is taken over, and callers update counters only after the pf work is done, so a lock left by a
# killed process never delays the rule. Daemon start removes a leftover lock.
counter_add() {
  local key="$1" add="${2:-1}" value=0 others tmp lock="${COUNTER_FILE}.lock" i
  for i in $(seq 1 20); do
    mkdir "${lock}" 2>/dev/null && break
    [ "${i}" = 20 ] && { rm -rf "${lock}"; mkdir "${lock}" 2>/dev/null; }
    sleep 0.05
  done
  tmp="${COUNTER_FILE}.tmp.${RANDOM}${RANDOM}"
  [ -f "${COUNTER_FILE}" ] && value=$(sed -n "s/^${key}=//p" "${COUNTER_FILE}" | head -1)
  case "${value}" in ''|*[!0-9]*) value=0 ;; esac
  others=$(grep -v "^${key}=" "${COUNTER_FILE}" 2>/dev/null || true)
  { [ -n "${others}" ] && printf '%s\n' "${others}"; printf '%s=%s\n' "${key}" "$((value + add))"; } \
    >"${tmp}" 2>/dev/null && mv -f "${tmp}" "${COUNTER_FILE}"
  rm -f "${tmp}" 2>/dev/null
  rmdir "${lock}" 2>/dev/null
  return 0
}
counter_bump() { counter_add "$1" 1; }

# Runs a command with a time limit; the watcher must not hold the caller's stdout open.
with_timeout() {
  local secs="$1" pid watcher rc
  shift
  "$@" &
  pid=$!
  ( sleep "${secs}"; kill "${pid}" 2>/dev/null ) >/dev/null 2>&1 &
  watcher=$!
  wait "${pid}" 2>/dev/null
  rc=$?
  kill "${watcher}" 2>/dev/null
  wait "${watcher}" 2>/dev/null
  return "${rc}"
}

# A desktop notification for the person at the console, at most once per key per 10 minutes.
notify() {
  local key="$1" text="$2" uid stamp now
  [ -n "${CVL_NO_NOTIFY:-}" ] && return 0
  mkdir -p "${NOTIFY_DIR}" 2>/dev/null
  stamp="${NOTIFY_DIR}/${key}"
  now=$(date +%s)
  if [ -f "${stamp}" ] && [ $((now - $(stat -f %m "${stamp}" 2>/dev/null || printf 0))) -lt 600 ]; then
    return 0
  fi
  touch "${stamp}" 2>/dev/null
  uid=$(stat -f %u /dev/console 2>/dev/null)
  [ -n "${uid}" ] && [ "${uid}" != 0 ] || return 0
  launchctl asuser "${uid}" /usr/bin/osascript \
    -e "display notification \"${text}\" with title \"claude-vpn-lock\"" >/dev/null 2>&1 &
  return 0
}

# ------------------------------------------------------------------ network facts

route_iface() {
  "${ROUTE}" -n get "${ROUTE_PROBE}" 2>/dev/null | awk '/interface:/ {print $2; exit}'
}

is_vpn_name() {
  case "$1" in utun*|ipsec*|ppp*|tun*|tap*) return 0 ;; *) return 1 ;; esac
}

# "<iface> <index> <generation> <addr>[,<addr>]" of the VPN interface that carries the route
# to Anthropic right now. Status 1 when that route is not a VPN tunnel with an address.
# The kernel marks interfaces owned by a VPN (NetworkExtension) with xflag IS_VPN; a system
# utun (iCloud, Continuity) or a bare ppp link without it never counts as a tunnel.
# index + generation change when the interface is re-created, even under the same name.
tunnel_identity() {
  local ifc
  ifc=$(route_iface)
  [ -n "${ifc}" ] || return 1
  is_vpn_name "${ifc}" || return 1
  "${IFCONFIG}" -v "${ifc}" 2>/dev/null | awk -v ifc="${ifc}" '
    NR == 1 { for (i = 1; i <= NF; i++) if ($i == "index") idx = $(i + 1) }
    /xflags=.*IS_VPN/ || /agent domain:NetworkExtension type:VPN/ { vpn = 1 }
    /generation id:/ { gen = $NF }
    /^[ \t]+inet / { addrs = addrs (addrs != "" ? "," : "") $2 }
    /^[ \t]+inet6 / {
      a = $2; sub(/%.*$/, "", a)
      if (a !~ /^fe80/) addrs = addrs (addrs != "" ? "," : "") a
    }
    END {
      if (addrs == "" || !vpn) exit 1
      print ifc, (idx == "" ? "-" : idx), (gen == "" ? "-" : gen), addrs
    }'
}

# "<iface> <index> <generation>": the interface instance, without its addresses.
instance_of() { printf '%s\n' "$1" | awk '{ print $1, $2, $3 }'; }

first_addr() { printf '%s\n' "$1" | awk '{ split($4, a, ","); print a[1] }'; }

# Address of the physical interface behind the non-VPN default route (diagnostics only).
direct_addr() {
  local ifc
  ifc=$("${NETSTAT}" -rn -f inet 2>/dev/null \
        | awk '$1 == "default" && $NF !~ /^(utun|ipsec|ppp|tun|tap)/ { print $NF; exit }')
  [ -n "${ifc}" ] || return 1
  "${IFCONFIG}" "${ifc}" 2>/dev/null | awk '/[ \t]inet / { print $2; exit }'
}

# ------------------------------------------------------------------ pf

pf_enabled() { "${PFCTL}" -s info 2>/dev/null | grep -q 'Status: Enabled'; }

main_has_apple_anchor() { "${PFCTL}" -s rules 2>/dev/null | grep -q '^anchor "com.apple/\*"'; }

anchor_rule() { "${PFCTL}" -a "${ANCHOR}" -s rules 2>/dev/null | head -1; }

# Packets matched by the anchor's rule since it was loaded.
rule_packets() {
  "${PFCTL}" -a "${ANCHOR}" -v -s rules 2>/dev/null | awk '
    /Packets:/ { for (i = 1; i <= NF; i++) if ($i == "Packets:") s += $(i + 1) }
    END { print s + 0 }'
}

# pf is reference-counted on macOS: -E takes a reference and prints a token, -X releases it.
# Holding our own reference means another component releasing its own cannot switch pf off.
pf_take_ref() {
  local old out token
  old=$(cat "${TOKEN_FILE}" 2>/dev/null)
  if [ -n "${old}" ] && pf_enabled && "${PFCTL}" -s References 2>/dev/null | grep -q "${old}"; then
    return 0
  fi
  out=$("${PFCTL}" -E 2>&1)
  token=$(printf '%s\n' "${out}" | sed -n 's/^Token : *//p' | head -1)
  if [ -n "${token}" ]; then
    printf '%s\n' "${token}" >"${TOKEN_FILE}"
    log "PF enabled, our reference token ${token}"
    if [ -n "${old}" ] && [ "${old}" != "${token}" ]; then
      "${PFCTL}" -X "${old}" >/dev/null 2>&1
    fi
  else
    log "ERROR pfctl -E returned no token: $(printf '%s' "${out}" | tr '\n' ' ' | cut -c1-200)"
    counter_bump pf_enable_failed
  fi
  return 0
}

# Public unicast addresses only; private, CGNAT, fake-IP, loopback and multicast never enter.
valid_public() {
  case "$1" in
    ''|0.*|10.*|127.*|169.254.*|192.168.*|198.18.*|198.19.*|255.*) return 1 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
    22[4-9].*|23[0-9].*|24[0-9].*|25[0-4].*) return 1 ;;
    ::|::1|[fF][eE]8*|[fF][cCdD]*|::ffff:*) return 1 ;;
    *.*.*.*) return 0 ;;
    *:*) return 0 ;;
  esac
  return 1
}

learned_addrs() {
  [ -f "${LEARNED_FILE}" ] && awk 'NF { print $1 }' "${LEARNED_FILE}"
  return 0
}

nets_list() {
  { for n in ${PINNED_NETS} ${CANARY_NET}; do printf '%s\n' "${n}"; done; learned_addrs; } \
    | awk 'NF && !seen[$1]++'
}

# $1 = closed | <interface name>
anchor_text() {
  local nets
  nets=$(nets_list | paste -s -d, - | sed 's/,/, /g')
  printf 'table <claude_nets> persist { %s }\n' "${nets}"
  if [ "$1" = closed ]; then
    printf 'block return out quick to <claude_nets> label "cvl-closed"\n'
  else
    printf 'block return out quick on ! %s to <claude_nets> label "cvl-offtunnel"\n' "$1"
  fi
}

load_rules() {
  local prev out
  prev=$(rule_packets)
  if out=$(anchor_text "$1" | "${PFCTL}" -a "${ANCHOR}" -f - 2>&1); then
    if [ "${prev:-0}" -gt 0 ] 2>/dev/null; then
      log "PF rule being replaced had blocked ${prev} packets"
      counter_add blocked_packets "${prev}"
    fi
    return 0
  fi
  log "ERROR loading anchor (${1}): $(printf '%s' "${out}" | tr '\n' ' ' | cut -c1-300)"
  counter_bump pf_load_failed
  return 1
}

# The table must hold every network the daemon means to block (someone may flush only the table).
table_matches() {
  local want have
  want=$(nets_list | grep -c .)
  have=$("${PFCTL}" -a "${ANCHOR}" -t claude_nets -T show 2>/dev/null | grep -c .)
  [ "${want}" = "${have}" ]
}

rule_matches_mode() {
  local rule
  rule=$(anchor_rule)
  if [ "${MODE}" = open ]; then
    case "${rule}" in *"on ! ${PINNED_IF} "*cvl-offtunnel*) return 0 ;; esac
  else
    case "${rule}" in *cvl-closed*) return 0 ;; esac
  fi
  return 1
}

# ------------------------------------------------------------------ learning

learn() {
  local now hosts_ips host ip found
  now=$(date +%s)
  hosts_ips=$(awk '$1 ~ /^[0-9a-fA-F:.]+$/ && $1 !~ /^#/ { print $1 }' "${ETC_HOSTS}" 2>/dev/null | sort -u)
  found=$(
    for host in ${LEARN_DOMAINS}; do
      with_timeout 5 "${DSCACHEUTIL}" -q host -a name "${host}" 2>/dev/null \
        | awk '/^ip(v6)?_address:/ { print $2 }' \
        | while read -r ip; do
            valid_public "${ip}" || continue
            # an /etc/hosts redirect (e.g. a relay) is not where Anthropic lives
            printf '%s\n' "${hosts_ips}" | grep -qxF "${ip}" && continue
            printf '%s %s %s\n' "${ip}" "${now}" "${host}"
          done
    done)
  if [ -z "${found}" ]; then
    counter_bump learn_empty
    log "WARN learning found no addresses; the previous list is kept"
    return 0
  fi
  { [ -f "${LEARNED_FILE}" ] && cat "${LEARNED_FILE}"; printf '%s\n' "${found}"; } \
    | awk -v now="${now}" -v maxage="${LEARN_MAX_AGE}" '
        NF >= 2 { if (!($1 in t) || $2 > t[$1]) { t[$1] = $2; h[$1] = $3 } }
        END { for (ip in t) if (now - t[ip] <= maxage) print ip, t[ip], h[ip] }' \
    | sort >"${LEARNED_FILE}.tmp" && mv -f "${LEARNED_FILE}.tmp" "${LEARNED_FILE}"
  nets_list >"${NETS_FILE}.new"
  if ! cmp -s "${NETS_FILE}.new" "${NETS_FILE}" 2>/dev/null; then
    if "${PFCTL}" -a "${ANCHOR}" -t claude_nets -T replace -f "${NETS_FILE}.new" >/dev/null 2>&1; then
      mv -f "${NETS_FILE}.new" "${NETS_FILE}"
      log "LEARN table claude_nets = $(tr '\n' ' ' <"${NETS_FILE}")"
    else
      counter_bump learn_table_failed
      log "WARN could not update table claude_nets"
    fi
  fi
  rm -f "${NETS_FILE}.new"
  return 0
}

# ------------------------------------------------------------------ exit country

# $1 = source address (the tunnel's), $2 = seconds left. Prints "<CC> <exit ip>".
# Understands Cloudflare's trace (loc=/ip=) and ipinfo-style JSON ("country"/"ip").
country_lookup() {
  local url body cc ip left t deadline first=1
  deadline=$(( $(date +%s) + $2 ))
  for url in ${COUNTRY_URLS}; do
    left=$(( deadline - $(date +%s) ))
    # The clock is read in whole seconds: a second boundary right after the deadline was set
    # must not cancel the first attempt (seen under load as "unknown" with nothing tried).
    [ "${first}" = 1 ] && [ "${left}" -lt 1 ] && left=1
    first=0
    [ "${left}" -ge 1 ] || return 1
    t=3
    [ "${left}" -lt 3 ] && t=${left}
    body=$("${CURL}" -s -m "${t}" --interface "$1" -A claude-vpn-lock "${url}" 2>/dev/null) || body=""
    cc=$(printf '%s\n' "${body}" | sed -n -e 's/^loc=\([A-Za-z][A-Za-z]\)$/\1/p' \
           -e 's/.*"country"[ ]*:[ ]*"\([A-Za-z][A-Za-z]\)".*/\1/p' | head -1)
    ip=$(printf '%s\n' "${body}" | sed -n -e 's/^ip=//p' \
           -e 's/.*"ip"[ ]*:[ ]*"\([0-9a-fA-F:.]*\)".*/\1/p' | head -1)
    if [ -n "${cc}" ]; then
      printf '%s %s\n' "$(printf '%s' "${cc}" | tr 'a-z' 'A-Z')" "${ip:-?}"
      return 0
    fi
  done
  return 1
}

is_blocked_cc() {
  local c
  for c in ${BLOCKED_COUNTRIES}; do [ "$1" = "${c}" ] && return 0; done
  return 1
}

# Status 0 = exit allowed, 1 = exit country blocked, 2 = unknown. Sets VERDICT.
# Hard limit COUNTRY_WAIT_MAX seconds in total: the event loop waits for it.
check_exit() {
  local deadline res cc ip left first=1
  deadline=$(( $(date +%s) + COUNTRY_WAIT_MAX ))
  while :; do
    left=$(( deadline - $(date +%s) ))
    [ "${first}" = 1 ] && [ "${left}" -lt 1 ] && left=1   # at least one attempt, see country_lookup
    first=0
    [ "${left}" -ge 1 ] || break
    if res=$(country_lookup "$1" "${left}"); then
      cc=${res%% *}
      ip=${res#* }
      printf 'at=%s\ncc=%s\nip=%s\n' "$(date +%s)" "${cc}" "${ip}" >"${COUNTRY_FILE}"
      VERDICT="exit ${cc} ${ip}"
      is_blocked_cc "${cc}" && return 1
      return 0
    fi
    [ $(( deadline - $(date +%s) )) -ge 2 ] || break
    sleep 1
  done
  printf 'at=%s\ncc=?\nip=?\n' "$(date +%s)" >"${COUNTRY_FILE}"
  VERDICT="exit country unknown"
  return 2
}

# Why the exit is in a blocked country: the VPN app routed past its tunnel, or the server is there.
explain_blocked_exit() {
  local exit_ip="$1" addr home
  addr=$(direct_addr) || addr=""
  [ -n "${addr}" ] || return 0
  home=$("${CURL}" -s -m 3 --interface "${addr}" https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' | head -1)
  if [ -n "${home}" ] && [ "${home}" = "${exit_ip}" ]; then
    printf ' (the VPN app sends flows past its tunnel: exit = this network'"'"'s own address)'
    counter_bump vpn_bypass_seen
  elif [ -n "${home}" ]; then
    printf ' (VPN server in a blocked country)'
  fi
}

# ------------------------------------------------------------------ state machine

apply() {   # $1 mode  $2 closed|<iface>  $3 identity  $4 reason
  if load_rules "$2"; then
    MODE="$1"
    PINNED_ID="$3"
  else
    load_rules closed
    MODE=closed
    PINNED_ID=""
    notify load_failed "pf rules could not be loaded, see /var/log/claude-vpn-lock.log"
  fi
  PINNED_IF=""
  [ "${MODE}" = open ] && PINNED_IF="${PINNED_ID%% *}"
  printf '%s\n' "${MODE}" >"${MODE_FILE}"
  printf '%s\n' "${PINNED_ID}" >"${PIN_FILE}"
  log "STATE ${MODE} :: $4"
  counter_bump "state_${MODE}"
  return 0
}

set_open() {
  if [ "${MODE}" = open ] && [ "${PINNED_IF}" = "${1%% *}" ] && rule_matches_mode; then
    PINNED_ID="$1"   # same interface, rule already right: no reload, no cut connections
    printf '%s\n' "${PINNED_ID}" >"${PIN_FILE}"
    log "STATE open :: $2 (same interface, rule kept)"
    return 0
  fi
  apply open "${1%% *}" "$1" "$2"
}
set_country() { apply country closed "$1" "$2"; }
set_closed()  { apply closed closed "" "$1"; }

verify_and_apply() {   # $1 identity  $2 why
  local src rc
  src=$(first_addr "$1")
  check_exit "${src}"
  rc=$?
  LAST_COUNTRY=$(date +%s)
  case "${rc}" in
    0)
      UNKNOWN_STREAK=0
      if [ "${MODE}" != open ] || [ "${PINNED_ID}" != "$1" ]; then
        set_open "$1" "$2; ${VERDICT}"
      fi
      ;;
    1)
      UNKNOWN_STREAK=0
      if [ "${MODE}" != country ] || [ "${PINNED_ID}" != "$1" ]; then
        set_country "$1" "$2; ${VERDICT}$(explain_blocked_exit "${VERDICT##* }")"
        notify country "Claude blocked: VPN exit is ${VERDICT#exit }"
      fi
      ;;
    *)
      counter_bump country_unknown
      UNKNOWN_STREAK=$((UNKNOWN_STREAK + 1))
      if [ "${PINNED_ID}" != "$1" ]; then
        # A tunnel with no verdict yet. Unknown is never a reason to leave a known state.
        if [ "${COUNTRY_FAIL}" = open ]; then
          counter_bump country_unknown_opened
          set_open "$1" "$2; ${VERDICT}, opened by COUNTRY_FAIL=open"
        elif [ "${MODE}" != closed ] || [ -n "${PINNED_ID}" ]; then
          set_closed "$2; ${VERDICT}, kept closed by COUNTRY_FAIL=closed"
        fi
      elif [ $((UNKNOWN_STREAK % 20)) -eq 1 ]; then
        log "WARN ${VERDICT} (streak ${UNKNOWN_STREAK}); state ${MODE} kept"
      fi
      ;;
  esac
  return 0
}

evaluate() {   # $1 = trigger
  local id now
  id=$(tunnel_identity) || id=""
  now=$(date +%s)
  if [ -z "${id}" ]; then
    if [ "${MODE}" != closed ] || [ -n "${PINNED_ID}" ]; then
      set_closed "$1: no VPN tunnel carries the route to Anthropic (via $(route_iface))"
    fi
    return 0
  fi
  if [ "${id}" != "${PINNED_ID}" ]; then
    # A tunnel we have not verified. Under a new name the pinned rule already blocks it;
    # under the pinned name it would pass, so close before checking.
    if [ "${MODE}" = open ] && [ "${id%% *}" = "${PINNED_IF}" ] \
       && [ "$(instance_of "${id}")" != "$(instance_of "${PINNED_ID}")" ]; then
      set_closed "$1: tunnel ${PINNED_IF} was re-created (${PINNED_ID} -> ${id})"
    fi
    verify_and_apply "${id}" "$1: tunnel ${id}"
    return 0
  fi
  case "${MODE}" in
    open)
      [ $((now - LAST_COUNTRY)) -ge "${COUNTRY_INTERVAL}" ] && verify_and_apply "${id}" "$1: periodic check"
      ;;
    *)
      [ $((now - LAST_COUNTRY)) -ge "${COUNTRY_RETRY}" ] && verify_and_apply "${id}" "$1: re-check"
      ;;
  esac
  return 0
}

heal() {
  if ! pf_enabled; then
    log "WARN pf was switched off by someone; switching it on"
    pf_take_ref
    counter_bump pf_reenabled
    notify pf_off "pf was switched off; claude-vpn-lock switched it back on"
  fi
  if ! rule_matches_mode; then
    log "WARN anchor ${ANCHOR} lost its rule (now: '$(anchor_rule)'); re-loading"
    if [ "${MODE}" = open ]; then load_rules "${PINNED_IF}" || load_rules closed; else load_rules closed; fi
    counter_bump anchor_healed
  fi
  if ! table_matches; then
    log "WARN table claude_nets lost entries ($("${PFCTL}" -a "${ANCHOR}" -t claude_nets -T show 2>/dev/null | grep -c .) of $(nets_list | grep -c .)); re-filling"
    nets_list >"${NETS_FILE}"
    "${PFCTL}" -a "${ANCHOR}" -t claude_nets -T replace -f "${NETS_FILE}" >/dev/null 2>&1 \
      || { log "ERROR cannot re-fill table claude_nets"; counter_bump table_heal_failed; }
    counter_bump table_healed
  fi
  return 0
}

check_main_anchor() {
  main_has_apple_anchor && return 0
  log "ERROR the main pf ruleset no longer has anchor \"com.apple/*\"; the rule is not evaluated"
  counter_bump main_anchor_missing
  notify main_anchor "PROTECTION OFF: pf main ruleset was replaced. Run: sudo pfctl -f /etc/pf.conf"
  return 1
}

restore_or_close() {
  local saved_mode saved_pin cur
  saved_mode=$(cat "${MODE_FILE}" 2>/dev/null)
  saved_pin=$(cat "${PIN_FILE}" 2>/dev/null)
  cur=$(tunnel_identity) || cur=""
  if [ "${saved_mode}" = open ] && [ -n "${saved_pin}" ] && [ "${saved_pin}" = "${cur}" ]; then
    MODE=open
    PINNED_ID="${saved_pin}"
    PINNED_IF="${saved_pin%% *}"
    if rule_matches_mode; then
      LAST_COUNTRY=0   # verify again on the first evaluation, without closing first
      log "RESTORE kept the open rule for ${saved_pin}"
      return 0
    fi
  fi
  MODE=closed
  PINNED_ID=""
  PINNED_IF=""
  set_closed "start: closed until a tunnel is verified"
}

# Interface events come from `route -n monitor` through a FIFO on fd 3 (not stdin, so nothing
# called inside the loop can swallow them). bash 3.2 returns 1 from `read -t` both on timeout
# and at end of stream, so the end of stream is told apart by the monitor's PID being gone.
MON_PID=""
MON_FIFO="${STATE_DIR}/route-events.fifo"

start_monitor() {
  rm -f "${MON_FIFO}"
  mkfifo -m 600 "${MON_FIFO}" || return 1
  "${ROUTE}" -n monitor >"${MON_FIFO}" 2>/dev/null &
  MON_PID=$!
  exec 3<"${MON_FIFO}"
}

stop_monitor() {
  exec 3<&- 2>/dev/null
  if [ -n "${MON_PID}" ]; then
    kill "${MON_PID}" 2>/dev/null
    wait "${MON_PID}" 2>/dev/null
  fi
  MON_PID=""
  rm -f "${MON_FIFO}"
}

LAST_TICK=0
LAST_LEARN=0
TICKS=0

# Housekeeping every TICK seconds, whatever the event source is doing.
maybe_tick() {
  local now
  now=$(date +%s)
  [ $((now - LAST_TICK)) -ge "${TICK}" ] || return 0
  LAST_TICK=${now}
  TICKS=$((TICKS + 1))
  heal
  evaluate tick
  [ $((TICKS % 12)) -eq 0 ] && check_main_anchor
  if [ $((now - LAST_LEARN)) -ge "${LEARN_INTERVAL}" ]; then
    LAST_LEARN=${now}
    learn &
  fi
  [ $((TICKS % 120)) -eq 0 ] && rotate_log
  return 0
}

cmd_run() {
  local line started fast_fails=0 backoff resume_at
  mkdir -p "${STATE_DIR}" 2>/dev/null
  touch "${LOG}" 2>/dev/null
  trap 'stop_monitor; log "STOP pid=$$"; exit 0' TERM INT
  rm -rf "${COUNTER_FILE}.lock"   # left by a killed predecessor; nothing else writes yet
  log "START claude-vpn-lock ${VERSION} pid=$$ anchor=${ANCHOR}"
  [ -n "${CONFIG_IGNORED}" ] && log "WARN config ${CONFIG} ignored: it or a folder above it can be changed by a non-root user"
  pf_take_ref
  restore_or_close
  check_main_anchor
  evaluate start
  while :; do
    started=$(date +%s)
    if start_monitor; then
      while :; do
        if IFS= read -r -t "${TICK}" -u 3 line; then
          case "${line}" in
            RTM_IFINFO*|RTM_NEWADDR*|RTM_DELADDR*|RTM_IFINFO2*) evaluate event ;;
          esac
        elif ! kill -0 "${MON_PID}" 2>/dev/null; then
          break   # route monitor exited
        fi
        maybe_tick
      done
      stop_monitor
    fi
    # No event source: keep ticking (the lock must not stop) and retry the monitor,
    # at once after a long run, after a minute when it keeps dying right away.
    if [ $(( $(date +%s) - started )) -lt 5 ]; then fast_fails=$((fast_fails + 1)); else fast_fails=0; fi
    counter_bump monitor_restart
    backoff=1
    [ "${fast_fails}" -ge 2 ] && backoff=60
    [ "${fast_fails}" -le 2 ] && log "WARN route monitor ended; polling every ${TICK} s, retry in ${backoff} s"
    resume_at=$(( $(date +%s) + backoff ))
    while [ "$(date +%s)" -lt "${resume_at}" ]; do
      sleep 1
      maybe_tick
    done
  done
}

# Used by the installer. On a fresh anchor it checks the exit first and loads the open rule
# directly, so installing does not cut the connections of a Claude session that is running
# through a good tunnel. Without a verified tunnel it loads the closed rule.
cmd_once() {
  mkdir -p "${STATE_DIR}" 2>/dev/null
  rm -rf "${COUNTER_FILE}.lock"
  log "ONCE claude-vpn-lock ${VERSION}"
  [ -n "${CONFIG_IGNORED}" ] && log "WARN config ${CONFIG} ignored: it or a folder above it can be changed by a non-root user"
  pf_take_ref
  if [ -z "$(anchor_rule)" ]; then
    MODE=closed
    PINNED_ID=""
    evaluate once
    [ -z "$(anchor_rule)" ] && set_closed "once: no verified tunnel"
  else
    restore_or_close
    evaluate once
  fi
  printf 'mode=%s pinned=%s\n' "${MODE}" "${PINNED_ID}"
}

cmd_status() {
  local age at
  at=$(sed -n 's/^at=//p' "${COUNTRY_FILE}" 2>/dev/null)
  age="?"
  [ -n "${at}" ] && age="$(( $(date +%s) - at )) s ago"
  printf 'version      : %s\n' "${VERSION}"
  printf 'config       : %s%s\n' "${CONFIG}" "$([ -n "${CONFIG_IGNORED}" ] && printf ' (IGNORED: can be changed by a non-root user)')"
  printf 'mode         : %s\n' "$(cat "${MODE_FILE}" 2>/dev/null || printf unknown)"
  printf 'pinned       : %s\n' "$(cat "${PIN_FILE}" 2>/dev/null)"
  printf 'route_iface  : %s (route to %s)\n' "$(route_iface)" "${ROUTE_PROBE}"
  printf 'tunnel_now   : %s\n' "$(tunnel_identity || printf none)"
  printf 'exit_check   : %s(%s)\n' "$(grep -v '^at=' "${COUNTRY_FILE}" 2>/dev/null | tr '\n' ' ')" "${age}"
  printf 'pf_enabled   : %s\n' "$(pf_enabled && printf yes || printf no)"
  printf 'pf_token     : %s\n' "$(cat "${TOKEN_FILE}" 2>/dev/null)"
  printf 'main_anchor  : %s\n' "$(main_has_apple_anchor && printf 'com.apple/* present' || printf MISSING)"
  printf 'rule         : %s\n' "$(anchor_rule)"
  printf 'rule_packets : %s\n' "$(rule_packets)"
  printf 'nets         : %s\n' "$("${PFCTL}" -a "${ANCHOR}" -t claude_nets -T show 2>/dev/null | tr -s ' \n' ' ')"
  printf 'counters     : %s\n' "$(tr '\n' ' ' <"${COUNTER_FILE}" 2>/dev/null)"
  return 0
}

# Proves the loaded rule with the canary address, never with Anthropic itself.
cmd_verify() {
  local fails=0 untested=0 addr before after rc
  printf 'rule: %s\n' "$(anchor_rule)"
  if ! main_has_apple_anchor; then
    printf 'FAIL main ruleset has no anchor "com.apple/*"\n'
    fails=$((fails + 1))
  fi
  pf_enabled || { printf 'FAIL pf is disabled\n'; fails=$((fails + 1)); }
  addr=$(direct_addr) || addr=""
  if [ -z "${addr}" ]; then
    printf 'NOT TESTED no physical interface address: the canary was not sent\n'
    untested=1
  else
    before=$(rule_packets)
    "${CURL}" -s -o /dev/null -m 3 --interface "${addr}" "http://${CANARY_NET}/" 2>/dev/null
    rc=$?
    after=$(rule_packets)
    printf 'canary from %s: curl exit %s, rule packets %s -> %s\n' "${addr}" "${rc}" "${before}" "${after}"
    if [ "${after}" -gt "${before}" ] 2>/dev/null; then
      printf 'OK the kernel dropped a packet that tried to leave past the tunnel\n'
    else
      printf 'FAIL the packet from the physical interface was not matched\n'
      fails=$((fails + 1))
    fi
  fi
  [ "${fails}" -eq 0 ] && [ "${untested}" = 1 ] && { printf 'VERIFY NOT TESTED\n'; return 2; }
  [ "${fails}" -eq 0 ] && { printf 'VERIFY OK\n'; return 0; }
  printf 'VERIFY FAILED (%s)\n' "${fails}"
  return 1
}

[ -n "${CVL_LIB:-}" ] && return 0

case "${1:-run}" in
  run) cmd_run ;;
  once) cmd_once ;;
  status) cmd_status ;;
  verify) cmd_verify ;;
  learn) mkdir -p "${STATE_DIR}"; learn ;;
  version) printf 'claude-vpn-lock %s (pf, interface-pinned)\n' "${VERSION}" ;;
  *) printf 'usage: %s {run|once|status|verify|learn|version}\n' "$0" >&2; exit 2 ;;
esac
