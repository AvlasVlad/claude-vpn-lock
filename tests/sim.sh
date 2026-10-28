#!/bin/bash
# Unprivileged simulation of the claude-vpn-lock daemon: fake pfctl/route/ifconfig/curl/netstat/
# dscacheutil read and write a "world" directory, so every state transition can be driven
# and asserted without root and without touching the machine.
#
#   bash tests/sim.sh            # all scenarios
#   CVL_SIM_KEEP=1 bash tests/sim.sh   # keep the world directory for inspection

set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
DAEMON="${CVL_SIM_DAEMON:-${HERE}/../lib/claude-vpn-lock-daemon.sh}"   # CVL_SIM_DAEMON: a mutated copy, for disable-probes
SIM="$(mktemp -d "${TMPDIR:-/tmp}/cvl-sim.XXXXXX")"
W="${SIM}/world"
BIN="${SIM}/bin"
mkdir -p "${W}/ifaces" "${W}/dns" "${BIN}" "${SIM}/state"

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$*"; }
check() { local what="$1"; shift; if "$@"; then ok "${what}"; else bad "${what}"; fi; }
check_not() { local what="$1"; shift; if "$@"; then bad "${what}"; else ok "${what}"; fi; }

# ------------------------------------------------------------------ fakes

cat >"${BIN}/pfctl" <<'EOF'
#!/bin/bash
W="${CVL_WORLD}"
anchor=""; table=""; op=""; file=""; show=""; verbose=0
while [ $# -gt 0 ]; do
  case "$1" in
    -a) anchor="$2"; shift ;;
    -t) table="$2"; shift ;;
    -T) op="$2"; shift ;;
    -f) file="$2"; shift ;;
    -s) show="$2"; shift ;;
    -v) verbose=1 ;;
    -E) echo yes >"$W/pf_enabled"; n=$(( $(cat "$W/token_seq" 2>/dev/null || echo 1000) + 1 )); echo "$n" >"$W/token_seq"
        echo "$n" >>"$W/refs"; printf 'pf enabled\nToken : %s\n' "$n"; exit 0 ;;
    -X) grep -vx "$2" "$W/refs" >"$W/refs.tmp" 2>/dev/null; mv "$W/refs.tmp" "$W/refs"; echo "released $2" >>"$W/pf_calls"; shift ;;
    -F) rm -f "$W/anchor"; shift ;;
  esac
  shift
done
echo "pfctl anchor=$anchor table=$table op=$op file=$file show=$show" >>"$W/pf_calls"
if [ "$show" = info ]; then
  [ "$(cat "$W/pf_enabled" 2>/dev/null)" = yes ] && echo "Status: Enabled for 0 days" || echo "Status: Disabled"; exit 0
fi
if [ "$show" = References ]; then printf 'TOKEN TIMESTAMP PROCESS\n'; cat "$W/refs" 2>/dev/null; exit 0; fi
if [ "$show" = rules ] && [ -z "$anchor" ]; then
  [ "$(cat "$W/main_anchor" 2>/dev/null)" = no ] || echo 'anchor "com.apple/*" all'; exit 0
fi
if [ "$show" = rules ]; then
  [ -f "$W/anchor" ] || exit 0
  sed -n '2p' "$W/anchor" | sed 's/ to </ from any to </'
  [ "$verbose" = 1 ] && printf '  [ Evaluations: 9 Packets: %s Bytes: 0 States: 0 ]\n' "$(cat "$W/packets" 2>/dev/null || echo 0)"
  exit 0
fi
if [ -n "$table" ] && [ "$op" = show ]; then cat "$W/table" 2>/dev/null; exit 0; fi
if [ -n "$table" ] && [ "$op" = replace ]; then cp "$file" "$W/table"; exit 0; fi
if [ "$file" = - ]; then
  [ -f "$W/fail_load" ] && { cat >/dev/null; echo "stdin:2: syntax error" >&2; exit 1; }
  cat >"$W/anchor"; echo 0 >"$W/packets"
  sed -n '1p' "$W/anchor" | sed 's/.*{ *//; s/ *}.*//; s/, */\n/g' | tr -s ' ' >"$W/table"
  exit 0
fi
exit 0
EOF

cat >"${BIN}/route" <<'EOF'
#!/bin/bash
W="${CVL_WORLD}"
case "$*" in
  *monitor*) [ -f "$W/monitor_dies" ] && exit 0; exec tail -n 0 -f "$W/events" ;;
  *get*) printf '   route to: x\n gateway: %s\n  interface: %s\n' "$(cat "$W/gateway" 2>/dev/null || echo 192.168.1.1)" "$(cat "$W/route_iface")" ;;
esac
EOF

cat >"${BIN}/ifconfig" <<'EOF'
#!/bin/bash
W="${CVL_WORLD}"
name="${@: -1}"
[ -f "$W/ifaces/$name" ] || { echo "ifconfig: interface $name does not exist" >&2; exit 1; }
cat "$W/ifaces/$name"
EOF

cat >"${BIN}/netstat" <<'EOF'
#!/bin/bash
printf 'Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\ndefault link#61 UCSg utun36\ndefault 192.168.1.1 UGScIg en0\n'
EOF

cat >"${BIN}/curl" <<'EOF'
#!/bin/bash
W="${CVL_WORLD}"
iface=""; url=""; maxt=""
while [ $# -gt 0 ]; do
  case "$1" in --interface) iface="$2"; shift ;; -m) maxt="$2"; shift ;; -A|-o|-w) shift ;; http*) url="$1" ;; esac
  shift
done
echo "curl iface=$iface url=$url" >>"$W/curl_calls"
# A slow network: every URL takes curl_delay seconds, and -m is honoured like real curl does.
if [ -f "$W/curl_delay" ]; then
  d=$(cat "$W/curl_delay")
  if [ -n "$maxt" ] && [ "$d" -gt "$maxt" ]; then sleep "$maxt"; exit 28; fi
  sleep "$d"
fi
case "$url" in
  *cdn-cgi/trace*)
    if [ "$iface" = 192.168.1.20 ]; then
      [ -f "$W/home_fail" ] && exit 28
      printf 'ip=%s\nloc=%s\n' "$(cat "$W/home_ip")" "$(cat "$W/home_loc" 2>/dev/null || echo RU)"; exit 0
    fi
    e=$(cat "$W/exit")
    [ "$e" = fail ] && exit 28
    printf 'fl=1\nip=%s\nts=1\nloc=%s\n' "${e#* }" "${e%% *}"; exit 0 ;;
esac
exit 7
EOF

default_arp() {   # scenarios that replace the fake restore it through reset_world
  cat >"${BIN}/arp" <<'EOF'
#!/bin/bash
W="${CVL_WORLD}"
printf '? (%s) at %s on en0 ifscope [ethernet]\n' "${@: -1}" "$(cat "$W/gw_mac" 2>/dev/null || echo aa:bb:cc:dd:ee:01)"
EOF
  chmod +x "${BIN}/arp"
}
default_arp

cat >"${BIN}/dscacheutil" <<'EOF'
#!/bin/bash
W="${CVL_WORLD}"
host="${@: -1}"
[ -f "$W/dns/$host" ] || exit 0
while read -r a; do
  case "$a" in *:*) printf 'name: %s\nipv6_address: %s\n\n' "$host" "$a" ;; *) printf 'name: %s\nip_address: %s\n\n' "$host" "$a" ;; esac
done <"$W/dns/$host"
EOF
chmod +x "${BIN}"/*

tunnel() {   # name index generation [addr]
  if [ -n "${4-198.18.0.1}" ]; then
    xf='xflags=4010004<NOAUTONX,IS_VPN>'
    [ "${5:-}" = novpn ] && xf='xflags=4<NOAUTONX>'
    printf '%s: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1500 index %s\n\t%s\n\tinet %s --> %s netmask 0xffff0000\n\tgeneration id: %s\n' \
      "$1" "$2" "${xf}" "${4-198.18.0.1}" "${4-198.18.0.1}" "$3" >"${W}/ifaces/$1"
  else
    printf '%s: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1500 index %s\n\tgeneration id: %s\n' "$1" "$2" "$3" >"${W}/ifaces/$1"
  fi
}

export CVL_WORLD="${W}" CVL_STATE_DIR="${SIM}/state" CVL_LOG="${SIM}/daemon.log" CVL_CONFIG=/nonexistent \
  CVL_HOSTS="${W}/hosts" CVL_PFCTL="${BIN}/pfctl" CVL_ROUTE="${BIN}/route" CVL_IFCONFIG="${BIN}/ifconfig" \
  CVL_NETSTAT="${BIN}/netstat" CVL_CURL="${BIN}/curl" CVL_DSCACHEUTIL="${BIN}/dscacheutil" CVL_ARP="${BIN}/arp" CVL_NO_NOTIFY=1

reset_world() {
  default_arp
  rm -rf "${W}" "${SIM}/state" "${SIM}/daemon.log"
  mkdir -p "${W}/ifaces" "${W}/dns" "${SIM}/state"
  : >"${W}/events"
  echo en0 >"${W}/route_iface"
  echo no >"${W}/pf_enabled"
  echo "NL 192.0.2.52" >"${W}/exit"
  echo 198.51.100.144 >"${W}/home_ip"
  printf 'en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500 index 14\n\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n' >"${W}/ifaces/en0"
  printf '127.0.0.1 localhost\n198.51.100.190 grok.com\n#198.51.100.190 claude.ai\n' >"${W}/hosts"
  printf '160.79.104.10\n2607:6bc0::10\n' >"${W}/dns/api.anthropic.com"
  printf '35.190.46.17\n10.1.2.3\n198.18.0.9\n198.51.100.190\n' >"${W}/dns/downloads.claude.ai"
}

# A fresh library instance per scenario (state is re-read from files, like a restarted daemon).
lib() { CVL_LIB=1 . "${DAEMON}"; COUNTRY_WAIT_MAX=1; }
rule() { sed -n '2p' "${W}/anchor" 2>/dev/null; }
mode() { cat "${SIM}/state/mode" 2>/dev/null; }
logged() { grep -q "$1" "${SIM}/daemon.log"; }
counter() { sed -n "s/^$1=//p" "${SIM}/state/counters" 2>/dev/null; }
wait_for() { local i; for i in $(seq 1 40); do eval "$1" && return 0; sleep 0.25; done; return 1; }

# ------------------------------------------------------------------ scenarios

printf '== 1. fresh install, no tunnel -> closed rule, pf enabled with our token\n'
reset_world; lib
cmd_once >/dev/null
check "rule blocks everything to Anthropic" grep -q 'block return out quick to <claude_nets> label "cvl-closed"' "${W}/anchor"
check "mode closed" [ "$(mode)" = closed ]
check "pf enabled by our reference" [ "$(cat "${W}/pf_enabled")" = yes ]
check "token saved" [ -s "${SIM}/state/pf_token" ]
check "table has pinned nets and canary" grep -qx '203.0.113.7' "${W}/table"

printf '== 2. VPN connects (utun36), exit NL -> open, pinned to utun36\n'
tunnel utun36 61 230; echo utun36 >"${W}/route_iface"
evaluate event
check "mode open" [ "$(mode)" = open ]
check "rule pinned to utun36" grep -q 'on ! utun36 to <claude_nets>' "${W}/anchor"
check "exit check went through the tunnel address" grep -q 'iface=198.18.0.1 url=https://1.1.1.1/cdn-cgi/trace' "${W}/curl_calls"

printf '== 3. tunnel re-created as utun37 before the daemon looks -> kernel already blocks it\n'
rm -f "${W}/ifaces/utun36"; tunnel utun37 62 231; echo utun37 >"${W}/route_iface"
check "rule still names utun36, so packets out utun37 match the block" grep -q 'on ! utun36 to' "${W}/anchor"
evaluate event
check "after verification the rule names utun37" grep -q 'on ! utun37 to' "${W}/anchor"
check "mode open" [ "$(mode)" = open ]

printf '== 4. same-name re-creation (utun37, new index/generation) -> closed, verified, reopened\n'
tunnel utun37 63 232
evaluate event
check "logged the re-creation and closed first" logged 'tunnel utun37 was re-created'
check "reopened on utun37" grep -q 'on ! utun37 to' "${W}/anchor"

printf '== 5. VPN drops: route to Anthropic via en0 -> closed\n'
rm -f "${W}/ifaces/utun37"; echo en0 >"${W}/route_iface"
evaluate event
check "mode closed" [ "$(mode)" = closed ]
check "closed rule" grep -q 'cvl-closed' "${W}/anchor"

printf '== 6. split tunnel: utun exists but Anthropic is routed via en0 -> closed\n'
tunnel utun38 64 233; echo en0 >"${W}/route_iface"
evaluate tick
check "stays closed" [ "$(mode)" = closed ]

printf '== 7. tunnel without an address -> closed\n'
tunnel utun39 65 234 ""; echo utun39 >"${W}/route_iface"
evaluate tick
check "stays closed" [ "$(mode)" = closed ]

printf '== 8. exit in RU through a VPN server -> blocked, reason named\n'
tunnel utun40 66 235; echo utun40 >"${W}/route_iface"; echo "RU 5.6.7.8" >"${W}/exit"
evaluate event
check "mode country" [ "$(mode)" = country ]
check "rule closed" grep -q 'cvl-closed' "${W}/anchor"
check "reason: VPN server in a blocked country" logged 'VPN server in a blocked country'

printf '== 9. exit RU with this network'"'"'s own address -> named as a VPN bypass\n'
echo "RU 198.51.100.144" >"${W}/exit"; LAST_COUNTRY=0; MODE=open; PINNED_ID=""
evaluate tick
check "bypass named" logged 'sends flows past its tunnel'
check "counter vpn_bypass_seen" [ "$(counter vpn_bypass_seen)" = 1 ]

printf '== 10. unknown exit never leaves a known blocked state\n'
echo fail >"${W}/exit"; LAST_COUNTRY=0
evaluate tick
check "still country" [ "$(mode)" = country ]
printf '== 11. exit back to NL -> open\n'
echo "NL 192.0.2.65" >"${W}/exit"; LAST_COUNTRY=0
evaluate tick
check "open" [ "$(mode)" = open ]
printf '== 12. unknown during periodic check keeps open, counted\n'
echo fail >"${W}/exit"; LAST_COUNTRY=0
evaluate tick
check "still open" [ "$(mode)" = open ]
check "counted" [ -n "$(counter country_unknown)" ]

printf '== 13. new tunnel with unknown exit: COUNTRY_FAIL=open opens, =closed stays closed\n'
rm -f "${W}/ifaces/utun40"; tunnel utun41 67 236; echo utun41 >"${W}/route_iface"
evaluate event
check "fail-open opens" [ "$(mode)" = open ]
check "fail-open counted" [ "$(counter country_unknown_opened)" = 1 ]
rm -f "${W}/ifaces/utun41"; tunnel utun42 68 237; echo utun42 >"${W}/route_iface"
COUNTRY_FAIL=closed
evaluate event
check "fail-closed stays closed" [ "$(mode)" = closed ]
check "fail-closed rule" grep -q 'cvl-closed' "${W}/anchor"
COUNTRY_FAIL=open; echo "NL 192.0.2.52" >"${W}/exit"
evaluate tick
check "opens once the exit is known" [ "$(mode)" = open ]

printf '== 14. heal: anchor flushed by someone, pf switched off\n'
rm -f "${W}/anchor"; echo no >"${W}/pf_enabled"
heal
check "pf on again" [ "$(cat "${W}/pf_enabled")" = yes ]
check "rule re-loaded, still pinned" grep -q 'on ! utun42 to' "${W}/anchor"
check "anchor heal counted" [ "$(counter anchor_healed)" = 1 ]
check "pf re-enable counted" [ "$(counter pf_reenabled)" = 1 ]

printf '== 15. main ruleset lost anchor com.apple/* -> error counted\n'
echo no >"${W}/main_anchor"
check_main_anchor
check "counted" [ "$(counter main_anchor_missing)" = 1 ]
echo yes >"${W}/main_anchor"

printf '== 16. learning: bogons, fake-IP and /etc/hosts redirects never enter; old entries kept\n'
printf '34.36.57.103 %s a-cdn.anthropic.com\n9.9.9.9 1 ancient.example\n' "$(date +%s)" >"${SIM}/state/learned"
learn
check "GCP address learned" grep -q '^35.190.46.17 ' "${SIM}/state/learned"
check_not "private 10.1.2.3 rejected" grep -q '^10.1.2.3 ' "${SIM}/state/learned"
check_not "fake-IP 198.18.0.9 rejected" grep -q '^198.18.0.9 ' "${SIM}/state/learned"
check_not "hosts redirect 198.51.100.190 rejected" grep -q '^198.51.100.190 ' "${SIM}/state/learned"
check "previous entry kept" grep -q '^34.36.57.103 ' "${SIM}/state/learned"
check_not "expired entry dropped" grep -q '^9.9.9.9 ' "${SIM}/state/learned"
check "pf table updated" grep -qx '35.190.46.17' "${W}/table"
printf '127.0.0.1 x\n' >"${W}/hosts"; rm -f "${W}/dns/"*
learn
check "empty answer keeps the previous list" grep -q '^35.190.46.17 ' "${SIM}/state/learned"

printf '== 17. restart: same tunnel keeps the open rule without a closed gap; other tunnel closes\n'
before=$(wc -l <"${SIM}/daemon.log")
lib; restore_or_close
check "restored open" [ "${MODE}" = open ]
check "restore logged" logged 'RESTORE kept the open rule'
check "no closed state logged on restore" [ "$(tail -n +"$((before + 1))" "${SIM}/daemon.log" | grep -c 'STATE closed')" = 0 ]
tunnel utun42 69 238
lib; restore_or_close
check "different identity -> closed" [ "${MODE}" = closed ]

printf '== 18. load failure of the open rule falls back to the closed rule\n'
echo utun42 >"${W}/route_iface"; touch "${W}/fail_load"
lib; MODE=closed; PINNED_ID=""; evaluate event
rm -f "${W}/fail_load"
check "mode closed after failed load" [ "${MODE}" = closed ]
check "failure counted" [ -n "$(counter pf_load_failed)" ]

printf '== 19. the event loop: events and ticks drive the running daemon\n'
reset_world
printf 'TICK=1\nCOUNTRY_INTERVAL=2\nCOUNTRY_RETRY=1\n' >"${SIM}/fast.conf"
( CVL_CONFIG="${SIM}/fast.conf" bash "${DAEMON}" run ) >/dev/null 2>&1 &
dpid=$!
check "starts closed" wait_for '[ "$(mode)" = closed ]'
tunnel utun50 70 239; echo utun50 >"${W}/route_iface"; echo 'RTM_NEWADDR: Address being added' >>"${W}/events"
check "opens on the address event" wait_for 'grep -q "on ! utun50 to" "${W}/anchor"'
echo "RU 5.6.7.8" >"${W}/exit"
check "periodic check blocks a RU exit" wait_for '[ "$(mode)" = country ]'
echo "NL 192.0.2.52" >"${W}/exit"
check "re-check reopens" wait_for '[ "$(mode)" = open ]'
rm -f "${W}/ifaces/utun50"; echo en0 >"${W}/route_iface"; echo 'RTM_DELADDR: Address being removed' >>"${W}/events"
check "closes on the address event" wait_for '[ "$(mode)" = closed ]'
rm -f "${W}/anchor"
check "tick heals a flushed anchor" wait_for 'grep -q cvl-closed "${W}/anchor"'
pkill -P "${dpid}" 2>/dev/null; kill "${dpid}" 2>/dev/null; wait "${dpid}" 2>/dev/null
for p in $(pgrep -f "tail -n 0 -f ${W}/events"); do kill "${p}" 2>/dev/null; done


printf '== 20. a utun without the IS_VPN flag (system tunnel) is never trusted\n'
reset_world; lib; cmd_once >/dev/null
tunnel utun3 7 5 10.9.9.9 novpn; echo utun3 >"${W}/route_iface"
evaluate event
check "stays closed" [ "$(mode)" = closed ]
check "closed rule" grep -q cvl-closed "${W}/anchor"

printf '== 21. address change on the same interface instance: re-checked, rule kept, no closed gap\n'
tunnel utun36 61 230; echo utun36 >"${W}/route_iface"; evaluate event
check "open on utun36" [ "$(mode)" = open ]
n_closed=$(grep -c 'STATE closed' "${SIM}/daemon.log")
tunnel utun36 61 230 198.18.0.2
evaluate event
check "still open" [ "$(mode)" = open ]
check "no closed state on an address change" [ "$(grep -c 'STATE closed' "${SIM}/daemon.log")" = "${n_closed}" ]
check "rule kept" logged 'same interface, rule kept'

printf '== 22. someone flushes only the table: heal re-fills it\n'
: >"${W}/table"
heal
check "table re-filled" grep -qx '160.79.104.0/21' "${W}/table"
check "counted" [ "$(counter table_healed)" = 1 ]

printf '== 23. exit check has a hard time limit\n'
echo 2 >"${W}/curl_delay"; echo fail >"${W}/exit"; COUNTRY_WAIT_MAX=3
# Every URL takes 2 s. With the 3 s limit the lookup stops after about 3 s (the daemon reads
# its clock in whole seconds, so up to ~4 s); without it the three URLs take 3 x 2 s = 6 s.
# Measured in milliseconds; 5.5 s separates the two cases.
ms() { /usr/bin/perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000'; }
t0=$(ms); check_exit 198.18.0.2; t1=$(ms)
check "returned unknown within the limit ($((t1 - t0)) ms < 5500)" [ $((t1 - t0)) -lt 5500 ]
rm -f "${W}/curl_delay"; echo "NL 192.0.2.52" >"${W}/exit"; COUNTRY_WAIT_MAX=1

printf '== 24. once loads the rule without waiting for DNS learning\n'
reset_world; lib
check "once does not call dscacheutil" [ "$(cmd_once >/dev/null; grep -c . "${SIM}/state/learned" 2>/dev/null || echo 0)" = 0 ]

printf '== 25. route monitor dies at once: ticks still heal and open\n'
reset_world; touch "${W}/monitor_dies"
printf 'TICK=1\nCOUNTRY_INTERVAL=2\nCOUNTRY_RETRY=1\n' >"${SIM}/fast.conf"
( CVL_CONFIG="${SIM}/fast.conf" bash "${DAEMON}" run ) >/dev/null 2>&1 &
dpid=$!
check "starts closed" wait_for '[ "$(mode)" = closed ]'
tunnel utun60 80 300; echo utun60 >"${W}/route_iface"
check "opens on a tick without events" wait_for '[ "$(mode)" = open ]'
rm -f "${W}/anchor"
check "tick heals a flushed anchor" wait_for 'grep -q "on ! utun60 to" "${W}/anchor"'
check "monitor warnings rate-limited (<= 2 lines)" [ "$(grep -c 'route monitor ended' "${SIM}/daemon.log")" -le 2 ]
pkill -P "${dpid}" 2>/dev/null; kill "${dpid}" 2>/dev/null; wait "${dpid}" 2>/dev/null

printf '== 26. two writers bump counters at once: no update is lost\n'
reset_world; rm -f "${SIM}/state/counters"
for k in alpha beta; do
  ( lib; for _ in $(seq 1 100); do counter_add "${k}" 1; done ) &
done
wait
check "alpha = 100" [ "$(counter alpha)" = 100 ]
check "beta = 100" [ "$(counter beta)" = 100 ]
check_not "no lock left behind" [ -d "${SIM}/state/counters.lock" ]

printf '== 27. the config is code run by root: read only if nobody else can change it\n'
mkdir -p "${SIM}/conf_ok" "${SIM}/conf_open"; chmod 755 "${SIM}/conf_ok"; chmod 777 "${SIM}/conf_open"
printf 'COUNTRY_INTERVAL=7\n' >"${SIM}/conf_ok/a.conf"; chmod 644 "${SIM}/conf_ok/a.conf"
check "own 644 file in a 755 folder is read" \
  [ "$(CVL_CONFIG="${SIM}/conf_ok/a.conf" bash -c 'CVL_LIB=1 . "$0"; printf "%s" "${COUNTRY_INTERVAL}"' "${DAEMON}")" = 7 ]
chmod 664 "${SIM}/conf_ok/a.conf"
check "group-writable file is ignored" \
  [ "$(CVL_CONFIG="${SIM}/conf_ok/a.conf" bash -c 'CVL_LIB=1 . "$0"; printf "%s %s" "${COUNTRY_INTERVAL}" "${CONFIG_IGNORED}"' "${DAEMON}")" = "30 1" ]
cp "${SIM}/conf_ok/a.conf" "${SIM}/conf_open/a.conf"; chmod 644 "${SIM}/conf_open/a.conf"
check "file in a world-writable folder is ignored" \
  [ "$(CVL_CONFIG="${SIM}/conf_open/a.conf" bash -c 'CVL_LIB=1 . "$0"; printf "%s" "${COUNTRY_INTERVAL}"' "${DAEMON}")" = 30 ]

printf '== 28. a second boundary right after the deadline is set still allows one attempt\n'
# A clock that reads T on its first call and T+1 afterwards: the worst case under load.
mkdir -p "${SIM}/clock"
cat >"${SIM}/clock/date" <<'EOF'
#!/bin/bash
if [ "$1" = "+%s" ]; then
  f="${CVL_WORLD}/clock_calls"; n=$(cat "$f" 2>/dev/null || echo 0); echo $((n + 1)) >"$f"
  [ "$n" = 0 ] && echo 1000 || echo 1001
else
  exec /bin/date "$@"
fi
EOF
chmod +x "${SIM}/clock/date"
reset_world; lib; COUNTRY_WAIT_MAX=1; echo "NL 192.0.2.52" >"${W}/exit"; rm -f "${W}/clock_calls"
v=$( PATH="${SIM}/clock:${PATH}"; check_exit 198.18.0.1 >/dev/null; printf '%s' "${VERDICT}" )
check "exit found despite the boundary (${v})" [ "${v}" = "exit NL 192.0.2.52" ]

printf '== 29. DIRECT_POLICY=country, no VPN, network exit in an allowed country -> open on the plain interface\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
cmd_once >/dev/null
check "mode open" [ "$(mode)" = open ]
check "rule is pinned to en0" grep -q 'block return out quick on ! en0 to <claude_nets> label "cvl-offtunnel"' "${W}/anchor"
check "pinned identity names the gateway and its MAC" grep -q '^en0 14 - 192.168.1.20,gw=192.168.1.1,mac=aa:bb:cc:dd:ee:01$' "${SIM}/state/pinned"
check "the country was asked through the physical address" grep -q 'iface=192.168.1.20 url=https://1.1.1.1/cdn-cgi/trace' "${W}/curl_calls"
check "logged as a direct network" logged 'direct network en0'

printf '== 30. same, but the network exit is in a blocked country -> closed (country)\n'
reset_world; lib; DIRECT_POLICY=country; echo RU >"${W}/home_loc"
cmd_once >/dev/null
check "mode country" [ "$(mode)" = country ]
check "rule blocks everything" grep -q 'cvl-closed' "${W}/anchor"
check "log says this is the network's own exit" logged "no VPN: this network's own exit"

printf '== 31. the network exit cannot be told -> closed, never opened by COUNTRY_FAIL=open; retried every COUNTRY_RETRY s\n'
reset_world; lib; DIRECT_POLICY=country; COUNTRY_FAIL=open; touch "${W}/home_fail"
cmd_once >/dev/null
check "mode closed" [ "$(mode)" = closed ]
check "counted" [ "$(counter link_unknown_closed)" = 1 ]
c1=$(grep -c 'iface=192.168.1.20' "${W}/curl_calls")
evaluate tick; evaluate event
c2=$(grep -c 'iface=192.168.1.20' "${W}/curl_calls")
check "no new lookup within COUNTRY_RETRY (${c1} -> ${c2})" [ "${c1}" = "${c2}" ]
LAST_COUNTRY=0; rm -f "${W}/home_fail"; echo VN >"${W}/home_loc"; evaluate tick
check "after the retry time the country is known and the lock opens" [ "$(mode)" = open ]

printf '== 32. default policy: no VPN stays closed and the network is never asked\n'
reset_world; lib; echo VN >"${W}/home_loc"
cmd_once >/dev/null
check "mode closed" [ "$(mode)" = closed ]
check_not "no lookup through the physical interface" grep -qs 'iface=192.168.1.20' "${W}/curl_calls"

printf '== 33. direct open -> a VPN is switched on: blocked until its exit is known; then follows the VPN\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
cmd_once >/dev/null
tunnel utun70 90 400; echo utun70 >"${W}/route_iface"; echo "RU 192.0.2.65" >"${W}/exit"
check "before the check the rule still names en0, so the new tunnel is already blocked" grep -q 'on ! en0 to' "${W}/anchor"
evaluate event
check "VPN exit RU -> country" [ "$(mode)" = country ]
echo "NL 192.0.2.52" >"${W}/exit"; LAST_COUNTRY=0; evaluate tick
check "VPN exit NL -> open on the tunnel" grep -q 'on ! utun70 to' "${W}/anchor"
rm -f "${W}/ifaces/utun70"; echo en0 >"${W}/route_iface"; evaluate event
check "VPN off, network exit VN -> open on en0 again" grep -q 'on ! en0 to' "${W}/anchor"

printf '== 34. the network changes under the same interface name -> closed at once, then checked\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
cmd_once >/dev/null
evaluate tick
check "an unchanged network does not reload anything" [ "$(counter state_open)" = 1 ]
echo 10.0.0.1 >"${W}/gateway"; echo "11:22:33:44:55:66" >"${W}/gw_mac"; echo RU >"${W}/home_loc"
evaluate event
check "closed first, with the reason" logged 'STATE closed :: event: network changed'
check "then the verdict for the new network: country" [ "$(mode)" = country ]
l1=$(grep -n 'network changed' "${SIM}/daemon.log" | head -1 | cut -d: -f1); l2=$(grep -n 'STATE country' "${SIM}/daemon.log" | head -1 | cut -d: -f1)
check "the closing line comes before the verdict line (${l1} < ${l2})" [ "${l1}" -lt "${l2}" ]
echo 192.168.1.1 >"${W}/gateway"; echo VN >"${W}/home_loc"; LAST_COUNTRY=0; evaluate tick
evaluate tick
check "back to the first network, allowed again" [ "$(mode)" = open ]
echo "99:88:77:66:55:44" >"${W}/gw_mac"; n0=$(grep -c 'network changed' "${SIM}/daemon.log"); evaluate event
check "only the gateway MAC differs (same range, same gateway address): still a new network" \
  [ "$(grep -c 'network changed' "${SIM}/daemon.log")" = $((n0 + 1)) ]

printf '== 35. only plain interfaces count as a direct network\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
printf 'bridge0: flags=8863<UP> mtu 1500 index 20\n\tinet 192.168.2.5 netmask 0xffffff00\n' >"${W}/ifaces/bridge0"; echo bridge0 >"${W}/route_iface"
cmd_once >/dev/null
check "bridge0 -> closed" [ "$(mode)" = closed ]
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
tunnel utun71 91 401 198.18.0.1 novpn; echo utun71 >"${W}/route_iface"
cmd_once >/dev/null
check "a utun that is not a VPN -> closed" [ "$(mode)" = closed ]
check_not "neither was asked about its country" grep -qs 'iface=' "${W}/curl_calls"

printf '== 36. daemon restart: the direct state is restored only for the same network\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
cmd_once >/dev/null
lib; DIRECT_POLICY=country; restore_or_close
check "same network -> the open rule is kept" logged 'RESTORE kept the open rule for en0'
echo 10.9.9.1 >"${W}/gateway"
lib; DIRECT_POLICY=country; restore_or_close
check "another gateway -> closed until verified" [ "$(mode)" = closed ]

printf '== 37. verify on a direct network does not claim a proof it cannot make\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
cmd_once >/dev/null
vout=$(cmd_verify); vrc=$?
check "verify says NOT TESTED (exit 2) and names the reason" bash -c '[ "$1" = 2 ] && printf "%s" "$2" | grep -q "NOT TESTED direct network"' _ "${vrc}" "${vout}"
st=$(cmd_status)
check "status shows the policy and the link" bash -c 'printf "%s" "$1" | grep -q "^direct_policy: country" && printf "%s" "$1" | grep -q "^link_now     : en0 14 - 192.168.1.20"' _ "${st}"

printf '== 38. an expired ARP entry for the gateway is not a change of network\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
cmd_once >/dev/null
cat >"${BIN}/arp" <<'EOF'
#!/bin/bash
printf '? (%s) -- no entry\n' "${@: -1}"
EOF
n0=$(counter state_open); evaluate tick
check "no entry -> same identity, nothing reloaded, still open" bash -c '[ "$1" = open ] && [ "$2" = "$3" ]' _ "$(mode)" "$(counter state_open)" "${n0}"
echo 10.0.0.1 >"${W}/gateway"; evaluate event
check "another gateway address with no ARP entry is still a new network" logged 'STATE closed :: event: network changed'

printf '== 39. the network exit country changes behind an unchanged address, gateway and MAC (phone SIM swap)\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
cmd_once >/dev/null
echo RU >"${W}/home_loc"
LAST_COUNTRY=$(( $(date +%s) - 5 )); evaluate tick
check "within DIRECT_INTERVAL nothing is asked yet" [ "$(mode)" = open ]
LAST_COUNTRY=$(( $(date +%s) - 11 )); evaluate tick
check "after DIRECT_INTERVAL (10 s, not COUNTRY_INTERVAL 30 s) the lock closes" [ "$(mode)" = country ]

printf '== 40. an open direct network whose country can no longer be told is closed, then reopened\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
cmd_once >/dev/null
touch "${W}/home_fail"
LAST_COUNTRY=$(( $(date +%s) - 11 )); evaluate tick
check "closed at the first periodic check without an answer" [ "$(mode)" = closed ]
check "counted" [ "$(counter link_unknown_closed)" = 1 ]
c1=$(grep -c 'iface=192.168.1.20' "${W}/curl_calls"); evaluate tick; c2=$(grep -c 'iface=192.168.1.20' "${W}/curl_calls")
check "not asked again within COUNTRY_RETRY (${c1} -> ${c2})" [ "${c1}" = "${c2}" ]
rm -f "${W}/home_fail"; LAST_COUNTRY=0; evaluate tick
check "answers are back -> open again" [ "$(mode)" = open ]

printf '== 41. ARP entry "(incomplete)": ignored on a tick, a difference on a routing event\n'
reset_world; lib; DIRECT_POLICY=country; echo VN >"${W}/home_loc"
cmd_once >/dev/null
cat >"${BIN}/arp" <<'EOF'
#!/bin/bash
printf '? (%s) at (incomplete) on en0 ifscope [ethernet]\n' "${@: -1}"
EOF
n0=$(counter state_open); evaluate tick
check "tick: same network, nothing reloaded" bash -c '[ "$1" = "$2" ] && [ "$3" = open ]' _ "$(counter state_open)" "${n0}" "$(mode)"
evaluate event
check "routing event: the unresolved gateway MAC is a difference, closed first" logged 'STATE closed :: event: network changed'
check "and the verified network opens again" [ "$(mode)" = open ]

printf '\nsimulation: %s passed, %s failed\n' "${PASS}" "${FAIL}"
[ -n "${CVL_SIM_KEEP:-}" ] && printf 'world kept in %s\n' "${SIM}" || rm -rf "${SIM}"
[ "${FAIL}" -eq 0 ]
