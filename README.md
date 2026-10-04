# claude-vpn-lock

[![tests](https://github.com/AvlasVlad/claude-vpn-lock/actions/workflows/test.yml/badge.svg)](https://github.com/AvlasVlad/claude-vpn-lock/actions/workflows/test.yml)

**Claude talks to Anthropic only through your VPN.** If the VPN drops for a split second,
reconnects, or your VPN app decides to send Claude "direct", the macOS kernel drops the
packets. There is no reaction window: the decision is made on every packet, not by a script
that has to notice something first.

Covers everything at once: the Claude desktop app, Claude Code in the terminal, the VS Code
extension. macOS only for now. [Русская версия](README.ru.md).

> Unofficial community tool. Not affiliated with or endorsed by Anthropic.

## Why

A VPN app leaks in three ordinary ways, and each one means Claude talks to Anthropic from
your real IP address:

1. **The tunnel drops** for a moment (Wi-Fi switch, sleep, server hiccup).
2. **The VPN app reconnects** and creates a new tunnel (`utun36` becomes `utun38`).
3. **Split tunnelling**: the VPN app's own rules send some traffic "direct", outside the
   tunnel, while the VPN icon still says "connected".

The kill switch built into most VPN apps does not cover the third case, and macOS's own
"include all networks" switch does not touch traffic the VPN app itself sends direct.

## How it works

```
Claude (any app) --> packet to Anthropic --> macOS kernel, pf rule:
                                             "to Anthropic networks: only via utun38"
                                              |
           leaves through utun38 (VPN)  <-----+  allowed
           leaves through en0 (Wi-Fi)   <-----+  dropped at once ("connection refused")

The daemon (not on the packet path):
  a tunnel appears/changes --> check the exit country through it --> not blocked? --> "only via utunN"
  no tunnel / blocked exit --> "to Anthropic: never"
  every 30 s               --> re-check the exit country
  every 5 s                --> is pf on? is the rule in place? (if not: put it back)
```

**pf** is the packet filter built into macOS. The rule lives in the anchor
`com.apple/000.ClaudeVPNLock`, which the stock `/etc/pf.conf` already loads through its
`anchor "com.apple/*"` line, so `/etc/pf.conf` is never edited.

The rule names **one** verified interface. VPN gone: the packet would leave through `en0`,
so it is dropped. Tunnel recreated under a new name: the new tunnel is blocked until the
daemon has checked its exit country (about a second in tests). VPN app sends a flow
direct: that flow leaves through `en0`, so it is dropped too.

## Requirements

- macOS with the stock `/etc/pf.conf` (tested on macOS 26 Tahoe, Apple silicon).
- A VPN app in **TUN mode** (it creates a `utunN` interface and macOS marks it as a VPN).
  Tested with **Happ**. Should work with WireGuard, Outline, V2Box, Hiddify, Clash Verge,
  sing-box in TUN mode, but not tested yet: please report.
- An administrator account (the lock is a system service).

## Install

Turn the VPN **on** first; the installer refuses to start without it.

```bash
git clone https://github.com/AvlasVlad/claude-vpn-lock.git
cd claude-vpn-lock
bash install.sh --dry-run     # shows the plan and checks your VPN; changes nothing
sudo bash install.sh          # installs and proves the lock works
```

The installer proves the lock before it finishes: a test packet sent past the tunnel must be
dropped by the kernel (otherwise everything is rolled back), then one request to Anthropic
goes through the tunnel. It never sends anything to Anthropic outside the tunnel to "see if it
gets through": blocking is proven on `203.0.113.7`, an address reserved for documentation
that does not exist on the internet.

### Or let Claude Code install it

Paste this into Claude Code:

```text
Install claude-vpn-lock on this Mac: https://github.com/AvlasVlad/claude-vpn-lock
Clone it, read README.md and every script before running anything, and tell me in plain
words what it will change. Run `bash install.sh --dry-run` and show me the result.
The install needs my admin password: give me the exact `sudo bash install.sh` command to run
myself in my terminal, wait for me, then read the output and explain it.
Never test whether Claude "gets through" by sending requests to Anthropic outside the VPN.
```

## Check that it works

```bash
sudo bash check.sh            # full check with pf counters as evidence (safe: never unblocks)
sudo bash check.sh --short    # the main checks only
sudo bash vpn-off-test.sh     # you turn the VPN off and on; it watches every second
```

Or simply: turn the VPN off, and Claude stops answering. Turn it on, and Claude works again
within about a second.

## Remove

```bash
sudo bash uninstall.sh --dry-run   # what would be removed
sudo bash uninstall.sh             # removes everything and compares the machine with the
                                   # snapshot taken before install
```

## What is covered and what is not

| Situation | What happens |
|---|---|
| VPN drops for a split second | packets to Anthropic are dropped by the kernel; no window |
| VPN app recreates the tunnel under a new name (`utun36` -> `utun38`) | the new tunnel is blocked until its exit country is checked |
| VPN app recreates the tunnel under the same name | traffic still goes through the VPN; the exit country is re-checked as soon as the daemon notices (route event, at most one 5 s tick) |
| VPN app sends Anthropic traffic direct, outside its tunnel | dropped by the kernel; no window |
| VPN server in a blocked country (`BLOCKED_COUNTRIES`) | blocked after the exit check: at once on connect, **up to 30 s** if the server changes without reconnecting. While the exit check keeps failing (no answer from Cloudflare and the fallbacks), the last verdict stays in force |
| Exit country cannot be checked for a new tunnel | open, noted in the log (`COUNTRY_FAIL=open`; can be `closed`) |
| Someone disables pf or flushes the rule or the table | put back on the next 5 s tick (5–6 s measured; up to ~13 s if an exit check is running), logged; a notification on screen when pf was switched off |
| Something replaces the whole pf ruleset without the stock `com.apple/*` hook (another VPN's kill switch, a custom `pf.conf`) | **the lock cannot work.** Noticed within 60 s: log entry and a notification |
| The daemon crashes | the last rule stays; launchd restarts the daemon within 5 s |
| Boot | the daemon starts with "closed" until a tunnel is verified |
| IPv6 networks | Anthropic over IPv6 (`2607:6bc0::/32`) is blocked by the same rule |
| Travelling without a VPN | **Claude does not work.** That is the point: only through the VPN |
| `a-cdn.claude.ai`, `status.claude.com` without the VPN | **not covered**: they sit on Amazon CloudFront with thousands of other sites, blocking those addresses would break other sites. Static files and the status page, not requests to the model |
| Other apps' error reports to Sentry / Datadog | Claude reports errors to shared Sentry and Datadog endpoints, so those addresses are also only allowed through the VPN. Other apps reporting to the same endpoints are affected the same way |

## Settings

`/opt/claude-vpn-lock/claude-vpn-lock.conf` (after editing:
`sudo launchctl kickstart -k system/io.github.avlasvlad.claude-vpn-lock`):

- `BLOCKED_COUNTRIES="RU BY"`: exit countries in which Claude must not be used
  (two-letter codes, checked through the tunnel via Cloudflare's `/cdn-cgi/trace`).
- `COUNTRY_INTERVAL=30`: how often the exit country is re-checked, seconds.
- `COUNTRY_FAIL=open`: a new tunnel whose exit country cannot be checked: `open` (noted
  in the log) or `closed`.

## Logs and status

```bash
sudo /opt/claude-vpn-lock/claude-vpn-lock-daemon.sh status
tail -f /var/log/claude-vpn-lock.log
```

- `STATE open :: ... exit NL 192.0.2.52`: tunnel verified, Claude works.
- `STATE closed :: no VPN tunnel ...`: no VPN, Claude blocked.
- `PF rule being replaced had blocked N packets`: how many packets were dropped while that
  rule was in place.

## What it connects to

- The daemon, through the tunnel: `https://1.1.1.1/cdn-cgi/trace` every 30 s to learn the exit
  country (fallbacks: `www.cloudflare.com/cdn-cgi/trace`, `ipinfo.io/json`); DNS lookups of
  Anthropic's host names every 30 minutes through the system resolver.
- `install.sh` and `check.sh`: one request to `https://api.anthropic.com/` through the tunnel
  (IPv4), never outside it. A test packet to `203.0.113.7`, which is dropped before it leaves.
- `check.sh` only: `77.88.44.55` (an address many VPN apps route "direct", to show such traffic
  is cut too; change it with `CVL_DIRECT_TEST_IP=...`), and `api.github.com`,
  `registry.npmjs.org`, `pypi.org`, `www.cloudflare.com` (to show other services still work).

## Security notes

- Everything root runs lives in `/opt/claude-vpn-lock`, owned by root. Not `/usr/local`: with
  Homebrew on an Intel Mac that folder belongs to the user, who could swap what root executes.
  The installer refuses to install if `/opt` can be changed by a non-root user, and the daemon
  ignores its config file (and logs it) if the file or a folder above it is not root-only.
- pf is off by default on macOS. If it is off and other rules are already loaded, switching it
  on would make them work too; the installer lists them and stops
  (`--enable-pf-anyway` goes ahead).

## Known limits

- Anthropic's own ranges `160.79.104.0/21` and `2607:6bc0::/32` are built in. Hosts outside
  them (downloads, assets, telemetry) are learned from DNS every 30 minutes and kept for 30
  days. If Anthropic moves to new addresses, the lock is incomplete until DNS reveals them.
- VPN apps in **proxy mode** (no TUN interface): the installer will not install. If you switch
  the VPN app to proxy mode later, the lock stays "closed": programs that use the proxy keep
  working, programs that ignore it are blocked (by design; not tested).
- pf stays enabled while the lock is installed (it is off by default on macOS).
- `check.sh --heal-tests` (used by `tests/acceptance.sh`) removes the rule for a few seconds to
  prove the daemon restores it. During those seconds Anthropic is not blocked outside the
  tunnel; that is why it is off by default.
- After uninstall, `pfctl -s Anchors` may still list empty `com.apple/00x.ClaudeVPNLock*`
  nodes (0 rules, 0 tables). The macOS kernel removes empty nodes only at reboot; they do
  nothing.

## How it was tested

On a real Mac (macOS 26, Apple silicon, Happ VPN), the full acceptance `tests/acceptance.sh
--with-vpn-off` of this version passed every step: dry runs change nothing, install, full
check, the VPN switched off and on by hand, uninstall, reinstall. From that run (4 Oct 2026):

- VPN off for 11 s: **0** connections from Claude to Anthropic from the real IP address; the
  kernel dropped 51 packets to Anthropic; the test packet was refused 10 of 10 times. For the
  first 2 s the daemon had not even noticed (it still said "open"), and the packets were
  already refused: the rule does the blocking, not the daemon. Claude was open again 1 s
  after the VPN came back.
- A packet to `160.79.104.10` from the Wi-Fi interface: refused at once, rule counter +1.
  Through the tunnel: Anthropic answers, rule counter unchanged. 51 live Claude connections,
  all from the tunnel address.
- The VPN app's own direct traffic (to a test address it routes "direct") is cut by the same
  kind of rule: HTTP 406 -> refused -> 406.
- GitHub, npm, PyPI, Cloudflare answer normally with the lock on.
- Rule removed by hand: back in 6 s; table flushed: back in 1 s; `pfctl -f /etc/pf.conf`: the
  rule survives, other anchors unchanged.
- Uninstall: the machine matches the pre-install snapshot line by line.

The daemon's logic is also covered by `tests/sim.sh`: 77 checks on fake `pfctl`, `route`,
`ifconfig`, `curl` and a fake clock, no root needed. It runs on every push.

## Development

```bash
bash tests/sim.sh                         # daemon logic, no root, no network
sudo bash tests/acceptance.sh             # full acceptance on a real Mac
sudo bash tests/acceptance.sh --with-vpn-off
```

Shell is bash 3.2 (the one macOS ships). Scripts are plain text: read them before you run
them with `sudo`.

## Windows, Linux

Not yet. The idea carries over: a firewall rule that allows Anthropic's addresses only on
the VPN interface, plus a small service that keeps the rule pinned to the right interface.

- Linux: nftables `oifname` rule plus a NetworkManager dispatcher or systemd unit.
- Windows: Windows Filtering Platform / `New-NetFirewallRule -InterfaceAlias`. There is a
  separate project for Clash/Mihomo TUN users:
  [wlsnD7/claude-kill-switch-windows](https://github.com/wlsnD7/claude-kill-switch-windows).

Pull requests welcome.

## License

[MIT](LICENSE). Provided as is, without warranty. You are responsible for following the
terms of the services you use.
