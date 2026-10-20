# vpnrelay

Fast VPN tunnels for [gluetun](https://github.com/qdm12/gluetun) under **rootless Docker**.

Rootless Docker sends container traffic through a user-space network stack (slirp4netns, pasta, vpnkit or
gvisor-tap-vsock). The stack handles TCP well, but it forwards a VPN tunnel's UDP one datagram at a time. A WireGuard
or OpenVPN tunnel in gluetun therefore tops out far below what the host's link can carry. vpnrelay picks up the
tunnel's UDP before it reaches that stack and sends it out through an ordinary host socket, in batches. gluetun keeps
its stock provider settings: server choice, failover and port forwarding all still work.

| Rootless Docker, slirp4netns (stock Pulsed Media seedbox, Debian 12) | Down | Up |
|---|---|---|
| gluetun (WireGuard) without vpnrelay | 24 MB/s | 30 MB/s |
| gluetun (WireGuard) with vpnrelay | 136 MB/s | 166 MB/s |

Medians of 6 interleaved Ookla runs through the tunnel against a nearby server. Other figures, all on the same host:
- With 1,660 peers on one torrent, the tunnel went from 16 to 81 MB/s.
- Two tunnels running at once shared about 210 MB/s of download.

Test VMs (LAN endpoint; download was capped by the test endpoint): see [Compatibility](#compatibility).

## How it works

```
gluetun A ─┐  UDP to <VPN server>:51820       ip rule: iif <bridge>, udp dport <ports> → local route
gluetun B ─┴─ <bridge> ────────────────────▶  vpnrelay child, inside rootless Docker's network namespace:
                                              reads the real destination (IP_RECVORIGDSTADDR) and answers
                                              from it (IP_TRANSPARENT)
                                                  ▲ per flow, two threads: recvmmsg+GRO ⇄ sendmmsg+GSO
                                                  ▼
                                              host UDP socket connected to the VPN server, created by the
                                              vpnrelay parent in the host namespace, passed over SCM_RIGHTS
```

- **One process per tenant, running as that tenant.** It needs no root, setuid bit or file capability. It joins the
  tenant's own rootless Docker user, mount and network namespaces, where the tenant already holds `CAP_NET_ADMIN`.
- **No listener and no NAT.** vpnrelay opens no port on the host. The only rule it adds is an `ip rule` inside Docker's
  namespace, and it catches only UDP from one bridge to the listed ports. Each host socket is `connect()`ed to a
  single VPN server and never sets `SO_REUSEADDR`, so other local users can't bind to the same flow.
- **Conntrack hand-over.** A UDP flow keeps the NAT decision of its first packet. At start and at stop, vpnrelay
  deletes the bridge's tunnel entries that are wrong for the new path, over ctnetlink. A running tunnel moves to the
  relay, or back to Docker's network, on its next packet, without restarting gluetun.
- **Fails slow, never broken.** If vpnrelay stops or crashes, its rule goes away and tunnels fall back to Docker's
  normal path at the old speed. They come back to the relay when it restarts.

Every tunnel on the bridge is covered, whichever server its gluetun picked, up to 64 flows (one tunnel is one flow).
Flows the container hasn't sent anything on for 180 s are closed.

## Requirements

- Linux x86_64, kernel 4.19 or later (`ip rule ... ipproto udp dport` needs 4.17).
  - UDP GSO needs 4.18; UDP GRO needs 5.0. On older kernels vpnrelay falls back to single datagrams and says so at
    startup.
- Rootless Docker started by `dockerd-rootless.sh` (RootlessKit), either layout: `--detach-netns` or not.
- `iproute2` (`ip`) in `PATH`.
- `net.core.rmem_max` and `net.core.wmem_max` of at least 4 MiB. vpnrelay asks for 16 MiB and logs a warning when it
  gets less. With the Debian default of 208 KiB, download is about halved.
- IPv4 tunnels only.

## Install

Download `vpnrelay-x86_64-linux-musl` and `SHA256SUMS` from the latest release, then check and install them:

```sh
sha256sum -c SHA256SUMS
install -m 0755 vpnrelay-x86_64-linux-musl ~/bin/vpnrelay      # or /usr/local/bin/vpnrelay as root
```

Or build it yourself (see [Build](#build)).

## Use

1. Give gluetun a Docker network with a fixed bridge name:

   ```sh
   docker network create vpnrelay -o com.docker.network.bridge.name=br-vpn
   ```

   In compose, use `networks: {default: {name: vpnrelay, external: true}}`. Containers that route through gluetun
   (`network_mode: service:gluetun`) need nothing.

2. Run the relay for that bridge and the VPN ports your providers use:

   ```sh
   vpnrelay supervise br-vpn 51820,1637,58237,1194
   ```

   `supervise` runs the relay, cleans up after every exit, and restarts it with a backoff of 5 s up to 60 s while
   Docker is down. If a supervisor for that bridge is already running, it exits at once, so a cron line is enough:

   ```
   */5 * * * * $HOME/bin/vpnrelay supervise br-vpn 51820,1637,58237,1194 >> $HOME/.vpnrelay.log 2>&1
   ```

   With a systemd user manager, use [`examples/vpnrelay.service`](examples/vpnrelay.service) instead.

3. Check: the log shows `flow 172.x.x.x:port -> <server>:<port>` for every relayed tunnel.

To stop it, send SIGTERM to the supervisor (`pkill -f 'vpnrelay supervise br-vpn'`). vpnrelay removes its rule and
resets conntrack, and the tunnels carry on through Docker's network.

**Default ports in gluetun (v3.40):**
- WireGuard: 51820 (Mullvad, ProtonVPN, NordVPN, Surfshark, FastestVPN), 1637 (AirVPN), 58237 (IVPN),
  1194 (Windscribe).
- OpenVPN over UDP: mostly 1194; some providers use 443 or 53.

The only raw UDP leaving a gluetun-only bridge is the VPN transport, because everything else goes inside the tunnel.
Listing extra ports is therefore harmless.

### Commands and switches

| Command | |
|---|---|
| `vpnrelay supervise <bridge> <ports>` | run, clean up and restart (use this) |
| `vpnrelay transparent <bridge> <ports>` | run the relay in the foreground |
| `vpnrelay cleanup <bridge> <ports>` | remove a stale rule and reset conntrack; does nothing while a relay runs |

| Environment | Default | |
|---|---|---|
| `VPNRELAY_RULE` | `4820` | `ip rule` priority and routing table number |
| `VPNRELAY_SOCKBUF` | 16 MiB | socket buffer request, capped by `net.core.[rw]mem_max` |
| `VPNRELAY_NO_GRO`, `VPNRELAY_NO_GSO` | unset | force the single-datagram paths |
| `VPNRELAY_DOCKER_STATE` | `$XDG_RUNTIME_DIR/dockerd-rootless` | RootlessKit state dir of another dockerd |

## Compatibility

Run on Debian test VMs with rootless Docker set up by [PMSS](https://github.com/MagnaCapax/PMSS) (slirp4netns,
bridge MTU 65520), gluetun v3.40.0 on the `custom` provider, and an endpoint on another VM. Figures are iperf3
through the tunnel in MB/s, relay off → on, medians of 2–3 runs.

| Debian | Kernel | Docker | RootlessKit layout | VPN | Up | Down |
|---|---|---|---|---|---|---|
| 10 | 4.19 (no GRO) | 26.1.4 | non-detached | WireGuard (userspace) | 216 → 549 | 98 → 99 * |
| 11 | 5.10 | 29.8.0 | `--detach-netns` | WireGuard (kernel) | 206 → 508 | 95 → 100 * |
| 12 | 6.1 | 29.9.1 | `--detach-netns` | WireGuard (kernel) | 97 → 104 * | 86 → 85 * |
| 12 | 6.1 | 29.9.1 | `--detach-netns` | OpenVPN UDP | 96 → 102 * | 143 → 173 * |

\* Limited by the test endpoint. A plain kernel WireGuard tunnel between the same VMs, with no containers, also ran at
about 100 MB/s on one stream. The real-world gain is the seedbox table above. On every row:
- the tunnel moved to the relay and back without a restart, and conntrack was reset in both directions;
- `nf_conntrack_netlink`, which isn't loaded after boot, loaded on demand from inside the rootless namespace;
- after SIGTERM no relay process was left.

## Security notes

- vpnrelay runs with the tenant's own privileges. Everything it changes is inside the tenant's own rootless Docker
  namespaces.
- Traffic leaves the host from a normal socket owned by the tenant, so per-UID accounting and firewall rules apply as
  they do to any other process of that user.
- Conntrack deletions are limited to the tenant's own network namespace. The host's conntrack table is not reachable
  from the tenant's user namespace: entries outside it return `ENOENT`.

## Build

```sh
./build.sh
```

This makes a static musl binary with the toolchain pinned in `rust-toolchain.toml`. The build is reproducible: the same
source gives the same bytes from any directory, and the script prints the SHA-256 to compare against a release. The
only dependency is `libc`.

## Related work

- [bypass4netns](https://github.com/rootless-containers/bypass4netns) speeds up rootless containers in general by
  replacing their sockets with host sockets through seccomp user notification. It needs kernel 5.9+ and a seccomp
  profile on each container, and is aimed at nerdctl. vpnrelay works with Docker as is, on older kernels, and for
  tunnels whose UDP the kernel itself sends, such as WireGuard.
- Switching the RootlessKit network driver (pasta instead of slirp4netns) helps TCP. It doesn't change the
  per-datagram cost of a VPN tunnel.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this work, as
defined in the Apache-2.0 license, is dual licensed as above, without any additional terms or conditions.
