//! Transparent mode: carry the VPN UDP of every gluetun container on one Docker bridge past rootless Docker's
//! user-space network (slirp4netns, pasta, ...), whatever server each gluetun picked. gluetun keeps its stock
//! provider settings (server choice, failover, port forwarding).
//!
//!   transparent <bridge> <port>[,<port>..]   host user service; forks once:
//!     parent: stays in the host netns and makes connected UDP sockets to VPN servers on request; hands each
//!             one to the child over a socketpair (SCM_RIGHTS). Exits when the child does or Docker restarts.
//!     child:  joins rootless Docker's netns. An ip rule sends UDP from <bridge> to <port> into a `local`
//!             route, so it lands on a wildcard socket here (no NAT, no TPROXY module). IP_RECVORIGDSTADDR
//!             gives the server; the flow then gets its own socket bound to the server address
//!             (IP_TRANSPARENT) and connected to the container, plus a host socket from the parent.
//!             Two threads per flow move batches between the two (recvmmsg + UDP_GRO, sendmmsg + UDP_SEGMENT).
//!   cleanup <bridge> <port>[,<port>..]       ExecStopPost: remove the rule, then reset the flows' conntrack
//!                                            entries so the tunnels fall back to Docker's network on the next packet.
//!   supervise <bridge> <port>[,<port>..]     for hosts without a systemd user manager (PMSS starts dockerd with
//!                                            nohup): runs `transparent`, cleans up after it and restarts it. Exits at
//!                                            once if a supervisor for <bridge> already runs, so cron can call it.
//!
//! The relay process also cleans up by itself on SIGTERM or when its parent dies. A lock per bridge keeps a second
//! instance (or a cleanup) away from a running one.
//!
//! Conntrack: a flow keeps the NAT decision of its first packet. A tunnel that started through Docker's network
//! keeps its MASQUERADE (the relay would see 10.0.2.100); one that started here has no NAT and would reach Docker's
//! network un-masqueraded after a fallback. So start and cleanup delete the entries whose NAT state is wrong for the new
//! mode, re-checking for ~3 s (see reset_conntrack).

use std::collections::HashMap;
use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs, mem, ptr, thread};

use crate::{setopt, sockaddr, SOL_UDP, UDP_GRO, UDP_SEGMENT};

const IP_TRANSPARENT: i32 = 19;
const IP_RECVORIGDSTADDR: i32 = 20;
// A flow is closed when the container has sent nothing for this long. Only that direction counts: a live WireGuard
// peer sends at least a keepalive within 10 s of receiving data, while a server may keep sending to a gone container.
const IDLE_SECS: u64 = 180;
const MSGS: usize = 32; // messages per recvmmsg
const BUF: usize = 65536; // per message (a GRO buffer is at most 64 KiB)
const GSO_MAX_SEGS: usize = 64;
const GSO_MAX_BYTES: usize = 60000;
const MAX_FLOWS: usize = 64; // a tunnel is one flow; more than this means something other than VPN clients on the bridge

/// ip rule pref and route table (VPNRELAY_RULE, default 4820).
fn rule() -> String {
    env::var("VPNRELAY_RULE").ok().filter(|r| r.parse::<u32>().is_ok()).unwrap_or_else(|| "4820".into())
}

/// Socket buffer request (VPNRELAY_SOCKBUF bytes, default 16 MiB); the kernel caps it at net.core.[rw]mem_max.
fn sockbuf() -> i32 {
    env::var("VPNRELAY_SOCKBUF").ok().and_then(|v| v.parse().ok()).unwrap_or(16 << 20)
}

/// UDP GRO on the flow sockets; VPNRELAY_NO_GRO forces it off (the receive path then handles single datagrams).
fn gro_wanted() -> bool {
    env::var("VPNRELAY_NO_GRO").is_err()
}

fn fail(msg: &str) -> ! {
    log!("vpnrelay: {msg}: {}", std::io::Error::last_os_error());
    std::process::exit(1)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn from_sa(s: &libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr)), u16::from_be(s.sin_port))
}

fn state_dir() -> String {
    env::var("VPNRELAY_DOCKER_STATE").unwrap_or_else(|_| {
        let run = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));
        format!("{run}/dockerd-rootless")
    })
}

static TERM: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: libc::c_int) {
    TERM.store(true, Ordering::Relaxed);
}

fn catch_term() {
    unsafe {
        let h = on_term as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
    }
}

/// Non-blocking exclusive lock on $XDG_RUNTIME_DIR/vpnrelay-<name>.lock. The fd stays open for the process
/// lifetime and is inherited across fork, so the lock is held until every holder has exited. False only when
/// another process holds it; if the file can't be opened, warn and carry on unlocked.
fn lock(name: &str) -> bool {
    let run = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));
    let path = format!("{run}/vpnrelay-{name}.lock");
    let c = CString::new(path.clone()).unwrap();
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600);
        if fd < 0 {
            log!("vpnrelay: cannot open {path} ({}), running without the instance lock", std::io::Error::last_os_error());
            return true;
        }
        libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) == 0
    }
}

fn child_pid(dir: &str) -> Option<String> {
    fs::read_to_string(format!("{dir}/child_pid")).ok().map(|s| s.trim().to_string())
}

/// Join rootless Docker's network namespace: its user ns, then its mount ns (where the netns file is
/// bind-mounted with --detach-netns), then the netns (that file, or the rootlesskit child's own). Must run before any thread is started.
fn enter_docker_netns(dir: &str) -> bool {
    let Some(pid) = child_pid(dir) else { return false };
    let open = |p: String| {
        let c = CString::new(p).unwrap();
        unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) }
    };
    let (user, mnt) = (open(format!("/proc/{pid}/ns/user")), open(format!("/proc/{pid}/ns/mnt")));
    unsafe {
        let mut net = -1;
        let ok = user >= 0 && mnt >= 0 && libc::setns(user, libc::CLONE_NEWUSER) == 0 && libc::setns(mnt, libc::CLONE_NEWNS) == 0 && {
            // rootlesskit --detach-netns keeps Docker's netns in a file; without it, it is the child's own netns
            net = open(format!("{dir}/netns"));
            if net < 0 {
                net = open(format!("/proc/{pid}/ns/net"));
            }
            net >= 0 && libc::setns(net, libc::CLONE_NEWNET) == 0
        };
        for fd in [user, mnt, net] {
            if fd >= 0 {
                libc::close(fd);
            }
        }
        ok
    }
}

fn ip(args: &[&str], quiet: bool) -> bool {
    let mut c = Command::new("ip");
    c.args(args);
    if quiet {
        c.stderr(Stdio::null());
    }
    c.status().map(|s| s.success()).unwrap_or(false)
}

fn add_rules(bridge: &str, ports: &[u16]) {
    let r = rule();
    if !ip(&["route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", &r], false) {
        fail("ip route add local");
    }
    for p in ports {
        let p = p.to_string();
        if !ip(&["rule", "add", "pref", &r, "iif", bridge, "ipproto", "udp", "dport", &p, "lookup", &r], false) {
            fail("ip rule add");
        }
    }
}

fn remove_rules() {
    let r = rule();
    for _ in 0..64 {
        if !ip(&["rule", "del", "pref", &r], true) {
            break;
        }
    }
    ip(&["route", "flush", "table", &r], true);
}

/// The bridge's IPv4 network, as (address, prefix mask).
fn bridge_net(bridge: &str) -> Option<(u32, u32)> {
    let out = Command::new("ip").args(["-4", "-o", "addr", "show", "dev", bridge]).stderr(Stdio::null()).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let cidr = s.split_whitespace().skip_while(|w| *w != "inet").nth(1)?;
    let (a, len) = cidr.split_once('/')?;
    let len: u32 = len.parse().ok()?;
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Some((u32::from(a.parse::<Ipv4Addr>().ok()?) & mask, mask))
}

fn nla(t: u16, p: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + p.len() + 3);
    v.extend(((4 + p.len()) as u16).to_ne_bytes());
    v.extend(t.to_ne_bytes());
    v.extend(p);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

/// Delete one UDP conntrack entry by its original tuple (ctnetlink IPCTNL_MSG_CT_DELETE). Returns errno (0 = ok).
fn ct_delete(src: SocketAddrV4, dst: SocketAddrV4) -> i32 {
    const NESTED: u16 = 0x8000;
    let tip = [nla(1, &src.ip().octets()), nla(2, &dst.ip().octets())].concat();
    let tpr = [nla(1, &[libc::IPPROTO_UDP as u8]), nla(2, &src.port().to_be_bytes()), nla(3, &dst.port().to_be_bytes())].concat();
    let mut body = vec![libc::AF_INET as u8, 0, 0, 0];
    body.extend(nla(1 | NESTED, &[nla(1 | NESTED, &tip), nla(2 | NESTED, &tpr)].concat()));
    let mut msg = Vec::new();
    msg.extend(((16 + body.len()) as u32).to_ne_bytes());
    msg.extend(((1u16 << 8) | 2).to_ne_bytes()); // NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_DELETE
    msg.extend((libc::NLM_F_REQUEST as u16 | libc::NLM_F_ACK as u16).to_ne_bytes());
    msg.extend(1u32.to_ne_bytes());
    msg.extend(0u32.to_ne_bytes());
    msg.extend(body);
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_NETFILTER);
        if fd < 0 {
            return -1;
        }
        let mut r = [0u8; 512];
        let mut err = -1;
        if libc::send(fd, msg.as_ptr() as *const _, msg.len(), 0) == msg.len() as isize
            && libc::recv(fd, r.as_mut_ptr() as *mut _, r.len(), 0) >= 20
        {
            err = -i32::from_ne_bytes([r[16], r[17], r[18], r[19]]);
        }
        libc::close(fd);
        err
    }
}

/// Netlink attributes in `b` as (type without flags, payload).
fn nlattrs(mut b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut v = Vec::new();
    while b.len() >= 4 {
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        if len < 4 || len > b.len() {
            break;
        }
        v.push((u16::from_ne_bytes([b[2], b[3]]) & 0x3fff, &b[4..len]));
        b = &b[((len + 3) & !3).min(b.len())..];
    }
    v
}

/// One conntrack tuple: (src, dst, proto, sport, dport).
fn ct_tuple(b: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u8, u16, u16)> {
    let (mut src, mut dst, mut proto, mut sp, mut dp) = (None, None, None, None, None);
    for (t, p) in nlattrs(b) {
        for (u, q) in nlattrs(p) {
            match (t, u, q.len()) {
                (1, 1, 4) => src = Some(Ipv4Addr::new(q[0], q[1], q[2], q[3])), // CTA_TUPLE_IP / CTA_IP_V4_SRC
                (1, 2, 4) => dst = Some(Ipv4Addr::new(q[0], q[1], q[2], q[3])),
                (2, 1, 1) => proto = Some(q[0]), // CTA_TUPLE_PROTO / CTA_PROTO_NUM
                (2, 2, 2) => sp = Some(u16::from_be_bytes([q[0], q[1]])),
                (2, 3, 2) => dp = Some(u16::from_be_bytes([q[0], q[1]])),
                _ => {}
            }
        }
    }
    Some((src?, dst?, proto?, sp?, dp?))
}

/// UDP conntrack entries of the current netns as (src, dst, reply dst, sport, dport) of the original direction.
/// Read over ctnetlink: it needs only CAP_NET_ADMIN in the netns's user namespace. /proc/net/nf_conntrack is the
/// fallback; it is unreadable when RootlessKit runs without --detach-netns (the netns was created before the uid
/// map was written, so procfs shows its files as owned by nobody).
fn ct_udp_entries() -> Option<Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr, u16, u16)>> {
    let mut msg = Vec::new();
    msg.extend(20u32.to_ne_bytes());
    msg.extend(((1u16 << 8) | 1).to_ne_bytes()); // NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET
    msg.extend((libc::NLM_F_REQUEST as u16 | libc::NLM_F_DUMP as u16).to_ne_bytes());
    msg.extend(1u32.to_ne_bytes());
    msg.extend(0u32.to_ne_bytes());
    msg.extend([libc::AF_INET as u8, 0, 0, 0]);
    let mut out = Vec::new();
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_NETFILTER);
        if fd < 0 {
            return ct_udp_entries_proc();
        }
        set_rcvtimeo(fd);
        let mut ok = libc::send(fd, msg.as_ptr() as *const _, msg.len(), 0) == msg.len() as isize;
        let mut buf = vec![0u8; 65536];
        'recv: while ok {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
            if n <= 0 {
                ok = false;
                break;
            }
            let mut b = &buf[..n as usize];
            while b.len() >= 16 {
                let len = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize;
                let typ = u16::from_ne_bytes([b[4], b[5]]);
                if len < 16 || len > b.len() {
                    break;
                }
                match typ {
                    3 => break 'recv, // NLMSG_DONE
                    2 => {
                        ok = false; // NLMSG_ERROR
                        break 'recv;
                    }
                    _ if len >= 20 => {
                        let (mut orig, mut reply) = (None, None);
                        for (t, p) in nlattrs(&b[20..len]) {
                            match t {
                                1 => orig = ct_tuple(p), // CTA_TUPLE_ORIG
                                2 => reply = ct_tuple(p), // CTA_TUPLE_REPLY
                                _ => {}
                            }
                        }
                        if let (Some((s, d, 17, sp, dp)), Some((_, rd, ..))) = (orig, reply) {
                            out.push((s, d, rd, sp, dp));
                        }
                    }
                    _ => {}
                }
                b = &b[((len + 3) & !3).min(b.len())..];
            }
        }
        libc::close(fd);
        if ok { Some(out) } else { ct_udp_entries_proc() }
    }
}

fn ct_udp_entries_proc() -> Option<Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr, u16, u16)>> {
    let table = fs::read_to_string("/proc/net/nf_conntrack").ok()?;
    Some(
        table
            .lines()
            .filter(|l| l.contains(" udp "))
            .filter_map(|line| {
                let vals = |k: &str| line.split_whitespace().filter_map(|w| w.strip_prefix(k)).collect::<Vec<_>>();
                let (src, dst, sport, dport) = (vals("src="), vals("dst="), vals("sport="), vals("dport="));
                if src.len() < 2 || dst.len() < 2 || sport.is_empty() || dport.is_empty() {
                    return None;
                }
                Some((src[0].parse().ok()?, dst[0].parse().ok()?, dst[1].parse().ok()?, sport[0].parse().ok()?, dport[0].parse().ok()?))
            })
            .collect(),
    )
}

/// Make the conntrack entries of the bridge's tunnels match the mode, deleting the ones that don't, for ~3 s so a
/// packet racing the switch can't leave a wrong entry behind. `relayed` = the relay is taking over: an entry with
/// NAT (MASQUERADE from Docker's path) is stale. Otherwise (fallback) an entry without NAT is stale. A tunnel's
/// next packet then creates a fresh entry for the current path. Matches both directions: if the relay's download
/// packet came first, the original tuple is server -> container.
fn reset_conntrack(bridge: &str, ports: &[u16], relayed: bool) {
    let Some((net, mask)) = bridge_net(bridge) else {
        log!("vpnrelay: no IPv4 address on {bridge}, conntrack not reset");
        return;
    };
    let (mut seen, mut deleted) = (0, 0);
    for round in 0..7 {
        if round > 0 {
            thread::sleep(Duration::from_millis(500));
        }
        let Some(table) = ct_udp_entries() else {
            log!("vpnrelay: cannot read the conntrack table (ctnetlink or /proc), conntrack not reset");
            return;
        };
        for (s, d, rd, sp, dp) in table {
            let ours = (ports.contains(&dp) && u32::from(s) & mask == net) || (ports.contains(&sp) && u32::from(d) & mask == net);
            if !ours {
                continue;
            }
            seen += 1;
            let natted = rd != s; // reply goes to someone other than the original sender: MASQUERADE applied
            if natted == relayed {
                let (a, b) = (SocketAddrV4::new(s, sp), SocketAddrV4::new(d, dp));
                log!("vpnrelay: conntrack reset {a} -> {b} ({}): errno {}", if natted { "NAT" } else { "no NAT" }, ct_delete(a, b));
                deleted += 1;
            }
        }
    }
    log!("vpnrelay: conntrack {}: {seen} tunnel entry sightings, {deleted} reset", if relayed { "to relay" } else { "to fallback" });
}

fn set_rcvtimeo(fd: i32) {
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const _, mem::size_of::<libc::timeval>() as _);
    }
}

/// UDP socket: optional transparent bind, optional connect. -1 on failure.
fn udp(bind: SocketAddrV4, connect: Option<SocketAddrV4>, transparent: bool) -> i32 {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return -1;
        }
        for opt in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            setopt(fd, libc::SOL_SOCKET, opt, sockbuf()); // clamped to net.core.[rw]mem_max
        }
        if transparent {
            setopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1);
            setopt(fd, libc::SOL_IP, IP_TRANSPARENT, 1);
        }
        let b = sockaddr(bind);
        let mut ok = libc::bind(fd, &b as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_in>() as _) == 0;
        if let (true, Some(c)) = (ok, connect) {
            let c = sockaddr(c);
            ok = libc::connect(fd, &c as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_in>() as _) == 0;
        }
        if !ok {
            libc::close(fd);
            return -1;
        }
        if gro_wanted() {
            setopt(fd, SOL_UDP, UDP_GRO, 1); // fails on kernels before 5.0; datagrams then arrive singly
        }
        set_rcvtimeo(fd);
        fd
    }
}

fn send_fd(sock: i32, fd: i32) {
    unsafe {
        let mut b = [if fd >= 0 { 0u8 } else { 1 }];
        let mut iov = libc::iovec { iov_base: b.as_mut_ptr() as *mut _, iov_len: 1 };
        let mut cbuf = [0u64; 4];
        let mut h: libc::msghdr = mem::zeroed();
        h.msg_iov = &mut iov;
        h.msg_iovlen = 1;
        if fd >= 0 {
            h.msg_control = cbuf.as_mut_ptr() as *mut _;
            h.msg_controllen = libc::CMSG_SPACE(4) as _;
            let c = libc::CMSG_FIRSTHDR(&h);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
            ptr::write_unaligned(libc::CMSG_DATA(c) as *mut i32, fd);
        }
        libc::sendmsg(sock, &h, 0);
    }
}

fn recv_fd(sock: i32) -> Option<i32> {
    unsafe {
        let mut b = [0u8; 1];
        let mut iov = libc::iovec { iov_base: b.as_mut_ptr() as *mut _, iov_len: 1 };
        let mut cbuf = [0u64; 4];
        let mut h: libc::msghdr = mem::zeroed();
        h.msg_iov = &mut iov;
        h.msg_iovlen = 1;
        h.msg_control = cbuf.as_mut_ptr() as *mut _;
        h.msg_controllen = mem::size_of_val(&cbuf) as _;
        if libc::recvmsg(sock, &mut h, libc::MSG_CMSG_CLOEXEC) != 1 || b[0] != 0 {
            return None;
        }
        let c = libc::CMSG_FIRSTHDR(&h);
        if c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
            return None;
        }
        Some(ptr::read_unaligned(libc::CMSG_DATA(c) as *const i32))
    }
}

/// Parent: host-netns socket factory. Request = server address (4 bytes ip + 2 bytes port, big endian).
fn factory(ctl: i32, child: libc::pid_t, dir: &str) -> ! {
    let docker = child_pid(dir);
    loop {
        let mut pfd = libc::pollfd { fd: ctl, events: libc::POLLIN, revents: 0 };
        let r = unsafe { libc::poll(&mut pfd, 1, 2000) };
        let mut st = 0;
        if unsafe { libc::waitpid(child, &mut st, libc::WNOHANG) } == child {
            log!("vpnrelay: relay process exited (status {st})");
            std::process::exit(1);
        }
        if child_pid(dir) != docker {
            log!("vpnrelay: rootless Docker restarted; exiting so systemd starts a fresh relay in its new netns");
            unsafe { libc::kill(child, libc::SIGKILL) };
            std::process::exit(1);
        }
        if r <= 0 {
            continue;
        }
        let mut req = [0u8; 6];
        let n = unsafe { libc::recv(ctl, req.as_mut_ptr() as *mut _, 6, 0) };
        if n <= 0 {
            unsafe { libc::kill(child, libc::SIGKILL) };
            std::process::exit(1);
        }
        if n != 6 {
            continue;
        }
        let server = SocketAddrV4::new(Ipv4Addr::new(req[0], req[1], req[2], req[3]), u16::from_be_bytes([req[4], req[5]]));
        // Never SO_REUSEADDR/SO_REUSEPORT here: this socket sits in the shared host netns, and for UDP the kernel lets
        // any other local user bind the same 4-tuple when both set SO_REUSEADDR (no UID check), taking over the
        // tunnel's replies.
        let fd = udp(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0), Some(server), false);
        send_fd(ctl, fd);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
}

struct Flow {
    host: i32, // connected to the VPN server, host netns
    local: i32, // bound to the server address, connected to the container, Docker netns
    stop: AtomicBool,
    last: AtomicU64, // last packet from the container
    up: AtomicU64, // bytes container -> server
    down: AtomicU64, // bytes server -> container
}

impl Drop for Flow {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.host);
            libc::close(self.local);
        }
    }
}

fn gro_seg(h: &libc::msghdr, len: usize) -> usize {
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(h);
        while !c.is_null() {
            if (*c).cmsg_level == SOL_UDP && (*c).cmsg_type == UDP_GRO {
                let d = libc::CMSG_DATA(c);
                return if (*c).cmsg_len as usize >= libc::CMSG_LEN(4) as usize {
                    ptr::read_unaligned(d as *const i32) as usize
                } else {
                    ptr::read_unaligned(d as *const u16) as usize
                };
            }
            c = libc::CMSG_NXTHDR(h, c);
        }
    }
    len
}

fn send_singly(tx: i32, bufs: &[u8], lens: &[(usize, usize)]) {
    for (k, &(len, seg)) in lens.iter().enumerate() {
        for chunk in bufs[k * BUF..k * BUF + len].chunks(seg) {
            unsafe { libc::send(tx, chunk.as_ptr() as *const _, chunk.len(), 0) };
        }
    }
}

/// Move datagrams rx -> tx, both connected. A GRO buffer is sent as it is with UDP_SEGMENT = its segment
/// size; runs of single datagrams of one size are grouped into GSO sends.
fn pump(rx: i32, tx: i32, f: Arc<Flow>, bytes: &AtomicU64, from_container: bool) {
    let mut bufs = vec![0u8; MSGS * BUF];
    let mut rctl = vec![[0u64; 8]; MSGS];
    let mut riov: Vec<libc::iovec> =
        (0..MSGS).map(|i| libc::iovec { iov_base: bufs[i * BUF..].as_mut_ptr() as *mut _, iov_len: BUF }).collect();
    let mut rmsg: Vec<libc::mmsghdr> = vec![unsafe { mem::zeroed() }; MSGS];
    let mut siov: Vec<libc::iovec> = vec![libc::iovec { iov_base: ptr::null_mut(), iov_len: 0 }; MSGS];
    let mut smsg: Vec<libc::mmsghdr> = vec![unsafe { mem::zeroed() }; MSGS];
    let mut sctl = vec![[0u64; 4]; MSGS];
    let mut lens = [(0usize, 0usize); MSGS]; // (bytes, segment size)
    let mut gso = env::var("VPNRELAY_NO_GSO").is_err();
    while !f.stop.load(Ordering::Relaxed) {
        for i in 0..MSGS {
            let h = &mut rmsg[i].msg_hdr;
            h.msg_iov = &mut riov[i];
            h.msg_iovlen = 1;
            h.msg_name = ptr::null_mut();
            h.msg_namelen = 0;
            h.msg_control = rctl[i].as_mut_ptr() as *mut _;
            h.msg_controllen = mem::size_of::<[u64; 8]>() as _;
            h.msg_flags = 0;
        }
        let n = unsafe { libc::recvmmsg(rx, rmsg.as_mut_ptr(), MSGS as _, libc::MSG_WAITFORONE as _, ptr::null_mut()) };
        if n <= 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) | Some(libc::ECONNREFUSED) => continue,
                _ => break,
            }
        }
        let n = n as usize;
        if from_container {
            f.last.store(now(), Ordering::Relaxed);
        }
        let mut total = 0;
        for i in 0..n {
            let len = rmsg[i].msg_len as usize;
            lens[i] = (len, gro_seg(&rmsg[i].msg_hdr, len).clamp(1, len.max(1)));
            total += len as u64;
        }
        bytes.fetch_add(total, Ordering::Relaxed);
        if !gso {
            send_singly(tx, &bufs, &lens[..n]);
            continue;
        }
        // build GSO messages
        let mut nmsg = 0;
        let mut i = 0;
        while i < n {
            let first = i;
            let (len, seg) = lens[i];
            siov[i] = libc::iovec { iov_base: bufs[i * BUF..].as_mut_ptr() as *mut _, iov_len: len };
            i += 1;
            let mut seg_size = seg;
            if seg == len {
                // single datagram: extend with following single datagrams of the same size (a shorter one ends it)
                let mut total = len;
                while i < n && i - first < GSO_MAX_SEGS {
                    let (l2, s2) = lens[i];
                    if s2 != l2 || l2 > len || total + l2 > GSO_MAX_BYTES {
                        break;
                    }
                    siov[i] = libc::iovec { iov_base: bufs[i * BUF..].as_mut_ptr() as *mut _, iov_len: l2 };
                    total += l2;
                    i += 1;
                    if l2 < len {
                        break;
                    }
                }
                if i - first == 1 {
                    seg_size = 0;
                }
            }
            let h = &mut smsg[nmsg].msg_hdr;
            *h = unsafe { mem::zeroed() };
            h.msg_iov = &mut siov[first];
            h.msg_iovlen = (i - first) as _;
            if seg_size > 0 {
                unsafe {
                    h.msg_control = sctl[nmsg].as_mut_ptr() as *mut _;
                    h.msg_controllen = libc::CMSG_SPACE(2) as _;
                    let c = libc::CMSG_FIRSTHDR(h);
                    (*c).cmsg_level = SOL_UDP;
                    (*c).cmsg_type = UDP_SEGMENT;
                    (*c).cmsg_len = libc::CMSG_LEN(2) as _;
                    ptr::write_unaligned(libc::CMSG_DATA(c) as *mut u16, seg_size as u16);
                }
            }
            nmsg += 1;
        }
        let mut sent = 0;
        while sent < nmsg {
            let r = unsafe { libc::sendmmsg(tx, smsg[sent..].as_mut_ptr(), (nmsg - sent) as _, 0) };
            if r > 0 {
                sent += r as usize;
                continue;
            }
            let e = std::io::Error::last_os_error().raw_os_error();
            if e == Some(libc::EIO) || e == Some(libc::EINVAL) {
                log!("vpnrelay: UDP GSO refused ({e:?}), sending datagrams one by one from now on");
                gso = false;
                send_singly(tx, &bufs, &lens[..n]); // duplicates of already-sent ones are dropped by WireGuard
            }
            break; // ENOBUFS, ECONNREFUSED etc.: drop, WireGuard copes with loss
        }
    }
    f.stop.store(true, Ordering::Relaxed);
}

struct Relay {
    ctl: Mutex<i32>,
    flows: Mutex<HashMap<(SocketAddrV4, SocketAddrV4), Arc<Flow>>>,
    net: Option<(u32, u32)>, // the bridge's network: only its containers are relayed
}

impl Relay {
    fn new_flow(&self, src: SocketAddrV4, dst: SocketAddrV4) -> Option<Arc<Flow>> {
        if self.flows.lock().unwrap().len() >= MAX_FLOWS {
            log!("vpnrelay: {MAX_FLOWS} flows open, not relaying {src} -> {dst}");
            return None;
        }
        let host = {
            let ctl = self.ctl.lock().unwrap();
            let mut req = [0u8; 6];
            req[..4].copy_from_slice(&dst.ip().octets());
            req[4..].copy_from_slice(&dst.port().to_be_bytes());
            if unsafe { libc::send(*ctl, req.as_ptr() as *const _, 6, 0) } != 6 {
                fail("socket request to host side");
            }
            recv_fd(*ctl)
        };
        let Some(host) = host else {
            log!("vpnrelay: host side could not open a socket to {dst}");
            return None;
        };
        let local = udp(dst, Some(src), true);
        if local < 0 {
            log!("vpnrelay: flow socket {dst} -> {src}: {}", std::io::Error::last_os_error());
            unsafe { libc::close(host) };
            return None;
        }
        let f = Arc::new(Flow {
            host,
            local,
            stop: AtomicBool::new(false),
            last: AtomicU64::new(now()),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
        });
        let (a, b) = (f.clone(), f.clone());
        thread::spawn(move || pump(a.local, a.host, a.clone(), &a.up, true));
        thread::spawn(move || pump(b.host, b.local, b.clone(), &b.down, false));
        log!("vpnrelay: flow {src} -> {dst}");
        self.flows.lock().unwrap().insert((src, dst), f.clone());
        Some(f)
    }

    /// Wildcard socket on 0.0.0.0:<port>: gets a flow's packets until its own socket exists.
    fn listen(&'static self, port: u16) {
        let fd = udp(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port), None, true);
        if fd < 0 {
            fail(&format!("listen on port {port}"));
        }
        setopt(fd, libc::SOL_IP, IP_RECVORIGDSTADDR, 1);
        setopt(fd, SOL_UDP, UDP_GRO, 0);
        let me = self;
        thread::spawn(move || {
            let mut buf = vec![0u8; BUF];
            let mut cbuf = [0u64; 16];
            loop {
                let mut name: libc::sockaddr_in = unsafe { mem::zeroed() };
                let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: BUF };
                let mut h: libc::msghdr = unsafe { mem::zeroed() };
                h.msg_name = &mut name as *mut _ as *mut _;
                h.msg_namelen = mem::size_of::<libc::sockaddr_in>() as _;
                h.msg_iov = &mut iov;
                h.msg_iovlen = 1;
                h.msg_control = cbuf.as_mut_ptr() as *mut _;
                h.msg_controllen = mem::size_of_val(&cbuf) as _;
                let n = unsafe { libc::recvmsg(fd, &mut h, 0) };
                if n < 0 {
                    if !matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                        thread::sleep(Duration::from_millis(100)); // don't spin on a persistent error
                    }
                    continue;
                }
                let mut dst = None;
                unsafe {
                    let mut c = libc::CMSG_FIRSTHDR(&h);
                    while !c.is_null() {
                        if (*c).cmsg_level == libc::SOL_IP && (*c).cmsg_type == IP_RECVORIGDSTADDR {
                            dst = Some(from_sa(&ptr::read_unaligned(libc::CMSG_DATA(c) as *const libc::sockaddr_in)));
                        }
                        c = libc::CMSG_NXTHDR(&h, c);
                    }
                }
                let (Some(dst), src) = (dst, from_sa(&name)) else { continue };
                // A packet that still matches a stale MASQUERADE entry arrives from the driver's address (10.0.2.100)
                // in the moment before the conntrack reset; it is not a tunnel of ours, so don't open a flow for it.
                if me.net.is_some_and(|(net, mask)| u32::from(*src.ip()) & mask != net) {
                    continue;
                }
                let existing = me.flows.lock().unwrap().get(&(src, dst)).cloned();
                if let Some(f) = existing.or_else(|| me.new_flow(src, dst)) {
                    unsafe { libc::send(f.host, buf.as_ptr() as *const _, n as usize, 0) };
                    f.last.store(now(), Ordering::Relaxed);
                }
            }
        });
    }

    /// Stop every flow; their sockets close once both pump threads have left recvmmsg (<= 1 s, SO_RCVTIMEO).
    fn close_all(&self) {
        for f in self.flows.lock().unwrap().drain().map(|(_, f)| f) {
            f.stop.store(true, Ordering::Relaxed);
        }
    }

    fn reap(&self) {
        let t = now();
        self.flows.lock().unwrap().retain(|(src, dst), f| {
            let dead = f.stop.load(Ordering::Relaxed) || t.saturating_sub(f.last.load(Ordering::Relaxed)) > IDLE_SECS;
            if dead {
                f.stop.store(true, Ordering::Relaxed);
                let mb = |b: &AtomicU64| b.load(Ordering::Relaxed) as f64 / 1e6;
                log!("vpnrelay: closing flow {src} -> {dst} ({:.0} MB up, {:.0} MB down)", mb(&f.up), mb(&f.down));
            }
            !dead
        });
    }
}

/// Whether the kernel accepts UDP_GRO on a socket (5.0+).
fn gro_supported() -> bool {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        let ok = fd >= 0 && setopt(fd, SOL_UDP, UDP_GRO, 1);
        if fd >= 0 {
            libc::close(fd);
        }
        ok
    }
}

fn parse_ports(s: &str) -> Vec<u16> {
    let p: Vec<u16> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    if p.is_empty() {
        log!("vpnrelay: bad port list {s}");
        std::process::exit(2);
    }
    p
}

pub fn cleanup(bridge: &str, ports: &str) {
    let ports = parse_ports(ports);
    if !lock(bridge) {
        log!("vpnrelay cleanup: a relay for {bridge} is still running, leaving its rules alone");
        return;
    }
    if !enter_docker_netns(&state_dir()) {
        log!("vpnrelay cleanup: Docker netns not available (Docker down?), nothing to do");
        return;
    }
    remove_rules();
    reset_conntrack(bridge, &ports, false);
    log!("vpnrelay cleanup: rules removed, tunnels on {bridge} fall back to Docker's own network");
}

pub fn run(bridge: &str, ports: &str) {
    let ports = parse_ports(ports);
    let dir = state_dir();
    if !lock(bridge) {
        log!("vpnrelay: a relay for {bridge} is already running");
        std::process::exit(3);
    }
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) } != 0 {
        fail("socketpair");
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        fail("fork");
    }
    if pid > 0 {
        unsafe { libc::close(sv[1]) };
        factory(sv[0], pid, &dir);
    }
    unsafe {
        libc::close(sv[0]);
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM); // parent gone: clean up below, then exit
    }
    catch_term();
    if !enter_docker_netns(&dir) {
        fail("joining rootless Docker's netns");
    }
    let relay: &'static Relay =
        Box::leak(Box::new(Relay { ctl: Mutex::new(sv[1]), flows: Mutex::new(HashMap::new()), net: bridge_net(bridge) }));
    remove_rules();
    for &p in &ports {
        relay.listen(p);
    }
    add_rules(bridge, &ports);
    reset_conntrack(bridge, &ports, true);
    log!(
        "vpnrelay transparent: UDP from {bridge} to port(s) {ports:?} relayed via the host netns (rule {}, GRO {}, GSO {})",
        rule(),
        if !gro_wanted() { "off" } else if gro_supported() { "on" } else { "unsupported" },
        if env::var("VPNRELAY_NO_GSO").is_ok() { "off" } else { "on" }
    );
    // The kernel clamps the requested buffers to these; at Debian's default (212992) download halves (bursts from
    // the server overflow the receive queue). PMSS sets 16 MiB (1 GbE) or 64 MiB (10 GbE).
    for k in ["rmem_max", "wmem_max"] {
        let v: i64 = fs::read_to_string(format!("/proc/sys/net/core/{k}")).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        if v > 0 && v < 4 << 20 {
            log!("vpnrelay: warning: net.core.{k} is {v}; the relay needs >= 4 MiB for full speed (asks for {})", sockbuf());
        }
    }
    for tick in 1u64.. {
        thread::sleep(Duration::from_secs(1));
        if TERM.load(Ordering::Relaxed) {
            // Same order as `cleanup` after an exit: rule, then sockets (an open connected flow socket keeps
            // receiving its flow without the rule), then conntrack.
            remove_rules();
            relay.close_all();
            thread::sleep(Duration::from_millis(1500));
            reset_conntrack(bridge, &ports, false);
            log!("vpnrelay: stopped; tunnels on {bridge} fall back to Docker's own network");
            std::process::exit(0);
        }
        if tick % 5 == 0 {
            relay.reap();
        }
    }
}

/// Run `transparent` under this process, clean up after every exit and restart it; on SIGTERM stop it and clean up.
pub fn supervise(bridge: &str, ports: &str) {
    parse_ports(ports);
    if !lock(&format!("{bridge}.supervise")) {
        return; // another supervisor runs: nothing to do (lets cron start this every few minutes)
    }
    catch_term();
    let exe = env::current_exe().unwrap_or_else(|_| "vpnrelay".into());
    let mut backoff = 5;
    while !TERM.load(Ordering::Relaxed) {
        let started = Instant::now();
        let Ok(mut child) = Command::new(&exe).args(["transparent", bridge, ports]).spawn() else {
            fail("starting the relay");
        };
        let status = loop {
            if TERM.load(Ordering::Relaxed) {
                unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
            }
            match child.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) => thread::sleep(Duration::from_millis(500)),
                Err(_) => break std::process::ExitStatus::default(),
            }
        };
        let _ = Command::new(&exe).args(["cleanup", bridge, ports]).status();
        if TERM.load(Ordering::Relaxed) {
            break;
        }
        // Docker down or still starting: back off up to 60 s instead of retrying every 5 s
        backoff = if started.elapsed() < Duration::from_secs(30) { (backoff * 2).min(60) } else { 5 };
        log!("vpnrelay supervise: relay exited ({status}), restarting in {backoff} s");
        for _ in 0..backoff * 2 {
            if TERM.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
    log!("vpnrelay supervise: stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let ip = [nla(1, &src), nla(2, &dst)].concat();
        let proto = [nla(1, &[17]), nla(2, &sport.to_be_bytes()), nla(3, &dport.to_be_bytes())].concat();
        [nla(1, &ip), nla(2, &proto)].concat()
    }

    #[test]
    fn ct_tuple_round_trip() {
        let t = tuple([172, 29, 0, 2], [10, 0, 0, 138], 40004, 51820);
        assert_eq!(ct_tuple(&t), Some((Ipv4Addr::new(172, 29, 0, 2), Ipv4Addr::new(10, 0, 0, 138), 17, 40004, 51820)));
    }

    #[test]
    fn ct_tuple_missing_field() {
        let ip = [nla(1, &[172, 29, 0, 2]), nla(2, &[10, 0, 0, 1])].concat();
        assert_eq!(ct_tuple(&nla(1, &ip)), None);
    }

    #[test]
    fn nlattrs_stops_on_truncated_input() {
        let a = [nla(1, &[1, 2, 3, 4]), nla(2, &[5])].concat();
        assert_eq!(nlattrs(&a).len(), 2);
        assert_eq!(nlattrs(&a[..a.len() - 2]).len(), 2); // only padding cut
        assert_eq!(nlattrs(&a[..a.len() - 4]).len(), 1);
        assert!(nlattrs(&[0xff, 0xff, 0, 0]).is_empty());
        assert!(nlattrs(&[2, 0, 0, 0]).is_empty());
    }

    #[test]
    fn nlattrs_masks_flags() {
        let mut a = nla(3, &[0; 4]);
        a[3] |= 0x80; // NLA_F_NESTED
        assert_eq!(nlattrs(&a)[0].0, 3);
    }

    #[test]
    fn parse_ports_skips_junk() {
        assert_eq!(parse_ports("51820, 1637,x,1194"), vec![51820, 1637, 1194]);
    }
}
