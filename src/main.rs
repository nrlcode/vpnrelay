//! vpnrelay: carry the VPN UDP (WireGuard, OpenVPN) of gluetun containers past rootless Docker's user-space network,
//! which otherwise handles every tunnel packet one by one. See transparent.rs.
//!
//!   transparent <bridge> <port>[,<port>..]   run the relay for the containers on <bridge>
//!   cleanup     <bridge> <port>[,<port>..]   remove the relay's rule and move the tunnels back to Docker's network
//!   supervise   <bridge> <port>[,<port>..]   run `transparent`, clean up after it and restart it (cron-friendly)

use std::env;
use std::mem;
use std::net::SocketAddrV4;

/// eprintln! with a UTC timestamp, for the log file (the user journal may not be readable).
macro_rules! log {
    ($($t:tt)*) => { eprintln!("{} {}", crate::stamp(), format!($($t)*)) };
}

mod transparent;

/// Current UTC time as YYYY-MM-DDTHH:MM:SSZ.
fn stamp() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
    // civil date from days since 1970-01-01 (H. Hinnant's algorithm)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs / 60 % 60, secs % 60)
}

const SOL_UDP: libc::c_int = 17;
const UDP_GRO: libc::c_int = 104;
const UDP_SEGMENT: libc::c_int = 103;

fn sockaddr(a: SocketAddrV4) -> libc::sockaddr_in {
    let mut s: libc::sockaddr_in = unsafe { mem::zeroed() };
    s.sin_family = libc::AF_INET as _;
    s.sin_port = a.port().to_be();
    s.sin_addr.s_addr = u32::from(*a.ip()).to_be();
    s
}

fn setopt(fd: i32, level: i32, name: i32, val: i32) -> bool {
    unsafe {
        libc::setsockopt(fd, level, name, &val as *const _ as *const libc::c_void, mem::size_of::<i32>() as _) == 0
    }
}

fn main() {
    let a: Vec<String> = env::args().collect();
    if a.len() == 2 && (a[1] == "--version" || a[1] == "-V") {
        println!("vpnrelay {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    match (a.len(), a.get(1).map(String::as_str)) {
        (4, Some("transparent")) => transparent::run(&a[2], &a[3]),
        (4, Some("cleanup")) => transparent::cleanup(&a[2], &a[3]),
        (4, Some("supervise")) => transparent::supervise(&a[2], &a[3]),
        _ => {
            eprintln!("usage: vpnrelay transparent|cleanup|supervise <bridge> <port>[,<port>..]");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn stamp_format() {
        let s = super::stamp();
        assert_eq!(s.len(), 20);
        assert!(s.starts_with("20") && s.ends_with('Z') && &s[10..11] == "T");
    }
}
