use std::os::raw::{c_int, c_char, c_ulong};
use std::os::unix::io::{RawFd};
use std::mem;
use libc::sockaddr;
use std::io::{self, Error, ErrorKind};
use nix::sys::socket::{socket, SockType, SockFlag, AddressFamily};

// TODO test this across other OSes
const SIOCGIFHWADDR: c_ulong = 0x00008927;

#[repr(C)]
struct IfReq {
    ifr_name: [c_char; 16],
    ifr_hwaddr: sockaddr,
    _padding: [u8; 8],
}

extern {
    fn ioctl(fd: c_int, request: c_ulong, ifreq: *mut IfReq) -> c_int;
}

#[derive(Debug)]
pub struct HwAddr(String);

///
/// Get Hardware (MAC) address for a given network interface
///
/// The response looks something like: HwAddr("08:00:27:4d:3c:39")
///
pub fn hw_addr(if_name: &str) -> io::Result<HwAddr> {

    let fd = try!(socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty()
    ));

    let mut req: Box<IfReq> = Box::new(unsafe { mem::zeroed() });

    if if_name.len() >= req.ifr_name.len() {
        return Err(Error::new(ErrorKind::Other, "Interface name too long"));
    }

    // basically a memcpy
    for (a, c) in req.ifr_name.iter_mut().zip(if_name.bytes()) {
        *a = c as i8;
    }

    if unsafe { ioctl(fd, SIOCGIFHWADDR, &mut *req) } == -1 {
        return Err(Error::last_os_error());
    }

    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        req.ifr_hwaddr.sa_data[0],
        req.ifr_hwaddr.sa_data[1],
        req.ifr_hwaddr.sa_data[2],
        req.ifr_hwaddr.sa_data[3],
        req.ifr_hwaddr.sa_data[4],
        req.ifr_hwaddr.sa_data[5],
    );

    Ok(HwAddr(mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hw_addr() {
        // TODO dynamically get interface
        assert_eq!(17, hw_addr("eth0").unwrap().0.len());
        assert!(hw_addr("nope").is_err());
        assert!(hw_addr("waytoolonginterface").is_err());
        assert!(hw_addr("1234567890123456").is_err());
    }
}
