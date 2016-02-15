use std::mem;
use std::fmt;
use std::io::{self, Error, ErrorKind};
use libc::{sockaddr, c_int, c_char, c_ulong};
use nix::sys::socket::{socket, SockType, SockFlag, AddressFamily};

// TODO test this across other OSes
const SIOCGIFHWADDR: c_ulong = 0x00008927;

#[repr(C)]
pub struct IfReq {
    ifr_name: [c_char; 16],
    ifr_hwaddr: sockaddr,
    _padding: [u8; 8],
}

impl IfReq {
    fn new() -> IfReq {
        let mut if_req: IfReq = unsafe { mem::zeroed() };

        if_req
    }

    ///
    /// Create an interface request struct with the interface name set
    ///
    pub fn with_if_name(if_name: &str) -> io::Result<IfReq> {
        let mut if_req = IfReq::new();

        if if_name.len() >= if_req.ifr_name.len() {
            return Err(Error::new(ErrorKind::Other, "Interface name too long"));
        }

        // basically a memcpy
        for (a, c) in if_req.ifr_name.iter_mut().zip(if_name.bytes()) {
            *a = c as i8;
        }

        Ok(if_req)
    }
}

extern {
    fn ioctl(fd: c_int, request: c_ulong, ifreq: *mut IfReq) -> c_int;
}

#[derive(Debug)]
pub struct HwAddr {
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
}

impl HwAddr {

    ///
    /// Get Hardware (MAC) address for a given network interface
    ///
    /// The interface name is something like `eth0`.
    /// The response looks something like: HwAddr("08:00:27:4d:3c:39")
    ///
    pub fn from_if(if_name: &str) -> io::Result<HwAddr> {

        let fd = try!(socket(
                AddressFamily::Inet,
                SockType::Datagram,
                SockFlag::empty()
                ));

        let if_req = try!(IfReq::with_if_name(if_name));
        let mut req: Box<IfReq> = Box::new(if_req);

        if unsafe { ioctl(fd, SIOCGIFHWADDR, &mut *req) } == -1 {
            return Err(Error::last_os_error());
        }

        Ok(
            HwAddr {
                a: req.ifr_hwaddr.sa_data[0] as u8,
                b: req.ifr_hwaddr.sa_data[1] as u8,
                c: req.ifr_hwaddr.sa_data[2] as u8,
                d: req.ifr_hwaddr.sa_data[3] as u8,
                e: req.ifr_hwaddr.sa_data[4] as u8,
                f: req.ifr_hwaddr.sa_data[5] as u8,
            }
        )
    }

    ///
    /// Returns the six eight-bit integers that make up this address.
    ///
    pub fn octets(&self) -> [u8; 6] {
        [
            self.a,
            self.b,
            self.c,
            self.d,
            self.e,
            self.f,
        ]
    }
}

impl fmt::Display for HwAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a,
            self.b,
            self.c,
            self.d,
            self.e,
            self.f,
        );

        write!(f, "{}", mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hw_addr() {
        // TODO dynamically get interface
        assert!(HwAddr::from_if("eth0").is_ok());
        assert!(HwAddr::from_if("nope").is_err());
        assert!(HwAddr::from_if("waytoolonginterface").is_err());
        assert!(HwAddr::from_if("1234567890123456").is_err());
    }

    #[test]
    fn test_format() {
        // TODO dynamically get interface
        let mac = format!("{}", HwAddr::from_if("eth0").unwrap());
        assert_eq!(17, mac.len());
    }
}
