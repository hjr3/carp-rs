// Copyright (c) 2016  Herman J. Radtke III <herman@hermanradtke.com>
//
// This file is part of carp-rs.
//
// carp-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// carp-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with carp-rs.  If not, see <http://www.gnu.org/licenses/>.

use std::fmt;
use std::io::{self, Error, ErrorKind};
use libc::{sockaddr, c_int, c_char, c_ulong};
use nix::sys::socket::{socket, SockType, SockFlag, AddressFamily};

const SIOCGIFHWADDR: c_ulong = 0x00008927;

// TODO check if this changes across OSes
const SIOCGIFINDEX: c_ulong = 0x00008933;

const IFREQUNIONSIZE: usize = 24;

#[repr(C)]
struct IfReqUnion {
    data: [u8; IFREQUNIONSIZE],
}

impl IfReqUnion {
    fn as_sockaddr(&self) -> sockaddr {
        // let len = mem::size_of::<sockaddr>();
        // mem::transmute(& *self.data[0..len])

        let mut s = sockaddr {
            sa_family: u16::from_be((self.data[0] as u16) << 8 | (self.data[1] as u16)),
            sa_data: [0; 14],
        };

        // basically a memcpy
        for (i, b) in self.data[2..16].iter().enumerate() {
            s.sa_data[i] = *b as i8;
        }

        s
    }

    fn as_int(&self) -> c_int {
        c_int::from_be((self.data[0] as c_int) << 24 |
                       (self.data[1] as c_int) << 16 |
                       (self.data[2] as c_int) <<  8 |
                       (self.data[3] as c_int))
    }
}

impl Default for IfReqUnion {
    fn default() -> IfReqUnion {
        IfReqUnion { data: [0; IFREQUNIONSIZE] }
    }
}

const IFNAMESIZE: usize = 16;

#[repr(C)]
pub struct IfReq {
    ifr_name: [c_char; IFNAMESIZE],
    union: IfReqUnion,
}

impl IfReq {
    ///
    /// Create an interface request struct with the interface name set
    ///
    pub fn with_if_name(if_name: &str) -> io::Result<IfReq> {
        let mut if_req = IfReq::default();

        if if_name.len() >= if_req.ifr_name.len() {
            return Err(Error::new(ErrorKind::Other, "Interface name too long"));
        }

        // basically a memcpy
        for (a, c) in if_req.ifr_name.iter_mut().zip(if_name.bytes()) {
            *a = c as i8;
        }

        Ok(if_req)
    }

    pub fn ifr_hwaddr(&self) -> sockaddr {
        self.union.as_sockaddr()
    }

    pub fn ifr_ifindex(&self) -> c_int {
        self.union.as_int()
    }
}

impl Default for IfReq {
    fn default() -> IfReq {
        IfReq {
            ifr_name: [0; IFNAMESIZE],
            union: IfReqUnion::default(),
        }
    }
}

extern "C" {
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

/// Representation of a MAC address
impl HwAddr {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> HwAddr {
        HwAddr {
            a: a,
            b: b,
            c: c,
            d: d,
            e: e,
            f: f,
        }
    }

    /// Returns the six eight-bit integers that make up this address.
    pub fn octets(&self) -> [u8; 6] {
        [self.a, self.b, self.c, self.d, self.e, self.f]
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

/// ioctl operations on a hardware interface
pub struct HwIf {
    if_name: String,
}

impl HwIf {
    /// Create new hardware interface instance
    ///
    /// The interface name is something like `eth0`.
    pub fn new<S>(if_name: S) -> HwIf
        where S: Into<String>
    {
        HwIf { if_name: if_name.into() }
    }

    /// Get Hardware (MAC) address for the network interface
    ///
    /// The response looks something like: HwAddr("08:00:27:4d:3c:39")
    pub fn hwaddr(&self) -> io::Result<HwAddr> {
        let if_req = try!(self.ioctl(&self.if_name, SIOCGIFHWADDR));

        let ifr_hwaddr = if_req.ifr_hwaddr();

        Ok(HwAddr {
            a: ifr_hwaddr.sa_data[0] as u8,
            b: ifr_hwaddr.sa_data[1] as u8,
            c: ifr_hwaddr.sa_data[2] as u8,
            d: ifr_hwaddr.sa_data[3] as u8,
            e: ifr_hwaddr.sa_data[4] as u8,
            f: ifr_hwaddr.sa_data[5] as u8,
        })
    }

    /// Get the index for the network interface
    pub fn index(&self) -> io::Result<c_int> {
        let if_req = try!(self.ioctl(&self.if_name, SIOCGIFINDEX));

        Ok(if_req.ifr_ifindex())
    }

    fn ioctl(&self, if_name: &str, ident: c_ulong) -> io::Result<IfReq> {
        let fd = try!(socket(AddressFamily::Inet,
                             SockType::Datagram,
                             SockFlag::empty(),
                             0));

        let if_req = try!(IfReq::with_if_name(if_name));
        let mut req: Box<IfReq> = Box::new(if_req);

        if unsafe { ioctl(fd, ident, &mut *req) } == -1 {
            return Err(Error::last_os_error());
        }

        Ok(*req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hw_addr() {
        // TODO dynamically get interface
        let hw_if = HwIf::new("eth0");
        assert!(hw_if.hwaddr().is_ok());

        for if_name in &["nope", "waytoolonginterface", "1234567890123456"] {
            let hw_if = HwIf::new(*if_name);
            assert!(hw_if.hwaddr().is_err());
        }
    }

    #[test]
    fn test_hw_addr_format() {
        // TODO dynamically get interface
        let hw_if = HwIf::new("eth0");
        let mac = format!("{}", hw_if.hwaddr().unwrap());
        assert_eq!(17, mac.len());
    }

    #[test]
    fn test_if_index() {
        // TODO dynamically get interface
        let hw_if = HwIf::new("eth0");
        assert!(hw_if.index().is_ok());
    }
}
