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

use std::io::Cursor;
use std::net::Ipv4Addr;

use libc::{uint8_t, uint16_t, uint32_t};
use rand::{self, Rng};
use byteorder::{self, ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

pub enum Protocol {
    Carp = 112, // VRRP
}

// this is triggering doc tests and i do not know why. plus, i don't even think is a good approach
// Various Control Flags
//
// The flags are part of a larger 16 bit value. These three values represent the first 3 bits of
// the 16 total bits.
//
// Bit 0: reserved, must be zero
// Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
// Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
//
//     0   1   2
//   +---+---+---+
//   |   | D | M |
//   | 0 | F | F |
//   +---+---+---+
pub struct Flags(uint16_t);

impl Flags {
    #[inline]
    pub fn reserved() -> Flags {
        Flags(0x0)
    }

    #[inline]
    pub fn may_fragment() -> Flags {
        Flags(0x0)
    }

    #[inline]
    pub fn dont_fragment() -> Flags {
        Flags(0x4000)
    }

    #[inline]
    pub fn last_fragment() -> Flags {
        Flags(0x0)
    }

    #[inline]
    pub fn more_fragment() -> Flags {
        Flags(0x2000)
    }
}

/// Type of Service
///
/// Bits 0-2:  Precedence.
/// Bit    3:  0 = Normal Delay,      1 = Low Delay.
/// Bits   4:  0 = Normal Throughput, 1 = High Throughput.
/// Bits   5:  0 = Normal Relibility, 1 = High Relibility.
/// Bit  6-7:  Reserved for Future Use.
///
///    0     1     2     3     4     5     6     7
/// +-----+-----+-----+-----+-----+-----+-----+-----+
/// |                 |     |     |     |     |     |
/// |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
/// |                 |     |     |     |     |     |
/// +-----+-----+-----+-----+-----+-----+-----+-----+
pub struct Tos(uint8_t);

impl Tos {
    pub fn normal_delay() -> Tos {
        Tos(0x0)
    }

    pub fn low_delay() -> Tos {
        Tos(0x10)
    }

    pub fn normal_throughput() -> Tos {
        Tos(0x0)
    }

    pub fn high_throughput() -> Tos {
        Tos(0x8)
    }

    pub fn normal_reliability() -> Tos {
        Tos(0x0)
    }

    pub fn high_reliability() -> Tos {
        Tos(0x4)
    }
}

/// Structure of an v4 internet header, naked of options.
///
/// The struct aims to keep the byte representation compatible with C. This allows for the use of
/// `from_bytes` as a safe method and transmute for speed. Transmute is not supported at this time.
/// I need to find a way to get ByteOrders API but not switch the endianness.
///
/// See: https://tools.ietf.org/html/rfc791
#[derive(Debug, Default)]
#[repr(C)]
pub struct Ipv4Header {
    /// Header length and version
    ///
    /// This is endian specific. Use helper methods.
    v_hl: uint8_t,

    /// Type of service
    ///
    /// This can also be the DSCP and ECN bits
    ///
    /// See: https://tools.ietf.org/html/rfc2474
    /// See: https://tools.ietf.org/html/rfc3168
    pub tos: uint8_t,

    /// Total length
    ///
    /// Total Length is the length of the datagram, measured in octets,
    /// including internet header and data.
    total_length: uint16_t,

    /// Identification
    id: uint16_t,

    /// Fragment offset field
    frag_off: uint16_t,

    /// Time to live
    pub ttl: uint8_t,

    /// Protocol
    pub protocol: uint8_t,

    /// Checksum
    cksum: uint16_t,

    /// Source address
    saddr: uint32_t,

    /// Destination address
    daddr: uint32_t,
}

impl Ipv4Header {
    pub fn from_bytes(buf: &[u8]) -> byteorder::Result<Ipv4Header> {
        let mut rdr = Cursor::new(buf);

        let v_hl = try!(rdr.read_u8());
        let tos = try!(rdr.read_u8());
        let total_length = try!(rdr.read_u16::<BigEndian>());
        let id = try!(rdr.read_u16::<BigEndian>());
        let frag_off = try!(rdr.read_u16::<BigEndian>());
        let ttl = try!(rdr.read_u8());
        let protocol = try!(rdr.read_u8());
        let cksum = try!(rdr.read_u16::<BigEndian>());

        let saddr = try!(rdr.read_u32::<BigEndian>());
        let daddr = try!(rdr.read_u32::<BigEndian>());

        Ok(Ipv4Header {
            v_hl: v_hl,
            tos: tos,
            total_length: total_length,
            id: id,
            frag_off: frag_off,
            ttl: ttl,
            protocol: protocol,
            cksum: cksum,
            saddr: saddr,
            daddr: daddr,
        })
    }

    pub fn into_bytes(&self) -> byteorder::Result<Vec<u8>> {
        let mut wtr = vec![];

        try!(wtr.write_u8(self.v_hl));
        try!(wtr.write_u8(self.tos));
        try!(wtr.write_u16::<BigEndian>(self.total_length));
        try!(wtr.write_u16::<BigEndian>(self.id));
        try!(wtr.write_u16::<BigEndian>(self.frag_off));
        try!(wtr.write_u8(self.ttl));
        try!(wtr.write_u8(self.protocol));
        try!(wtr.write_u16::<BigEndian>(self.cksum));
        try!(wtr.write_u32::<BigEndian>(self.saddr));
        try!(wtr.write_u32::<BigEndian>(self.daddr));

        Ok(wtr)
    }

    /// Apply checksum value to bytes version of Ipv4Header
    pub fn apply_cksum(buf: &mut [u8]) {
        let cksum = Self::checksum(buf);

        BigEndian::write_u16(&mut buf[10..12], cksum as u16);
    }

    /// IPv4 checksum
    ///
    /// Form the ones' complement of the ones' complement sum of the buffers's
    /// 16-bit words.
    pub fn checksum(buf: &[u8]) -> uint16_t {
        if buf.len() <= 0 {
            return 0;
        }

        let mut sum: usize = 0;
        for chunk in buf.chunks(2) {
            let i = if chunk.len() == 2 {
                BigEndian::read_u16(chunk)
            } else {
                let t = [chunk[0], 0];
                BigEndian::read_u16(&t)
            };

            sum += i as usize;
            if sum > 0xFFFF {
                sum &= 0xFFFF;
                sum += 1;
            }
        }

        let r = !(sum as u16);

        r
    }

    #[cfg(target_endian = "big")]
    #[inline]
    pub fn version(&self) -> uint8_t {
        self.v_hl & 0xF
    }

    /// Internet Header Length
    #[cfg(target_endian = "big")]
    #[inline]
    pub fn ihl(&self) -> uint8_t {
        self.v_hl >> 4
    }

    #[cfg(target_endian = "big")]
    pub fn set_version(&mut self, version: uint8_t) {
        let len = ::std::mem::size_of::<Self>() / 4;
        self.v_hl = ((len << 4) as u8) + version;
    }

    #[cfg(target_endian = "little")]
    #[inline]
    pub fn version(&self) -> uint8_t {
        self.v_hl >> 4
    }

    /// Internet Header Length
    #[cfg(target_endian = "little")]
    #[inline]
    pub fn ihl(&self) -> uint8_t {
        self.v_hl & 0xF
    }

    #[cfg(target_endian = "little")]
    pub fn set_version(&mut self, version: uint8_t) {
        let len = ::std::mem::size_of::<Self>() / 4;
        self.v_hl = len as u8 + (version << 4);
    }

    /// Total length
    #[inline]
    pub fn total_length(&self) -> uint16_t {
        self.total_length
    }

    pub fn set_total_length(&mut self, length: uint16_t) {
        self.total_length = length;
    }

    /// Identification
    #[inline]
    pub fn id(&self) -> uint16_t {
        self.id
    }

    pub fn generate_id(&mut self) {
        let mut rng = rand::thread_rng();
        self.id = rng.gen();
    }

    /// Fragment offset field
    #[inline]
    pub fn frag_off(&self) -> uint16_t {
        self.frag_off
    }

    pub fn set_frag_off(&mut self, frag_off: Flags) {
        let Flags(f) = frag_off;
        self.frag_off = f;
    }

    /// Checksum
    #[inline]
    pub fn cksum(&self) -> uint16_t {
        self.cksum
    }

    pub fn set_cksum(&mut self, cksum: uint16_t) {
        self.cksum = cksum;
    }

    /// Source address
    #[inline]
    pub fn saddr(&self) -> uint32_t {
        self.saddr
    }

    pub fn set_saddr(&mut self, saddr: uint32_t) {
        self.saddr = saddr;
    }

    /// Destination address
    #[inline]
    pub fn daddr(&self) -> uint32_t {
        self.daddr
    }

    pub fn set_daddr(&mut self, daddr: uint32_t) {
        self.daddr = daddr;
    }
}

/// Building a Ipv4Header struct
///
/// Ipv4Header has the same byte representation as `struct ip` in C. The
/// builder pattern provides a better interface for dealing with byte order
/// specific unions. It also means we can use types like `Ipv4Addr` instead
/// of `c::in_addr`.
#[derive(Default)]
pub struct Ipv4HeaderBuilder {
    version: uint8_t,
    tos: uint8_t,
    total_length: uint16_t,
    id: uint16_t,
    frag_off: uint16_t,
    ttl: uint8_t,
    protocol: uint8_t,
    cksum: uint16_t,
    saddr: uint32_t,
    daddr: uint32_t,
}

impl Ipv4HeaderBuilder {
    pub fn new() -> Ipv4HeaderBuilder {
        let mut ipb = Self::default();
        ipb.version = 4;
        ipb
    }

    pub fn tos(&mut self, tos: Tos) -> &mut Ipv4HeaderBuilder {
        let Tos(t) = tos;
        self.tos = t;
        self
    }

    pub fn data_length(&mut self, data_length: uint16_t) -> &mut Ipv4HeaderBuilder {
        let header_length = ::std::mem::size_of::<Ipv4Header>();
        self.total_length = header_length as uint16_t + data_length;
        self
    }

    pub fn random_id(&mut self) -> &mut Ipv4HeaderBuilder {
        let mut rng = rand::thread_rng();
        self.id = rng.gen();
        self
    }

    pub fn flags(&mut self, frag_off: Flags) -> &mut Ipv4HeaderBuilder {
        let Flags(f) = frag_off;
        self.frag_off = f;
        self
    }

    pub fn ttl(&mut self, ttl: uint8_t) -> &mut Ipv4HeaderBuilder {
        self.ttl = ttl;
        self
    }

    pub fn protocol(&mut self, protocol: Protocol) -> &mut Ipv4HeaderBuilder {
        self.protocol = protocol as uint8_t;
        self
    }

    pub fn source_address(&mut self, addr: Ipv4Addr) -> &mut Ipv4HeaderBuilder {
        self.saddr = BigEndian::read_u32(&addr.octets());
        self
    }

    pub fn destination_address(&mut self, addr: Ipv4Addr) -> &mut Ipv4HeaderBuilder {
        self.daddr = BigEndian::read_u32(&addr.octets());
        self
    }

    pub fn build(&mut self) -> Ipv4Header {
        let mut ip = Ipv4Header {
            v_hl: 0,
            tos: self.tos,
            total_length: self.total_length,
            id: self.id,
            frag_off: self.frag_off,
            ttl: self.ttl,
            protocol: self.protocol,
            cksum: self.cksum,
            saddr: self.saddr,
            daddr: self.daddr,
        };

        ip.set_version(self.version);
        ip
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_from_builder() {
        let ip = Ipv4HeaderBuilder::new()
                     .tos(Tos::low_delay())
                     .data_length(20)
                     .flags(Flags::dont_fragment())
                     .ttl(255)
                     .protocol(Protocol::Carp)
                     .source_address(FromStr::from_str("10.0.0.2").unwrap())
                     .destination_address(FromStr::from_str("10.0.0.3").unwrap())
                     .build();

        assert_eq!(4, ip.version());
        assert_eq!(5, ip.ihl());
        assert_eq!(40, ip.total_length());
        assert_eq!(0x4000, ip.frag_off());
        assert_eq!(255, ip.ttl);
        assert_eq!(112, ip.protocol);
        assert_eq!(167772162, ip.saddr());
        assert_eq!(167772163, ip.daddr());
        assert_eq!(0, ip.cksum());
    }

    #[test]
    fn test_from_bytes() {
        let bytes: [u8; 20] = [69, 16, 0, 56, 36, 97, 64, 0, 255, 112, 0, 0, 10, 0, 2, 30, 224, 0,
                               0, 18];
        let iph = Ipv4Header::from_bytes(&bytes).unwrap();

        assert_eq!(iph.version(), 4);
        assert_eq!(iph.ihl(), 5);
        assert_eq!(iph.tos, 16);
        assert_eq!(iph.total_length(), 56);
        assert_eq!(iph.id(), 9313);
        assert_eq!(iph.frag_off(), 16384);
        assert_eq!(iph.ttl, 255);
        assert_eq!(iph.protocol, 112);
        assert_eq!(iph.cksum(), 0);
        assert_eq!(Ipv4Addr::from(iph.saddr()), "10.0.2.30".parse().unwrap());
        assert_eq!(Ipv4Addr::from(iph.daddr()), "224.0.0.18".parse().unwrap());
    }

    #[test]
    fn test_into_bytes() {
        let bytes: [u8; 20] = [69, 16, 0, 56, 36, 97, 64, 0, 255, 112, 0, 0, 10, 0, 2, 30, 224, 0,
                               0, 18];
        let iph = Ipv4Header::from_bytes(&bytes).unwrap();
        let given = iph.into_bytes().unwrap();

        assert_eq!(bytes, given.as_slice());
    }

    // #[test]
    // fn test_transmute() {
    //    let bytes: [u8; 20] = [69, 16, 0, 56, 36, 97, 64, 0, 255, 112, 0, 0, 10, 0, 2, 30, 224, 0, 0, 18];
    //    let iph: Ipv4Header = unsafe { ::std::mem::transmute(bytes) };

    //    assert_eq!(iph.version(), 4);
    //    assert_eq!(iph.ihl(), 5);
    //    assert_eq!(iph.tos, 16);
    //    assert_eq!(iph.total_length, 56);
    //    assert_eq!(iph.id, 9313);
    //    assert_eq!(iph.frag_off, 16384);
    //    assert_eq!(iph.ttl, 255);
    //    assert_eq!(iph.protocol, 112);
    //    assert_eq!(iph.cksum, 0);
    //    assert_eq!(Ipv4Addr::from(iph.saddr), "10.0.2.30".parse().unwrap());
    //    assert_eq!(Ipv4Addr::from(iph.daddr), "224.0.0.18".parse().unwrap());
    // }

    #[test]
    fn test_cksum_zero_len() {
        let buf = [];

        assert_eq!(0, Ipv4Header::checksum(&buf));
    }

    #[test]
    fn test_calculate_cksum_even_len() {
        let mut buf = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 0, 0, 192, 168, 0, 1, 192, 168, 0, 199];
        let expected = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 184, 97, 192, 168, 0, 1, 192, 168, 0,
                        199];

        Ipv4Header::apply_cksum(&mut buf);
        assert_eq!(expected, buf);
    }

    #[test]
    fn test_calculate_cksum_odd_len() {
        let mut buf = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 0, 0, 192, 168, 0, 1, 192, 168, 0, 199,
                       0];
        let expected = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 184, 97, 192, 168, 0, 1, 192, 168, 0,
                        199, 0];

        Ipv4Header::apply_cksum(&mut buf);
        assert_eq!(expected, buf);
    }

    #[test]
    fn test_verify_cksum_even_len() {
        let buf = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 184, 97, 192, 168, 0, 1, 192, 168, 0, 199];

        assert_eq!(0, Ipv4Header::checksum(&buf));
    }

    #[test]
    fn test_verify_cksum_odd_len() {
        let buf = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 184, 97, 192, 168, 0, 1, 192, 168, 0, 199,
                   0];

        assert_eq!(0, Ipv4Header::checksum(&buf));
    }
}
