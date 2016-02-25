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

use libc::{uint8_t, uint16_t, uint32_t};

use rand::{self, Rng};
use std::io::Cursor;
use byteorder::{self, ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

pub enum Protocol {
    Carp = 112, // VRRP
}

// this is triggering doc tests and i do not know why. plus, i don't even think is a good approach
// since i cannot reuse enum values. i will need to change these into constants.
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
pub enum Flags {
//    Reserved = 0x0,
//    MayFragment = 0x0,
    DontFragment = 0x4000,
//    LastFragment = 0x0,
//    MoreFragment = 0x2000,
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
pub enum Tos {
//    NormalDelay = 0x0,
    LowDelay = 0x10,
//    NormalThroughput = 0x0,
//    HighThroughput = 0x8,
//    NormalReliability = 0x0,
//    HighReliability = 0x4,
}

/// Structure of an internet header, naked of options.
///
/// The struct aims to keep the byte representation compatible with C. This allows for the use of
/// `from_bytes` as a safe method and transmute for speed. Transmute is not supported at this time.
/// I need to find a way to get ByteOrders API but not switch the endianness.
///
/// See: https://tools.ietf.org/html/rfc791
#[derive(Debug, Default)]
#[repr(C)]
pub struct IpHeader {
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

impl IpHeader {

    #[inline]
    pub fn ipv4() -> uint8_t {
        4
        //let len = ::std::mem::size_of::<IpHeader>();
        //let version = 4 << 4;

        //len as u8 + version
    }

    //#[cfg(target_endian = "little")]
    //#[inline]
    //pub fn ipv4() -> uint8_t {
    //    let version = 4;
    //    let len = ::std::mem::size_of::<IpHeader>() << 4;

    //    version + len as u8
    //}

    //pub fn generate_id() -> uint16_t {
    //    let mut rng = rand::thread_rng();
    //    rng.gen()
    //}

    pub fn from_bytes(buf: &[u8]) -> byteorder::Result<IpHeader> {
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

        Ok(IpHeader {
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

    /// Apply checksum value to bytes version of IpHeader
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
    pub fn ihl(&self) -> uint8_t{
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
    pub fn id(&self) ->uint16_t {
        self.id
    }

    pub fn generate_id(&mut self) {
        let mut rng = rand::thread_rng();
        self.id = rng.gen();
    }

    /// Fragment offset field
    #[inline]
    pub fn frag_off(&self) ->uint16_t {
        self.frag_off
    }

    pub fn set_frag_off(&mut self, frag_off: uint16_t) {
        self.frag_off = frag_off;
    }

    /// Checksum
    #[inline]
    pub fn cksum(&self) ->uint16_t {
        self.cksum
    }

    pub fn set_cksum(&mut self, cksum: uint16_t) {
        self.cksum = cksum;
    }

    /// Source address
    #[inline]
    pub fn saddr(&self) ->uint32_t {
        self.saddr
    }

    pub fn set_saddr(&mut self, saddr: uint32_t) {
        self.saddr = saddr;
    }

    /// Destination address
    #[inline]
    pub fn daddr(&self) ->uint32_t {
        self.daddr
    }

    pub fn set_daddr(&mut self, daddr: uint32_t) {
        self.daddr = daddr;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_from_bytes() {
        let bytes: [u8; 20] = [69, 16, 0, 56, 36, 97, 64, 0, 255, 112, 0, 0, 10, 0, 2, 30, 224, 0, 0, 18];
        let iph = IpHeader::from_bytes(&bytes).unwrap();

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
        let bytes: [u8; 20] = [69, 16, 0, 56, 36, 97, 64, 0, 255, 112, 0, 0, 10, 0, 2, 30, 224, 0, 0, 18];
        let iph = IpHeader::from_bytes(&bytes).unwrap();
        let given = iph.into_bytes().unwrap();

        assert_eq!(bytes, given.as_slice());
    }

    //#[test]
    //fn test_transmute() {
    //    let bytes: [u8; 20] = [69, 16, 0, 56, 36, 97, 64, 0, 255, 112, 0, 0, 10, 0, 2, 30, 224, 0, 0, 18];
    //    let iph: IpHeader = unsafe { ::std::mem::transmute(bytes) };

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
    //}

    #[test]
    fn test_cksum_zero_len() {
        let buf = [];

        assert_eq!(0, IpHeader::checksum(&buf));
    }

    #[test]
    fn test_calculate_cksum_even_len() {
        let mut buf = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 0, 0, 192, 168, 0, 1, 192, 168, 0, 199];
        let expected = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 184, 97, 192, 168, 0, 1, 192, 168, 0, 199];

        IpHeader::apply_cksum(&mut buf);
        assert_eq!(expected, buf);
    }

    #[test]
    fn test_calculate_cksum_odd_len() {
        let mut buf = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 0, 0, 192, 168, 0, 1, 192, 168, 0, 199, 0];
        let expected = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 184, 97, 192, 168, 0, 1, 192, 168, 0, 199, 0];

        IpHeader::apply_cksum(&mut buf);
        assert_eq!(expected, buf);
    }

    #[test]
    fn test_verify_cksum_even_len() {
        //use byteorder::{BigEndian, WriteBytesExt};

        //let header = [0x4500, 0x0073, 0x0000, 0x4000, 0x4011, 0xb861, 0xc0a8, 0x0001, 0xc0a8, 0x00c7];
        //let mut buf = vec![];

        //for val in header.iter() {
        //    buf.write_u16::<BigEndian>(*val).unwrap();
        //}
        //println!("{:?}", buf);

        let buf = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 184, 97, 192, 168, 0, 1, 192, 168, 0, 199];

        assert_eq!(0, IpHeader::checksum(&buf));
    }

    #[test]
    fn test_verify_cksum_odd_len() {
        let buf = [69, 0, 0, 115, 0, 0, 64, 0, 64, 17, 184, 97, 192, 168, 0, 1, 192, 168, 0, 199, 0];

        assert_eq!(0, IpHeader::checksum(&buf));
    }
}
