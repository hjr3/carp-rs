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

/*
 * The CARP header layout is as follows:
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Version| Type  | VirtualHostID |    AdvSkew    |    Auth Len   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Reserved    |     AdvBase   |          Checksum             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Counter (1)                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Counter (2)                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (1)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (2)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (3)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (4)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (5)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

use libc::{c_uchar, uint8_t, uint16_t, uint64_t};

use std::io::{Read, Cursor};
use byteorder::{self, BigEndian, ReadBytesExt, WriteBytesExt};

/// CarpHeader
///
/// The struct aims to keep the byte representation compatible with C. This allows for the use of
/// `from_bytes` as a safe method and transmute for speed. Transmute is not supported at this time.
/// I need to find a way to get ByteOrders API but not switch the endianness.
#[derive(Debug, Default)]
#[repr(C, packed)]
pub struct CarpHeader {
    carp_version_type: uint8_t,

    /// Virtual host id
    pub carp_vhid: uint8_t,

    /// Advertisement skew
    pub carp_advskew: uint8_t,

    /// Size of counter+md, 32bit chunks
    pub carp_authlen: uint8_t,

    /// Reserved
    pub carp_pad1: uint8_t,

    /// Advertisement interval
    pub carp_advbase: uint8_t,

    carp_cksum: uint16_t,
    carp_counter: uint64_t,

    /// SHA1 HMAC
    pub carp_md: [c_uchar; 20],
}

impl CarpHeader {

    #[inline]
    pub fn version() -> uint8_t {
        2
    }

    /// Type of CARP header to send
    #[inline]
    pub fn advertisement() -> uint8_t {
        1
    }

    #[inline]
    pub fn authlen() -> uint8_t {
        7
    }

    #[inline]
    pub fn ttl() -> uint8_t {
        255
    }

    pub fn from_bytes(data: &[u8]) -> byteorder::Result<CarpHeader> {
        let mut rdr = Cursor::new(data);

        let carp_version_type = try!(rdr.read_u8());
        let carp_vhid = try!(rdr.read_u8());
        let carp_advskew = try!(rdr.read_u8());
        let carp_authlen = try!(rdr.read_u8());
        let carp_pad1 = try!(rdr.read_u8());
        let carp_advbase = try!(rdr.read_u8());
        let carp_cksum = try!(rdr.read_u16::<BigEndian>());
        let carp_counter = try!(rdr.read_u64::<BigEndian>());

        let mut carp_md: [c_uchar; 20] = [0; 20];
        try!(rdr.read_exact(&mut carp_md));

        Ok(CarpHeader {
            carp_version_type: carp_version_type,
            carp_vhid: carp_vhid,
            carp_advskew: carp_advskew,
            carp_authlen: carp_authlen,
            carp_pad1: carp_pad1,
            carp_advbase: carp_advbase,
            carp_cksum: carp_cksum,
            carp_counter: carp_counter,
            carp_md: carp_md,
        })
    }

    pub fn into_bytes(&self) -> byteorder::Result<Vec<u8>> {
        let mut wtr = vec![];

        try!(wtr.write_u8(self.carp_version_type));
        try!(wtr.write_u8(self.carp_vhid));
        try!(wtr.write_u8(self.carp_advskew));
        try!(wtr.write_u8(self.carp_authlen));
        try!(wtr.write_u8(self.carp_pad1));
        try!(wtr.write_u8(self.carp_advbase));
        try!(wtr.write_u16::<BigEndian>(self.carp_cksum));
        try!(wtr.write_u64::<BigEndian>(self.carp_counter));

        for i in self.carp_md.iter() {
            try!(wtr.write_u8(*i));
        }

        Ok(wtr)
    }

    #[cfg(target_endian = "little")]
    #[inline]
    pub fn carp_type(&self) -> uint8_t {
        self.carp_version_type & 0xF
    }

    #[cfg(target_endian = "little")]
    #[inline]
    pub fn carp_version(&self) -> uint8_t {
        self.carp_version_type >> 4
    }

    #[cfg(target_endian = "little")]
    #[inline]
    pub fn carp_set_version_type(&mut self, version: uint8_t, type_: uint8_t) {
        self.carp_version_type = (version << 4) + type_;
    }

    #[cfg(target_endian = "big")]
    #[inline]
    pub fn carp_type(&self) -> uint8_t {
        self.carp_version_type >> 4
    }

    #[cfg(target_endian = "big")]
    #[inline]
    pub fn carp_version(&self) -> uint8_t {
        self.carp_version_type & 0xF
    }

    #[cfg(target_endian = "big")]
    #[inline]
    pub fn carp_set_version_type(&mut self, version: uint8_t, type_: uint8_t) {
        self.carp_version_type = (type_ << 4) + version;
    }

    #[inline]
    pub fn carp_cksum(&self) -> uint16_t {
        self.carp_cksum
    }

    pub fn carp_set_cksum(&mut self, cksum: uint16_t) {
        self.carp_cksum = cksum;
    }

    #[inline]
    pub fn carp_counter(&self) -> u64 {
        self.carp_counter
        //let mut t: u64 = self.carp_counter[0] as u64;
        //t = t << 32;
        //t = t + self.carp_counter[1] as u64;
        //t
    }

    pub fn carp_set_counter(&mut self, counter: u64) {
        self.carp_counter = counter;
    }

    #[inline]
    pub fn carp_bulk_update_min_delay(&self) -> usize {
        240
    }
}

//impl Default for CarpHeader {
//    fn default() -> CarpHeader {
//        let ch = CarpHeader {
//            carp_version_type: CarpHeader::version(),
//            carp_vhid: self.config.vhid,
//            carp_advskew: self.config.advskew,
//            carp_authlen: CarpHeader::authlen(),
//            carp_pad1: 0,
//            carp_advbase: self.config.advbase,
//            carp_cksum: 0,
//            carp_counter: [0; 2],
//            carp_md: md,
//        };
//    }
//}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let bytes: [u8; 36] = [33, 1, 1, 7, 0, 1, 67, 60, 54, 208, 19, 50, 106, 121, 153, 232, 11, 225, 167, 175, 127, 243, 33, 245, 83, 103, 152, 57, 240, 194, 21, 219, 160, 185, 99, 228];

        let ch = CarpHeader::from_bytes(&bytes).unwrap();

        assert_eq!(ch.carp_version(), 2);
        assert_eq!(ch.carp_type(), 1);
        assert_eq!(ch.carp_vhid, 1);
        assert_eq!(ch.carp_advskew, 1);
        assert_eq!(ch.carp_authlen, 7);
        assert_eq!(ch.carp_pad1, 0);
        assert_eq!(ch.carp_advbase, 1);
        assert_eq!(ch.carp_cksum, 17212);
        assert_eq!(ch.carp_counter, 3949677980459571688);
        //assert_eq!(ch.carp_counter[0], 919606066);
        //assert_eq!(ch.carp_counter[1], 1786354152);

        // TODO test sha1 HMAC
    }

    #[test]
    fn test_into_bytes() {
        let bytes: [u8; 36] = [33, 1, 1, 7, 0, 1, 67, 60, 54, 208, 19, 50, 106, 121, 153, 232, 11, 225, 167, 175, 127, 243, 33, 245, 83, 103, 152, 57, 240, 194, 21, 219, 160, 185, 99, 228];

        let ch = CarpHeader::from_bytes(&bytes).unwrap();

        let given = ch.into_bytes().unwrap();

        // PartialEq is not implemented for [T; 36], so turn it into a &[T]
        assert_eq!(&bytes[..], given.as_slice());
    }
}
