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

use libc::{uint8_t, uint16_t};

use std::io::Cursor;
use byteorder::{self, BigEndian, ReadBytesExt, WriteBytesExt};

use mac::HwAddr;

pub const ETH_ALEN: usize = 6;

/// Ethernet frame types
pub enum EtherType {
    Ip = 0x0800,
    //Arp = 0x0806,
}

/// Ethernet header
///
/// Follows Ethernet Type II Frame structure
#[derive(Debug, Eq, PartialEq)]
#[repr(C, packed)]
pub struct EtherHeader {
    /// Destination hardware (MAC) address
    ether_dhost: [uint8_t; ETH_ALEN],

    /// Source hardware (MAC) address
    ether_shost: [uint8_t; ETH_ALEN],

    /// packet type ID field
    ether_type: uint16_t,
}

impl EtherHeader {
    pub fn new(dhost: &HwAddr, shost: &HwAddr, type_: EtherType) -> EtherHeader {
        EtherHeader {
            ether_dhost: dhost.octets(),
            ether_shost: shost.octets(),
            ether_type: type_ as uint16_t,
        }
    }

    pub fn from_bytes(data: &[u8]) -> byteorder::Result<EtherHeader> {
        let mut rdr = Cursor::new(data);

        let ether_dhost = [
            try!(rdr.read_u8()),
            try!(rdr.read_u8()),
            try!(rdr.read_u8()),
            try!(rdr.read_u8()),
            try!(rdr.read_u8()),
            try!(rdr.read_u8())
        ];

        let ether_shost = [
            try!(rdr.read_u8()),
            try!(rdr.read_u8()),
            try!(rdr.read_u8()),
            try!(rdr.read_u8()),
            try!(rdr.read_u8()),
            try!(rdr.read_u8())
        ];

        let ether_type = try!(rdr.read_u16::<BigEndian>());

        Ok(EtherHeader {
            ether_dhost: ether_dhost,
            ether_shost: ether_shost,
            ether_type: ether_type,
        })
    }

    pub fn into_bytes(&self) -> byteorder::Result<Vec<u8>> {
        let mut wtr = vec![];

        for i in self.ether_dhost.iter() {
            try!(wtr.write_u8(*i));
        }

        for i in self.ether_shost.iter() {
            try!(wtr.write_u8(*i));
        }

        try!(wtr.write_u16::<BigEndian>(self.ether_type));

        Ok(wtr)
    }
}

#[cfg(test)]
mod test {

    use libc::{uint8_t, uint16_t};
    use super::*;

    #[test]
    fn test_from_bytes() {
        let bytes: [uint8_t; 14] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x01, 0x08, 0x00];

        let eh = EtherHeader::from_bytes(&bytes).unwrap();

        let shost: [uint8_t; ETH_ALEN] = [
            0x00,
            0x00,
            0x5e,
            0x00,
            0x00,
            0x01,
        ];

        let dhost: [uint8_t; ETH_ALEN] = [
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
        ];

        let expected = EtherHeader {
            ether_dhost: dhost,
            ether_shost: shost,
            ether_type: EtherType::Ip as uint16_t,
        };

        assert_eq!(expected, eh);
    }

    #[test]
    fn test_into_bytes() {
        let shost: [uint8_t; ETH_ALEN] = [
            0x00,
            0x00,
            0x5e,
            0x00,
            0x00,
            0x01,
        ];

        let dhost: [uint8_t; ETH_ALEN] = [
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
        ];

        let eh = EtherHeader {
            ether_dhost: dhost,
            ether_shost: shost,
            ether_type: EtherType::Ip as uint16_t,
        };

        let bytes = eh.into_bytes().unwrap();

        let expected: [uint8_t; 14] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x01, 0x08, 0x00];

        assert_eq!(expected, bytes[..]);
    }
}
