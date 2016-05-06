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

use byteorder;
use net::ip::Ipv4Header;
use net::ether::EtherHeader;
use ip_carp::CarpHeader;

/// A Carp packet
///
/// Follows Ethernet Type II Frame structure
#[derive(Debug)]
#[repr(C, packed)]
pub struct CarpPacket {
    ether_header: EtherHeader,
    pub ip: Ipv4Header,
    pub carp: CarpHeader,
}

impl CarpPacket {
    pub fn new(eh: EtherHeader, ip: Ipv4Header, ch: CarpHeader) -> CarpPacket {
        CarpPacket {
            ether_header: eh,
            ip: ip,
            carp: ch,
        }
    }

    pub fn into_bytes(&self) -> byteorder::Result<Vec<u8>> {
        let mut wtr: Vec<u8> = vec![];

        let mut t = try!(self.ether_header.into_bytes());
        wtr.append(&mut t);

        let mut t = try!(self.ip.into_bytes());
        wtr.append(&mut t);

        let mut t = try!(self.carp.into_bytes());
        wtr.append(&mut t);

        Ok(wtr)
    }
}
