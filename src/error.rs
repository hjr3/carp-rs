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

use std::io;
use std::fmt;

use pcap;

#[derive(Debug)]
pub enum Error {
    InvalidVirtualIp,
    InvalidMulticastIp,
    InvalidSourceIp,
    InvalidVirtualHardwareId,
    InvalidNetworkInterface,
    InvalidPassword,
    InvalidDeadRatio,
    InvalidUnknown,
    CarpFailure,
    Pcap(pcap::Error),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            InvalidVirtualIp => write!(fmt, "InvalidVirtualIp"),
            InvalidMulticastIp => write!(fmt, "InvalidMulticastIp"),
            InvalidSourceIp => write!(fmt, "InvalidSourceIp"),
            InvalidVirtualHardwareId => write!(fmt, "InvalidVirtualHardwareId"),
            InvalidNetworkInterface => write!(fmt, "InvalidNetworkInterface"),
            InvalidPassword => write!(fmt, "InvalidPassword"),
            InvalidDeadRatio => write!(fmt, "InvalidDeadRatio"),
            InvalidUnknown => write!(fmt, "InvalidUnknown"),
            CarpFailure => write!(fmt, "CarpFailure"),
            Pcap(ref err) => write!(fmt, "{}", err),
            Io(ref err) => write!(fmt, "{}", err),
        }
    }
}

impl From<pcap::Error> for Error {
    fn from(err: pcap::Error) -> Self {
        Error::Pcap(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}
