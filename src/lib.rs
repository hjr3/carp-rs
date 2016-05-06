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

extern crate libc;

#[macro_use]
extern crate log;

#[cfg(unix)]
extern crate nix;

extern crate rand;
extern crate pcap;
extern crate crypto;
extern crate byteorder;

use std::result;

pub mod net;

pub mod config;
pub mod ip_carp;
pub mod error;
pub mod advert;
pub mod carp;
pub mod node;

pub type Result<T> = result::Result<T, error::Error>;
