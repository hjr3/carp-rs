//!
//! Copyright (c) 2016  Herman J. Radtke III <herman@hermanradtke.com>
//!
//! This file is part of carp-rs.
//!
//! carp-rs is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Lesser General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! carp-rs is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU Lesser General Public License for more details.
//!
//! You should have received a copy of the GNU Lesser General Public License
//! along with carp-rs.  If not, see <http://www.gnu.org/licenses/>.

fn carp() {
    #[link(name="pcap")]
    extern {
        fn libmain(argc: i32, argv: *const *const u8) -> i32;
    }

    let argv = &[
        "test".as_ptr(),
        0 as *const u8
    ];

    unsafe {
        let _ = libmain(1, argv.as_ptr());
    }

}
