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

// This should become stable in 1.7
#![feature(ip_addr)]

extern crate libc;

#[cfg(unix)]
extern crate nix;

use std::net::IpAddr;
use std::os::raw::{c_char, c_uchar, c_uint};
use std::str::FromStr;
use std::fmt;

mod mac;
mod arp;

/// Configuration options for CARP
#[derive(Debug)]
pub struct Config {
    /// Virtual shared IP address
    ///
    /// This is the value that will be dynamically answered by one alive host.
    vaddr: IpAddr,

    /// Real IP address of the host
    srcip: IpAddr,

    /// Virtual IP identifier. Must be between 1-255
    ///
    /// The virtual IP identifier field only is only eight bits, providing up
    /// to 255 different virtual IPs on the same multicast group IP. For larger
    /// deployments, and more flexibility in allocation, ucarp can optionally
    /// use a different multicast IP.
    vhid: u8,

    /// Password used to encrypt CARP messages
    ///
    /// This password will never be sent in plaintext over the network.
    password: String,

    /// Advertisement base (in seconds)
    advbase: u8,

    /// Advertisement skew. Must be between 1-255
    advskew: u8,

    /// Ratio to consider host as dead. Default is 3.
    ///
    /// This ratio changes how long a backup server will wait for an
    /// unresponsive primary before considering it as dead, and becoming the
    /// new primary. In the original protocol, the ratio is 3.
    dead_ratio: u32,

    /// Bind interface.
    ///
    /// Defaults to using `pcap_lookupdev` to find the default device on which
    /// to capture.
    interface: Option<String>,

    /// Multicast group IP address (default 224.0.0.18).
    ///
    /// This is how servers will send and receive CARP messages.  By default,
    /// carp will send/listen on 224.0.0.18, which is the assigned IP for VRRP.
    /// Consult the [IPv4 Multicast Address Space Registry](http://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml)
    /// before deciding to use a different one.
    ///
    /// Other useful links:
    /// http://tools.ietf.org/html/rfc5771
    /// http://tools.ietf.org/html/rfc2365
    ///
    /// Addresses within 239.192.0.0/14 should be most appropriate.
    ///
    /// If carp isn't working on a different IP, check that your networking gear is
    /// set up to handle it. tcpdump on each host can be handy for diagnosis:
    ///
    /// tcpdump -n 'net 224.0.0.0/4'
    mcast: IpAddr,

    /// Become master as soon as possible
    preempt: bool,

    /// Do not run `onShutdown` callback at start if in backup state
    neutral: bool,

    /// Call `onShutdown` callback on exit if not in backup state
    shutdown_at_exit: bool,

    /// Ignore interface state (down, no carrier).
    ///
    /// This option tells CARP to ignore unplugged network cable. It is useful
    /// when you connect ucarp nodes with a crossover patch cord (not via a hub
    /// or a switch). Without this option the node in MASTER state will switch
    /// to BACKUP state when the other node is powered down, because network
    /// interface shows that cable is unplugged (NO-CARRIER). Some network interface
    /// drivers don't support NO-CARRIER feature, and this option is not needed for
    /// these network cards. The card that definitely supports this feature is
    /// Realtek 8139.
    ignoreifstate: bool,

    /// Use broadcast (instead of multicast) advertisements
    no_mcast: bool,
}

// facility: CString, // type?

impl Config {
    pub fn new<S>(vaddr: IpAddr, srcip: IpAddr, password: S) -> Config
        where S: Into<String>
    {
        Config {
            vaddr: vaddr,
            srcip: srcip,
            vhid: 1,
            password: password.into(),
            advbase: 1,
            advskew: 1,
            dead_ratio: 3,
            interface: None,
            mcast: FromStr::from_str("224.0.0.18").unwrap(),
            preempt: false,
            neutral: false,
            shutdown_at_exit: false,
            ignoreifstate: false,
            no_mcast: false,
        }
    }

    pub fn set_password<S>(&mut self, password: S)
        where S: Into<String>
    {
        self.password = password.into();
    }
}

// Private globals. I do not love this, but it currently is the best way I
// have found to allow a user to register callback functions that will be
// triggerd by the C carp code.
static mut registered_up_callback: Option<fn()> = None;
static mut registered_down_callback: Option<fn()> = None;

/// Register a function to call when server is in a state of _up_
///
/// The callback is executed in a separate thread.
///
/// This must be a normal function. A closure cannot be used as this function
/// is being called from the C code and the environment is not guranteed.
///
/// Example:
///
/// ```rust
/// fn my_up_callback() {
///     println!("In my_up_callback()");
/// }
///
/// carp::on_up(my_up_callback);
/// ```
pub fn on_up(cb: fn()) {
    unsafe {
        registered_up_callback = Some(cb);
    }
}

/// Register a function to call when server is in a state of _down_
///
/// The callback is executed in a separate thread.
///
/// This must be a normal function. A closure cannot be used as this function
/// is being called from the C code and the environment is not guranteed.
///
/// Example:
///
/// ```rust
/// fn my_down_callback() {
///     println!("In my_down_callback()");
/// }
///
/// carp::on_down(my_down_callback);
/// ```
pub fn on_down(cb: fn()) {
    unsafe {
        registered_down_callback = Some(cb);
    }
}

/// Called by carp C code when state changes to _up_
extern "C" fn up_callback() {
    let func = unsafe {
        match registered_up_callback {
            Some(func) => func,
            None => return,
        }
    };

    std::thread::spawn(move || func());
}

/// Called by carp C code when state changes to _down_
extern "C" fn down_callback() {
    let func = unsafe {
        match registered_down_callback {
            Some(func) => func,
            None => return,
        }
    };

    std::thread::spawn(move || func());
}

#[derive(Debug)]
pub enum CarpError {
    InvalidVirtualIp,
    InvalidMulticastIp,
    InvalidSourceIp,
    InvalidVirtualHardwareId,
    InvalidNetworkInterface,
    InvalidPassword,
    InvalidDeadRatio,
    InvalidUnknown,
    CarpFailure,
}

impl fmt::Display for CarpError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use CarpError::*;

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
        }
    }
}

pub fn carp(config: Config) -> Result<(), CarpError> {
    #[link(name="pcap")]
    extern "C" {
        fn set_vaddr(vaddr: *const c_uchar) -> i32;
        fn set_mcast(mcast: *const c_uchar) -> i32;
        fn set_srcip(srcip: *const c_uchar) -> i32;
        fn set_vhid(vhid: c_uchar) -> i32;
        fn set_interface(interface: *const c_uchar) -> i32;
        fn set_password(password: *const c_uchar) -> i32;
        fn set_advbase(advbase: c_uchar);
        fn set_advskew(advskew: c_uchar);
        fn set_dead_ratio(dead_ratio: c_uint) -> i32;
        fn set_neutral(neutral: c_char);
        fn set_shutdown_at_exit(shutdown_at_exit: c_char);
        fn set_ignoreifstate(ignoreifstate: c_char);
        fn set_no_mcast(no_mcast: c_char);

        fn register_up_callback(cb: extern "C" fn());
        fn register_down_callback(cb: extern "C" fn());

        fn libmain() -> i32;
    }

    // The `IpAddr` type has no other way of converting back into a string
    let vaddr = format!("{}", config.vaddr);
    let srcip = format!("{}", config.srcip);
    let mcast = format!("{}", config.mcast);

    unsafe {
        if set_vaddr(vaddr.as_ptr()) != 0 {
            return Err(CarpError::InvalidVirtualIp);
        }

        if set_srcip(srcip.as_ptr()) != 0 {
            return Err(CarpError::InvalidSourceIp);
        }

        if set_mcast(mcast.as_ptr()) != 0 {
            return Err(CarpError::InvalidMulticastIp);
        }

        if set_vhid(config.vhid) != 0 {
            return Err(CarpError::InvalidVirtualHardwareId);
        }

        if match config.interface {
            Some(interface) => set_interface(interface.as_ptr()),
            None => set_interface(0 as *const c_uchar),
        } != 0 {
            return Err(CarpError::InvalidNetworkInterface);
        }

        if set_password(config.password.as_ptr()) != 0 {
            return Err(CarpError::InvalidPassword);
        }

        if set_dead_ratio(config.dead_ratio) != 0 {
            return Err(CarpError::InvalidDeadRatio);
        }

        set_advbase(config.advbase);
        set_advskew(config.advskew);
        set_neutral(config.neutral as i8);
        set_shutdown_at_exit(config.shutdown_at_exit as i8);
        set_ignoreifstate(config.ignoreifstate as i8);
        set_no_mcast(config.no_mcast as i8);

        if registered_up_callback.is_some() {
            register_up_callback(up_callback);
        }

        if registered_down_callback.is_some() {
            register_down_callback(down_callback);
        }

        match libmain() {
            0 => Ok(()),
            2 => Err(CarpError::CarpFailure),
            _ => Err(CarpError::InvalidUnknown), // covers return 1 case too
        }
    }
}
