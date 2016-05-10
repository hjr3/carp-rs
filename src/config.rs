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

use std::net::IpAddr;
use std::str::FromStr;

/// Configuration options for CARP
#[derive(Debug)]
pub struct Config {
    /// Virtual shared IP address
    ///
    /// This is the value that will be dynamically answered by one alive host.
    pub vaddr: IpAddr,

    /// Real IP address of the host
    pub srcip: IpAddr,

    /// Virtual IP identifier. Must be between 1-255
    ///
    /// The virtual IP identifier field only is only eight bits, providing up
    /// to 255 different virtual IPs on the same multicast group IP. For larger
    /// deployments, and more flexibility in allocation, ucarp can optionally
    /// use a different multicast IP.
    pub vhid: u8,

    /// Password used to encrypt CARP messages
    ///
    /// This password will never be sent in plaintext over the network.
    pub password: String,

    /// Advertisement base (in seconds)
    pub advbase: u8,

    /// Advertisement skew. Must be between 1-255
    pub advskew: u8,

    /// Ratio to consider host as dead. Default is 3.
    ///
    /// This ratio changes how long a backup server will wait for an
    /// unresponsive primary before considering it as dead, and becoming the
    /// new primary. In the original protocol, the ratio is 3.
    pub dead_ratio: u32,

    /// Bind interface.
    ///
    /// Defaults to using `pcap_lookupdev` to find the default device on which
    /// to capture.
    pub interface: Option<String>,

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
    pub mcast: IpAddr,

    /// Become master as soon as possible
    pub preempt: bool,

    /// Do not run `onShutdown` callback at start if in backup state
    pub neutral: bool,

    /// Call `onShutdown` callback on exit if not in backup state
    pub shutdown_at_exit: bool,

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
    pub ignoreifstate: bool,

    /// Use broadcast (instead of multicast) advertisements
    pub no_mcast: bool,
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
            advskew: 0,
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

    pub fn set_interface<S>(&mut self, interface: S)
        where S: Into<String>
    {
        self.interface = Some(interface.into());
    }

    pub fn set_advbase(&mut self, advbase: u8) {
        self.advbase = advbase;
    }

    pub fn set_advskew(&mut self, advskew: u8) {
        self.advskew = advskew;
    }

    pub fn set_preempt(&mut self, preempt: bool) {
        self.preempt = preempt;
    }
}
