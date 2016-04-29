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

use std::cmp;
use std::fmt;
use std::mem;
use std::io::{self};
use std::os::unix::io::{RawFd, AsRawFd};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::thread;
use std::result;
use std::time::{SystemTime, Duration};
use std::process;

use libc::{uint8_t, uint32_t};

use nix::poll::{self, PollFd, EventFlags, POLLIN, POLLERR, POLLHUP};
use nix::sys::signal;
use nix::sys::socket::{self, ip_mreq, socket, setsockopt, SockType, SockFlag, AddressFamily};
use nix::sys::socket::sockopt::IpAddMembership;
use nix::unistd::write;

use pcap::{self, Capture, Active, Packet};

use crypto::mac::{Mac, MacResult};
use crypto::hmac::Hmac;
use crypto::digest::Digest;
use crypto::sha1::Sha1;

use byteorder::{ByteOrder, BigEndian};

use config::Config;
use Result;
use mac::{HwIf, HwAddr};
use ether::{EtherHeader, EtherType};
use ip::{self, IpHeader};
use ip_carp::CarpHeader;
use advert::CarpPacket;
use node;
use socket::gratuitous_arp;

const ETHERNET_MTU: i32 = 1500;
const IPPROTO_CARP: uint8_t = 112;

static mut received_signal: usize = 0;

#[derive(Debug, Eq, PartialEq)]
enum State {
    Primary,
    Backup,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        match *self {
            State::Primary => {
                write!(f, "Primary")
            }
            State::Backup => {
                write!(f, "Backup")
            }
        }
    }
}

pub struct Carp {
    config: Config,
    state: State,
    interface: String,
    iface_running: bool,
    capture: Capture<Active>,
    fd: Option<RawFd>,

    /// Advertisement timeout
    ad_tmo: Option<SystemTime>,

    /// Primary down timeout
    pd_tmo: Option<SystemTime>,
    counter: Option<u64>,

    delayed_arp: isize,

    up_cb: Option<Box<Fn()>>,
    down_cb: Option<Box<Fn()>>,
}

impl Carp {
    pub fn default_pcap(interface: &str) -> result::Result<Capture<Active>, pcap::Error> {
        let cap = try!(try!(Capture::from_device(interface))
                           .snaplen(ETHERNET_MTU)
                           .timeout(1000)
                           .open());

        Ok(cap)
    }

    pub fn new(config: Config, capture: Capture<Active>) -> Carp {
        let interface = config.interface.clone().expect("Interface is not set");
        Carp {
            config: config,
            state: State::Backup,
            interface: interface,
            iface_running: false,
            capture: capture,
            fd: None,
            ad_tmo: None,
            pd_tmo: None,
            counter: None,
            delayed_arp: -1,
            up_cb: None,
            down_cb: None,
        }
    }

    /// Register callback when role changes from backup to primary
    pub fn on_up<F>(&mut self, cb: F) where F: Fn() + 'static {
        self.up_cb = Some(Box::new(cb));
    }

    /// Register callback when role changes from primary to backup
    pub fn on_down<F>(&mut self, cb: F) where F: Fn() + 'static {
        self.down_cb = Some(Box::new(cb));
    }

    fn up_callback(&self) {
        match self.up_cb {
            Some(ref func) => {
                func();
            }
            None => {
                warn!("No up callback registered");
            }
        }
    }

    fn down_callback(&self) {
        match self.down_cb {
            Some(ref func) => {
                func();
            }
            None => {
                warn!("No down callback registered");
            }
        }
    }

    pub fn is_backup(&self) -> bool {
        self.state == State::Backup
    }

    pub fn is_primary(&self) -> bool {
        self.state == State::Primary
    }

    pub fn run_once(&mut self) -> io::Result<bool> {
        if self.check_interface() == false {
            trace!("Check interface failed");
            return Ok(false);
        }

        if self.check_signals() == false {
            trace!("Check signals failed");
            return Ok(false);
        }

        match self.poll() {
            Err(e) => {
                if e.kind() != io::ErrorKind::Interrupted {
                    return Ok(true);
                } else {
                    return Err(e);
                }
            }
            Ok(_) => {
                self.check_primary_tmo();
            }
        }

        Ok(true)
    }

    // Roles: Primary, Backup
    // States: check interface, check signals, poll, check timeout, send advert
    // Transitions:
    // * Primary -> Backup: we need to advertise, then change role
    // * Backup -> Primary: we change role, then advertise
    // * Other case: Primary reasserting dominance
    pub fn run(&mut self) -> Result<()> {
        try!(self.setup());

        trace!("starting to loop");
        loop {
            let should_keep_running = try!(self.run_once());
            if should_keep_running == false {
                break;
            }
        }

        self.tear_down();

        Ok(())
    }

    pub fn setup(&mut self) -> Result<()> {
        try!(self.setup_hwaddr());
        try!(self.setup_pcap());

        try!(self.setup_signal_handlers());

        self.fd = Some(try!(self.setup_socket()));

        self.reset_timers();

        Ok(())
    }

    // TODO can probably get rid of this since gratuitious_arp function handles it
    fn setup_hwaddr(&self) -> io::Result<()> {
        info!("Using [{}] as a network interface", self.interface);

        let hw_if = HwIf::new(self.interface.as_ref());
        let mac = try!(hw_if.hwaddr());

        info!("Local advertised ethernet address is [{}]", mac);

        Ok(())
    }

    fn setup_pcap(&mut self) -> result::Result<(), pcap::Error> {
        trace!("setup_pcap");

        match self.config.srcip {
            IpAddr::V4(ip) => {
                let bpf_rule = self.bpf_rule(ip);
                try!(self.capture.filter(bpf_rule.as_ref()));
            }
            _ => {
                panic!("IPv6 is not supported at this time");
            }
        }

        Ok(())
    }

    fn bpf_rule(&self, srcip: Ipv4Addr) -> String {
        format!("proto {} and src host not {}", IPPROTO_CARP, srcip)
    }

    fn setup_signal_handlers(&self) -> io::Result<()> {
        trace!("setup_signal_handlers");

        if self.config.shutdown_at_exit == true {
            let sig_action = signal::SigAction::new(
                signal::SigHandler::Handler(sighandler_exit),
                signal::SA_NODEFER,
                signal::SigSet::empty());

            unsafe {
                try!(signal::sigaction(signal::SIGINT, &sig_action));
                try!(signal::sigaction(signal::SIGQUIT, &sig_action));
                try!(signal::sigaction(signal::SIGTERM, &sig_action));
                try!(signal::sigaction(signal::SIGHUP, &sig_action));
            }
        }

        let sig_action = signal::SigAction::new(
            signal::SigHandler::Handler(sighandler_usr),
            signal::SA_NODEFER,
            signal::SigSet::empty());

        unsafe {
            try!(signal::sigaction(signal::SIGUSR1, &sig_action));
            try!(signal::sigaction(signal::SIGUSR2, &sig_action));
        }

        Ok(())
    }

    fn setup_socket(&self) -> io::Result<RawFd> {
        trace!("setup_socket");

        let fd = try!(socket(AddressFamily::Inet,
                             SockType::Datagram,
                             SockFlag::empty(),
                             0));

        if self.config.no_mcast == false {
            let srcip = match self.net_ipaddr_to_nix_ipaddr(self.config.srcip) {
                socket::IpAddr::V4(ip) => {
                    ip
                }
                _ => {
                    panic!("IPv6 is not supported at this time");
                }
            };

            let mcast = match self.net_ipaddr_to_nix_ipaddr(self.config.mcast) {
                socket::IpAddr::V4(ip) => {
                    ip
                }
                _ => {
                    panic!("IPv6 is not supported at this time");
                }
            };

            debug!("srcip = {}", srcip);
            debug!("mcast = {}", mcast);
            let req_add = ip_mreq::new(mcast, Some(srcip));
            try!(setsockopt(fd, IpAddMembership, &req_add));
        }

        Ok(fd)
    }

    fn net_ipaddr_to_nix_ipaddr(&self, ip: IpAddr) -> socket::IpAddr {
        match ip {
            IpAddr::V4(ref ip) => {
                socket::IpAddr::V4(socket::Ipv4Addr::from_std(ip))
            }
            _ => {
                panic!("IPv6 is not supported at this time");
            }
        }
    }

    fn check_interface(&mut self) -> bool {
        trace!("check_interface");

        let mut hw_if = HwIf::new(self.interface.as_ref());
        hw_if.use_raw_fd(self.fd.expect("Network interface fd is not set"));
        let hw_flags = hw_if.flags().unwrap();

        if hw_flags.is_running() == false {
            if self.config.ignoreifstate == false {
                self.state = State::Backup;
                self.down_callback();
                self.reset_timers();

                self.iface_running = false;

                thread::sleep(Duration::from_millis(10000));
                return false;
            }
        } else {
            if self.iface_running == false {
                debug!("Interface switched to running");
                self.iface_running = true;
                self.reset_timers();
            }
        }

        true
    }

    fn check_signals(&mut self) -> bool {
        trace!("check_signals");

        let flag = unsafe { received_signal };
        if flag != 0 {

            unsafe { received_signal = 0; }

            match flag {
                1 => {
                    info!("{} on {} id {}", self.state, self.interface, self.config.vhid);
                }
                2 => {
                    debug!("Caught signal (USR2) considering going down");

                    if self.state != State::Backup {
                        self.state = State::Backup;
                        self.down_callback();
                        thread::sleep(Duration::from_millis(3000));
                        self.reset_timers();
                        return false;
                    }
                }
                15 => {
                    debug!("sighandler_exit(): Triggering callback and exiting");
                    // if state is PRIMARY, then trigger callback
                    // callback is async, so this might be tricky
                    process::exit(0);
                }
                _ => { /* skip */ }
            }
        }

        true
    }

    fn calc_next_timeout(&self, ratio: u8) -> SystemTime {
        let now = SystemTime::now();

        now + calc_adv_freq(self.config.advbase, self.config.advskew, ratio)
    }

    fn reset_timers(&mut self) {
        match self.state {
            State::Primary => {
                let tmo = self.calc_next_timeout(1);
                debug!("Next primary timeout in {:?}", tmo);
                self.pd_tmo = Some(tmo);
            }
            State::Backup => {
                self.ad_tmo = None;
                let tmo = self.calc_next_timeout(self.config.dead_ratio as u8);
                debug!("Next primary timeout in {:?}", tmo);
                self.pd_tmo = Some(tmo);
            }
        }
    }

    fn poll(&mut self) -> io::Result<()> {
        trace!("poll");

        // TODO fix this to reuse capture
        let mut capture = Self::default_pcap(self.interface.as_ref()).unwrap();
        let dev_fd = capture.as_raw_fd();

        let poll_sleep_time = self.calculate_poll_sleep_time();

        let fd = PollFd {
            fd: dev_fd,
            events: POLLIN | POLLERR | POLLHUP,
            revents: EventFlags::empty(),
        };

        let mut pfds = [fd];

        let max = cmp::max(1, poll_sleep_time);

        trace!("Polling for {} milliseconds", max);

        // need to set the capture back here if we are in a soft error state
        let nfds = try!(poll::poll(&mut pfds, max as i32));

        // TODO push this up the stack
        //if nfds.is_err() {
        //    let error = io::Error::from(nfds.unwrap_err());
        //    if error.kind() == ErrorKind::Interrupted {
        //        return Ok(false);
        //    }
        //}

        if self.poll_revent_error(&pfds).is_err() {
            return Err(io::Error::new(io::ErrorKind::Other, "Poll revent error"));
        }

        let mut cp = Err(());
        if nfds == 1 {
            let packet = capture.next();
            if packet.is_ok() {
                cp = self.handle_packet(&packet.unwrap());
            };
        }

        if cp.is_ok() {
            self.check_role_change(&cp.unwrap());
        }

        Ok(())
    }

    fn calculate_poll_sleep_time(&self) -> u64 {

        match self.ad_tmo {
            None => {
                let tmpskew = (self.config.advskew as u64) * 1000 / 256;
                (self.config.advbase as u64) * 1000 + tmpskew
            }
            Some(ad_tmo) => {
                let now = SystemTime::now();

                let t = match ad_tmo.duration_since(now) {
                    Ok(t) => {
                        t
                    }
                    Err(e) => {
                        error!("Error calculating timeout: {}. Defaulting to 10000 ms", e);
                        Duration::from_secs(10)
                    }
                };
                (t.as_secs() * 1000) + (t.subsec_nanos() as u64 / 1000000)
            }
        }
    }

    fn poll_revent_error(&self, pfds: &[PollFd]) -> result::Result<(), ()> {
        if (pfds[0].revents & (POLLERR | POLLHUP)) != EventFlags::empty() {
            error!("exiting: pfds[0].revents = POLLERR | POLLHUP");


            // TODO move this up in the stack
            //if ((sc.sc_state != BACKUP) && (shutdown_at_exit != 0)) {
            //    trigger_down_callback();
            //}

            Err(())
        } else {
            Ok(())
        }
    }

    /// Parse incoming packet into a CarpPacket
    ///
    /// If parsing fails, return an err. This is a soft failure case.
    fn handle_packet(&mut self, packet: &Packet) -> result::Result<CarpPacket, ()> {
        let header = match EtherHeader::from_bytes(&packet.data) {
            Ok(header) => header,
            Err(e) => {
                warn!("Unable create EtherHeader: {:?}", e);
                return Err(());
            }
        };

        let eh_len = mem::size_of::<EtherHeader>();
        let ip = match IpHeader::from_bytes(&packet.data[eh_len..]) {
            Ok(ip) => ip,
            Err(e) => {
                warn!("Unable create Ip: {:?}", e);
                return Err(());
            }
        };

        let ip_len = mem::size_of::<IpHeader>();
        //println!("size of ether header = {:?}", eh_len);
        //println!("size of ip header = {:?}", ip_len);
        //println!("size of carp header = {:?}", ::std::mem::size_of::<CarpHeader>());
        //println!("size of data = {:?}", &packet.data.len());
        //println!("data = {:?}", &packet.data);

        let ch = match CarpHeader::from_bytes(&packet.data[eh_len + ip_len..]) {
            Ok(ip) => ip,
            Err(e) => {
                warn!("Unable create CarpHeader: {:?}", e);
                return Err(());
            }
        };

        if ip.protocol != IPPROTO_CARP {
            trace!("Protocol {} does not match {}", ip.protocol, IPPROTO_CARP);
            return Err(());
        }

        // TODO just make this impl Debug
        // debug!("{}", ch);
        debug!("CARP type: {}", ch.carp_type());
        debug!("CARP version: {}", ch.carp_version());
        debug!("CARP vhid: {}", ch.carp_vhid);
        debug!("CARP advskew: {}", ch.carp_advskew);
        debug!("CARP advbase: {}", ch.carp_advbase);
        debug!("CARP cksum: {}", ch.carp_cksum());
        debug!("CARP counter: {:?}", ch.carp_counter());

        if ip.ttl != CarpHeader::ttl() {
            warn!("Bad TTL: {}", ip.ttl);
            return Err(());
        }

        if ch.carp_version() != CarpHeader::version() {
            warn!("Bad version: {}", ch.carp_version());
            return Err(());
        }

        if ch.carp_vhid != self.config.vhid {
            debug!("Ignoring vhid: {}", ch.carp_vhid);
            return Err(());
        }

        match self.config.mcast {
            IpAddr::V4(mcast) => {
                let ip_dst = Ipv4Addr::from(ip.daddr());

                if ip_dst != mcast {
                    debug!("Ignoring different multicast ip: {}", ip_dst);
                    return Err(());
                }
            }
            IpAddr::V6(_) => {
                panic!("IpV6 not supported at this time");
            }
        }

        if IpHeader::checksum(&packet.data[eh_len + ip_len..]) != 0 {
            warn!("Bad IP checksum");
            return Err(());
        }

        if self.check_digest(&ch) != true {
            warn!("Bad digest! Check vhid, password and virtual IP address");
            return Err(());
        }

        let cp = CarpPacket::new(header, ip, ch);

        Ok(cp)
    }

    pub fn check_role_change(&mut self, cp: &CarpPacket) {

        let ip = &cp.ip;
        let ch = &cp.carp;

        self.counter = Some(ch.carp_counter());

        let skew = if self.config.preempt && (self.config.advskew as usize) < ch.carp_bulk_update_min_delay() {
            ch.carp_bulk_update_min_delay() as u8
        } else {
            self.config.advskew
        };

        let adv_freq = calc_adv_freq(self.config.advbase, skew, 1);
        let ch_adv_freq = calc_adv_freq(ch.carp_advbase, ch.carp_advskew, 1);
        let saddr_ip = IpAddr::V4(Ipv4Addr::from(ip.saddr()));
        debug!("adv_freq = {:?}, ch_adv_freq = {:?}", adv_freq, ch_adv_freq);

        let state = if self.state == State::Primary {
            node::Role::Primary
        } else {
            node::Role::Backup
        };

        let node = node::Node::new(state, adv_freq, self.config.srcip);
        let other = node::Node::new(node::Role::Primary, ch_adv_freq, saddr_ip);

        let role = node.role_change(&other, node::Alignment::Aggressive);

        match state {
            node::Role::Primary => {
                match role {
                    node::Role::Primary => {
                        warn!("Non-preferred primary advertised: {}. Reasserting primary role.", saddr_ip);
                        match self.config.srcip {
                            IpAddr::V4(srcip) => {
                                gratuitous_arp(self.interface.as_ref(), srcip).unwrap();
                            }
                            _ => {
                                panic!("IPv6 is not supported at this time");
                            }
                        }
                    }
                    node::Role::Backup => {
                        warn!("Preferred primary advertised: {}. Going back to backup role.", saddr_ip);
                        self.send_advert();

                        self.state = State::Backup;
                        self.down_callback();
                        self.reset_timers();
                    }
                }
            }
            node::Role::Backup => {
                match role {
                    node::Role::Primary => {
                        warn!("Putting remote primary {} down.", saddr_ip);
                        self.state = State::Primary;

                        self.send_advert();

                        self.delayed_arp += 1;

                        self.reset_timers();
                    }
                    node::Role::Backup => {
                        self.reset_timers();
                    }
                }
            }
        }
    }

    fn generate_digest(&self, counter: u64) -> MacResult {
        let mut hmac = Hmac::new(Sha1::new(), self.config.password.as_bytes());
        hmac.input(&[
            CarpHeader::version(),
            CarpHeader::advertisement(),
            self.config.vhid, // why is the C code doing `& 0xFF` here?
        ]);

        match self.config.vaddr {
            IpAddr::V4(ref vaddr) => {
                hmac.input(&vaddr.octets());
            }
            _ => {
                panic!("IPv6 is not supported at this time");
            }
        }

        let mut buf: [u8; 8]  = [0; 8];
        BigEndian::write_u64(&mut buf, counter);
        hmac.input(&buf);

        hmac.result()
    }

    fn check_digest(&self, ch: &CarpHeader) -> bool {
        let result = self.generate_digest(ch.carp_counter());
        let expected = MacResult::new(&ch.carp_md);

        result == expected
    }

    fn handle_remote_primary_down(&mut self) {
        trace!("Handling remote primary being down");

        if self.state == State::Backup {

            info!("Remote primary down. Switching to Primary state");
            self.state = State::Primary;
            self.up_callback();

            self.send_advert();

            self.delayed_arp += 1;

            self.reset_timers();
        }
    }

    fn check_primary_tmo(&mut self) {
        trace!("Checking timeouts");
        let now = SystemTime::now();

        //debug!("now = {:?}", now);
        //debug!("self.pd_tmo = {:?}", self.pd_tmo);

        if self.pd_tmo.is_some() && now > self.pd_tmo.unwrap() {
            self.handle_remote_primary_down();
        }


        // TODO simplify advertisement timeout logic
        // we can simplify this by subtracting now from the timeout
        // if within 1 millisecond, then we can advertise
        if self.ad_tmo.is_some() {
            if now > self.ad_tmo.unwrap() {
                self.send_advert();
            } else {
                // TODO handle failure here
                let duration = self.ad_tmo.unwrap().duration_since(now).unwrap();

                let diff_ms = (duration.as_secs() * 1000) + ((duration.subsec_nanos() / 1000) as u64);

                if diff_ms <= 1 {
                    self.send_advert();
                }
            }
        }
    }

    // here are all the places we send advertisements from:
    // * primary timeout - aka we have not heard from primary server in a long time
    // * advert timeout - aka we have not been able to send an advert due to some system issue
    // * the remote primary is down - this is triggered from a few areas
    fn send_advert(&mut self) {
        trace!("Sending advertisement");

        if self.counter.is_none() {
            // TODO fix this to use some rng
            let now = SystemTime::now();
            self.counter = Some(now.elapsed().unwrap().as_secs());
        }

        let hmac = self.generate_digest(self.counter.unwrap());

        let mut md: [u8; 20] = [0; 20];
        md.clone_from_slice(hmac.code());

        let mut ch = CarpHeader::default();
        ch.carp_set_version_type(CarpHeader::version(), CarpHeader::advertisement());
        ch.carp_vhid = self.config.vhid;
        ch.carp_advskew = self.config.advskew;
        ch.carp_authlen = CarpHeader::authlen();
        ch.carp_pad1 = 0;
        ch.carp_advbase = self.config.advbase;
        ch.carp_set_counter(self.counter.unwrap());
        ch.carp_md = md;

        let ch_bytes = ch.into_bytes().unwrap();
        ch.carp_set_cksum(IpHeader::checksum(ch_bytes.as_slice()));

        let total_length = mem::size_of::<IpHeader>() + mem::size_of::<CarpHeader>();

        let mut ip = IpHeader::default();
        ip.set_version(IpHeader::ipv4());
        ip.tos = ip::Tos::LowDelay as u8;
        ip.set_total_length(total_length as u16);
        ip.generate_id();
        ip.set_frag_off(ip::Flags::DontFragment as u16);
        ip.ttl = CarpHeader::ttl();
        ip.protocol = ip::Protocol::Carp as u8;
        ip.set_saddr(ipaddr_to_uint(self.config.srcip));
        ip.set_daddr(ipaddr_to_uint(self.config.mcast));

        let mut ch_bytes = ch.into_bytes().unwrap();
        let mut ip_bytes = ip.into_bytes().unwrap();
        ip_bytes.append(&mut ch_bytes);

        ip.set_cksum(IpHeader::checksum(ip_bytes.as_slice()));

        let dhost = if self.config.no_mcast {
            HwAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
        } else {
            HwAddr::from_multicast_ip(self.config.mcast)
        };

        let shost = HwAddr::new(0x00, 0x00, 0x5e, 0x00, 0x00, self.config.vhid);

        let eh = EtherHeader::new(&dhost, &shost, EtherType::Ip);
        let cp = CarpPacket::new(eh, ip, ch);
        let buf = cp.into_bytes().unwrap();

        write(self.capture.as_raw_fd(), &buf).unwrap();

        // TODO handle interrupt
        // TODO handle advert send errors
        if self.delayed_arp > 0 {
            self.delayed_arp -= 1;
        }

        if self.delayed_arp == 0 {
            if self.state == State::Primary {
                match self.config.srcip {
                    IpAddr::V4(srcip) => {
                        gratuitous_arp(self.interface.as_ref(), srcip).unwrap();
                    }
                    _ => {
                        panic!("IPv6 is not supported at this time");
                    }
                }
            }
            self.delayed_arp = -1;
        }

        if self.config.advbase != 255 || self.config.advskew != 255 {
            self.ad_tmo = Some(self.calc_next_timeout(1));
        }
    }

    fn tear_down(&self) {
        // TODO pcap_close
        // TODO pcap_freecode
    }
}

fn ipaddr_to_uint(ip: IpAddr) -> uint32_t {
    match ip {
        IpAddr::V4(ref ip) => {
            BigEndian::read_u32(&ip.octets())
        }
        _ => {
            panic!("IPv6 is not supported at this time");
        }
    }
}

/// Calculate the advertisement frequency
pub fn calc_adv_freq(advbase: u8, advskew: u8, ratio: u8) -> Duration {
    let secs = advbase as u64 * ratio as u64;
    let nanos = advskew as u64 * 1000000000 / 256000 as u64;

    Duration::new(secs, nanos as u32)
}

extern fn sighandler_exit(_: signal::SigNum) {
    unsafe {
        received_signal = 15;
    }
}

extern fn sighandler_usr(sig: signal::SigNum) {
    unsafe {
        match sig {
            signal::SIGUSR1 => {
                received_signal = 1;
            }
            signal::SIGUSR2 => {
                received_signal = 2;
            }
            _ => {
                panic!("Unknown signal received");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    //#[test]
    // fn test_bpf_rule() {
    //    let expect = "proto 112 and src host not 127.0.0.1";
    //    let ip = "127.0.0.1".parse().unwrap();

    //    assert_eq!(expect.to_owned(), bpf_rule(ip));
    // }

    #[test]
    fn test_calc_adv_freq() {
        let advbase = 1;
        let advskew = 1;
        let ratio = 3;

        let given = calc_adv_freq(advbase, advskew, ratio);

        let expected = Duration::new(3, 3906);

        assert_eq!(expected, given);
    }
}
