use std::io::{self, Error, ErrorKind};
use std::mem::size_of;
use std::net::Ipv4Addr;
use libc::{socket, sendto, sockaddr, sockaddr_ll, AF_PACKET, SOCK_RAW, uint8_t,
           uint16_t, c_void, c_int};
use mac::{HwIf, HwAddr};

const ETH_ALEN: usize = 6;
const ETH_P_ARP: c_int = 0x0806;

/// Ethernet frame types
enum EtherType {
    Arp = 0x0806,
}

enum ArpOp {
    Request = 1,
    Reply = 2,
}

///
/// An Arp packet
///
/// Follows Ethernet Type II Frame structure
///
#[derive(Debug)]
#[repr(C, packed)]
struct ArpPacket {
    /// Destination hardware (MAC) address
    ether_dhost: [uint8_t; ETH_ALEN],

    /// Source hardware (MAC) address
    ether_shost: [uint8_t; ETH_ALEN],

    /// packet type ID field
    ether_type: uint16_t,

    /// Hardware type
    ///
    /// This field specifies the network protocol type. Example: Ethernet is 1.
    htype: uint16_t,

    /// Protocol type
    ///
    /// This field specifies the internetwork protocol for which the ARP request is intended.
    ptype: uint16_t,

    /// Hardware length
    ///
    /// Length (in octets) of a hardware address.
    hlen: uint8_t,

    /// Protocol length
    ///
    /// Length (in octets) of addresses used in upper layer protocol (ptype).
    plen: uint8_t,

    /// Operation
    ///
    /// Specifies the operation that the sender is performing: 1 for request, 2 for reply.
    operation: uint16_t,

    /// Sender hardware address
    ///
    /// Media address of the sender. In an ARP request this field is used to indicate the address
    /// of the host sending the request. In an ARP reply this field is used to indicate the address
    /// of the host that the request was looking for. (Not necessarily address of the host replying
    /// as in the case of virtual media.) Note that switches do not pay attention to this field,
    /// particularly in learning MAC addresses. The ARP PDU is encapsulated in Ethernet frame, and
    /// that is what Layer 2 devices examine.
    sender_hw_addr: [uint8_t; 6],

    /// Sender protocol address
    ///
    /// Internetwork address of the sender.
    sender_proto_addr: [uint8_t; 4],

    /// Target hardware address
    ///
    /// Media address of the intended receiver. In an ARP request this field is ignored. In an ARP
    /// reply this field is used to indicate the address of the host that originated the ARP
    /// request.
    target_hw_addr: [uint8_t; 6],

    /// Target protocol address
    ///
    /// Internetwork address of the intended receiver.
    target_proto_addr: [uint8_t; 4],

    _padding: [uint8_t; 18],
}

impl ArpPacket {
    fn new(sender_hw_addr: &HwAddr,
           sender_proto_addr: &Ipv4Addr,
           target_hw_addr: &HwAddr,
           target_proto_addr: &Ipv4Addr,
           operation: ArpOp,
           ether_type: EtherType)
           -> ArpPacket {

        ArpPacket {
            ether_dhost: target_hw_addr.octets(),
            ether_shost: sender_hw_addr.octets(),
            ether_type: (ether_type as u16).to_be(),
            htype: (1 as u16).to_be(), // ethernet
            ptype: (0x0800 as u16).to_be(), // IPv4
            hlen: 6, // ethernet
            plen: 4,
            operation: (operation as u16).to_be(),
            sender_hw_addr: sender_hw_addr.octets(),
            sender_proto_addr: sender_proto_addr.octets(),
            target_hw_addr: target_hw_addr.octets(),
            target_proto_addr: target_proto_addr.octets(),
            _padding: [0; 18],
        }
    }
}

/// Update ARP tables on other machines
///
/// See: https://wiki.wireshark.org/Gratuitous_ARP
pub fn gratuitous_arp(if_name: &str, ip: Ipv4Addr) -> io::Result<()> {

    let hw_if = HwIf::new(if_name);

    let mac = try!(hw_if.hwaddr());
    let idx = try!(hw_if.index());

    // TODO build safe interface
    let fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ARP.to_be()) };

    if fd == -1 {
        return Err(Error::last_os_error());
    }

    let sa = Box::new(sockaddr_ll {
        sll_family: AF_PACKET as u16,
        sll_protocol: (ETH_P_ARP as u16).to_be(),
        sll_ifindex: idx,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    });

    let broadcast_mac = HwAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

    let frame = Box::new(ArpPacket::new(&mac, &ip, &broadcast_mac, &ip, ArpOp::Request, EtherType::Arp));

    let f = &*frame as *const _ as *const c_void;
    let flen = size_of::<ArpPacket>();
    let s = &*sa as *const _ as *const sockaddr;
    let slen = size_of::<sockaddr_ll>() as u32;

    loop {
        // TODO build safe interface
        let rc = unsafe { sendto(fd, f, flen, 0, s, slen) };

        if rc >= 0 {
            break;
        }

        if rc < 0 {
            let err = Error::last_os_error();
            match err.kind() {
                ErrorKind::Interrupted => {}
                _ => {
                    println!("err = {}", err);
                    return Err(err);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_gratuitous_arp() {

        let device = "eth0";
        let ip = "10.0.2.15".parse().unwrap();

        assert!(gratuitous_arp(device, ip).is_ok());
    }
}
