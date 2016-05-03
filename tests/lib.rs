extern crate carp;

#[macro_use] extern crate log;
extern crate env_logger;

use std::env;
use std::str::FromStr;

use carp::ip::{Ipv4Header, Ipv4HeaderBuilder, Flags, Tos, Protocol};
use carp::mac::HwAddr;
use carp::ether::{EtherHeader, EtherType};
use carp::ip_carp::CarpHeader;
use carp::advert::CarpPacket;
use carp::carp::Carp;

/// Tests for the primary selection process
///
/// Note: integration tests have to be run with a privileged user capable of running pcap
/// functions.

fn setup(advbase: u8) -> Carp {

    let ip = env::var("TEST_SRCIP").unwrap_or("10.0.2.40".to_string());
    debug!("srcip = {}", ip);

    let interface = env::var("TEST_INF").unwrap_or("eth3".to_string());
    debug!("interface = {}", interface);

    let mut config = carp::config::Config::new(
        FromStr::from_str("10.0.2.100").unwrap(),
        FromStr::from_str(&ip).unwrap(),
        "secret"
    );
    config.set_interface(interface.as_ref());
    config.set_advbase(advbase);
    config.set_advskew(0);
    let capture = carp::carp::Carp::default_pcap(&interface).unwrap();
    let mut carp = carp::carp::Carp::new(config, capture);
    carp.setup().unwrap();

    carp
}

fn setup_ether_header() -> EtherHeader {
    let shost = HwAddr::new(0x08, 0x00, 0x27, 0xc0, 0xee, 0xbe);
    let dhost = HwAddr::new(0x08, 0x00, 0x27, 0xf4, 0x18, 0xd5);
    EtherHeader::new(&dhost, &shost, EtherType::Ip)
}

fn setup_ipv4_header(source: &str) -> Ipv4Header {
    Ipv4HeaderBuilder::new()
        .tos(Tos::low_delay())
        .data_length(20)
        .random_id()
        .flags(Flags::dont_fragment())
        .ttl(255)
        .protocol(Protocol::Carp)
        .source_address(FromStr::from_str(source).unwrap())
        .destination_address(FromStr::from_str("127.0.0.1").unwrap())
        .build()
}

fn setup_carp_header(advbase: u8) -> CarpHeader {
    let mut ch = CarpHeader::default();
    ch.carp_advbase = advbase;
    ch
}

fn force_primary(carp: &mut Carp) {
    loop {
        carp.run_once().unwrap();

        if carp.is_primary() {
            break;
        }
    }
}

#[test]
fn test_role_is_backup_on_init() {
    let carp = setup(1);

    assert!(carp.is_backup());
}

#[test]
fn test_role_change_primary_on_timeout() {
    let mut carp = setup(1);

    force_primary(&mut carp);

    assert!(carp.is_primary());
}

#[test]
fn test_role_change_backup_if_larger_advert_base() {
    env_logger::init().ok().expect("Failed to init logger");
    let cp = CarpPacket::new(
        setup_ether_header(),
        setup_ipv4_header("10.0.0.2"),
        setup_carp_header(1)
    );

    let mut carp = setup(2);

    force_primary(&mut carp);

    carp.check_role_change(&cp);

    assert!(carp.is_backup());
}

#[test]
fn test_role_change_primary_if_shorter_advert_base() {
    let cp = CarpPacket::new(
        setup_ether_header(),
        setup_ipv4_header("10.0.0.2"),
        setup_carp_header(2)
    );

    let mut carp = setup(1);

    carp.check_role_change(&cp);

    assert!(carp.is_primary());
}

#[test]
fn test_role_change_backup_if_equal_advbase_lower_ip() {
    let cp = CarpPacket::new(
        setup_ether_header(),
        setup_ipv4_header("10.244.244.244"),
        setup_carp_header(1)
    );

    let mut carp = setup(1);

    force_primary(&mut carp);

    assert!(carp.is_primary());

    carp.check_role_change(&cp);

    assert!(carp.is_backup());
}

#[test]
fn test_role_stay_primary_if_equal_advbase_higher_ip() {
    let cp = CarpPacket::new(
        setup_ether_header(),
        setup_ipv4_header("10.0.0.2"),
        setup_carp_header(1)
    );

    let mut carp = setup(1);

    force_primary(&mut carp);

    assert!(carp.is_primary());

    carp.check_role_change(&cp);

    assert!(carp.is_primary());
}
