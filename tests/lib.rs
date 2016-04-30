extern crate carp;

#[macro_use] extern crate log;
extern crate env_logger;

use std::env;
use std::str::FromStr;

/// Tests for the primary selection process
///
/// Note: integration tests have to be run with a privileged user capable of running pcap
/// functions.

fn setup() -> carp::carp::Carp {

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
    config.set_advbase(1);
    config.set_advskew(0);
    let capture = carp::carp::Carp::default_pcap(&interface).unwrap();
    let mut carp = carp::carp::Carp::new(config, capture);
    carp.setup().unwrap();

    carp
}

#[test]
fn test_role_is_backup_on_init() {
    let carp = setup();

    assert!(carp.is_backup());
}

#[test]
fn test_role_change_primary_on_timeout() {
    env_logger::init().ok().expect("Failed to init logger");

    let mut carp = setup();

    // running three times should trigger the use case
    carp.run_once().unwrap();
    carp.run_once().unwrap();
    carp.run_once().unwrap();

    assert!(carp.is_primary());
}

#[test]
fn test_role_change_backup_if_larger_advert_base() {
}

#[test]
fn test_role_change_primary_if_shorter_advert_base() {
}

#[test]
fn test_role_change_backup_if_equal_advbase_lower_ip() {
}

#[test]
fn test_role_change_primary_if_equal_advbase_lower_ip() {
}
