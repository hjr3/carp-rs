extern crate carp;

#[macro_use] extern crate log;
extern crate env_logger;

use std::str::FromStr;
use std::process::Command;

/// Tests for the primary selection process
///
/// Note: integration tests have to be run with a privileged user capable of running pcap
/// functions.

fn setup() -> carp::carp::Carp {

    let output = Command::new("/sbin/ifconfig eth0 | /bin/grep 'inet addr:' | /usr/bin/cut -d: -f2 | /usr/bin/awk '{ print $1}'")
        .output()
        .unwrap_or_else(|e| { panic!("failed to execute process: {}", e) });

    let ip = String::from_utf8_lossy(&output.stdout);
    println!("dynamic testing ip = {}", ip);

    let mut config = carp::config::Config::new(
        FromStr::from_str("10.0.2.100").unwrap(),
        FromStr::from_str(&ip).unwrap(),
        "secret"
    );
    config.set_interface("eth0");
    config.set_advbase(1);
    config.set_advskew(0);
    let capture = carp::carp::Carp::default_pcap("eth0").unwrap();
    let mut carp = carp::carp::Carp::new(config, capture);
    carp.setup().unwrap();

    carp
}

#[test]
#[ignore]
fn test_role_is_backup_on_init() {
    let carp = setup();

    assert!(carp.is_backup());
}

#[test]
#[ignore]
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
