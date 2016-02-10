extern crate carp;

use std::str::FromStr;

fn main() {
    let mut config = carp::Config::new(
        FromStr::from_str("127.0.0.1").unwrap(),
        FromStr::from_str("127.0.0.1").unwrap(),
        "secret"
    );

    config.set_password("thisisatest");

    carp::carp(config);
}
