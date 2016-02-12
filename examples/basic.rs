extern crate carp;

use std::str::FromStr;

fn main() {
    let mut config = carp::Config::new(
        FromStr::from_str("127.0.0.1").unwrap(),
        FromStr::from_str("127.0.0.1").unwrap(),
        "secret"
    );

    config.set_password("thisisatest");

    carp::on_up(my_up_callback);
    carp::on_down(my_down_callback);

    carp::carp(config).unwrap();
}

fn my_up_callback()
{
    println!("In my_up_callback()");
}

fn my_down_callback()
{
    println!("In my_down_callback()");
}
