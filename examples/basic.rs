extern crate carp;
extern crate getopts;

use std::str::FromStr;
use getopts::Options;
use std::env;

#[macro_use] extern crate log;
extern crate env_logger;

fn main() {
    env_logger::init().ok().expect("Failed to init logger");
    trace!("Starting basic example");

    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();
    opts.optopt("s", "", "The src ip", "SRCIP");
    opts.optopt("i", "", "The interface. Example: eth0", "INTERFACE");

    let matches = opts.parse(&args[1..]).unwrap();
    let srcip = matches.opt_str("s").unwrap();
    let if_name = matches.opt_str("i").unwrap();

    let mut config = carp::config::Config::new(
        FromStr::from_str("10.0.2.100").unwrap(),
        FromStr::from_str(&srcip).unwrap(),
        "secret"
    );

    //config.set_password("thisisatest");
    config.set_interface(if_name.as_ref());
    config.set_advbase(1);
    config.set_advskew(1);
    config.set_preempt(true);

    let capture = carp::carp::Carp::default_pcap(&if_name).unwrap();
    let mut carp = carp::carp::Carp::new(config, capture);
    carp.on_up(my_up_callback);
    carp.on_down(|| {
        println!("In my_down_callback()");
    });
    carp.run().unwrap();
}

fn my_up_callback()
{
    println!("In my_up_callback()");
}
