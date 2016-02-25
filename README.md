# Common Address Redundancy Protocol

carp-rs allows a couple of hosts to share common virtual IP addresses in order
to provide automatic failover. It is a portable userland implementation of the
secure and patent-free Common Address Redundancy Protocol (CARP, OpenBSD's
alternative to the patents-bloated VRRP).

Strong points of the CARP protocol are: very low overhead, cryptographically
signed messages, interoperability between different operating systems and no
need for any dedicated extra network link between redundant hosts.

This project has been forked from https://github.com/jedisct1/UCarp and
relicensed under the LGPL. The original BSD license has been moved to
the COPYING.OLD file.

[![Build Status](https://travis-ci.org/hjr3/carp-rs.svg?branch=master)](https://travis-ci.org/hjr3/carp-rs)

## Compilation

   * libpcap (http://www.tcpdump.org/) must be installed on your system, with
   development files (headers).
      * On Ubuntu: `apt-get install libtool autoconf gettext libpcap0.8 libpcap0.8-dev libpcap-dev sqlite3 libsqlite3-dev`

The Rust library has only been tested with Ubuntu precise 64.

## Examples

There is a basic example at `examples/basic.rs`. To run this example:

```
sudo RUST_LOG=carp=debug cargo run --example basic -- -i eth3 -s 10.0.2.40
```

Note: carp uses the pcap library which requires root for certain operations.

You should see some output similar to:

```
INFO:carp::carp: Using [eth3] as a network interface
INFO:carp::carp: Local advertised ethernet address is [08:00:27:f4:18:d5]
DEBUG:carp::carp: srcip = 10.0.2.40
DEBUG:carp::carp: mcast = 224.0.0.18
DEBUG:carp::carp: Next primary timeout in SystemTime { tv_sec: 1461942434, tv_nsec: 156471873 }
DEBUG:carp::carp: Interface switched to running
DEBUG:carp::carp: Next primary timeout in SystemTime { tv_sec: 1461942434, tv_nsec: 157813524 }
INFO:carp::carp: Remote primary down. Switching to Primary state
In my_up_callback()
DEBUG:carp::carp: Next primary timeout in SystemTime { tv_sec: 1461942435, tv_nsec: 177767553 }
```


## Primary Selection Process

When carp first runs, it starts as a backup and listens to the network
to determine if it should become the primary. If at any time more than
three times the node's advertising interval (defined as the advertising
base (seconds) plus a fudge factor, the advertising skew) passes without
hearing a peer's CARP advertisement, the node will transition itself to
being a primary.

Transitioning from backup to primary means:

   1. Calling the specified callback to assign the vip to the local system.
   2. Sending a gratuitous arp to the network to claim the vip.
   3. Continuously sending CARP advertisements to the network every interval.

Transitioning from primary to backup means:

   1. Calling the specified callback to remove the vip from the local system

To understand how carp works, it's important to note that the
advertisement interval is not only used as the time in between which
each CARP advertisement is sent by the primary, but also as a priority
mechanism where shorter (i.e. more frequent) is better. The interval
base and skew values are stored in the CARP advertisement and are used
by other nodes to make certain decisions.

By default, once a node becomes the primary, it will continue on
indefinitely as the primary. If you like/want/need this behavior, or don't
have a preferred primary, then choose the same interval on all hosts.
If for whatever reason you were to choose different intervals on the
hosts, then over time the one with the shortest interval would tend to
become the primary as machines are rebooted, after failures, etc.

Also of note is a conflict resolution algorithm that in case a primary
hears another, equal (in terms of its advertised interval) primary, the
one with the lower IP address will remain primary and the other will
immediately demote itself.  This is simply to eliminate flapping and
quickly determine who should remain primary.  This situation should not
happen very often but it can.

If you want a "preferred" primary to always be the primary (even if another
host is already the primary), add the preempt switch and
assign a shorter interval via the advertisement base and
skew.  This will cause the preferred node to ignore a
primary who is advertising a longer interval and promote itself to primary.
The old primary will quickly hear the preferred node advertising a shorter
interval and immediately demote itself.

In summary, a backup will become primary if:

   * no one else advertises for 3 times its own advertisement interval
   * you specified --preempt and it hears a primary with a longer interval

and a primary will become backup if:

   *  another primary advertises a shorter interval
   *  another primary advertises the same interval, and has a lower IP address

## Original Authors

The carp-rs project is based upon the hard work of many people on the original UCarp project.

   * Frank DENIS <j at pureftpd dot org>
   * Eric Evans <eevans at sym-link dot com> - maintainer of Debian packages.
   * David H <dmalloc at users dot sf dot net> - maintainer of Fink packages.
   * Richard Bellamy <richard dot bellamy at virgin dot net> - helped a lot with Solaris portability.
   * Russell Mosemann - neutral mode and bug fixes.
   * Dean Gaudet <dean at arctic dot org> - EINTR handling, log exec errors, --passfile.
   * Steve Kehlet and Marcus Goller - fixed the bogus code that issued poisonous
     gratuitous ARP, and improved the behavior when multiple nodes are started
     with the same interval and skew.  Steve helped a lot on many things.
   * Tim Niemeyer <niemeyer at kdo dot de> - Ensure remastering works when the
     preferred master has its network connection flap.
   * Serve Sireskin - --ignoreifstate option.
