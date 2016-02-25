#!/bin/bash

set -e

sudo apt-get update
sudo apt-get install -y libtool autoconf gettext libpcap0.8 libpcap0.8-dev libpcap-dev sqlite3 libsqlite3-dev gdb git
curl -sSf https://static.rust-lang.org/rustup.sh | sh -s -- --channel=nightly

cd /home/vagrant/
git clone https://github.com/jedisct1/UCarp
cd UCarp
patch src/ucarp.c /vagrant/ucarp.c.patch
libtoolize
gettextize -f
cp po/Makevars.template po/Makevars
autoreconf -i
./configure && make
