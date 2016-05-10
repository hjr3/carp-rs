#!/bin/bash

DIR=/home/vagrant/UCarp

sudo $DIR/src/ucarp --interface=eth1 --srcip=10.0.2.30 --vhid=1 \
      --pass=secret --addr=10.0.2.100 --advbase=3 \
      --upscript=$DIR/examples/linux/vip-up.sh \
      --downscript=$DIR/examples/linux/vip-down.sh
