#!/bin/bash
# Create bridge with a private IP
ip link add br0 type bridge
ip addr add 192.168.0.2/24 dev br0
ip link set up dev br0

# Create network tap and add to bridge
ip tuntap add vm0 mode tap
ip link set vm0 up
ip link set vm0 master br0
