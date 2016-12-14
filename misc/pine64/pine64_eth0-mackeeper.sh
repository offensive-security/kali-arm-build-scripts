#!/bin/sh

set -e

ENV="/boot/uEnv.txt"
ETH="eth0"

if [ ! -w "$ENV" -o ! -e /sys/class/net/$ETH/address ]; then
	exit 0
fi

if grep -q "ethaddr=" "$ENV"; then
	exit 0
fi

MAC=$(cat /sys/class/net/$ETH/address)
echo $MAC

echo "ethaddr=$MAC" >> "$ENV"
