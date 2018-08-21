#!/bin/bash

IFACE=ens33
QDISC="cake"
#QDISC="fq_codel"
#QDISC="sfq"

off() {
	tc qdisc del dev $IFACE root 2>/dev/null || true
	rm -f /sys/fs/bpf/tc/globals/tc_users_mac \
		/sys/fs/bpf/tc/globals/tc_users_ip4 \
		/sys/fs/bpf/tc/globals/tc_users_ip6 \
		/sys/fs/bpf/tc/globals/tc_users_config
}

on() {
	tc qdisc add dev $IFACE root $QDISC
	major_id=`tc qdisc show dev $IFACE | cut -f3 -d " "`
	tc filter add dev $IFACE parent $major_id bpf direct-action obj tc-users-bpf.o section action
}

show() {
	tc qdisc show dev $IFACE
	tc filter show dev $IFACE
}

if [ "$1" == "off" ]; then
	off
elif [ "$1" == "on" ]; then
	on
elif [ "$1" == "show" ]; then
	:
else
	off
	on
fi

show
