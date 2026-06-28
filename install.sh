#!/bin/bash
config=/etc/whoisd.yaml
whoisd_user=whoisd
whoisd_home=/var/whoisd

if [[ ! -f $config ]]; then
	cp config.yaml $config
fi

if ! grep -q $whoisd_user: /etc/passwd; then
	useradd -m -d $whoisd_home $whoisd_user
fi

if [[ ! -f /usr/sbin/whoisd ]]; then
	cp whoisd /usr/sbin/whoisd
fi
