#!/bin/bash
config=/etc/whoisd.yaml
whoisd_user=whoisd
whoisd_home=/var/whoisd

if [[ ! -f $config ]]; then
	cp config.yaml $config
	chown whoisd: $config
fi

if ! grep -q $whoisd_user: /etc/passwd; then
	useradd -m -d $whoisd_home $whoisd_user
fi

if [[ ! -f /usr/sbin/whoisd ]]; then
	cp whoisd /usr/sbin/whoisd
fi
if [[ ! -f /usr/share/man/man8/whoisd.8 ]]; then
	install -m644 whoisd.8 /usr/share/man/man8/whoisd.8
fi

if [[ ! -f /etc/systemd/system/whoisd.service ]]; then
	cp whoisd.service /etc/systemd/system/whoisd.service
	systemctl enable whoisd
fi

echo -n "Do you want to start whoisd, now? (y/n): "
read ans
if [[ $ans == y ]]; then
	systemctl start whoisd
fi

