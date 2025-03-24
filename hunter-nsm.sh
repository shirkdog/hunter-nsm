#!/bin/sh
#
# Hunter NSM Platform
# Simple install script for Suricata/Zeek NSM with JSON logging on FreeBSD
#
# Copyright (c) 2025, Michael Shirk, Daemon Security Inc.
# All rights reserved.

# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this 
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, 
# this list of conditions and the following disclaimer in the documentation 
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Prereqs
# Minimal FreeBSD/HardenedBSD install with ports and the following requirements
# - Static IP defined on an interface (in rc.conf)
# - Ensure you are using the "latest" pkgs for FreeBSD in /etc/pkg/FreeBSD.pkg
# - freebsd-update fetch install OR hbsd-update
# (then reboot the system to make sure the system binaries are up to date)
#
# Install Versions using OS: FreeBSD/HardenedBSD 14 amd64
# NSM Tools
# - Suricata: 7.0.8
# - Zeek: 7.0.5
# Logging Tools
# - Grafana: 11.4.0
# - Grafana-Loki: 2.9.2
# Analysis Tools
# - termshark: 2.4.2
#
# Future Support
# tcpdump (short term PCAP on startup)
# gotm/stenographer/time-machine for PCAP (long term)
# silk or analysis of traffic flows (long term)
#
# ToDo:
# FIX Zeek does not startup cleanly on reboot
# Fully test logging

VERSION="0.5.1"

UID=$(id -u);

if [ $UID -ne "0" ];
then
	echo "Error: This script must run as root";
	exit 13;
fi

help_message() 
{
	echo "";
	echo "Hunter NSM Platform - Version $VERSION"
	echo
	echo "Simple install script for Suricata/Zeek with JSON logging on FreeBSD"
	echo
	echo "Usage hunterNSM.sh --install <suricata|zeek|both> --netmap <interface> --logging";
	echo
	echo "suricata = Install Suricata with JSON(eve) output."
	echo "zeek = Install Zeek with JSON output."
	echo "both = Install Suricata and Zeek with JSON output."
	echo "netmap = Configures this interface to use netmap (requires netmap support)."
	echo "logging = Sets up Grafana/Loki with Promtail providing a UI (3000/tcp)."
	echo "";
	exit 13;
}


# Process command line
while [ $# -ge 1 ]; do
	case $1 in
        	--install)
                    shift
                    INSTALL=$1
                ;;
                --netmap)
                    shift
                    NETMAP=$1
                ;;
                --logging)
                    shift
                    LOGGING=1
                ;;
                *)
                    echo "Invalid Option: $1"
                    exit 13
                ;;
	esac
        shift
done

if [ ! $INSTALL ]; 
then
	help_message;
fi

#check network configuration

FBSD_IPADDRESS=$(grep ifconfig_ /etc/rc.conf | grep -v _alias | grep -v DHCP | grep '="\ *inet' | awk '{print $2}')
FBSD_NETWORK=$(grep ifconfig_ /etc/rc.conf | grep -v _alias | grep -v DHCP | grep '="\ *inet' | awk '{print $4}'|tr -d '"')


if [ ! $FBSD_IPADDRESS ] || [ "$FBSD_IPADDRESS" == "inet" ];
then
	echo "Error: a static IP is required for setting up Hunter-NSM.";
	echo "Check that rc.conf has a static IP configured.";
	echo "";
	exit 13;
fi

FBSD_INTERFACE=$(grep ifconfig_ /etc/rc.conf | grep -v _alias | grep -v DHCP | grep '="\ *inet' | awk -F\_ '{print $2}' | awk -F\= '{print $1}')

if [ ! $FBSD_INTERFACE ];
then
	echo "Error: an interface has not been configured with a static IP which is required for Hunter-NSM";
	echo "Check that rc.conf has a static IP configured.";
	echo "";
	exit 13;
fi

if [ "$FBSD_INTERFACE" == "$NETMAP" ];
then
	echo "Error: the netmap interface cannot be the same as the interface used for regular networking.";
	echo "Select another interface and try again";
	echo "";
	exit 13;
fi


LOCALHOST=$(hostname)

# Update /etc/hosts
echo "$FBSD_IPADDRESS   $LOCALHOST    $LOCALHOST.localdomain" >> /etc/hosts


touch /root/log.install

# Bootstrap pkg
env ASSUME_ALWAYS_YES=YES pkg bootstrap
env ASSUME_ALWAYS_YES=YES pkg update -f

if [ "$INSTALL" == "zeek" ] || [ "$INSTALL" == "both" ];
then
	pkg install -y zeek
fi

echo "Zeek Pkg Installed" >> /root/log.install

# Configure Zeek Package Manager zkg
/usr/local/bin/zkg autoconfig

if [ "$INSTALL" == "zeek" ] || [ "$INSTALL" == "both" ];
then
	if [ $NETMAP ] && [ -e /dev/netmap ] && [ -e /usr/include/net/netmap_user.h ] && [ "$FBSD_INTERFACE" != "$NETMAP" ];
	then
		#install netmap plugin with zkg
		/usr/local/bin/zkg install zeek/zeek-netmap
	fi

	# setup directories for Zeek
	mkdir -p /nsm/zeek/logs
	mkdir -p /nsm/zeek/spool
	
        echo 'fdesc           /dev/fd         fdescfs rw      0       0' >> /etc/fstab
        sysrc zeek_enable="YES"

	# save defaults, but comment out everything
	sed -i '' -e 's/^/#/g' /usr/local/etc/node.cfg
	sed -i '' -e 's/^/#/g' /usr/local/etc/networks.cfg

	# updates for logging 
	sed -i '' -e 's/LogDir = \/usr\/local/LogDir = \/nsm\/zeek/g' /usr/local/etc/zeekctl.cfg
	sed -i '' -e 's/SpoolDir = \/usr\/local/SpoolDir = \/nsm\/zeek/g' /usr/local/etc/zeekctl.cfg
	sed -i '' -e 's/BrokerDBDir = \/usr\/local/BrokerDBDir = \/nsm\/zeek/g' /usr/local/etc/zeekctl.cfg
	sed -i '' -e 's/FileExtractDir = \/usr\/local/FileExtractDir = \/nsm\/zeek/g' /usr/local/etc/zeekctl.cfg

	# setting a default retention of 365 days
	sed -i '' -e 's/LogExpireInterval = .*$/LogExpireInterval = 365 days/g' /usr/local/etc/zeekctl.cfg
	sed -i '' -e 's/StatsLogExpireInterval = .*$/StatsLogExpireInterval = 365/g' /usr/local/etc/zeekctl.cfg

	if [ $NETMAP ] && [ -e /dev/netmap ] && [ -e /usr/include/net/netmap_user.h ] && [ "$FBSD_INTERFACE" != "$NETMAP" ];
	then
		#setup netmap interface
        	cat << EOF >> /usr/local/etc/node.cfg
[zeek]
type=standalone
host=$LOCALHOST
interface=netmap::$NETMAP
EOF
        echo "Netmap configured for Zeek" >> /root/log.install
	else
        	cat << EOF >> /usr/local/etc/node.cfg
[zeek]
type=standalone
host=$LOCALHOST
interface=$FBSD_INTERFACE
EOF
        echo "Standard Network configured for Zeek" >> /root/log.install
	fi

	# defaults to looking for Class C as your network, but this can be edited later
        if [ $FBSD_NETWORK = "0xffffff00" ] || [ $FBSD_NETWORK = "255.255.255.0" ];
        then
		FBSD_NETADDR=$(echo $FBSD_IPADDRESS |awk -F\. {'print $1"."$2"."$3".0"}')
                cat << EOF >> /usr/local/etc/networks.cfg
$FBSD_NETADDR/24          Home Network
EOF
        else
                cat << EOF >> /usr/local/etc/networks.cfg
$FBSD_IPADDRESS/32        Host IP
EOF
        fi

        cat << EOF >> /etc/crontab
# Zeek tasks
*/5  *       *       *       *       root    /usr/local/bin/zeekctl cron
EOF

	# service script was added to the zeek pkg thanks to Craig Leres

	# setup json output
        cat << EOF >> /usr/local/share/zeek/site/local.zeek
# json output
@load policy/tuning/json-logs.zeek
EOF

        # install the default configs

        /usr/local/bin/zeekctl install
        /usr/local/bin/zeekctl deploy
        /usr/local/bin/zeekctl start
        /usr/local/bin/zeekctl stop
        /usr/local/bin/zeekctl cleanup --all
        /usr/local/bin/zeekctl deploy

        echo "Zeek Installed" >> /root/log.install
fi

if [ "$INSTALL" == "suricata" ] || [ "$INSTALL" == "both" ];
then
	# install the port
	pkg install -y suricata

	# setup starting of Suricata
	sysrc suricata_enable="YES"
	sysrc suricata_interface="$FBSD_INTERFACE"

	# setup directories for Zeek
	mkdir -p /nsm/suricata

	# setup suricata to update signatures
	cat << EOF >> /etc/crontab;
# Cronjob for suricata rule updates, runs at 2:36 AM to update signatures and reload rules
36      2       *       *       *       root    suricata-update update
EOF
	
	# Prepare Suricata configuration updates
	sed -i '' -e 's/default-log-dir: \/var\/log/default-log-dir: \/nsm/g' /usr/local/etc/suricata/suricata.yaml
	sed -i '' -e 's/suricata-version: ""/suricata-version: "7.0.8-BSDNSM"/' /usr/local/etc/suricata/suricata.yaml

	if [ "$INSTALL" == "suricata" ];
	then
		# Without Zeek, Suricata will look at specific protocol data.
		# Leaving the defaults.

	elif [ "$INSTALL" == "both" ];
	then
		# Update suricata.yaml by cleaning it up to not log any protocol data, as Zeek will handle it
		sed -i '' '/- alert:/{p;s/.*/            payload: yes/;}' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/community-id: false/community-id: true/g' /usr/local/etc/suricata/suricata.yaml
  		sed -i '' -e 's/community-id-seed: 0/community-id-seed: 708/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- dns:/#- dns:/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- http:/#- http:/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e '/- tls/{n;N;d;}' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- tls:/#- tls:/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e '/- files:/{n;N;d;}' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- files:/#- files:/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- smtp:/#- smtp:/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- ftp/#- ftp/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- rdp/#- rdp/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- nfs/#- nfs/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- smb/#- smb/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- tftp/#- tftp/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- ike/#- ike/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- dcerpc/#- dcerpc/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- krb5/#- krb5/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- bittorrent-dht/#- bittorrent-dht/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- snmp/#- snmp/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- rfb/#- rfb/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- sip/#- sip/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- quic/#- quic/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e '/- dhcp/{n;N;d;}' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e '/- dhcp/{n;n;n;n;N;d;}' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- dhcp/#- dhcp/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- ssh/#- ssh/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- mqtt/#- mqtt/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- http2/#- http2/g' /usr/local/etc/suricata/suricata.yaml
		sed -i '' -e 's/- flow/#- flow/g' /usr/local/etc/suricata/suricata.yaml
		# This changes the 8 second stats to be every hour
		sed -i '' -e 's/interval: 8/interval: 3600/g' /usr/local/etc/suricata/suricata.yaml
	fi
	
	# Create the initial signature set
	suricata-update update
fi

echo "Suricata rc.conf and system config done" >> /root/log.install
	
# Use zero-copy bpf
echo "net.bpf.zerocopy_enable=1" >> /etc/sysctl.conf

# Setup Grafana, Loki and Alloy
if [ "$LOGGING" ];
then
	# Install the packages
	pkg install -y grafana grafana-loki alloy termshark
	
	# Enable services
	sysrc grafana_enable="YES"
	sysrc loki_enable="YES"
	sysrc promtail_enable="YES"

	# Grafana
	# As of this version, nothing is changed from the default, except setting up a self-signed cert for TLS
	openssl req -newkey rsa:2048 -noenc -keyout /usr/local/etc/grafana/grafana.key -out /usr/local/etc/grafana/grafana.csr -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com,DNS:*.example.com,IP:$FBSD_IPADDRESS"

	openssl x509 -signkey /usr/local/etc/grafana/grafana.key -in /usr/local/etc/grafana/grafana.csr -req -days 365 -out /usr/local/etc/grafana/grafana.crt
	
	chown grafana:grafana /usr/local/etc/grafana/grafana.crt /usr/local/etc/grafana/grafana.key
	chmod 400 /usr/local/etc/grafana/grafana.crt /usr/local/etc/grafana/grafana.key

	sed -i -e 's/\(# https certs & key file\)/\1\ncert_key=\/usr\/local\/etc\/grafana\/grafana.key\ncert_file=\/usr\/local\/etc\/grafana\/grafana.crt/g' /usr/local/etc/grafana/grafana.ini
	sed -i -e 's/;protocol = http/protocol = https/g' /usr/local/etc/grafana/grafana.ini
	
	
	# Loki
	# These configurations ensure that loki will continue to process large amount of messages
	# The changes are not on by default
	sed -i -e s'/\(grpc_listen_port: 9096\)/\1\n  grpc_server_max_send_msg_size: 104857600\n  grpc_server_max_recv_msg_size: 104857600\n  grpc_server_max_concurrent_streams: 1000/g' /usr/local/etc/loki.yaml

	# Promtail (Alloy in the future)
	# Most of the customization is here for bringing in Suricata/Zeek logs. 
	# Due this, we create a brand new file
	cat << EOF > /usr/local/etc/promtail.yaml;
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /var/db/promtail/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:

  - job_name: system
    static_configs:
    - targets:
        - localhost
      labels:
        job: varlogs
        __path__: /var/log/*log

  - job_name: suricata
    pipeline_stages:
    - json:
        expressions:
           timestamp: timestamp
           flow_id: flow_id
           event_type: event_type
           alert: 
    - json:
        expressions:
           signature:
        source: alert
    static_configs:
    - targets:
        - localhost
      labels:
        job: suricata
        type: alert
        __path__: /nsm/suricata/eve.json
  - job_name: zeek 
    pipeline_stages:
    - json:
        expressions:
           timestamp: timestamp
    static_configs:
    - targets:
        - localhost
      labels:
        job: zeek
        type: alert
        __path__: /nsm/zeek/logs/current/*
EOF
fi

echo
echo
echo "Setup is complete: type reboot to restart the system"
echo "When the system comes back up:"

if [ "$INSTALL" == "suricata" ] || [ "$INSTALL" == "both" ];
then 
	echo 
	echo "Suricata will startup and begin to log to /nsm/suricata/eve.json"
fi

if [ "$INSTALL" == "zeek" ] || [ "$INSTALL" == "both" ];
then
	echo 
	echo "Zeek will startup and begin to log to /nsm/zeek/spool"
fi
if [ "$LOGGING" ];
then
	echo
	echo "Grafana will be available at https://$FBSD_IPADDRESS:3000";
fi

cat << EOF > /etc/hunter-version;
# Hunter NSM Platform
#
# Copyright (c) 2025, Michael Shirk, Daemon Security Inc.
# All rights reserved.

# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this 
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, 
# this list of conditions and the following disclaimer in the documentation 
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
Hunter NSM Version $VERSION
Suricata: 7.0.8
Zeek: 7.0.5
Grafana: 11.4.0
Grafana-Loki: 2.9.2
EOF

exit 0;
