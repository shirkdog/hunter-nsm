#!/bin/sh
#
# Hunter NSM Platform
# Simple install script for Snort/Bro IDS with JSON logging on FreeBSD
#
# Copyright (c) 2016, Michael Shirk, Daemon Security Inc.
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
# Minimal FreeBSD/HardenedBSD install with ports
# Static IP defined on an interface (in rc.conf)
# freebsd-update fetch install (then reboot the system to make sure the system binaries are up to date)
#
# Install Versions
# OS: FreeBSD/HardenedBSD 10/11 amd64
# Snort: 2.9.8.2
# DAQ: 2.0.6
# PulledPork: 0.7.2
# Bro: 2.4.1
# ids-tools: 0.4.4

VERSION="0.2.4"

UID=`id -u`;

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
	echo "Simple install script for Snort/Bro IDS with JSON logging on FreeBSD"
	echo
	echo "Usage hunterNSM.sh --install <snort|bro|both> --oinkcode <oinkcode> --netmap <interface>";
	echo
	echo "snort = Install Snort with JSON output."
	echo "bro = Install Bro with JSON output."
	echo "both = Install Snort and Bro with JSON output."
	echo "oinkcode = Uses this oinkcode to configure Snort rule updates."
	echo "netmap = Configures this interface to use netmap (requires netmap support)."
	echo "";
	echo "You need to supply a correct oinkcode for the";
	echo "snort or both install option.";
	echo "You can retrieve an oinkcode by registering at";
	echo "http://www.snort.org";
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
                --oinkcode)
                    shift
                    OINKCODE=$1
                ;;
                --netmap)
                    shift
                    NETMAP=$1
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
elif [ "$INSTALL" == "snort"  ] && [ ! $OINKCODE ];
then
	help_message;
elif [ "$INSTALL" == "both"  ] && [ ! $OINKCODE ];
then
	help_message;
fi

#check network configuration

FBSD_IPADDRESS=`grep ifconfig_ /etc/rc.conf | grep -v _alias | grep '="\ *inet' | awk '{print $2}'`
FBSD_NETWORK=`grep ifconfig_ /etc/rc.conf | grep -v _alias | grep '="\ *inet' | awk '{print $4}'|tr -d '"'`

if [ ! $FBSD_IPADDRESS ] || [ "$FBSD_IPADDRESS" == "inet" ];
then
	echo "Error: a static IP is required for setting up Snort.";
	echo "Check that rc.conf has a static IP configured.";
	echo "";
	exit 13;
fi

FBSD_INTERFACE=`grep ifconfig_ /etc/rc.conf | grep -v _alias | grep '="\ *inet' | awk -F\_ '{print $2}' | awk -F\= '{print $1}'`

if [ ! $FBSD_INTERFACE ];
then
	echo "Error: an interface has not been configured with a static IP which is required for Snort";
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


LOCALHOST=`hostname`

touch /root/log.install

# Install the necessary ports and packages
env ASSUME_ALWAYS_YES=YES pkg bootstrap
env ASSUME_ALWAYS_YES=YES pkg update -f

if [ "$INSTALL" == "bro" ] || [ "$INSTALL" == "both" ];
then
	pkg install -y flex bash cmake swig perl5 py27-sqlite3 bison automake git pcre libdnet libxml2 libxslt lwp \
	gmake p5-LWP-UserAgent-WithCache p5-Crypt-SSLeay p5-LWP-Protocol-https python py27-setuptools27 GeoIP geoipupdate \
	ca_root_nss

else
	pkg install -y flex bison automake git pcre libdnet libxml2 libxslt lwp p5-LWP-UserAgent-WithCache p5-Crypt-SSLeay \
	gmake p5-LWP-Protocol-https python py27-setuptools27 ca_root_nss
fi

echo "Packages Installed" >> /root/log.install

if [ "$INSTALL" == "bro" ] || [ "$INSTALL" == "both" ];
then
	cd /usr/src
	fetch https://www.bro.org/downloads/release/bro-2.4.1.tar.gz
	tar -xzf bro-2.4.1.tar.gz
	cd bro-2.4.1
	./configure --prefix=/opt/bro2 --logdir=/nsm/bro2/logs --spooldir=/nsm/bro2/spool
	gmake && gmake install
	#netmap will change the mode of the active NIC
	if [ $NETMAP ] && [ -e /dev/netmap ] && [ -e /usr/include/net/netmap_user.h ] && [ "$FBSD_INTERFACE" != "$NETMAP" ];
	then
		#build netmap plugin
		cd /usr/src/bro-2.4.1/aux/plugins/netmap
		./configure --bro-dist=/usr/src/bro-2.4.1/ --install-root=/opt/bro2/lib/bro/plugins --with-netmap=/usr/src
		gmake && gmake install
	fi

	mkdir -p /nsm/bro2/logs
	mkdir -p /nsm/bro2/spool
	
        echo 'fdesc           /dev/fd         fdescfs rw      0       0' >> /etc/fstab
        echo 'bro_enable="YES"' >> /etc/rc.conf.local
        # GeoIP Update
        /usr/local/bin/geoipupdate
	# save defaults, but comment out everything
	sed -i '' -e 's/^/#/g' /opt/bro2/etc/node.cfg
	sed -i '' -e 's/^/#/g' /opt/bro2/etc/networks.cfg
	if [ $NETMAP ] && [ -e /dev/netmap ] && [ -e /usr/include/net/netmap_user.h ] && [ "$FBSD_INTERFACE" != "$NETMAP" ];
	then
		#setup netmap interface
        	cat << EOF >> /opt/bro2/etc/node.cfg
[bro]
type=standalone
host=$LOCALHOST
interface=netmap::$NETMAP
EOF
        echo "Netmap configured for Bro" >> /root/log.install
	else
        	cat << EOF >> /opt/bro2/etc/node.cfg
[bro]
type=standalone
host=$LOCALHOST
interface=$FBSD_INTERFACE
EOF
        echo "Standard Network configured for Bro" >> /root/log.install
	fi

        if [ $FBSD_NETWORK = "0xffffff00" ] || [ $FBSD_NETWORK = "255.255.255.0" ];
        then
                FBSD_NETADDR=`echo $FBSD_IPADDRESS |awk -F\. {'print $1"."$2"."$3".0"}'`
                cat << EOF >> /opt/bro2/etc/networks.cfg
$FBSD_NETADDR/24          Home Network
EOF
        else
                cat << EOF >> /opt/bro2/etc/networks.cfg
$FBSD_IPADDRESS/32        Host IP
EOF
        fi

        cat << EOF >> /etc/crontab
# Bro tasks
*/5  *       *       *       *       root    /opt/bro2/bin/broctl cron
EOF
        cat << EOF > /usr/local/etc/rc.d/bro
#!/bin/sh
#
# PROVIDE: bro
# REQUIRE: NETWORKING
# REQUIRE: LOGIN
# KEYWORD: shutdown
#

# bro config
PATH=/opt/bro2/bin:/usr/local/bro/bin:/usr/local/bin:$PATH

# control methods
bro_start() {
    /opt/bro2/bin/broctl deploy
}

bro_stop() {
    /opt/bro2/bin/broctl stop
}

bro_status() {
    /opt/bro2/bin/broctl status
}

bro_restart() {
    bro_stop
    bro_start
}

. /etc/rc.subr

name="bro"
rcvar=\`set_rcvar\`

load_rc_config \$name

start_cmd="bro_start"
stop_cmd="bro_stop"
status_cmd="bro_status"
restart_cmd="bro_restart"

bro_enable=\${bro_enable-"NO"}

run_rc_command "\$1"
EOF
        chmod 500 /usr/local/etc/rc.d/bro

	# setup json output
        cat << EOF >> /opt/bro2/share/bro/site/local.bro
# json output
@load policy/tuning/json-logs.bro
EOF

        # install the default configs
	# some of this is repeated as the necessary
	# directories do not get created
        /opt/bro2/bin/broctl install
        /opt/bro2/bin/broctl deploy
        /opt/bro2/bin/broctl start

        echo "Bro Installed" >> /root/log.install
fi

if [ "$INSTALL" == "snort" ] || [ "$INSTALL" == "both" ];
then

# Setup directories for Pulledpork and Snort
mkdir -p /usr/local/etc/snort
mkdir -p /usr/local/lib/snort_dynamicrules/
mkdir -p /usr/local/etc/snort/rules/iplists
mkdir -p /usr/local/etc/snort/so_rules
mkdir -p /usr/local/etc/snort/preproc_rules
mkdir -p /var/log/snort
mkdir -p /usr/src/snort
mkdir -p /nsm/snort
touch /usr/local/etc/snort/rules/local.rules
touch /usr/local/etc/snort/rules/white_list.rules
touch /usr/local/etc/snort/rules/black_list.rules

# DAQ/Snort install
mkdir -p /usr/src/snort
cd /usr/src/snort
fetch https://snort.org/downloads/snort/snort-2.9.8.2.tar.gz -o snort.tar.gz
fetch https://snort.org/downloads/snort/daq-2.0.6.tar.gz -o daq.tar.gz
tar -xvf snort.tar.gz 
tar -xzf daq.tar.gz
cd daq-2.0.6
./configure
make
make install

echo "DAQ Installed" >> /root/log.install

cd /usr/src/snort/snort-2.9.8.2
./configure --enable-sourcefire
make
make install

# need gen-msg.map from the build
cp /usr/src/snort/snort-2.9.8.2/etc/gen-msg.map /usr/local/etc/snort

echo "Snort Installed" >> /root/log.install

# Use Pulledpork from github
cd /usr/src/snort
git clone https://github.com/shirkdog/pulledpork.git
cd /usr/src/snort/pulledpork
sed -i '' -e 's/\/usr\/bin\/perl/\/usr\/local\/bin\/perl/' /usr/src/snort/pulledpork/pulledpork.pl 
sed -i '' -e 's/|<oinkcode>/|'"$OINKCODE"'/g' /usr/src/snort/pulledpork/etc/pulledpork.conf
sed -i '' -e "s/rule_url=https:\/\/rules.emergingthreats.net\/|/#/g" /usr/src/snort/pulledpork/etc/pulledpork.conf
sed -i '' -e "s/black_list=.*$/black_list=\/usr\/local\/etc\/snort\/rules\/black_list.rules/g" /usr/src/snort/pulledpork/etc/pulledpork.conf
sed -i '' -e "s/distro=FreeBSD-.*$/distro=FreeBSD-10-0/g" /usr/src/snort/pulledpork/etc/pulledpork.conf
chmod 500 /usr/src/snort/pulledpork/pulledpork.pl
/usr/src/snort/pulledpork/pulledpork.pl -c /usr/src/snort/pulledpork/etc/pulledpork.conf -w
rehash

cat << EOF >> /etc/crontab;
# Cronjob for pulled-pork, runs at 2:36 AM to update signatures, and reload rules
36      2       *       *       *       root    /usr/local/bin/snortUpdate.sh
EOF

cat << EOF >> /usr/local/bin/snortUpdate.sh;
#!/bin/sh
# Run pulledpork
/usr/src/snort/pulledpork/pulledpork.pl -c /usr/src/snort/pulledpork/etc/pulledpork.conf -w 
# Restart snort with the new rules
/usr/local/etc/rc.d/snort restart
EOF
chmod 500 /usr/local/bin/snortUpdate.sh

echo "PulledPork Installed" >> /root/log.install

# new snort.conf required from ruleset before continuing.
cd /tmp
tar -xzf snortrules-snapshot-*.tar.gz
cp /tmp/etc/*.conf /usr/local/etc/snort
cp /tmp/etc/*.config /usr/local/etc/snort
cp /tmp/etc/*.map /usr/local/etc/snort

sed -i '' "s/ipvar HOME_NET any/ipvar HOME_NET \[${FBSD_IPADDRESS}\/32\]/" /usr/local/etc/snort/snort.conf
sed -i '' 's/ipvar EXTERNAL_NET any/ipvar EXTERNAL_NET \[!\$HOME_NET\]/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var RULE_PATH \.\.\/rules/var RULE_PATH rules/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var WHITE_LIST_PATH \.\.\/rules/var WHITE_LIST_PATH rules/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var BLACK_LIST_PATH \.\.\/rules/var BLACK_LIST_PATH rules/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var SO_RULE_PATH \.\.\/so_rules/var SO_RULE_PATH so_rules/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var PREPROC_RULE_PATH \.\.\/preproc_rules/var PREPROC_RULE_PATH preproc_rules/' /usr/local/etc/snort/snort.conf
sed -i '' '/^include \$RULE_PATH\/.*.rules$/d' /usr/local/etc/snort/snort.conf
echo "output unified2: filename snortunified2.log, limit 128" >> /usr/local/etc/snort/snort.conf
echo "include \$RULE_PATH/local.rules" >> /usr/local/etc/snort/snort.conf
echo "include \$RULE_PATH/snort.rules" >> /usr/local/etc/snort/snort.conf
grep '^[^#]' /usr/local/etc/snort/snort.conf > /usr/local/etc/snort/temp.conf
mv -f /usr/local/etc/snort/temp.conf /usr/local/etc/snort/snort.conf

rehash
echo "Snort Installed" >> /root/log.install

# u2json issue with version 0.5, so 0.4.4 is used
cd /usr/src/snort
fetch --no-verify-peer https://pypi.python.org/packages/source/i/idstools/idstools-0.4.4.tar.gz
tar -xzf idstools-0.4.4.tar.gz
cd idstools-0.4.4
python setup.py install

cat << EOF > /usr/local/bin/du2json;
#!/bin/sh
/usr/local/bin/idstools-u2json -C /usr/local/etc/snort/classification.config \
    -S /usr/local/etc/snort/sid-msg.map \
    -G /usr/local/etc/snort/gen-msg.map \
    --directory /var/log/snort \
    --prefix snortunified2.log \
    --follow \
    --bookmark \
    --delete \
    --output /nsm/snort/alerts.json 
EOF
chmod 500 /usr/local/bin/du2json

cat << EOF > /usr/local/bin/snortStartup.sh
#!/bin/sh
#
# Startup anything outside of Snort
/usr/local/bin/du2json &
EOF
chmod 500 /usr/local/bin/snortStartup.sh

#Add snortStartup.sh to /etc/rc.local
echo "/usr/local/bin/snortStartup.sh" >> /etc/rc.local

echo "du2json installed" >> /root/log.install

cat << EOF > /usr/local/etc/rc.d/snort;
#!/bin/sh

# \$FreeBSD\$
#
# PROVIDE: snort
# REQUIRE: NETWORK
# KEYWORD: shutdown
#

. /etc/rc.subr

name="snort"
rcvar=\${name}_enable

command=/usr/local/bin/\${name}
pidfile=/var/run/\${name}_${FBSD_INTERFACE}.pid

load_rc_config \$name

: \${snort_enable="NO"}
: \${snort_config="/usr/local/etc/snort/snort.conf"}

command_args="--pid-path \$pidfile -c \$snort_config -D not arp"

run_rc_command "\$1"

EOF
chmod 500 /usr/local/etc/rc.d/snort;


echo 'snort_enable="YES"' >> /etc/rc.conf.local
echo "Snort rc.conf.local and system config done" >> /root/log.install
fi

# Update /etc/hosts
echo "$FBSD_IPADDRESS   $LOCALHOST    $LOCALHOST.localdomain" >> /etc/hosts

echo
echo
echo "Setup is complete: type reboot to restart the system"
echo "When the system comes back up:"

if [ "$INSTALL" == "snort" ] || [ "$INSTALL" == "both" ];
then 
	echo 
	echo "Snort will startup and begin to log to /nsm/snort/alerts.json"
fi

if [ "$INSTALL" == "bro" ] || [ "$INSTALL" == "both" ];
then
	echo 
	echo "Bro will startup and begin to log to /nsm/bro2/spool"
fi
echo

cat << EOF > /etc/hunter-version;
# Hunter NSM Platform
#
# Copyright (c) 2016, Michael Shirk, Daemon Security Inc.
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
Snort: 2.9.8.2
DAQ: 2.0.6
PulledPork: 0.7.2
Bro: 2.4.1
ids-tools: 0.4.4
EOF

exit 0;
