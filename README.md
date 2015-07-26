Hunter NSM
==========

Simple install script for Snort/Bro IDS with JSON logging on FreeBSD

Copyright (C) 2015 Michael Shirk, Daemon Security Inc.

Hunter NSM is a modular platform for deploying network sensors. Instead of adding additional
security vulnerabilities with the addition numerous tools, Hunter provides a minimalist approach to achieving
full network monitoring with Bro NSM and Snort IDS.

## Features and Capabilities

 * Automates the installation of Snort or Bro on a FreeBSD server
 * Configures JSON output using ids-tools and Bro native JSON output to work with any type of logging tool.
 * Uses PulledPork to automate signature updates
 * Configures startup scripts to work with FreeBSD

## Key features of Hunter NSM

All logging is configured to output to the /nsm directory (/nsm/bro2 for Bro, /nsm/snort for Snort). Before running 
the script, ensure that you have a enough disk space to log the security data.

Custom configs for Snort:
`/usr/local/bin/snortUpdate.sh` This script runs PulledPork and restarts Snort for rule updates
`/usr/local/bin/snortStartup.sh` This script starts u2json by way of `/etc/rc.local` and reads the snort output from /var/log/snort and writes out JSON events.
`/usr/local/bin/du2json` This script that runs u2json.

Custom configs for Bro
`/opt/bro2/share/bro/site/local.bro` Updated the default site policy for JSON output

