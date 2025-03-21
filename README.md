Hunter NSM
==========

Simple install script for Suricata/Zeek NSM with JSON logging on FreeBSD

Copyright (C) 2016-2025 Michael Shirk, Daemon Security Inc.

Hunter NSM is a modular platform for deploying network sensors. Instead of adding additional
security vulnerabilities with the addition of numerous tools, Hunter provides a minimalist approach to achieving
full network monitoring with Zeek NSM and Suricata in IDS mode.

## Features and Capabilities

 * Automates the installation of Suricata or Zeek (or both paired together) on a FreeBSD server
 * Configures JSON output to work with any type of logging tool.
 * Includes Grafana/Loki for a simple UI to view alerts.
 * Configures startup scripts to work with FreeBSD

## Key features of Hunter NSM

All logging is configured to output to the /nsm directory (/nsm/zeek for Zeek, /nsm/suricata for Suricata). Before running 
the script, ensure that you have a enough disk space to log the security data.

Custom configs for Suricata:

`/etc/crontab` Setup for Suricata rule updates

Custom configs for Zeek:

`/etc/crontab` Setup for the zeekctl cronjob every 5 minutes

`/usr/local/share/zeek/site/local.site` Updated the default site policy for JSON output

## Future Plans
 * tcpdump (Planning to add tcpdump to start with `/etc/rc.local` and to log to /nsm/pcap)
 * gotm/stenographer/time-machine for PCAP (Whichever of these works)
 * silk or analysis of traffic flows (long term)
