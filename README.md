# ndefence - internal security log parser and firewall, written in golang 

A humble golang application to generate daily data from log file entries
from common servers, such as nginx or apache. In addition, it will try
to refine and potentially block IPs that attempt too many connections.

Specifically it takes IPv4 address data from the access.log files and
conducts the following:

* hostname lookup
* whois lookup
* records server requests of HTML code 302

This program checks for high counts of anonymous connections, and it will
add them to firewall those addresses if they appear to come from unusual
sources.

Feel free to fork it and use it for other projects if you find it
useful.


# Requirements

The following is needed in order for this to function as intended:

* Linux kernel 4.0+
* cron
* golang 1.6+
* host
* apache / nginx
* whois

Older kernels could still give some kind of result, but I *think* most of
the newer versions of golang require newer kernels. Feel free to email me if
this is incorrect.


# Installation

0) Build this program as you would a simple golang module.

    make

1) Install this program on your server.

    make install

2) Adjust the cron job to set the choice of server (default is nginx).

    vim /etc/cron.d/ndefence

Alternatively, if you are running Arch Linux w/ systemd, you can use the
included ndefence.service instead. However, the cron job is recommended
since it has greater compatibility with more distros.

# Uninstallation

1) To remove this program from your system.

    make uninstall

2) Consider cleaning up any remaining logs, if they are no longer needed.

    rm /var/www/html/data/blocked.log
    rm /var/www/html/data/ip.log
    rm /var/www/html/data/redirect.log
    rm /var/www/html/data/whois.log


# TODOs

* Hostname check on the IP addresses as soon as they access the server
* Create a systemd service that works better with alternative distros
* Consider adding the ability to block IPv6 addresses as well


# Author

Written by Robert Bisewski at Ibis Cybernetics. For more information, contact:

* Website -> www.ibiscybernetics.com

* Email -> contact@ibiscybernetics.com
