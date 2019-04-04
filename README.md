## Amun

Amun was the first python-based low-interaction honeypot, following the concepts of Nepenthes but extending it with
more sophisticated emulation and easier maintenance.

## Requirements

* Pyhon >= 2.6 (no Python3 support yet)
* (optional) Python Psyco (available at http://psyco.sourceforge.net/)
* (optional) MySQLdb if submit-mysql or log-mysql is used
* (optional) psycopg2 if log-surfnet is used

## Installation

* Clone Git repository: `git clone https://github.com/zeroq/amun.git`
* Edit Amun main configuration file: `vim conf/amun.conf`
  * for example set the ip address for Amun to listen on (0.0.0.0 to listen on all)
  * enable or disbale vulnerability modules as needed
* start the Amun by issuing: `./amun_server`

## Tips and Tricks

In case you encounter problems with too many open files due to a lot of attackers hitting your honeypot at the same time, the following settings can be adjusted:

* To increase the maximum number of open files on Linux:
  * `echo "104854" > /proc/sys/fs/file-max`
  * `ulimit -Hn 104854`
  * `ulimit -n 104854`
* To increase the maximum number of open files on BSD:
  * `sysctl kern.maxfiles=104854`
  * `ulimit -Hn 104854`
  * `ulimit -n 104854`

## Logging

All logging information are stored in the "logs" subdirectory of your Amun installation. Following log files will be created:

* amun\_server.log
  * contains general information, errors, and alive messages of the amun server
* amun\_request\_handler.log
  * contains information about unknown exploits and not matched exploit stages
* analysis.log
  * contains information about manual shellcode analysis (performed via the -a option)
* download.log
  * contains information about all download modules (ftp, tftp, bindport, etc...)
* exploits.log
  * contains information about all exploits that where triggert
* shellcode_manager.log
  * contains information and errors of the shellcode manager
* submissions.log
  * contains information about unique downloads
* successfull_downloads.log
  * contains information about all downloaded malware
* unknown_downloads.log
  * contains information about unknown download methods
* vulnerabilities.log
  * contains information about certain vulnerability modules

## Parameters

Amun can be executed with `-a` parameter to analyse a given file for known shellcode instead of running the honeypot. 
