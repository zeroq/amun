
Configuration
=============

The core configuration for Amun is done in the file amun.conf in the conf directory.

Operating System Configuration
------------------------------

In case you encounter problems with too many open files. The following configuration changes might solve the problem:

Linux:

  .. code: python
    
    - echo "104854" > /proc/sys/fs/file-max

Amun Honeypot Configuration
---------------------------
