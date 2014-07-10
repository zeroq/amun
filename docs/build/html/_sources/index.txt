.. Amun documentation master file, created by
   sphinx-quickstart on Tue Jan 28 20:53:40 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Amun's documentation!
================================

Amun is a so-called low-interaction honeypot, aimed at capturing malware that
propagates by exploiting vulnerabilities in remotely accessible services. An 
example of such a malware is the infamous Conficker or the SQL Slammer worm. 
In order to catch such malicious software, Amun emulates a large
variety of vulnerable services, such as Microsoft SMB. Due to the fact that
all services are just emulated, the honeypot itself is never really under the 
control of the malware, but just pretends to be successfully exploited.

Contents:

.. toctree::
   :maxdepth: 2

   installation
   configuration


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

