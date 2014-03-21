
Installation
=================

Installation of Amun is pretty easy and does not require compilation or complex configuration procedures.

Requirements
------------

Amun is primarily intended to run on Linux systems. It was programmed on Debian, but should run on any Linux platform that has Python support.
Amun requires Python (>=2.6) to run. It works fine with Python 2.7, but it is not intended to run with Python 3.

* Linux (e.g. Debian)
* Python 2.7

Optional Components
-------------------

* Python Psyco (available at http://psyco.sourceforge.net/)
    + Psyco is a JIT (Just-In-Time compiler) to speed up the execution of Python code
* Python MySQLdb
    + In order to use the MySQL logging module
* Python Psycopg2
    + In order ot use Surfnet or PostgreSQL logging module
