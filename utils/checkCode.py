#!/usr/bin/python

"""
[Amun - low interaction honeypot]
Copyright (C) [2014]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""


import sys
import os
import re


def start(content):
	### api
	checksbin = {}
	checksbin['listen'] =              re.compile('\\xa4\\xad\\x2e\\xe9', re.S|re.I)
	checksbin['bind'] =                re.compile('\\xa4\\x1a\\x70\\xc7', re.S|re.I)
	checksbin['closeSocket'] =         re.compile('\\xe7\\x79\\xc6\\x79', re.S|re.I)
	checksbin['accept'] =              re.compile('\\xe5\\x49\\x86\\x49', re.S|re.I)
	checksbin['LoadLibraryA'] =        re.compile('\\x8e\\x4e\\x0e\\xec', re.S|re.I)
	checksbin['WSASocketA'] =          re.compile('\\xd9\\x09\\xf5\\xad', re.S|re.I)
	checksbin['WSAStartup'] =          re.compile('\\xCB\\xED\\xFC\\x3B', re.S|re.I)
	checksbin['ExitProcess'] =         re.compile('\\x7e\\xd8\\xe2\\x73', re.S|re.I)
	checksbin['CreateProcessA'] =      re.compile('\\x72\\xfe\\xb3\\x16', re.S|re.I)
	checksbin['WaitForSingleObject'] = re.compile('\\xad\\xd9\\x05\\xce', re.S|re.I)
	checksbin['system'] =              re.compile('\\x44\\x80\\xc2\\x77', re.S|re.I)
	checksbin['SetStdHandle'] =        re.compile('\\x1d\\x20\\xe8\\x77', re.S|re.I)
	checksbin['GetProcAddress'] =      re.compile('\\xcc\\x10\\xbe\\x77', re.S|re.I)
	checksbin['URLDownloadToFileA'] =  re.compile('\\x36\\x1a\\x2f\\x70', re.S|re.I)
	checksbin['connect'] =             re.compile('\\xec\\xf9\\xaa\\x60', re.S|re.I)
	checksbin['socket'] =              re.compile('\\x6e\\x0b\\x2f\\x49', re.S|re.I)
	checksbin['socket2'] = 		   re.compile('\\x83\\x53\\x83\\x00', re.S|re.I)
	checksbin['send'] =                re.compile('\\xa4\\x19\\x70\\xe9', re.S|re.I)
	checksbin['receive'] =             re.compile('\\xb6\\x19\\x18\\xe7', re.S|re.I)
	checksbin['WinExec'] =             re.compile('\\x98\\xfe\\x8a\\x0e', re.S|re.I)
	checksbin['WriteFile'] =           re.compile('\\x1f\\x79\\x0a\\e8', re.S|re.I)
	checksbin['Unknown (sign for correct decryption)'] =             re.compile('\\x68\\x33\\x32\\x00\\x00\\x68\\x77\\x73\\x32\\x5F', re.S|re.I)

	### plain
	checksplain = {}
	checksplain['possible windows cmd'] = re.compile('\\x63\\x6d\\x64', re.S|re.I)
	checksplain['http address'] =         re.compile('\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f', re.S|re.I)
	checksplain['ftp address'] =          re.compile('\\x66\\x74\\x70\\x3a\\x2f\\x2f', re.S|re.I)
	checksplain['tftp.exe'] =             re.compile('\\x74\\x66\\x74\\x70\\x2e\\x65\\x78\\x65', re.S|re.I)
	checksplain['kernel32'] =             re.compile('\\x6b\\x65\\x72\\x6e\\x65\\x6c\\x33\\x32',re.S|re.I)
	checksplain['WSAStartup'] =           re.compile('\\x57\\x53\\x41\\x53\\x74\\x61\\x72\\x74\\x75\\x70', re.S|re.I)
	checksplain['WSASocketA'] =           re.compile('\\x57\\x53\\x41\\x53\\x6f\\x63\\x6b\\x65\\x74\\x41', re.S|re.I)
	checksplain['GetProcAddress'] =       re.compile('\\x47\\x65\\x74\\x50\\x72\\x6f\\x63\\x41\\x64\\x64\\x72\\x65\\x73\\x73',re.S|re.I)
	checksplain['CreateProcessA'] =       re.compile('\\x43\\x72\\x65\\x61\\x74\\x65\\x50\\x72\\x6f\\x63\\x65\\x73\\x73\\x41', re.S|re.I)
	checksplain['linux shell (sh)'] =     re.compile('\\x68\\x73\\x2f\\x2f', re.S|re.I)
	checksplain['linux shell (bin)'] =    re.compile('\\x6e\\x69\\x62\\x2f', re.S|re.I)

	print
	print "\033[0;32m>> checking binary for known windows API calls\033[0m"
	print

	### plaintext commands
	print "\033[0;32m >> checking for plaintext commands or calls\033[0m"
	keys = checksplain.keys()
	for key in keys:
		match = checksplain[key].search(content)
		if match:
			print "\033[0;33m\t>> found plaintext: %s\033[0m" % (key)

	print
	### api calls / commands
	print "\033[0;32m >> checking for windows api calls\033[0m"
	keys = checksbin.keys()
	for key in keys:
		match = checksbin[key].search(content)
		if match:
			print "\033[0;31m\t>> found API: %s\033[0m" % (key)
	print

if __name__ == '__main__':
	filename = sys.argv[1]
	if os.path.exists(filename):
		fp = open(filename, 'r')
		content = "".join(fp.readlines())
		fp.close()
		start(content)
	else:
		print "\033[0;31m >> no such file\033[0m"
	print "\033[0;32m>> done\033[0m"
	print
