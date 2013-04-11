#!/usr/bin/python

"""
[Amun - low interaction honeypot]
Copyright (C) [2008]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

import pefile
import os
import sys

if __name__ == '__main__':
	single_file = False
	if len(sys.argv)==1:
		list = os.listdir("../malware/md5sum/")
		single_file = False
	else:
		single_file = True
		list = ['none']
	for file in list:
		if single_file:
			filename = sys.argv[1]
			file = sys.argv[1]
		else:
			filename = "../malware/md5sum/%s" % (file)
		try:
			pe = pefile.PE(filename, fast_load=False)
			#print pe.dump_info()
			#print dir(pe)
			print "Warnings for: %s" % (file)
			warns = pe.show_warnings()
			print warns
		except pefile.PEFormatError, e:
			print e
		print "-------------------------------------------------------"
