#!/usr/bin/python

"""
[Amun - low interaction honeypot]
Copyright (C) [2014]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

import md5
import os
import sys

def write_md5(file_data, file_data_length):
	hash = md5.new(file_data)
	fname = hash.hexdigest()
	filename = "unknown-%s.bin" % (fname)
	if not os.path.exists(filename):
		fp = open(filename, 'a+')
		fp.write(file_data)
		fp.close()
		print "successfull write: %s (size: %s)" % (filename, file_data_length)
	else:
		print "file exists"

def check_file(data, data_length):
	i = 0
	found = False
	if data[i]=='\x4d' and data[i+1]=='\x5a':
		return data,data_length
	while i <= data_length-4:
		if data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x90' and data[i+3]=='\x00' and data[i+4]=='\x03':
			found = True
			break
		elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x50' and data[i+3]=='\x00' and data[i+4]=='\x02':
			found = True
			break
		elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x4b' and data[i+3]=='\x45' and data[i+4]=='\x52':
			found = True
			break
		elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x66' and data[i+3]=='\x61' and data[i+4]=='\x72':
			found = True
			break
		elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x00' and data[i+3]=='\x00' and data[i+4]=='\x00':
			found = True
			break
		elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x90' and data[i+3]=='\xeb' and data[i+4]=='\x01':
			found = True
			break
		elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x4c' and data[i+3]=='\x6f' and data[i+4]=='\x61':
			found = True
			break
		i += 1
	if i>0 and found:
		print "cutting header (size: %i)" % (i)
		data = data[i:]
		data_length = len(data)
	return data,data_length


if __name__ == "__main__":
	filename = sys.argv[1]
	print "reading file %s ... " % (filename),
	fp = open(filename, 'r')
	content = "".join(fp.readlines())
	fp.close()
	print "done."
	content_len = len(content)
	print "checking file ... "
	(newfile, newlen) = check_file(content, content_len)
	write_md5(newfile, newlen)
