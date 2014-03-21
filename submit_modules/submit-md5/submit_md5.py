"""
[Amun - low interaction honeypot]
Copyright (C) [2014]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import os
import amun_logging

# 69 6c 6c 65  67 61 6c 20 54 46 54 50 20 6f 70 65 72 61 74 69  6f 6e 2e 00

class submit(object):
	__slots__ = ("submit_name", "log_obj")

	def __init__(self):
		try:
			self.submit_name = "Submit MD5"
			if not os.path.exists('malware/md5sum'):
				os.makedirs('malware/md5sum')
		except KeyboardInterrupt:
			raise

	def incoming(self, file_data, file_data_length, downMethod, attIP, victimIP, smLogger, md5hash, attackedPort, vulnName, downURL, fexists):
		try:
			self.log_obj = amun_logging.amun_logging("submit_md5", smLogger)

			### store to disc
			filename = "malware/md5sum/%s.bin" % (md5hash)
			if not fexists:
				fp = open(filename, 'a+b')
				fp.write(file_data)
				fp.close()
				self.log_obj.log("download (%s): %s (size: %i) - %s" % (downURL, md5hash, file_data_length, vulnName.replace(' Vulnerability','')), 12, "div", Log=True, display=True)
			else:
				self.log_obj.log("file exists", 12, "crit", Log=False, display=False)
		except KeyboardInterrupt:
			raise
