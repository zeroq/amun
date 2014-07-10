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

import time

class amun_logging:
	def __init__(self, classname, Logger=None):
		self.classname = classname
		self.logfile = "logs/%s.log" % (self.classname)
		self.Logger = Logger

	def log(self, message, tabs=0, type="normal", Log=False, display=True):
		try:
			if not Log and not display:
				return
			empty = ""
			for i in xrange(0, tabs):
				empty += " "
		
			if display:
				if type=="debug":
					### blue
					print "\033[0;34m%s.::[Amun - %s] %s ::.\033[0m" % (empty, self.classname, message)
				elif type=="warn":
					### yellow
					print "\033[0;33m%s.::[Amun - %s] %s ::.\033[0m" % (empty, self.classname, message)
				elif type=="info":
					### green
					print "\033[0;32m%s.::[Amun - %s] %s ::.\033[0m" % (empty, self.classname, message)
				elif type=="crit":
					### red
					print "\033[0;31m%s.::[Amun - %s] %s ::.\033[0m" % (empty, self.classname, message)
				elif type=="fade":
					### almost white
					print "\033[0;37m%s.::[Amun - %s] %s ::.\033[0m" % (empty, self.classname, message)
				elif type=="div":
					### lighter blue
					print "\033[0;36m%s.::[Amun - %s] %s ::.\033[0m" % (empty, self.classname, message)
				else:
					### black
					print "\033[0m%s.::[Amun - %s] %s ::.\033[0m" % (empty, self.classname, message)

			if Log and self.Logger!=None:
				logline = "[%s] %s" % (self.classname, message)
				self.Logger.info(logline)
			elif Log:
				logline = "[%s][%s] %s\n" % (time.strftime('%Y-%m-%d %H:%M:%S'), self.classname, message)
				try:
					fp = open(self.logfile, 'a+')
					fp.write(logline)
					fp.close()
				except IOError, e:
					print "\033[0;31m%s.::[Amun - %s] %s ::.\033[0m"  % (empty, self.classname, message)
		except KeyboardInterrupt:
			raise
