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

class IPRange:
        def __init__(self, net):
		try:
	                self.net = net
        	        (self.ip, self.pattern) = net.split("/")
                	self.ip = self.dottedQuadToNum(self.ip)
	                if self.pattern == "" or self.pattern == "0":
        	                self.pattern = ~0
                	else:
                        	self.pattern = ~int("1" * (32 - int(self.pattern)), 2)
		except KeyboardInterrupt:
			raise

        def contains(self, tip):
		try:
	                return self.ip & self.pattern == self.dottedQuadToNum(tip) & self.pattern
		except KeyboardInterrupt:
			raise

        def dottedQuadToNum(self,ip):
		try:
	                l = map(int, ip.split('.'))
       		        addr = 0
               		for byte in l:
                       		addr = 256*addr+byte
	                return long(addr)
		except KeyboardInterrupt:
			raise
