"""
[Amun - low interaction honeypot]
Copyright (C) [2013]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import struct
import random
import check_shellcodes
import hashlib
import os
import amun_logging

import traceback
import StringIO
import sys

### Module for testing new vulnerability modules / port_watcher
### Simulate Solaris Telnet without password

class vuln:

	def __init__(self):
		try:
			self.vuln_name = "CHECK Vulnerability"
			self.stage = "CHECK_STAGE1"
			self.welcome_message = ""
			self.shellcode = []
		except KeyboardInterrupt:
			raise

        def write_hexdump(self, shellcode=None, extension=None):
                if not shellcode:
                        hash = hashlib.sha("".join(self.shellcode))
                else:
                        hash = hashlib.sha("".join(shellcode))
                if extension!=None:
                        filename = "hexdumps/%s-%s.bin" % (extension, hash.hexdigest())
                else:
                        filename = "hexdumps/%s.bin" % (hash.hexdigest())
                if not os.path.exists(filename):
                        fp = open(filename, 'a+')
                        if not shellcode:
                                fp.write("".join(self.shellcode))
                        else:
                                fp.write("".join(shellcode))
                        fp.close()
                        print ".::[Amun - CHECK] no match found, writing hexdump ::."
                return

	def print_message(self, data):
		print "\n"
		counter = 1
		for byte in data:
			if counter==16:
				ausg = hex(struct.unpack('B',byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split('x')
					ausg = "%sx0%s" % (list[0],list[1])
					print ausg
				else:
					print ausg
				counter = 0
			else:
				ausg = hex(struct.unpack('B',byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split('x')
					ausg = "%sx0%s" % (list[0],list[1])
					print ausg,
				else:
					print ausg,
			counter += 1
		print "\n>> Incoming Codesize: %s\n\n" % (len(data))

	def getVulnName(self):
		return self.vuln_name

	def getCurrentStage(self):
		return self.stage

	def getWelcomeMessage(self):
		return self.welcome_message

	def incoming(self, message, bytes, ip, vuLogger, random_reply, ownIP):
		try:
			self.log_obj = amun_logging.amun_logging("vuln_check", vuLogger)

			self.reply = random_reply[:62]
			#for i in range(0,510):
			#	try:
			#		self.reply.append( struct.pack("B", random.randint(0,255)) )
			#	except KeyboardInterrupt:
			#		raise

			resultSet = {}
			resultSet['vulnname'] = self.vuln_name
			resultSet['result'] = False
			resultSet['accept'] = False
			resultSet['shutdown'] = False
			resultSet['reply'] = "None"
			resultSet['stage'] = self.stage
			resultSet['shellcode'] = "None"
			resultSet["isFile"] = False

			
			#if bytes>0:
				#self.log_obj.log("CHECK Incoming: %s (Bytes: %s)" % (message, bytes), 6, "debug", True, False)
				#self.print_message(message)

			if self.stage=="CHECK_STAGE1":
				if message.rfind('USER')!=-1:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "login without authentication\n\nsolaris#"
					self.stage="CHECK_STAGE1"
					return resultSet
				elif bytes==3:
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "login without authentication\n\nsolaris#"
					self.stage="CHECK_STAGE1"
					return resultSet
				elif message.rfind('quit')!=-1 or message.rfind('exit')!=-1 or message.rfind('QUIT')!=-1 or message.rfind('EXIT')!=-1:
					resultSet['result'] = True
					resultSet['accept'] = False
					resultSet['reply'] = "command unknown\n\nsolaris#"
					self.stage="CHECK_STAGE1"
					return resultSet
				else:
					if bytes>0:
						self.log_obj.log("CHECK (%s) Incoming: %s (Bytes: %s)" % (ip, message, bytes), 6, "debug", True, True)
					resultSet['result'] = True
					resultSet['accept'] = True
					resultSet['reply'] = "command unknown\n\nsolaris#"
					self.stage="CHECK_STAGE1"
					return resultSet
			elif self.stage=="SHELLCODE":
				if bytes>0:
					print "CHECK Collecting Shellcode"
					resultSet['result'] = True
					resultSet['accept'] = True
					#resultSet['reply'] = "".join(self.reply)
					resultSet['reply'] = "None"
					self.shellcode.append(message)
					#resultSet['shellcode'] = "".join(self.shellcode)
					self.stage="SHELLCODE"
					return resultSet
				else:
					print "CHECK finished Shellcode"
					resultSet['result'] = False
					resultSet["accept"] = True
					resultSet['reply'] = "None"
					self.shellcode.append(message)
					resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
			else:
				resultSet["result"] = False
				resultSet["accept"] = False
				resultSet["reply"] = "None"
				return resultSet
			return resultSet
		except KeyboardInterrupt:
			raise
		except StandardError, e:
			print e
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
			sys.exit(1)
