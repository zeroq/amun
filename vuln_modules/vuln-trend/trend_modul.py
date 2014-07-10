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

import traceback
import StringIO
import sys
import struct
import amun_logging
import random
import trend_shellcodes

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "TREND_MICRO Vulnerability"
			self.stage = "TREND_STAGE1"
			self.welcome_message = ""
			self.shellcode = []
		except KeyboardInterrupt:
			raise

	def print_message(self, data):
		print "\n"
		counter = 1
		for byte in data:
			if counter==16:
				ausg = hex(struct.unpack("B",byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split("x")
					ausg = "%sx0%s" % (list[0],list[1])
					print ausg
				else:
					print ausg
				counter = 0
			else:
				ausg = hex(struct.unpack("B",byte)[0])
				if len(ausg) == 3:
					list = str(ausg).split("x")
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
			### logging object
			self.log_obj = amun_logging.amun_logging("vuln_trend_micro", vuLogger)
			### construct standard reply
			self.reply = []
			for i in range(0,64):
				try:
					self.reply.append("\x00")
				except KeyboardInterrupt:
					raise

			### prepare default resultSet
			resultSet = {}
			resultSet["vulnname"] = self.vuln_name
			resultSet["accept"] = False
			resultSet["result"] = False
			resultSet["shutdown"] = False
			resultSet["reply"] = "None"
			resultSet["stage"] = self.stage
			resultSet["shellcode"] = "None"
			resultSet["isFile"] = False

			if self.stage == "TREND_STAGE1" and bytes == 72:
				if message == trend_shellcodes.dce_bind1 or message == trend_shellcodes.dce_bind2:
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "".join(self.reply)+'*'
					self.stage = "TREND_STAGE2"
					return resultSet
			elif self.stage == "TREND_STAGE1" and bytes > 72 and message[2] == '\x0b':
				#print ".::[Amun - TREND] Stage 1_2: %s ::." % (bytes)
				resultSet["result"] = True
				resultSet["accept"] = True
				self.reply[0] = '\x05'
				self.reply[1] = message[1]
				self.reply[2] = '\x0c'
				resultSet["reply"] = "".join(self.reply)+'*'
				self.stage = "TREND_STAGE2"
				return resultSet
			elif self.stage == "TREND_STAGE2" and (bytes == 48 or bytes == 1024):
				if message == trend_shellcodes.rpc_bind1:
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "".join(self.reply)+'*'
					self.stage = "SHELLCODE"
					return resultSet
				else:
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "".join(self.reply)+'*'
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					return resultSet
			elif self.stage == "SHELLCODE":
				if bytes>0:
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "".join(self.reply)+'*'
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					#resultSet["shellcode"] = "".join(self.shellcode)
					return resultSet
				else:
					resultSet["result"] = False
					resultSet["accept"] = True
					resultSet["reply"] = "None"
					self.shellcode.append(message)
					resultSet["shellcode"] = "".join(self.shellcode)
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
		except:
			print "TREND_MICRO fatal error"
