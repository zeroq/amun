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

import struct
import amun_logging
import random
import rdp_shellcodes
import sys

sys.path.append("../../core")
import amun_rdp_core

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "RDP Vulnerability"
			self.stage = "RDP_STAGE1"
			self.welcome_message = ""
			self.shellcode = []
			self.rdpHandler = amun_rdp_core.amun_rdp_prot()
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
			self.log_obj = amun_logging.amun_logging("vuln_rdp", vuLogger)

			### construct standard reply
			self.reply = []
			for i in range(0,510):
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


			#self.print_message(message)
			#self.log_obj.log("Incoming: %s" % (message), 6, "debug", True, False)

			if self.stage == "RDP_STAGE1" and bytes>=len(self.welcome_message):
				reply, code = self.rdpHandler.consume(message, ownIP)
				if reply!=None:
					resultSet['reply'] = reply+'*'
				else:
					return resultSet

				resultSet["result"] = True
				resultSet["accept"] = True
				self.stage = "SHELLCODE"
				return resultSet
			elif self.stage == "SHELLCODE":
				if bytes>0:
					#print "shellcode bytes>0"
					reply, code = self.rdpHandler.consume(message, ownIP)
					if reply!=None:
						resultSet['reply'] = reply+'*'
						resultSet["result"] = True
						resultSet["accept"] = True
						self.stage = "SHELLCODE"
					return resultSet
				else:
					#print "shellcode else"
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
		except:
			print "RDP fatal error"
