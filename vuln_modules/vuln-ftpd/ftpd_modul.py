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
import random
import ftpd_shellcodes

import amun_logging

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "FTPD Vulnerability"
			self.stage = "FTPD_STAGE1"
			self.welcome_message = "220 Welcome to my FTP Server"
			self.shellcode = []
		except KeyboardInterrupt:
			raise

	def getVulnName(self):
		return self.vuln_name

	def getCurrentStage(self):
		return self.stage

	def getWelcomeMessage(self):
		return self.welcome_message

	def incoming(self, message, bytes, ip, vuLogger, random_reply, ownIP):
		try:
			self.log_obj = amun_logging.amun_logging("vuln_ftpd", vuLogger)

			### construct standard reply
			self.reply = []
			self.reply.append("220 OK")

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

			if bytes>3:
				m = "Attacker: %s Message: %s Bytes: %s Stage: %s" % (ip, [message], bytes, self.stage)
				self.log_obj.log(m, 6, "info", True, False)

			if self.stage == "FTPD_STAGE1":
				if (message.startswith('USER') or message.startswith('user')) and bytes>=75:
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "None"
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					resultSet["shellcode"] = "".join(self.shellcode)
					return resultSet
				elif message.startswith('USER') or message.startswith('user'):
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "331 User OK, Password required"
					self.stage = "FTPD_STAGE1"
					return resultSet
				elif message.startswith('QUIT') or message.startswith('quit'):
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["shutdown"] = True
					resultSet["reply"] = "221 Quit.\r\n221 Goodbye!"
					return resultSet
				elif message.startswith('PASS') and bytes>=75:
					resultSet["result"] = True
					resultSet["accept"] = True
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					resultSet["shellcode"] = "".join(self.shellcode)
					return resultSet
				elif message.startswith('PASS'):
					resultSet["result"] = True
					resultSet["accept"] = True
					#resultSet["reply"] = "530 Authentication failed, sorry"
					resultSet["reply"] = "230 User logged in, proceed"
					self.stage = "FTPD_STAGE2"
					return resultSet
				else:
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "500 Unknown Command"
					self.stage = "FTPD_STAGE2"
					return resultSet
			elif self.stage == "FTPD_STAGE2":
				if message.startswith('QUIT'):
					resultSet["result"] = False
					resultSet["accept"] = False
					resultSet["reply"] = "221 Quit.\r\n221 Goodbye!"
					return resultSet
				elif message.startswith('RMD'):
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "200 Command Okay."
					self.stage = "FTPD_STAGE2"
					return resultSet
				elif message.startswith('MKD'):
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "200 Command Okay."
					self.stage = "FTPD_STAGE2"
					return resultSet
				elif message.startswith('CWD'):
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "250 Directory successfully changed."
					self.stage = "FTPD_STAGE2"
				else:
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "500 Unknown Command."
					self.stage = "FTPD_STAGE2"
					return resultSet
			elif self.stage == "SHELLCODE":
				if bytes>0:
					resultSet["result"] = True
					resultSet["accept"] = True
					#resultSet["reply"] = "None"
					resultSet["reply"] = "230 User logged in, proceed"
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
		except:
			print "FTPD fatal error"
