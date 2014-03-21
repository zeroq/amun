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
import iis_shellcodes

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "IIS Vulnerability"
			self.stage = "IIS_STAGE1"
			self.welcome_message = ""
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
			### construct standard reply
			self.reply = []
			for i in range(0,62):
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

			if self.stage == "IIS_STAGE1" and (bytes==133 or bytes>=140 or bytes==78):
				resultSet["result"] = True
				resultSet["accept"] = True
				resultSet["reply"] = "".join(self.reply)
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				return resultSet
			elif self.stage == "SHELLCODE":
				if bytes>0:
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet["reply"] = "".join(self.reply)
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					#resultSet["shellcode"] = "".join(self.shellcode)
					return resultSet
				else:
					resultSet["reply"] = "None"
					self.shellcode.append(message)
					resultSet["shellcode"] = "".join(self.shellcode)
					if len(resultSet["shellcode"])!=142:
						resultSet["result"] = False
						resultSet["accept"] = True
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
			print "IIS fatal error"
