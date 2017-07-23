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

import sys
import struct
import random
import smb_shellcodes

import traceback
import StringIO

sys.path.append("../../core")
import amun_smb_core


class vuln:
	def __init__(self):
		try:
			self.vuln_name = "SMB (Unknown) Vulnerability"
			self.stage = "SMB_STAGE1"
			self.welcome_message = ""
			self.shellcode = []
			self.smbHandler = amun_smb_core.amun_smb_prot()
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

			### construct standard reply
			self.reply = random_reply
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

			if self.stage == "SMB_STAGE1" and bytes>0:
				#print ".::[Amun - SMB STAGE1] Negotiation Request (bytes %s ip %s) ::." % (bytes,ip)
				reply, code = self.smbHandler.consume(message, ownIP)
				if reply!=None:
					resultSet['reply'] = reply+'*'
                                elif reply==None and code!='noreply' and code!='shellcode':
					resultSet['reply'] = "".join(self.reply)+'*'
				elif code=='noreply' or code=='shellcode':
					resultSet["reply"] = "None"
				else:
					return resultSet

				resultSet["result"] = True
				resultSet["accept"] = True
				self.stage = "SHELLCODE"
				return resultSet
			elif self.stage == "SHELLCODE":
				if bytes>0:
					#print ".::[Amun - SMB SHELLCODE] collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
					reply, code = self.smbHandler.consume(message, ownIP)
                                	if reply!=None:
                                        	resultSet['reply'] = reply+'*'
                                	elif reply==None and code!='noreply' and code!='shellcode':
						resultSet['reply'] = "".join(self.reply)+'*'
					elif code=='noreply' or code=='shellcode':
						resultSet["reply"] = "None"

					if code=='shellcode':
						self.vuln_name = self.smbHandler.getVulnName()
						resultSet["vulnname"] = self.vuln_name
						data = self.smbHandler.getShellcode()
						if data!=None:
							self.shellcode.append(data)
						else:
							self.shellcode.append(message)

					self.stage = "SHELLCODE"

					if code!='quit':
						resultSet["result"] = True
						resultSet["accept"] = True
						#resultSet["shellcode"] = "".join(self.shellcode)
					else:
						resultSet["result"] = False
						resultSet["accept"] = True
						resultSet["reply"] = "None"
						resultSet["shellcode"] = "".join(self.shellcode)
						resultSet["shutdown"] = True
						#del self.smbHandler
					return resultSet
				else:
					#print ".::[Amun - SMB SHELLCODE] finish collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
					if bytes>0:
						reply, code = self.smbHandler.consume(message, ownIP)
					else:
						code = None
						reply = None

					if code=='shellcode':
						self.vuln_name = self.smbHandler.getVulnName()
						resultSet["vulnname"] = self.vuln_name

					resultSet["result"] = False
					resultSet["accept"] = True
					resultSet["reply"] = "None"
					resultSet["shutdown"] = True

					data = self.smbHandler.getShellcode()
					if data!=None:
						self.shellcode.append(data)
					else:
						self.shellcode.append(message)

					resultSet["shellcode"] = "".join(self.shellcode)
					del self.smbHandler
					return resultSet
			else:
				#print ".::[Amun - SMB] no match - drop (Stage: %s bytes %s ip %s) ::." % (self.stage, bytes,ip)
				resultSet["result"] = False
				resultSet["accept"] = False
				resultSet["reply"] = "None"
				del self.smbHandler
				return resultSet
			return resultSet
		except KeyboardInterrupt:
			#del self.smbHandler
			raise
		except StandardError, e:
			#del self.smbHandler
			print "SMB error: %s" % (self.stage)
			print e
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
		except:
			#del self.smbHandler
			print "SMB fatal error"
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
