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
import dcom_shellcodes

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "DCOM Vulnerability"
			self.stage = "DCOM_STAGE1"
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
			self.reply = []
			for i in range(0,370):
				try:
					self.reply.append("\x00")
				except KeyboardInterrupt:
					raise

			resultSet = {}
			resultSet['vulnname'] = self.vuln_name
			resultSet['result'] = False
			resultSet['accept'] = False
			resultSet['shutdown'] = False
			resultSet['reply'] = "None"
			resultSet['stage'] = self.stage
			resultSet['shellcode'] = "None"
			resultSet["isFile"] = False
		
			if self.stage == "DCOM_STAGE1" and bytes>0: # (bytes == 72 or bytes == 1024 or bytes == 116 or bytes == 205 or bytes == 204 or bytes==408 or bytes==168):
				if dcom_shellcodes.dcom_request_stage1_1==message or dcom_shellcodes.dcom_request_stage1_2==message or dcom_shellcodes.dcom_request_stage1_3==message or dcom_shellcodes.dcom_request_stage1_5==message:
					#print ".::[Amun - DCOM] STAGE1_1 (bytes: %s) ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[2] = "\x0C"
					resultSet['reply'] = "".join(self.reply[:64])+'*'
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					return resultSet
				#elif dcom_shellcodes.dcom_request_stage1_4==message:
				#	print ".::[Amun - DCOM] STAGE1_2 (bytes: %s) ::." % (bytes)
				#	resultSet['result'] = True
				#	resultSet['accept'] = True
				#	resultSet['reply'] = "".join(self.reply[:64])+'*'
				#	self.stage = "SHELLCODE"
				#	return resultSet
				elif dcom_shellcodes.dcom_request_stage1_7==message or dcom_shellcodes.dcom_request_stage1_4==message:
					#print ".::[Amun - DCOM] STAGE1_2 (bytes: %s) ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[2] = "\x0C"
					self.reply[20] = "\x05"
					self.reply[21] = "\x06"
					self.reply[22] = "\x07"
					self.reply[23] = "\x08"
					resultSet['reply'] = "".join(self.reply[:64])+'*'
					self.stage = "DCOM_STAGE2"
					return resultSet
				else:
					#print ".::[Amun - DCOM] STAGE1_3 (bytes: %s) ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[2] = "\x0C"
					self.reply[20] = "\x01"
					self.reply[21] = "\x02"
					self.reply[22] = "\x03"
					self.reply[23] = "\x04"
					resultSet['reply'] = "".join(self.reply[:62])
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					return resultSet
			elif self.stage == "DCOM_STAGE1" and (bytes==1024 or bytes==872):
				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "".join(self.reply[:362])
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				return resultSet
			elif self.stage == "DCOM_STAGE2" and bytes==944:
				resultSet['result'] = True
				resultSet['accept'] = True
				self.reply[0] = "\x05"
				self.reply[2] = "\x02"
				self.reply[3] = "\x03"
				self.reply[4] = "\x10"
				self.reply[8] = "\x28"
				self.reply[12] = "\x01"
				self.reply[16] = "\x10"
				self.reply[36] = "\x04"
				self.reply[37] = "\x00"
				self.reply[38] = "\x08"
				self.reply[39] = "\x80"
				resultSet['reply'] = "".join(self.reply[:40])
				self.stage = "DCOM_STAGE3"
				return resultSet
			elif self.stage == "DCOM_STAGE3" and bytes==944:
				resultSet['result'] = True
				resultSet['accept'] = True
				self.reply[0] = "\x05"
				self.reply[2] = "\x02"
				self.reply[3] = "\x03"
				self.reply[4] = "\x10"
				self.reply[8] = "\x28"
				self.reply[12] = "\x02"
				self.reply[16] = "\x10"
				self.reply[36] = "\x54"
				self.reply[37] = "\x01"
				self.reply[38] = "\x04"
				self.reply[39] = "\x80"
				resultSet['reply'] = "".join(self.reply[:40])
				self.stage = "DCOM_STAGE4"
				return resultSet
			elif self.stage == "DCOM_STAGE4" and bytes==72:
				resultSet['result'] = True
				resultSet['accept'] = True
				self.reply[0] = "\x05"
				self.reply[2] = "\x0f"
				self.reply[3] = "\x03"
				self.reply[4] = "\x10"
				self.reply[8] = "\x38"
				self.reply[12] = "\x03"
				self.reply[16] = "\xd0"
				self.reply[17] = "\x16"
				self.reply[18] = "\xd0"
				self.reply[19] = "\x16"
				self.reply[20] = "\x05"
				self.reply[21] = "\x06"
				self.reply[22] = "\x07"
				self.reply[23] = "\x08"
				self.reply[28] = "\x01"
				self.reply[36] = "\x04"
				self.reply[37] = "\x5d"
				self.reply[38] = "\x88"
				self.reply[39] = "\x8a"
				self.reply[40] = "\xeb"
				self.reply[41] = "\x1c"
				self.reply[42] = "\xc9"
				self.reply[43] = "\x11"
				self.reply[44] = "\x9f"
				self.reply[45] = "\xe8"
				self.reply[46] = "\x08"
				self.reply[48] = "\x2b"
				self.reply[49] = "\x10"
				self.reply[50] = "\x48"
				self.reply[51] = "\x60"
				self.reply[52] = "\x02"
				resultSet['reply'] = "".join(self.reply[:56])
				self.stage = "DCOM_STAGE5"
				return resultSet
			elif self.stage == "DCOM_STAGE5" and bytes==154:
				resultSet['result'] = True
				resultSet['accept'] = True
				self.reply[0] = "\x05"
				self.reply[2] = "\x02"
				self.reply[3] = "\x03"
				self.reply[4] = "\x10"
				self.reply[8] = "\x5c"
				self.reply[12] = "\x03"
				self.reply[16] = "\x44"
				self.reply[20] = "\x01"
				self.reply[64] = "\x05"
				self.reply[66] = "\x02"
				self.reply[68] = "\x54"
				self.reply[69] = "\x01"
				self.reply[70] = "\x04"
				self.reply[71] = "\x80"
				self.reply[72] = "\x01"
				self.reply[80] = "\x01"
				resultSet['reply'] = "".join(self.reply[:92])
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				return resultSet
			elif self.stage == "SHELLCODE":
				if bytes == 24:
					#print ".::[Amun - DCOM] DCOM Version Request ::."
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[2] = "\x02"
					resultSet['reply'] = "".join(self.reply[:362])
					self.stage = "SHELLCODE"
					return resultSet
				elif bytes>0:
					#print ".::[Amun - DCOM] collecting shellcode (bytes: %s) ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True
					self.reply[2] = "\x02"
					resultSet['reply'] = "".join(self.reply[:362])
					self.shellcode.append(message)
					#resultSet['shellcode'] = "".join(self.shellcode)
					self.stage = "SHELLCODE"
					return resultSet
				else:
					#print ".::[Amun - DCOM] finish collecting shellcode (bytes %s ip %s) ::." % (bytes,ip)
					resultSet['result'] = False
					resultSet['accept'] = True
					resultSet['reply'] = "None"
					self.shellcode.append(message)
					resultSet['shellcode'] = "".join(self.shellcode)
					return resultSet
			else:
				resultSet['result'] = False
				resultSet['accept'] = False
				resultSet['reply'] = "None"
				return resultSet
			return resultSet
		except KeyboardInterrupt:
			raise
		except StandardError, e:
			print "DCOM error: %s" % (self.stage)
			print e

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
