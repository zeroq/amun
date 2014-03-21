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
import wins_shellcodes
import sys

sys.path.append("../../core")
import amun_smb_core

class vuln:
	def __init__(self):
		try:
			self.vuln_name = "WINS Vulnerability"
			self.stage = "WINS_STAGE1"
			self.welcome_message = ""
			self.shellcode = []
			self.smbHandler = amun_smb_core.amun_smb_prot()
			self.num = random.randint(1,5)
		except KeyboardInterrupt:
			raise

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

	def spversion(self, num):
		if num == 1:
			### windows 2000 service pack 0
			#print "windows 2000 service pack 0"
			self.reply[40] = "\x78"
			self.reply[41] = "\xae"
			self.reply[42] = "\xf8"
			self.reply[43] = "\x77"
		elif num == 2:
			### windows 2000 service pack 2
			#print "windows 2000 service pack 2"
			self.reply[40] = "\x80"
			self.reply[41] = "\x26"
			self.reply[42] = "\xf8"
			self.reply[43] = "\x77"
		elif num == 3:
			### windows 2000 service pack 3
			#print "windows 2000 service pack 3"
			self.reply[40] = "\x08"
			self.reply[41] = "\x36"
			self.reply[42] = "\xf8"
			self.reply[43] = "\x77"
		elif num == 4:
			### windows 2000 service pack 4
			#print "windows 2000 service pack 4"
			self.reply[40] = "\x40"
			self.reply[41] = "\x96"
			self.reply[42] = "\xf8"
			self.reply[43] = "\x77"
		elif num == 5:
			### windows 2000 service pack 3/4
			#print "windows 2000 service pack 3/4"
			self.reply[40] = "\x48"
			self.reply[41] = "\x16"
			self.reply[42] = "\xf8"
			self.reply[43] = "\x77"

			

	def incoming(self, message, bytes, ip, vuLogger, random_reply, ownIP):
		try:
			self.reply = []
			for i in range(0,62):
				try:
					#self.reply.append( struct.pack("B", random.randint(0,255)) )
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

			#self.print_message(message)

			if self.stage=="WINS_STAGE1" and bytes == 1024:
				self.stage="SHELLCODE"

			###  0x5391f40, 0x53df4c4, 0x53922e0
			if self.stage=="WINS_STAGE1" and bytes == 45:
				#print ".::[Amun - WINS] fingerprint query: %s ::." % (bytes)

				self.print_message(message)

				resultSet['result'] = True
				resultSet['accept'] = True

				### set packet size
				self.reply[3] = "\x29"
				### opcode/reply command
				self.reply[4] = "\x78"
				self.reply[5] = "\x01"
				self.reply[6] = "\x78"
				self.reply[7] = "\x05"
				### assoc ctx
				self.reply[11] = "\x40"
				### msg type WREPL_START_ASSOC
				self.reply[15] = "\x01"
				### pointer 
				self.reply[16] = "\x05"
				self.reply[17] = "\x37"
				self.reply[18] = "\x1e"
				self.reply[19] = "\x90"
				### minor version
				self.reply[20] = "\x00"
				self.reply[21] = "\x02"
				### major version
				self.reply[22] = "\x00"
				self.reply[23] = "\x05"

				### others
				self.reply[25] = "\x29"
				self.reply[29] = "\x29"

				self.reply[32] = "\xa4"
				self.reply[33] = "\xff"
				self.reply[34] = "\x3d"
				self.reply[35] = "\x05"
				self.reply[36] = "\xdb"
				self.reply[37] = "\x80"
				self.reply[38] = "\xfb"
				self.reply[39] = "\x77"

				### win version reply
				self.spversion(self.num)
				### end
				self.reply[44] = "\x01"

				resultSet['reply'] = "".join(self.reply[:45])+'*'
				self.stage = "WINS_STAGE2"
				return resultSet
			elif self.stage=="WINS_STAGE2" and bytes == 20:
				#print ".::[Amun - WINS] check vulnerable: %s (malformed packet) ::." % (bytes)

				self.print_message(message)

				resultSet['result'] = True
				resultSet['accept'] = True

				### set packet size
				self.reply[3] = "\x2c"
				### reply command
				self.reply[6] = "\x78"
				### assoc ctx
				self.reply[11] = "\x40"
				### msg type WREPL_STOP_ASSOC
				self.reply[15] = "\x02"
				### reason
				self.reply[16] = "\x00"
				self.reply[17] = "\x00"
				self.reply[18] = "\x00"
				self.reply[19] = "\x04"
				### others
				self.reply[20] = "\x78"
				self.reply[21] = "\xfe"
				self.reply[22] = "\x51"
				self.reply[23] = "\x05"
				self.reply[24] = "\x7a"
				self.reply[25] = "\x33"
				self.reply[26] = "\x13"
				self.reply[27] = "\x70"
				self.reply[28] = "\x48"
				self.reply[29] = "\x03"
				self.reply[30] = "\x16"
				self.reply[31] = "\x05"

				self.reply[36] = "\xac"
				self.reply[37] = "\x9a"
				self.reply[38] = "\xe7"
				self.reply[39] = "\x77"
				self.reply[40] = "\x80"
				self.reply[41] = "\x04"
				self.reply[42] = "\x5c"
				self.reply[43] = "\x00"
				self.reply[44] = "\x01"
				
				resultSet['reply'] = "".join(self.reply[:48])+'*'
				self.stage = "WINS_STAGE3"
				return resultSet
			elif self.stage=="WINS_STAGE3":
				#print ".::[Amun - WINS] intermediate: %s ::." % (bytes)

				self.print_message(message)

				resultSet['result'] = True
				resultSet['accept'] = True
				resultSet['reply'] = "*"
				self.stage = "WINS_STAGE4"
				return resultSet
			elif self.stage=="WINS_STAGE4":
				#print ".::[Amun - WINS] fingerprint quit: %s ::." % (bytes)

				resultSet['result'] = False
				resultSet['accept'] = False
				return resultSet
			elif self.stage=="SHELLCODE":
				if bytes == 524:
					#print ".::[Amun - WINS] collecting shellcode (rep request): %s ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True

					resultSet['reply'] = "*"
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					return resultSet
				elif bytes>0:
					#print ".::[Amun - WINS] collecting shellcode: %s ::." % (bytes)
					resultSet['result'] = True
					resultSet['accept'] = True

					resultSet['reply'] = "*"
					self.shellcode.append(message)
					#resultSet['shellcode'] = "".join(self.shellcode)
					self.stage = "SHELLCODE"
					return resultSet
				else:
					#print ".::[Amun - WINS] finish collecting shellcode (bytes %s) ::." % (bytes)
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
			print e
		except:
			print "WINS FATAL ERROR!"
