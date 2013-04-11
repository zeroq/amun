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
import peercast_shellcodes

class vuln(object):
	__slots__ = ("vuln_name", "stage", "welcome_message", "shellcode", "reply", "log_obj")

	def __init__(self):
		try:
			self.vuln_name = "PeerCast Vulnerability"
			self.stage = "SHELLCODE"
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
			self.log_obj = amun_logging.amun_logging("vuln_peercast", vuLogger)
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

			if self.stage == "SHELLCODE" and bytes==233 and message==peercast_shellcodes.stage1:
					resultSet["result"] = False
					resultSet["accept"] = True
					resultSet["reply"] = "".join(self.reply)
					self.shellcode.append(message)
					resultSet["shellcode"] = "".join(self.shellcode)
					self.stage = "SHELLCODE"
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
			print "PeerCast fatal error"
