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
import time
import http_shellcodes

class vuln(object):
	__slots__ = ("vuln_name", "stage", "welcome_message", "shellcode", "reply", "log_obj", "logoright", "stylephpmyadmin", "prevStage")

	def __init__(self):
		try:
			self.vuln_name = "HTTP Vulnerability"
			self.stage = "HTTP_STAGE1"
			self.prevStage = ""
			self.welcome_message = ""
			self.shellcode = []
			try:
				fp = open('http_images/logo_right.png', 'r')
				self.logoright = fp.read()
				fp.close()
			except:
				self.logoright = "Not available"
			try:
				fp = open('http_images/style.css.phpmyadmin', 'r')
				self.stylephpmyadmin = fp.read()
				fp.close()
			except:
				self.stylephpmyadmin = "Not available"
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
			self.log_obj = amun_logging.amun_logging("vuln_http", vuLogger)

			### construct standard reply
			self.reply = http_shellcodes.defaultReply

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

			#if bytes>0 and self.stage!="SHELLCODE":
			#	m = "ip: %s Message: %s Bytes: %s Stage: %s" % (ip, [message], bytes, self.stage)
			#	self.log_obj.log(m, 6, "info", True, False)

			if self.stage == "HTTP_STAGE1" and message.startswith('GET / HTTP'):
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' % (len(http_shellcodes.defaultReply))
				resultSet["reply"] = header+self.reply
				return resultSet
			elif self.stage == "HTTP_STAGE1" and message.startswith('GET /phpmyadmin') and message.count('logo_right.png')>0:
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: image/png\r\nConnection: close\r\n\r\n' % (len(self.logoright))
				resultSet["reply"] = header+self.logoright
				return resultSet
			elif self.stage == "HTTP_STAGE1" and message.startswith('GET /phpmyadmin') and message.count('style.css')>0:
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' % (len(self.stylephpmyadmin))
				resultSet["reply"] = self.stylephpmyadmin+"\r\n\r\n"
				return resultSet
			elif self.stage == "HTTP_STAGE1" and (message.startswith('GET /phpmyadmin') or message.startswith('GET /pmamy/main.php') or message.startswith('GET /phpMyAdmin')):
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' % (len(http_shellcodes.phpmyadmin))
				resultSet["reply"] = header+http_shellcodes.phpmyadmin
				return resultSet
			elif self.stage == "HTTP_STAGE1" and (message.startswith('GET /vhcs2/') or message.startswith('GET /phpBB/index.php') or message.startswith('GET /roundcube/bin/msgimport') or message.startswith('GET /webmail/program/js/list.js') or message.startswith('GET /manager/html')):
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' % (len(http_shellcodes.defaultReply))
				resultSet["reply"] = header+self.reply
				return resultSet
			elif self.stage == "HTTP_STAGE1" and message.startswith('OPTIONS'):
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' % (len(http_shellcodes.badRequest))
				resultSet["reply"] = http_shellcodes.badRequest
				return resultSet
			elif self.stage == "HTTP_STAGE1" and message.startswith('POST /_vti_bin/_vti_aut/fp30reg.dll') and len(message)>=530:
				resultSet["result"] = False
				resultSet["accept"] = True
				resultSet["reply"] = "None"
				self.shellcode.append(message)
				resultSet["shellcode"] = "".join(self.shellcode)
				#self.stage = "SHELLCODE"
				return resultSet
			elif self.stage == "HTTP_STAGE1" and message.startswith('SEARCH /') and len(message)>=1024:
				self.vuln_name = "MS03007 (IIS) Vulnerability"
				self.prevStage = "IIS-1"
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/5.0\r\nDate: %s GMT\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\nCache-control: private\r\n\r\n' % (time.ctime(), len(http_shellcodes.defaultReply))
				resultSet["reply"] = header+self.reply
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				return resultSet
			elif self.stage == "HTTP_STAGE1" and message.startswith('GET /user/soapCaller.bs HTTP'):
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' % (len(http_shellcodes.defaultReply))
				resultSet["reply"] = header+self.reply
				return resultSet
			elif self.stage == "HTTP_STAGE1" and message.startswith('GET /') and bytes==1024:
				self.vuln_name = "MS02018 (IIS) Vulnerability"
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/5.0\r\nDate: %s GMT\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\nCache-control: private\r\n\r\n' % (time.ctime(), len(http_shellcodes.defaultReply))
				resultSet["reply"] = header+self.reply
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				return resultSet
			elif self.stage == "HTTP_STAGE1" and bytes==1024:
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 200 OK\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' % (len(http_shellcodes.defaultReply))
				resultSet["reply"] = header+self.reply
				self.shellcode.append(message)
				self.stage = "SHELLCODE"
				return resultSet
			elif self.stage == "SHELLCODE":
				if bytes==198 and self.prevStage == "IIS-1":
					resultSet["result"] = False
					resultSet["accept"] = True
					resultSet["reply"] = "None"
					self.shellcode.append(message)
					resultSet["shellcode"] = "".join(self.shellcode)
					return resultSet
				if bytes>0:
					#print "Shellcode Stage (Bytes: %s)" % (bytes)
					resultSet["result"] = True
					resultSet["accept"] = True
					resultSet['reply'] = "None"
					self.shellcode.append(message)
					self.stage = "SHELLCODE"
					return resultSet
				else:
					resultSet["result"] = False
					resultSet["accept"] = True
					resultSet["reply"] = "None"
					self.shellcode.append(message)
					resultSet["shellcode"] = "".join(self.shellcode)
					return resultSet
			else:
				resultSet["result"] = True
				resultSet["accept"] = True
				header = 'HTTP/1.1 404 Not Found\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: %s\r\nContent-Language: de\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' % (len(http_shellcodes.badRequest))
				resultSet["reply"] = header+http_shellcodes.badRequest
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
			print "HTTP fatal error"
