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

from re import compile, S as reS
from urlparse import urlsplit, urlunparse
from hashlib import md5
from os import path as ospath
from socket import inet_ntoa
from struct import pack, unpack
from base64 import decodestring, b64encode

from sys import exit, stdout
from StringIO import StringIO
import traceback

from iprange import IPRange
from amun_logging import amun_logging

class shell_mgr:
	def __init__(self, decodersDict, shLogger, config_dict):
		"""initialize shellcode decoder class

		Keyword arguments:
		decodersDict -- dictionary of all decoders from shellcodes/decoders.py
		shLogger -- shellcode manager logging instance
		config_dict -- dictionary containing amun configuration options

		"""
		self.config_dict = config_dict
		### create local network ranges
		self.localIPliste = []
		self.localIPliste.append( IPRange("0.0.0.0/8") )
		self.localIPliste.append( IPRange("10.0.0.0/8") )
		self.localIPliste.append( IPRange("127.0.0.0/8") )
		self.localIPliste.append( IPRange("169.254.0.0/16") )
		self.localIPliste.append( IPRange("172.16.0.0/12") )
		self.localIPliste.append( IPRange("192.168.0.0/16") )
		### local logging instance
		self.log_obj = amun_logging("shellcode_manager", shLogger)
		### load shellcodes
		self.decodersDict = decodersDict

	def getNewResultSet(self, vulnName, attIP, ownIP):
		"""Return a new empty result set to be used for detected shellcode

		Keyword arguments:
		vulnName -- name of the vulnerability that triggered the shellcode manager
		attIP -- IP address of the potential attacker that the shellcode came from
		ownIP -- IP address of amun honeypot that was attacked

		"""
		resultSet = {}
		resultSet['vulnname'] = vulnName
		resultSet['result'] = False
		resultSet['hostile_host'] = attIP
		resultSet['own_host'] = ownIP
		resultSet['found'] = "None"
		resultSet['path'] = "None"
		resultSet['host'] = "None"
		resultSet['port'] = "None"
		resultSet['xorkey'] = "None"
		resultSet['username'] = "None"
		resultSet['passwort'] = "None"
		resultSet['dlident'] = "None"
		resultSet['displayURL'] = "None"
		resultSet['isLocalIP'] = False
		resultSet['shellcodeName'] = "None"
		return resultSet

	def start_matching(self, vulnResult, attIP, ownIP, ownPort, replace_locals=0, displayShellCode=False):
		"""Start matching the received potential shellcode against known obfuscation techniques

		Keyword arguments:
		vulnResult -- dictionary of results returned by the vulnerability module that reached the shellcode stage
		attIP -- Attacker IP address
		ownIP -- Amun IP address
		ownPort -- Amun port of vulnerability that was attacked
		replace_locals -- if True every local IP address will be replaced by the attacker IP address
		displayShellcode -- if True will display each type of shellcode that is tested

		"""
		try:
			self.shellcode = str(vulnResult['shellcode']).replace('\0','').strip()
			self.shellcode2 = str(vulnResult['shellcode']).strip()
			self.attIP = attIP
			self.ownIP = ownIP
			self.replace_locals = replace_locals
			self.displayShellCode = displayShellCode
			### list of all results
			self.overallResults = []
			self.resultSet = self.getNewResultSet(vulnResult['vulnname'], attIP, ownIP)
			### check for http urls first
			http_result = self.match_url()
			if http_result==1 and self.resultSet['result']:
				self.overallResults.append(self.resultSet)
				return self.overallResults
			### url matched but incomplete
			if http_result==2:
				self.overallResults.append(self.resultSet)
				return self.overallResults
			### shellcodes matchen
			if self.match_shellcodes() and self.resultSet['result']:
				self.overallResults.append(self.resultSet)
				return self.overallResults
			### plain FTP matchen
			if self.match_plainFTP() and self.resultSet['result']:
				self.overallResults.append(self.resultSet)
				return self.overallResults
			### HTTP embedded TFTP matchen
			if self.match_embeddedTFTP() and self.resultSet['result']:
				self.overallResults.append(self.resultSet)
				return self.overallResults
			### no match than write hexdump
			if len(self.overallResults)<=0:
				self.write_hexdump(self.shellcode, vulnResult['vulnname'].split(' ')[0], ownPort)
				self.write_hexdump(self.shellcode2, vulnResult['vulnname'].split(' ')[0], "raw-"+str(ownPort))
			return self.overallResults
		except KeyboardInterrupt:
			raise

	def start_shellcommand_matching(self, vulnResult, attIP, ownIP, ownPort, replace_locals, displayShellCode):
		"""Start matching received shell commands (e.g. from bindshell) for known stuff

		Keyword arguments:
		vulnResult -- dictionary of results returned by the vulnerability module that reached the shellcode stage
		attIP -- Attacker IP address
		ownIP -- Amun IP address
		ownPort -- Amun port of vulnerability that was attacked
		replace_locals -- if True every local IP address will be replaced by the attacker IP address
		displayShellcode -- if True will display each type of shellcode that is tested

		"""
		try:
			self.shellcode = str(vulnResult['shellcode']).strip()
			self.attIP = attIP
			self.ownIP = ownIP
			self.ownPort = ownPort
			self.replace_locals = replace_locals
			self.displayShellCode = displayShellCode
			### list of all results
			self.overallResults = []
			self.resultSet = self.getNewResultSet(vulnResult['vulnname'], attIP, ownIP)
			### check for direct file submission
			direct_file_result = self.match_direct_file()
			if direct_file_result==1 and self.resultSet['result']:
				self.overallResults.append(self.resultSet)
				return self.overallResults
			self.resultSet = self.getNewResultSet(vulnResult['vulnname'], attIP, ownIP)
			self.shellcode = str(vulnResult['shellcode']).strip()
			### check for http urls
			http_result = self.match_url()
			if http_result==1 and self.resultSet['result']:
				self.overallResults.append(self.resultSet)
			### url matched but incomplete
			if http_result==2:
				self.overallResults.append(self.resultSet)
			self.resultSet = self.getNewResultSet(vulnResult['vulnname'], attIP, ownIP)
			self.shellcode = str(vulnResult['shellcode']).strip()
			### plain FTP matchen
			if self.match_plainFTP() and self.resultSet['result']:
				self.overallResults.append(self.resultSet)
			self.resultSet = self.getNewResultSet(vulnResult['vulnname'], attIP, ownIP)
			self.shellcode = str(vulnResult['shellcode']).strip()
			### plain TFTP matchen
			if self.match_plainTFTP() and self.resultSet['result']:
				self.overallResults.append(self.resultSet)
			self.resultSet = self.getNewResultSet(vulnResult['vulnname'], attIP, ownIP)
			self.shellcode = str(vulnResult['shellcode']).strip()
			### old plain FTP matchen
			#if self.match_FTPold() and self.resultSet['result']:
			#	self.overallResults.append(self.resultSet)
			### no match than write hexdump
			if len(self.overallResults)<=0:
				self.write_hexdump(self.shellcode, vulnResult['vulnname'].split(' ')[0], ownPort)
			return self.overallResults
		except KeyboardInterrupt:
			raise

	def decXorHelper(self, char, key):
		"""Perform XOR command of char and key

		Keyword arguments:
		char -- character to XOR
		key -- XOR key to use

		"""
		return pack('B', unpack('B',char)[0] ^ key )

	def decrypt_xor(self, key, data):
		"""Decrypt given data using a simple single byte XOR key

		Keyword arguments:
		key -- XOR key
		data -- character string to XOR with given key

		"""
		return "".join([self.decXorHelper(char,key) for char in data])

	def decrypt_multi_xor(self, keys, data, position=0):
		"""Decrypt given data using a multi-byte XOR key starting at given position

		Keyword arguments:
		keys -- list of bytes to be used as XOR keys
		data -- character string to XOR
		position -- position where to start in given string to XOR (default 0)

		"""
		decrypted = []
		keyPos = position % len(keys)
		for char in data:
			decrypted.append(pack('B', unpack('B',char)[0] ^ keys[keyPos]  ))
			keyPos = (keyPos + 1) % len(keys)
		return "".join(decrypted)

	def checkFTP(self, cmd):
		"""Check given command for known FTP shell commands

		Keyword arguments:
		cmd -- received command string to check

		"""
		if cmd.startswith('cmd /c echo open'):
			cmd_liste = cmd.split(' ')
			target_ip = cmd_liste[4]
			match = self.decodersDict['checkIP'].search(target_ip)
			if match:
				local = self.check_local(target_ip)
				if local and self.replace_locals:
					target_ip = self.attIP
				elif local and not self.replace_locals:
					self.resultSet['isLocalIP'] = True
					self.log_obj.log("local IP found" , 6, "crit", True, True)
			else:
				self.log_obj.log("no IP: %s" % (ip) , 6, "crit", True, True)
			self.resultSet['host'] = target_ip
			self.resultSet['port'] = int(cmd_liste[5]) % 65551
			if cmd_liste[8]=="user":
				self.resultSet['username'] = cmd_liste[9]
				self.resultSet['passwort'] = cmd_liste[10]
			if cmd_liste[14]=="get":
				self.resultSet['path'] = [cmd_liste[15]]
			self.resultSet['dlident'] = "%s%i%s" % (target_ip.replace('.',''), self.resultSet['port'], cmd_liste[15].replace('/',''))
			ftpURL = "ftp://%s:%s@%s:%s%s" % (self.resultSet['username'], self.resultSet['passwort'], self.resultSet['host'], self.resultSet['port'], self.resultSet['path'])
			self.log_obj.log("found Windows CMD FTP (server: %s:%s user: %s:%s file: %s)" % (self.resultSet['host'],self.resultSet['port'],self.resultSet['username'],self.resultSet['passwort'],self.resultSet['path']), 9, "info", True, False)
			self.resultSet['displayURL'] = ftpURL
			self.resultSet['shellcodeName'] = "plainftp"
			return True
		return False

	def match_shellcodes(self):
		"""Match found shellcode (self.shellcode) against known shellcode obfuscation techniques

		"""
		try:
			### Match Wuerzburg Shellcode
			if self.displayShellCode:
				print "starting Wuerzburg matching ..."
				stdout.flush()
			match = self.decodersDict['wuerzburg'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "wuerzburg")
				raw_port = match.groups()[0]
				port = unpack('!H',raw_port)[0]
				raw_ip = match.groups()[1]
				ip = unpack('I',raw_ip)[0]
				ip = pack('I',ip^0xaaaaaaaa)
				ip = inet_ntoa(ip)
				key = unpack('B',match.groups()[2])[0]
				if self.replace_locals and self.check_local(ip):
					ip = self.attIP
				elif self.check_local(ip):
					self.resultSet['isLocalIP'] = True
				self.log_obj.log("found wuerzburg shellcode (key: %s port: %s ip: %s)" % (key, port, ip), 9, "info", False, True)
				self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
				self.resultSet['result'] = True
				self.resultSet['host'] = ip
				self.resultSet['port'] = port
				self.resultSet['found'] = "connectbackfiletrans"
				filename = self.handle_wuerzburg(key)
				connbackURL = "cbackf://%s:%s/%s" % (ip, port, filename)
				self.resultSet['displayURL'] = connbackURL
				self.resultSet['shellcodeName'] = "wuerzburg"
				return True
			### Match Leimbach shellcode
			if self.displayShellCode:
				print "starting Leimbach matching ..."
				stdout.flush()
			match = self.decodersDict['leimbach'].search( self.shellcode )
			if match:
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found leimbach xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_leimbach( key, dec_shellcode ):
					return True
			### Match Conficker Shellcode
			if self.displayShellCode:
				print "starting Conficker matching ..."
				stdout.flush()
			match = self.decodersDict['conficker'].search( self.shellcode )
			if match:
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found conficker xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.match_url(dec_shellcode) == 1:
					return True
			### Match Adenau Shellcode
			if self.displayShellCode:
				print "starting Adenau matching ..."
				stdout.flush()
			match = self.decodersDict['adenau'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "adenau")
				keys = {}
				for i in xrange(0,4):
					keys[i] =  unpack('B',match.groups()[i])[0]
				self.resultSet['xorkey'] = keys
				self.log_obj.log("found adenau xor decoder (keys: %s)" % (keys), 9, "info", False, True)
				if self.handle_adenau( keys ):
					return True
			### Match Mannheim Shellcode1
			if self.displayShellCode:
				print "starting Mannheim matching ..."
				stdout.flush()
			match = self.decodersDict['mannheim'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "mannheim")
				key = unpack('B',match.groups()[0])[0]
				self.log_obj.log("found shell1 (key: %s)" % (key), 9, "info", True, True)
				enc_command = match.groups()[1]
				dec_command = self.decrypt_xor(key,enc_command)
				if self.checkFTP(dec_command):
					self.log_obj.log("command found: %s" % (dec_command), 9, "info", True, True)
					self.resultSet['result'] = True
					self.resultSet['xorkey'] = key
					self.resultSet['found'] = "ftp"
					self.resultSet['shellcodeName'] = "mannheim"
					return True
			### Match Unnamed Shellcode2
			if self.displayShellCode:
				print "starting Unnamed Shellcode2 matching ..."
				stdout.flush()
			match = self.decodersDict['plain2'].search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = unpack('!H',raw_port)[0]
				self.log_obj.log("found shell2 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedshell2"
				return True
			### Match Aachen Shellcode (aka zuc_winshit)
			if self.displayShellCode:
				print "starting Aachen Shellcode matching ..."
				stdout.flush()
			match = self.decodersDict['aachen'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "aachen")
				ipkey = unpack('!L',match.groups()[0])[0]
				portkey = unpack('!H',match.groups()[1])[0]
				self.log_obj.log("found aachen shellcode (ipkey: %s portkey: %s)" % (ipkey, portkey), 9, "info", False, True)
				if self.handle_aachen( ipkey, portkey ):
					return True
			### Match Mainz / Bielefeld Shellcode
			if self.displayShellCode:
				print "starting Mainz / Bielefeld matching ..."
				stdout.flush()
			match = self.decodersDict['mainz'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "mainz")
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found mainz/bielefeld xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_bielefeld(key, dec_shellcode):
					return True
				else:
					self.write_hexdump(dec_shellcode, "mainz-bielefeld", "decoded")
			### Match Heidelberg Shellcode
			if self.displayShellCode:
				print "starting Heidelberg matching ..."
				stdout.flush()
			match = self.decodersDict['heidelberg'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "heidelberg")
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found heidelberg xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				### DEBUG
				self.write_hexdump(dec_shellcode, "heidelberg")
				if self.handle_heidelberg(key, dec_shellcode):
					return True
			### Match Rothenburg / Schoenborn Shellcode
			if self.displayShellCode:
				print "starting Rothenburg / Schoenborn matching ..."
				stdout.flush()
			match = self.decodersDict['rothenburg'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "rothenburg")
				keys = {}
				for i in xrange(0,4):
					keys[i] = unpack('B',match.groups()[i])[0]
				self.resultSet['xorkey'] = keys
				self.log_obj.log("found rothenburg/schoenborn xor decoder (keys: %s)" % (keys), 9, "info", False, True)
				if self.handle_rothenburg( keys ):
					return True
			### Match Koeln Shellcode
			if self.displayShellCode:
				print "starting Koeln matching ..."
				stdout.flush()
			match = self.decodersDict['koeln'].search( self.shellcode )
			if match:
				keys = {}
				for i in xrange(0,4):
					keys[i] = unpack('B',match.groups()[i])[0]
				self.resultSet['xorkey'] = keys
				self.log_obj.log("found koeln xor decoder (keys: %s)" % (keys), 9, "info", False, True)
				if self.handle_koeln( keys ):
					return True
			### Match linkbot XOR shellcode (aka Lindau)
			if self.displayShellCode:
				print "starting Lindau matching ..."
				stdout.flush()
			match = self.decodersDict['linkbot'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "lindau")
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found linkbot xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_linkbot( key, dec_shellcode ):
					return True
			### Match schauenburg XOR shellcode
			if self.displayShellCode:
				print "starting schauenburg matching ..."
				stdout.flush()
			match = self.decodersDict['schauenburg'].search( self.shellcode )
			if match:
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found schauenburg xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_schauenburg( key, dec_shellcode ):
					return True
			### Match plain1 shellcode
			if self.displayShellCode:
				print "starting plain1 matching ..."
				stdout.flush()
			match = self.decodersDict['plain1'].search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = unpack('<H',raw_port)[0]
				self.log_obj.log("found plain1 shellcode (port: %s)" % (port), 9, "info", False, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "plain1"
				return True
			### Match PexAlphaNumeric shellcode (mixedcase_w32sehgetpc)
			if self.displayShellCode:
				print "starting PexAlphaNumeric matching ..."
				stdout.flush()
			match = self.decodersDict['pexalphanum'].search( self.shellcode )
			if match:
				decoder = match.groups()[0]
				payload = match.groups()[1]
				self.log_obj.log("found PexAlphaNum shellcode", 9, "info", False, True)
				if self.handle_pexalphanum( decoder, payload ):
					return True
			### Alpha Upper shellcode
			if self.displayShellCode:
				print "starting Alpha_Upper matching ..."
				stdout.flush()
			match = self.decodersDict['alphaupper'].search( self.shellcode )
			if match:
				decoder = match.groups()[0]
				payload = match.groups()[1]
				self.log_obj.log("found Alpha_Upper decoder", 9, "info", False, True)
				if self.handle_alphaupper( decoder, payload ):
					return True
			match = self.decodersDict['alphaupper2'].search( self.shellcode )
			if match:
				decoder = match.groups()[0]
				payload = match.groups()[1]
				self.log_obj.log("found Alpha_Upper decoder", 9, "info", False, True)
				if self.handle_alphaupper( decoder, payload ):
					return True
			match = self.decodersDict['alphaupper_generic'].search( self.shellcode )
			if match:
				decoder = match.groups()[0]
				payload = match.groups()[1]
				self.log_obj.log("found Alpha_Upper generic decoder", 9, "info", False, True)
				if self.handle_alphaupper( decoder, payload ):
					return True
			### Match Lichtenfels shellcode
			if self.displayShellCode:
				print "starting Lichtenfels matching ..."
				stdout.flush()
			match = self.decodersDict['lichtenfels'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "lichtenfels")
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found lichtenfels xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_lichtenfels( key, dec_shellcode ):
					return True
			### Match Berlin shellcode
			if self.displayShellCode:
				print "starting Berlin matching ..."
				stdout.flush()
			match = self.decodersDict['berlin'].search( self.shellcode )
			if match:
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found berlin xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_berlin( key, dec_shellcode ):
					return True
			### Match Furth shellcode
			if self.displayShellCode:
				print "starting Furth matching ..."
				stdout.flush()
			match = self.decodersDict['furth'].search( self.shellcode )
			if match:
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found furth xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.match_url(dec_shellcode) == 1:
					return True
				if self.match_plainFTP(dec_shellcode):
					return True
			### Match Duesseldorf shellcode
			if self.displayShellCode:
				print "starting Duesseldorf matching ..."
				stdout.flush()
			match = self.decodersDict['duesseldorf'].search( self.shellcode )
			if match:
				key1 = unpack('B',match.groups()[0])[0]
				key2 = unpack('B',match.groups()[1])[0]
				self.log_obj.log("found duesseldorf xor decoder (key1: %s, key2: %s)" % (key1, key2), 9, "info", False, True)
				if key1 == key2:
					self.resultSet['xorkey'] = key1
					dec_shellcode = self.decrypt_xor(key1, self.shellcode)
					if self.match_url(dec_shellcode) == 1:
						return True
				self.log_obj.log("xor keys differ, aborting for manual analysis", 9, "info", True, True)
			### Match Siegburg shellcode
			if self.displayShellCode:
				print "starting Siegburg matching ..."
				stdout.flush()
			match = self.decodersDict['siegburg'].search( self.shellcode )
			if match:
				key = unpack('B',match.groups()[0])[0]
				self.log_obj.log("found siegburg xor decoder (key: %s)" % (key), 9, "info", False, True)
				self.resultSet['xorkey'] = key
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_siegburg( key, dec_shellcode ):
					return True
			### Match Ulm shellcode
			if self.displayShellCode:
				print "starting Ulm matching ..."
				stdout.flush()
			match = self.decodersDict['ulm'].search( self.shellcode )
			if match:
				keys = {}
				for i in xrange(0,4):
					keys[i] = unpack('B',match.groups()[i])[0]
				self.resultSet['xorkey'] = keys
				self.log_obj.log("found ulm xor decoder (keys: %s)" % (keys), 9, "info", False, True)
				if self.handle_ulm( keys ):
					return True
			### Match Langenfeld shellcode
			if self.displayShellCode:
				print "starting Langenfeld matching ..."
				stdout.flush()
			match = self.decodersDict['langenfeld'].search( self.shellcode )
			if match:
				key = unpack('B',match.groups()[0])[0]
				self.log_obj.log("found langenfeld xor decoder (key: %s)" % (key), 9, "info", False, True)
				self.resultSet['xorkey'] = key
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_langenfeld( key, dec_shellcode ):
					return True
			### Match Bonn shellcode
			if self.displayShellCode:
				print "starting Bonn matching ..."
				stdout.flush()
			match = self.decodersDict['bonn'].search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "bonn")
				key = unpack('B',match.groups()[0])[0]
				self.log_obj.log("found bonn xor decoder (key: %s)" % (key), 9, "info", False, True)
				self.resultSet['xorkey'] = key
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.match_url(dec_shellcode) == 1:
					return True
			### Match Unnamed BindShellcode1
			if self.displayShellCode:
				print "starting Unnamed BindShellcode1 matching ..."
				stdout.flush()
			match = self.decodersDict['bindshell1'].search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell1 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind1"
				return True
			### Match Unnamed BindShellcode2
			if self.displayShellCode:
				print "starting Unnamed BindShellcode2 matching ..."
				stdout.flush()
			match = self.decodersDict['bindshell2'].search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell2 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind2"
				return True
			### Match Unnamed BindShellcode3
			if self.displayShellCode:
				print "starting Unnamed BindShellcode3 matching ..."
				stdout.flush()
			match = self.decodersDict['bindshell3'].search( self.shellcode2 )
			if match:
				raw_port = match.groups()[0]
				port = unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell3 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind3"
				return True
			### Match Unnamed BindShellcode4
			if self.displayShellCode:
				print "starting Unnamed BindShellcode4 matching ..."
				stdout.flush()
			match = self.decodersDict['bindshell4'].search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell4 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind4"
				return True
			### Match Unnamed BindShellcode5
			if self.displayShellCode:
				print "starting Unnamed BindShellcode5 matching ..."
				stdout.flush()
			match = self.decodersDict['bindshell5'].search( self.shellcode2 )
			if match:
				raw_port = match.groups()[0]
				port = unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell5 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind5"
				return True
			### Match Unnamed BindShellcode6
			if self.displayShellCode:
				print "starting Unnamed BindShellcode6 matching ..."
				stdout.flush()
			match = self.decodersDict['bindshell6'].search( self.shellcode2 )
			if match:
				raw_port = match.groups()[0]
				port = unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell6 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind6"
				return True
			### Match Unnamed AlphaNumeric Shellcode
			if self.displayShellCode:
				print "starting Base64Encoded PexAlphaNumeric matching ..."
				stdout.flush()
			match = self.decodersDict['alphaNum'].search( self.shellcode )
			if match:
				payload = match.groups()[0]
				payload += "=="
				try:
					decodedPayload = decodestring(payload)
					match = self.decodersDict['pexalphanum'].search( decodedPayload )
					if match:
						decoder = match.groups()[0]
						payload = match.groups()[1]
						self.log_obj.log("found PexAlphaNum shellcode", 9, "info", False, True)
						if self.handle_pexalphanum( decoder, payload ):
							return True
				except:
					pass
			### Unnamed Plain URL Alpha
			if self.displayShellCode:
				print "starting Base64Encoded AlphaNumeric plain URL matching ..."
				stdout.flush()
			match = self.decodersDict['alphaNum2'].search( self.shellcode )
			if match:
				payload = match.groups()[0]
				payload += "=="
				try:
					decodedPayload = decodestring(payload)
					http_result = self.match_url( decodedPayload )
					if http_result==1 and self.resultSet['result']:
						return True
				except:
					pass
			### Match Alpha2 zero tolerance Shellcode
			if self.displayShellCode:
				print "starting Alpha2 zero tolerance matching ..."
				stdout.flush()
			match = self.decodersDict['alpha2endchar'].search( self.shellcode )
			if match:
				endChar = match.groups()[0]
				load = match.groups()[1]
				payload = load[27:]
				find_encoded = compile('(.*?)%s' % (endChar), reS)
				match = find_encoded.search(payload)
				if match:
					encoded = match.groups()[0]
					shell_length = len(encoded)
					if self.handle_alpha2zero( encoded, shell_length ):
						return True
			### Match Bergheim shellcode
			if self.displayShellCode:
				print "starting Bergheim matching ..."
				stdout.flush()
			match = self.decodersDict['bergheim'].search( self.shellcode )
			if match:
				key = unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found bergheim xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_bergheim(key, dec_shellcode):
					return True
			### End
			self.resultSet['result'] = False
		except KeyboardInterrupt:
			raise
		except:
			f = StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
			exit(0)
		return False

	def handle_alphaupper(self, decoder, payload):
		"""Metasploit Alpha_Upper shellcode obfuscation technique

		Keyword arguments:
		decoder -- decoding routine that matched the initial shellcode check
		payload -- payload that was extracted by the initial match

		"""
		messageSize = len(decoder)
		self.log_obj.log("AlphaUpper payload size: %s" % (messageSize), 9, "debug", False, True)

		decodedMessage = list(decoder)

		ecx = -5
		edx = -5
		initecx = -5
		initedx = -5

		m1 = False
		m2 = False

		while True:
			while True:
				ecx += 2
				edx += 1
				if ecx>=messageSize or ecx+1>=messageSize:
					break
				decodedMessage[edx] = pack('B', (0xff&(unpack('B', decodedMessage[ecx])[0]*0x10)^unpack('B', decodedMessage[ecx+1])[0]))
			dec_shellcode = "".join(decodedMessage)

			m1 = self.decodersDict['alphaupper_bindport'].search( dec_shellcode )
			m2 = self.decodersDict['alphaupper_connback'].search( dec_shellcode )
			if m1 or m2:
				break
			initecx += 1
			initedx += 1
			ecx = initecx
			edx = initedx
			if edx>=messageSize:
				break

		if m1:
			raw_port = m1.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found alphaupper bindshell (port: %s)" % (port), 9, "info", False, True)
			self.resultSet['result'] = True
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "alphaupper"
			return True
		if m2:
			raw_ip = m2.groups()[0]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m2.groups()[1]
			port = unpack('!H',raw_port)[0]
			self.log_obj.log("found alphaupper connectback (ip: %s, port: %s)" % (ip, port), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "alphaupper"
			return True
		else:
			self.write_hexdump( dec_shellcode, "alphaupper" )
			self.write_hexdump( decoder, "alphaupper-encoded" )
			return False

	def handle_pexalphanum(self, decoder, payload):
		"""Metasploit PexAlphaNumeric shellcode obfuscation technique

		Keyword arguments:
		decoder -- decoding routine that matched the initial shellcode check
		payload -- payload that was extracted by the initial match

		"""
		payloadSize = len(payload)
		self.log_obj.log("AlphaNum payload size: %s" % (payloadSize), 9, "debug", False, True)
		if payloadSize % 2 != 0:
			payloadSize -= 1
		decodedMessage = {}
		for i in xrange(0, payloadSize, 2):
			decodedMessage[i] = '\x90'
			lowBit = (unpack('B', payload[i])[0] - 1) ^ 0x41
			highBit = unpack('B', payload[i+1])[0] & 0x0f
			resultBit = lowBit | (highBit << 4)
			decodedMessage[i/2] = pack('B',resultBit)
		dec_shellcode = "".join(decodedMessage.values())

		m = self.decodersDict['pexalphanum_bindport'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found pexalphanum bindshell (port: %s)" % (port), 9, "info", False, True)
			self.resultSet['result'] = True
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "pexalphanum"
			return True
		else:
			self.write_hexdump( dec_shellcode, "pexalphanum" )
			return False

	def handle_alpha2zero(self, payload, length):
		"""Metasploit Alpha2 zero tolerance shellcode obfuscation technique

		Keyword arguments:
		payload -- payload that was extracted by the initial match
		length -- length of encoded shellcode

		"""
		if length % 2 != 0:
			length -= 1
		decodedMessage = {}
		for i in xrange(0, length, 2):
			decodedMessage[i] = '\x90'
			first = unpack('B', payload[i])[0]
			second = unpack('B', payload[i+1])[0]
			C = (first & 0xf0) >> 4
			D = first & 0x0f
			E = (second & 0xf0) >> 4
			B = second & 0x0f
			A = (D ^ E)
			resultBit = (A << 4) + B
			decodedMessage[i/2] = pack('B',resultBit)
		decoded_shellcode = "".join(decodedMessage.values())
		### connectback shell (reverse shell)
		match = self.decodersDict['alpha2connback'].search( decoded_shellcode )
		if match:
			raw_ip = match.groups()[0]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			raw_port = match.groups()[1]
			port = unpack('!H',raw_port)[0]
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found alpha2 connectback shell (port: %s ip: %s)" % (port, ip), 9, "info", False, True)
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			self.resultSet['result'] = True
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "alpha2zero"
			return True
		### bindshell
		match = self.decodersDict['alpha2bind'].search( decoded_shellcode )
		if match:
			raw_port = match.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found alpha2 bindshell (port: %s)" % (port), 9, "info", False, True)
			self.resultSet['result'] = True
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "alpha2zero"
			return True
		return False

	def handle_wuerzburg(self, key):
		"""Wuerzburg single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key to use

		"""
		m = False
		filename = "None"
		dec_shellcode = self.decrypt_xor(key, self.shellcode)
		m = self.decodersDict['wuerzburg_file'].search( dec_shellcode )
		if m:
			filename = str(m.groups()[0]).replace('\\','')
		return filename

	def handle_aachen(self, ip_key, port_key):
		"""Aachen two XOR keys shellcode decoder

		Keyword arguments:
		ip_key -- XOR key for the encoded IP address
		port_key -- XOR key for the encoded network port

		"""
		m = False
		m = self.decodersDict['aachen_connback'].search( self.shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]^port_key
			raw_ip = m.groups()[1]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip^ip_key)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found aachen connectback shell (port: %s ip: %s)" % (port, ip), 9, "info", False, True)
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			self.resultSet['result'] = True
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "aachen"
			return True
		else:
			return False

	def handle_bergheim(self, key, dec_shellcode):
		"""Bergheim single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key that was used
		dec_shellcode -- already decoded shellcode

		"""
		m = False
		### bergheim ConnectBack Shellcode
		m = self.decodersDict['bergheim_connback'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found bergheim shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "bergheim"
			return True
		return False


	def handle_langenfeld(self, key, dec_shellcode):
		"""Langenfeld single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key that was used
		dec_shellcode -- already decoded shellcode

		"""
		m = False
		### langenfeld ConnectBack Shellcode
		m = self.decodersDict['langenfeld_connback'].search( dec_shellcode )
		if not m:
			m = self.decodersDict['langenfeld_connback2'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found langenfeld shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "langenfeld"
			return True
		return False

	def handle_heidelberg(self, key, dec_shellcode):
		"""Heidelberg single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key
		dec_shellcode -- already decoded shellcode

		FIXME: shellcode information need to be extracted
		"""
		return True

	def handle_bielefeld(self, key, dec_shellcode):
		"""Bielefeld single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key
		dec_shellcode -- already decoded shellcode

		"""
		m = False
		### Mainz / Bielefeld - BindPort Shellcode 1
		m = self.decodersDict['mainz_bindport1'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found mainz shellcode (key: %s port: %s)" % (key, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "mainz"
			return True
		### Mainz / Bielefeld - BindPort Shellcode 2
		m = self.decodersDict['mainz_bindport2'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found mainz shellcode (key: %s port: %s)" % (key, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "mainz"
			return True
		### Mainz / Bielefeld - BindPort Shellcode 3
		m = self.decodersDict['mainz_bindport3'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found mainz shellcode (key: %s port: %s)" % (key, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "mainz"
			return True
		### Mainz / Bielefeld - ConnectBack Shellcode 1
		m = self.decodersDict['mainz_connback1'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found bielefeld shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "bielefeld"
			return True
		### Mainz / Bielefeld - ConnectBack Shellcode 2
		m = self.decodersDict['mainz_connback2'].search( dec_shellcode )
		if m:
			raw_ip = m.groups()[0]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m.groups()[1]
			port = unpack('!H',raw_port)[0]
			self.log_obj.log("found bielefeld shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "bielefeld"
			return True
		### Mainz / Bielefeld - ConnectBack Shellcode 3
		m = self.decodersDict['mainz_connback3'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found bielefeld shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "bielefeld"
			return True
		### Mainz / Bielefeld - embedded URL
		http_result = self.match_url( dec_shellcode )
		if http_result==1 and self.resultSet['result']:
			return True
		return False

	def handle_ulm(self, keys):
		"""Ulm multi-byte XOR shellcode decoder

		Keyword arguments:
		keys -- multi-byte XOR key

		"""
		m1 = False
		m2 = False
		m3 = False
		m4 = False
		i = 0
		while i<=len(keys):
			dec_shellcode = self.decrypt_multi_xor(keys, self.shellcode, i)
			#self.write_hexdump(dec_shellcode, "ulm-%i" % (i), "decoded")
			m1 = self.decodersDict['ulm_bindshell'].search( dec_shellcode )
			m2 = self.decodersDict['ulm_connback'].search( dec_shellcode )
			m3 = self.decodersDict['ulm_bindshell2'].search( dec_shellcode )
			m4 = self.decodersDict['ulm_connback2'].search( dec_shellcode )
			if m1 or m2 or m3 or m4:
				break
			i += 1
		### Ulm bindport
		if m1:
			raw_port = m1.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found ulm shellcode (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "ulm"
			return True
		### Ulm connectback shellcode
		if m2 or m4:
			if m4:
				m2 = m4
			raw_ip = m2.groups()[0]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m2.groups()[1]
			port = unpack('!H',raw_port)[0]
			self.log_obj.log("found ulm shellcode (key: %s, ip: %s, port: %s)" % (keys, ip, port), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "ulm"
			return True
		### Ulm bindport
		if m3:
			raw_port = m3.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found ulm shellcode (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "ulm"
			return True
		return False

	def handle_adenau(self, keys):
		"""Adenau multi-byte XOR shellcode decoder

		Keyword arguments:
		keys -- multi-byte XOR key

		"""
		m1 = False
		m2 = False
		i = 0
		while i<=len(keys):
			dec_shellcode = self.decrypt_multi_xor(keys, self.shellcode, i)
			dec_shellcode2 = self.decrypt_multi_xor(keys, self.shellcode2, i)
			m1 = self.decodersDict['adenau_bindport'].search( dec_shellcode )
			m2 = self.decodersDict['adenau_bindport'].search( dec_shellcode2 )
			if m1 or m2:
				break
			i += 1
		### Adenau bindport
		if m1:
			raw_port = m1.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found adenau shellcode (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "adenau"
			return True
		### Adenau bindport
		if m2:
			raw_port = m2.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found adenau shellcode (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "adenau"
			return True
		return False

	def handle_rothenburg(self, keys):
		"""Rothenburg multi-byte XOR shellcode decoder

		Keyword arguments:
		keys -- multi-byte XOR key

		"""
		m1 = False
		m2 = False
		m3 = False
		m4 = False
		m5 = False
		m6 = False
		i = 0
		while i<=len(keys):
			dec_shellcode = self.decrypt_multi_xor(keys, self.shellcode, i)
			#self.write_hexdump(dec_shellcode, "unknown")
			m1 = self.decodersDict['rothenburg_bindport'].search( dec_shellcode )
			m2 = self.decodersDict['schoenborn_connback'].search( dec_shellcode )
			m3 = self.decodersDict['rothenburg_bindport2'].search( dec_shellcode )
			m4 = self.decodersDict['schoenborn_bindport'].search( dec_shellcode )
			m5 = self.decodersDict['schoenborn_connback2'].search( dec_shellcode )
			m6 = self.decodersDict['schoenborn_portopening'].search( dec_shellcode )
			if m1 or m2 or m3 or m4 or m5 or m6:
				break
			i += 1
		### Rothenburg bindport
		if m1:
			raw_port = m1.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found rothenburg shellcode 1 (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "rothenburg"
			return True
		### Rothenburg connectback shellcode
		if m2 or m5:
			if m5:
				m2 = m5
			raw_ip = m2.groups()[0]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m2.groups()[1]
			port = unpack('!H',raw_port)[0]
			self.log_obj.log("found schoenborn shellcode (key: %s, ip: %s, port: %s)" % (keys, ip, port), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "schoenborn"
			return True
		### Rothenburg bindport
		if m3:
			raw_port = m3.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found rothenburg shellcode 2 (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "rothenburg"
			return True
		### Rothenburg bindport
		if m4:
			raw_port = m4.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found schoenborn shellcode 2 (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "schoenborn"
			return True
		if m6:
			port = m6.groups()[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found schoenborn shellcode 3 (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "schoenborn"
			return True
		return False

	def handle_siegburg(self, key, dec_shellcode):
		"""Siegburg single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key
		dec_shellcode -- already decoded shellcode

		"""
		m = False
		m = self.decodersDict['siegburg_bindshell'].search( dec_shellcode)
		### Siegburg bindport
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.log_obj.log("found siegburg shellcode (key: %s, port: %s)" % (key, port), 9, "info", False, True)
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "siegburg"
			return True
		return False

	def handle_koeln(self, keys):
		"""Koeln multi-byte XOR shellcode decoder

		Keyword arguments:
		keys -- multi-byte XOR key

		"""
		m = False
		i = 0
		while i<=len(keys):
			dec_shellcode = self.decrypt_multi_xor(keys, self.shellcode, i)
			m = self.decodersDict['koeln_bindport'].search( dec_shellcode )
			if m:
				break
			i += 1
		### Koeln bindport
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found koeln shellcode (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "koeln"
			return True
		return False

	def handle_linkbot(self, key, dec_shellcode):
		"""Linkbot single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key
		dec_shellcode -- already decoded shellcode

		"""
		m = False
		m = self.decodersDict['linkbot_connback'].search( dec_shellcode )
		if m:
			raw_ip = m.groups()[0]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m.groups()[1]
			port = unpack('!H',raw_port)[0]
			authkey = b64encode(m.groups()[2])
			self.log_obj.log('found lindau (linkbot) connectback transfer 1 (ip: %s port: %s auth: %s)' % (ip, port, authkey), 9, "info", False, True)
			self.resultSet['found'] = "connectbackfiletrans"
			self.resultSet['passwort'] = authkey
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['result'] = True
			cbackURL = "cbackf://%s:%s/%s" % (ip, port, authkey)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "linkbot"
			return True
		m = self.decodersDict['linkbot_connback2'].search( dec_shellcode )
		if m:
			raw_ip = m.groups()[0]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m.groups()[1]
			port = unpack('!H',raw_port)[0]
			authkey = b64encode(m.groups()[2])
			self.log_obj.log('found lindau (linkbot) connectback transfer 2 (ip: %s port: %s auth: %s)' % (ip, port, authkey), 9, "info", False, True)
			self.resultSet['found'] = "connectbackfiletrans"
			self.resultSet['passwort'] = authkey
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['result'] = True
			cbackURL = "cbackf://%s:%s/%s" % (ip, port, authkey)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "linkbot"
			return True
		m = self.decodersDict['linkbot_connback3'].search( dec_shellcode )
		if m:
			raw_ip = m.groups()[1]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			authkey = b64encode(m.groups()[2])
			self.log_obj.log('found lindau (linkbot) connectback transfer 3 (ip: %s port: %s auth: %s)' % (ip, port, authkey), 9, "info", False, True)
			self.resultSet['found'] = "connectbackfiletrans"
			self.resultSet['passwort'] = authkey
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['result'] = True
			cbackURL = "cbackf://%s:%s/%s" % (ip, port, authkey)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "linkbot"
			return True
		return False

	def handle_schauenburg(self, key, dec_shellcode):
		"""Schauenburg single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key
		dec_shellcode -- already decoded shellcode

		"""
		m = False
		m = self.decodersDict['schauenburg_bindport'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found schauenburg bindport (key: %s, port: %s)" % (key, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "schauenburg"
			return True
		m = False
		m = self.decodersDict['schauenburg_connback'].search( dec_shellcode )
		if m:
			raw_ip = m.groups()[0]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			raw_port = m.groups()[1]
			port = unpack('!H',raw_port)[0]
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found schauenburg reverse shell (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbackf://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "schauenburg"
			return True
		return False

	def handle_berlin(self, key, dec_shellcode):
		"""Berlin single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key
		dec_shellcode -- already decoded shellcode

		"""
		m = self.decodersDict['ftpcmd'].search( dec_shellcode )
		if m:
			self.log_obj.log("Windows CMD FTP checking", 9, "crit", True, False)
			ip = m.groups()[0]
			cipmatch = self.decodersDict['checkIP'].search(ip)
			if cipmatch:
				local = self.check_local(ip)
				if local and self.replace_locals:
					ip = self.attIP
				elif local and not self.replace_locals:
					self.resultSet['isLocalIP'] = True
					self.log_obj.log("local IP found" , 6, "crit", True, True)
			else:
				self.log_obj.log("no IP: %s" % (ip) , 6, "crit", True, True)
			port = m.groups()[1]
			user = m.groups()[2]
			passw = m.groups()[3]
			filename = m.groups()[4]
			filename = self.checkFTPcmdFilename(filename)
			self.log_obj.log("found Windows CMD FTP (server: %s:%s user: %s:%s file: %s)" % (ip,port,user,passw,filename), 9, "info", True, False)
			self.resultSet['host'] = ip
			self.resultSet['port'] = int(port) % 65551
			self.resultSet['found'] = "ftp"
			self.resultSet['username'] = user
			self.resultSet['passwort'] = passw
			self.resultSet['path'] = [filename]
			self.resultSet['result'] = True
			self.resultSet['dlident'] = "%s%i%s" % (self.resultSet['host'].replace('.',''), self.resultSet['port'], filename.replace('/',''))
			ftpURL = "ftp://%s:%s@%s:%s%s" % (user,passw,ipself.resultSet['port'],filename)
			self.resultSet['displayURL'] = ftpURL
			self.resultSet['shellcodeName'] = "berlin"
			return True
		return False

	def handle_leimbach(self, key, dec_shellcode):
		"""Leimbach single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key
		dec_shellcode -- already decoded shellcode

		"""
		m = self.decodersDict['tftp'].search( dec_shellcode )
		if m:
			tftp_command = m.groups()[0]
			ip = m.groups()[2]
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			get_command = m.groups()[3]
			file = m.groups()[4]
			self.log_obj.log("found leimbach tftp download (key: %s, ip: %s, file: %s)" % (key,ip,file), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''),file)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = 69
			self.resultSet['path'] = file
			self.resultSet['found'] = "tftp"
			tftpURL = "tftp://%s:%s/%s" % (ip,self.resultSet['port'],file)
			self.resultSet['displayURL'] = tftpURL
			self.resultSet['shellcodeName'] = "leimbach"
			return True
		### Leimbach - embedded URL
		if self.match_plainTFTP(dec_shellcode) and self.resultSet['result']:
			return True
		http_result = self.match_url( dec_shellcode )
		if http_result==1 and self.resultSet['result']:
			return True
		return False

	def handle_lichtenfels(self, key, dec_shellcode):
		"""Lichtenfels single byte XOR shellcode decoder

		Keyword arguments:
		key -- XOR key
		dec_shellcode -- already decoded shellcode

		"""
		m = self.decodersDict['lichtenfels_connback'].search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = unpack('I',raw_ip)[0]
			ip = pack('I',ip)
			ip = inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found lichtenfels shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			connbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = connbackURL
			self.resultSet['shellcodeName'] = "lichtenfels"
			return True
		return False

	def write_hexdump(self, shellcode=None, extension=None, ownPort="None"):
		"""Write unknown/undetected shellcode as a hexdump to disc for later analysis

		Keyword arguments:
		shellcode -- specific shellcode that was not detected (default None, i.e. use global self.shellcode)
		extension -- use specifial extension on stored hexdump (default None)
		ownPort -- attach the network port of the vulnerability that was exploited to filename (default "None")

		"""
		if not shellcode:
			file_data = "".join(self.shellcode)
		else:
			file_data = "".join(shellcode)
		### ignore zero size hexdumps
		if len(file_data)==0 or (extension=="MS03049" and (file_data.count('PIPE')>=2 or file_data.count('\x50\x00\x49\x00\x50\x00\x45')>=2)) or len(file_data)<100:
			return
		### generate md5 fingerprint of shellcode
		hash = md5(file_data)
		digest = hash.hexdigest()
		if extension!=None:
			filename = "hexdumps/%s-%s-%s.hex" % (extension.strip(), digest, ownPort)
		else:
			filename = "hexdumps/%s-%s.hex" % (digest, ownPort)
		### write hexdump to disc
		if not ospath.exists(filename):
			try:
				fp = open(filename, 'a+')
				fp.write(file_data)
				fp.close()
				self.log_obj.log("(%s) no match, writing hexdump (%s :%s) - %s" % (self.attIP, digest, len(file_data), self.resultSet['vulnname']), 9, "warn", True, True)
			except IOError, e:
				self.log_obj.log("(%s) failed writing hexdump (%s) (%s :%s) - %s" % (self.attIP, e, digest, len(file_data), self.resultSet['vulnname']), 9, "crit", True, True)
				return False
		return True

	def match_direct_file(self, dec_shellcode=None):
		"""Check if given shellcode is an executable file

		Keyword arguments:
		dec_shellcode -- decoded shellcode (default None, i.e. use global self.shellcode)
		"""
		if self.displayShellCode:
			print "starting DirectFile matching ..."
			stdout.flush()
		if not dec_shellcode:
			match = self.decodersDict['directfile'].search( self.shellcode )
		else:
			match = self.decodersDict['directfile'].search( dec_shellcode )
		if match:
			self.resultSet['result'] = True
			self.resultSet['found'] = "directfile"
			self.resultSet['dlident'] = "%s%s%s" % (self.attIP.replace('.',''), self.ownIP.replace('.',''), self.ownPort)
			self.resultSet['isLocalIP'] = False
			self.resultSet['shellcodeName'] = "directfile"
			return 1
		return 0


	def match_url(self, dec_shellcode=None):
		"""Check given shellcode for known http urls

		Keyword arguments:
		dec_shellcode -- decoded shellcode (default None, i.e. use global self.shellcode)
		"""
		try:
			if not dec_shellcode:
				match = self.decodersDict['url'].search( self.shellcode )
			else:
				match = self.decodersDict['url'].search( dec_shellcode )
			if self.displayShellCode:
				print "starting AnyURL matching ..."
				stdout.flush()
			if match:
				#self.write_hexdump(self.shellcode, "http")
				path = match.groups()[0]
				url_obj = urlsplit(path)
				if self.config_dict['verbose_logging']==1:
					self.log_obj.log("found path: %s (%s)" % (path, url_obj), 9, "debug", True, True)
				### ('http', '192.168.116.2:5806', '/x.exe', '', '')
				### ('ftp', 'bla:bla@natout.sfldlib.org:22679', '/bot.exe', '', '')
				if (url_obj[0]!='http' and url_obj[0]!='ftp') or len(url_obj[1])<7 or len(url_obj[2])<1:
					self.log_obj.log("(%s) found unknown/incomplete download URL: %s (%s)" % (self.attIP, match.groups(),self.resultSet['vulnname']), 9, "div", True, False)
					return 2
				if url_obj[0]=='http':
					#self.write_hexdump(self.shellcode, "URL")
					new_url = []
					new_url.append(url_obj[0])
					if url_obj[1].count(':')>0:
						(dl_host, dl_port) = url_obj[1].split(':')
						if len(dl_port)<=0:
							dl_port = '80'
					else:
						dl_host = url_obj[1]
						dl_port = '80'
					### host ersetzen falls locate addresse
					ipmatch = self.decodersDict['checkIP'].search(dl_host)
					if ipmatch:
						if self.replace_locals and self.check_local(dl_host):
							dl_host = self.attIP
						elif self.check_local(dl_host):
							self.resultSet['isLocalIP'] = True
					new_url.append("%s:%s" % (dl_host, dl_port))
					new_url.append(url_obj[2])
					new_url.append(url_obj[3])
					new_url.append(url_obj[4])
					new_url.append('')
					found_url = urlunparse(new_url)
					dlident = "%s%s%s" % (dl_host.replace('.',''),dl_port,url_obj[2].replace('/',''))
					if len(url_obj[3])>0:
						http_path = "%s?%s" % (url_obj[2], url_obj[3])
					else:
						http_path = url_obj[2]
					self.resultSet['path'] = http_path
					self.resultSet['host'] = dl_host
					self.resultSet['port'] = dl_port
					self.resultSet['dlident'] = dlident
					self.resultSet['displayURL'] = found_url
					self.resultSet['found'] = "httpurl"
					self.resultSet['result'] = True
					self.resultSet['shellcodeName'] = "plainurl"
					self.log_obj.log("found download URL: %s" % (found_url), 9, "info", False, True)
					return 1
				elif url_obj[0]=='ftp':
					(userpass, hostport) = url_obj[1].split('@')
					(username, passwort) = userpass.split(':')
					(hostname, port) = hostport.split(':')
					### if ip and not hostname check replace locals
					ipmatch = self.decodersDict['checkIP'].search(hostname)
					if ipmatch:
						if self.replace_locals and self.check_local(hostname):
							hostname = self.attIP
						elif self.check_local(hostname):
							self.resultSet['isLocalIP'] = True
					dlident = "%s%s%s" % (hostname.replace('.',''),port,url_obj[2].replace('/',''))
					self.resultSet['result'] = True
					self.resultSet['found'] = "ftp"
					self.resultSet['host'] = hostname
					self.resultSet['port'] = port
					self.resultSet['username'] = username
					self.resultSet['passwort'] = passwort
					self.resultSet['path'] = [url_obj[2].replace('/','')]
					self.resultSet['dlident'] = dlident
					ftpURL = "ftp://%s:%s@%s:%s/%s" % (username,passwort,hostname,port,self.resultSet['path'])
					self.resultSet['displayURL'] = ftpURL
					self.resultSet['shellcodeName'] = "plainurl"
					self.log_obj.log("found download URL: %s" % (path), 9, "info", True, True)
					return 1
			### no match found
			return 0
		except KeyboardInterrupt:
			raise

	def checkFTPcmdFilename(self, filename):
		"""Extract filename from FTP command (remove leftovers)

		Keyword arguments:
		filename -- string with filename that needs to be cleared from leftovers

		"""
		try:
			if filename.find('&echo')>0:
				filelist = filename.split('&echo')
				filename = filelist[1].strip()
			return filename
		except KeyboardInterrupt:
			raise

	def check_local(self, host):
		"""Check if a given host IP address is a local address

		Keyword arguments:
		host -- IP address to check
		"""
		try:
			for localAddress in self.localIPliste:
				if localAddress.contains(str(host)):
					self.log_obj.log("local ip address found %s replacing with %s" % (host,self.attIP), 9, "div", False, False)
					return True
			return False
		except KeyboardInterrupt:
			raise
		except:
			return False

	def match_embeddedTFTP(self, dec_shellcode=None):
		"""Check if given shellcode contains TFTP commands

		Keyword arguments:
		dec_shellcode -- decoded shellcode to search for TFTP commands (default None, i.e. use global self.shellcode)

		"""
		try:
			if self.displayShellCode:
				print "starting embedded TFTP command matching ..."
				stdout.flush()
			if not dec_shellcode:
				ShellcodeToAnalyse = self.shellcode
			else:
				ShellcodeToAnalyse = dec_shellcode
			match = self.decodersDict['cmdtftp'].search(ShellcodeToAnalyse)
			if match:
				ip = match.groups()[0]
				file = match.groups()[1]
				if self.replace_locals and self.check_local(ip):
					ip = self.attIP
				elif self.check_local(ip):
					self.resultSet['isLocalIP'] = True
				self.log_obj.log("found Windows TFTP command (server: %s file: %s)" % (ip,file), 9, "info", True, False)
				dlident = "%s%s" % (ip.replace('.',''),file)
				self.resultSet['dlident'] = dlident
				self.resultSet['host'] = ip
				self.resultSet['port'] = 69
				self.resultSet['path'] = file
				self.resultSet['found'] = "tftp"
				tftpURL = "tftp://%s:%s/%s" % (ip,self.resultSet['port'],file)
				self.resultSet['displayURL'] = tftpURL
				self.resultSet['result'] = True
				self.resultSet['shellcodeName'] = "plaintftp"
				return True
			return False
		except KeyboardInterrupt:
			raise

	def match_plainFTP(self, dec_shellcode=None):
		"""Check if given shellcode contains FTP commands

		Keyword arguments:
		dec_shellcode -- decoded shellcode to search for TFTP commands (default None, i.e. use global self.shellcode)

		"""
		try:
			### Match Plain FTP CMD 3 shellcode
			if self.displayShellCode:
				print "starting Plain FTP CMD 3 Shell matching ..."
				stdout.flush()
			if not dec_shellcode:
				ShellcodeToAnalyse = self.shellcode
			else:
				ShellcodeToAnalyse = dec_shellcode
			match = self.decodersDict['ftpcmd3ip'].search(ShellcodeToAnalyse)
			if match:
				ip = match.groups()[0]
				position = ShellcodeToAnalyse.find(ip)
				Cutshellcode = ShellcodeToAnalyse[position:]
				cipmatch = self.decodersDict['checkIP'].search(ip)
				if cipmatch:
					local = self.check_local(ip)
					if local and self.replace_locals:
						ip = self.attIP
					elif local and not self.replace_locals:
						self.resultSet['isLocalIP'] = True
						self.log_obj.log("local IP found" , 6, "crit", True, True)
				else:
					self.log_obj.log("no IP: %s" % (ip) , 6, "crit", True, True)
					self.log_obj.log("complete shellcode: %s" % ([dec_shellcode]), 6, "crit", True, False)
				port = match.groups()[1]
				if not port:
					port = 21
					self.log_obj.log("no Port setting default 21" , 6, "crit", True, True)
				if int(port)<1 or int(port)>65550:
					self.log_obj.log("wrong port: %s" % (port), 6, "crit", True, True)
					self.log_obj.log("trying default 21" , 6, "crit", True, True)
					port = 21
				match2 = self.decodersDict['ftpcmd3userpass'].search(Cutshellcode)
				if match2:
					if match2.groups()[0] != None:
						user = match2.groups()[0].strip()
						passw = match2.groups()[1].strip()
					elif match2.groups()[2] != None:
						user = match2.groups()[2].strip()
						passw = match2.groups()[3].strip()
					elif match2.groups()[4] != None:
						user = match2.groups()[4].strip()
						passw = match2.groups()[5].strip()
					else:
						user = match2.groups()[6].strip()
						passw = match2.groups()[7].strip()
					#self.log_obj.log("found user %s and pass %s" % (user, passw), 6, "crit", True, True)
					match3 = self.decodersDict['ftpcmd3binary'].findall(Cutshellcode)
					if match3:
						filenameList = []
						for fileMatch in match3:
							if fileMatch.count(' ')<=0:
								filenameList.append(fileMatch.strip())
							else:
								moreThanOneList = fileMatch.split(' ')
								for moreItem in moreThanOneList:
									if moreItem!='':
										filenameList.append(moreItem)
						filenameList = list(set(filenameList))
						### FIXME:
						#if "/hail/windf.exe" in filenameList:
						#	filenameList.append('windf.exe')
						self.log_obj.log("found Windows CMD 3 FTP (server: %s:%s user: %s:%s file: %s)" % (ip,port,user,passw,filenameList), 9, "info", True, False)
						self.resultSet['host'] = ip
						self.resultSet['port'] = int(port)
						self.resultSet['found'] = "ftp"
						self.resultSet['username'] = user
						self.resultSet['passwort'] = passw
						self.resultSet['path'] = filenameList
						self.resultSet['result'] = True
						self.resultSet['dlident'] = "%s%i%s" % (ip.replace('.',''),self.resultSet['port'],filenameList[0].replace('/',''))
						ftpURL = "ftp://%s:%s@%s:%s/%s" % (user, passw, ip, self.resultSet['port'], filenameList)
						self.resultSet['displayURL'] = ftpURL
						self.resultSet['shellcodeName'] = "plainftp"
						return True
					else:
						if self.config_dict['verbose_logging']==1:
							self.log_obj.log("no file found: %s" % (Cutshellcode), 9, "crit", True, False)
						return False
				else:
					if self.config_dict['verbose_logging']==1:
						self.log_obj.log("no username/password found: %s" % (Cutshellcode), 9, "crit", True, False)
					return False
			else:
				if self.config_dict['verbose_logging']==1:
					self.log_obj.log("no remote host found: %s" % (ShellcodeToAnalyse), 9, "crit", True, False)
				return False
			return False
		except KeyboardInterrupt:
			raise

	def match_FTPold(self):
		"""Old method to check for FTP commands, currently not used

		Deprecated and can be removed in the future

		"""
		try:
			### Match Plain FTP CMD Shell shellcode
			if self.displayShellCode:
				print "starting Plain FTP CMD Shell matching ..."
				stdout.flush()
			match = self.decodersDict['ftpcmd'].search(self.shellcode)
			if match:
				#self.log_obj.log("Windows CMD FTP checking", 9, "crit", True, False)
				ip = match.groups()[0]
				cipmatch = self.decodersDict['checkIP'].search(ip)
				if cipmatch:
					local = self.check_local(ip)
					if local and self.replace_locals:
						ip = self.attIP
					elif local and not self.replace_locals:
						self.resultSet['isLocalIP'] = True
						self.log_obj.log("local IP found" , 6, "crit", True, True)
				else:
					self.log_obj.log("no IP: %s" % (ip) , 6, "crit", True, True)
				port = match.groups()[1]
				user = match.groups()[2]
				passw = match.groups()[3]
				filename = match.groups()[4]
				filename = self.checkFTPcmdFilename(filename)
				self.log_obj.log("found Windows CMD FTP (server: %s:%s user: %s:%s file: %s)" % (ip,port,user,passw,filename), 9, "info", True, False)
				self.resultSet['host'] = ip
				self.resultSet['port'] = int(port) % 65551
				self.resultSet['found'] = "ftp"
				self.resultSet['username'] = user
				self.resultSet['passwort'] = passw
				self.resultSet['path'] = [filename]
				self.resultSet['result'] = True
				self.resultSet['dlident'] = "%s%i%s" % (ip.replace('.',''), self.resultSet['port'], filename.replace('/',''))
				ftpURL = "ftp://%s:%s@%s:%s/%s" % (user, passw, ip, self.resultSet['port'], filename)
				self.resultSet['displayURL'] = ftpURL
				self.resultSet['shellcodeName'] = "plainftpold"
				return True
			### Match Plain FTP CMD 2 Shell shellcode
			if self.displayShellCode:
				print "starting Plain FTP CMD 2 Shell matching ..."
				stdout.flush()
			match = self.decodersDict['ftpcmd2'].search(self.shellcode)
			if match:
				#self.log_obj.log("Windows CMD FTP 2 checking", 9, "crit", True, False)
				###('hack95fy.3322.or', None, 'sb', 'sb', 'ftp.txt\r\necho bin>>ftp.txt\r\necho get sx.exe>>', 'sx.exe', 'ftp.txt\r\necho get qq.exe>>', 'qq.exe', 'ftp.txt\r\necho get 3389.exe>>', '3389.exe')
				#print match.groups()
				ip = match.groups()[0]
				if self.replace_locals and self.check_local(ip):
					ip = self.attIP
				elif self.check_local(ip):
					self.resultSet['isLocalIP'] = True
				port = match.groups()[1]
				if not port:
					port = 21
				user = match.groups()[2]
				passw = match.groups()[3]
				filename1 = match.groups()[5]
				filename2 = match.groups()[7]
				filename3 = match.groups()[9]
				files = [filename1]
				if filename2!=None:
					files.append(filename2)
				if filename3!=None:
					files.append(filename3)
				self.log_obj.log("found Windows CMD FTP 2 (server: %s:%s user: %s:%s file: %s)" % (ip,port,user,passw,files), 9, "info", True, False)
				self.resultSet['host'] = ip
				self.resultSet['port'] = int(port) % 65551
				self.resultSet['found'] = "ftp"
				self.resultSet['username'] = user
				self.resultSet['passwort'] = passw
				self.resultSet['path'] = files
				self.resultSet['result'] = True
				self.resultSet['dlident'] = "%s%i" % (ip.replace('.',''), self.resultSet['port'])
				self.resultSet['displayURL'] = "ftp://%s:%s@%s:%s/%s" % (user, passw, ip, self.resultSet['port'], files)
				self.resultSet['shellcodeName'] = "plainftpold"
				return True
			return False
		except KeyboardInterrupt:
			raise

	def match_plainTFTP(self, dec_shellcode=None):
		"""Check for plain TFTP commands in given shellcode

		Keyword arguments:
		dec_shellcode -- decoded shellcode (default None, i.e. use global self.shellcode)

		"""
		try:
			### Match Plain TFTP 1 CMD Shell shellcode
			if self.displayShellCode:
				print "starting Plain TFTP 1 CMD Shell matching ..."
				stdout.flush()
			if not dec_shellcode:
				match = self.decodersDict['tftp1'].search(self.shellcode)
			else:
				match = self.decodersDict['tftp1'].search(dec_shellcode)
			if match:
				#self.log_obj.log("Windows CMD TFTP 1 checking", 9, "crit", True, False)
				if match.groups()[2]!=None:
					ip = match.groups()[2]
					file = match.groups()[4]
				else:
					ip = match.groups()[7]
					file = match.groups()[9]
				if self.replace_locals and self.check_local(ip):
					ip = self.attIP
				elif self.check_local(ip):
					self.resultSet['isLocalIP'] = True
				self.log_obj.log("found Windows CMD TFTP 1 (server: %s file: %s)" % (ip,file), 9, "info", True, False)
				dlident = "%s%s" % (ip.replace('.',''),file)
				self.resultSet['dlident'] = dlident
				self.resultSet['host'] = ip
				self.resultSet['port'] = 69
				self.resultSet['path'] = file
				self.resultSet['found'] = "tftp"
				tftpURL = "tftp://%s:%s/%s" % (ip,self.resultSet['port'],file)
				self.resultSet['displayURL'] = tftpURL
				self.resultSet['result'] = True
				self.resultSet['shellcodeName'] = "plaintftp"
				return True
			### Match Plain TFTP CMD Shell shellcode
			if self.displayShellCode:
				print "starting Plain TFTP 2 CMD Shell matching ..."
				stdout.flush()
			if not dec_shellcode:
				match = self.decodersDict['tftp'].search(self.shellcode)
			else:
				match = self.decodersDict['tftp'].search(dec_shellcode)
			if match:
				#self.log_obj.log("Windows CMD TFTP checking", 9, "crit", True, False)
				ip = match.groups()[2]
				if self.replace_locals and self.check_local(ip):
					ip = self.attIP
				elif self.check_local(ip):
					self.resultSet['isLocalIP'] = True
				file = match.groups()[4]
				self.log_obj.log("found Windows CMD TFTP (server: %s file: %s)" % (ip,file), 9, "info", True, False)
				dlident = "%s%s" % (ip.replace('.',''),file)
				self.resultSet['dlident'] = dlident
				self.resultSet['host'] = ip
				self.resultSet['port'] = 69
				self.resultSet['path'] = file
				self.resultSet['found'] = "tftp"
				tftpURL = "tftp://%s:%s/%s" % (ip,self.resultSet['port'],file)
				self.resultSet['displayURL'] = tftpURL
				self.resultSet['result'] = True
				self.resultSet['shellcodeName'] = "plaintftp"
				return True
			return False
		except KeyboardInterrupt:
			raise
