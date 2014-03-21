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

import asyncore
import asynchat
import StringIO
import sys
import traceback
import socket
import time

import amun_logging
import shellemulator
import shellcode_mgr_core

class req_handler(asynchat.async_chat):
	def __init__(self, divLogger, config_dict, decodersDict):
		self.shellcmds = []
		self.bindport_closed = False
		self.divLogger = divLogger
		self.config_dict = config_dict
		self.shellcode_manager = shellcode_mgr_core.shell_mgr(decodersDict, divLogger['shellcode'], config_dict)
		self.log_obj = amun_logging.amun_logging("bindport", divLogger['download'])
		self.shellemu = shellemulator.shellemulator(divLogger['shellemulator'])
		self.shellInfo = self.shellemu.getShellInfoLine()

	def handle_incoming_connection(self, socket_object, addr, currentDownloads, item, event_dict, replace_locals, attIP, attPort, ownIP, ownPort, bindports):
		asynchat.async_chat.__init__(self, socket_object)
		self.socket_object = socket_object
		self.socket_object.settimeout(60.0)
		self.settimeout(60.0)
		self.item = item
		self.event_dict = event_dict
		self.currentDownloads = currentDownloads
		self.bindports = bindports
		self.replace_locals = replace_locals
		if self.config_dict['verbose_logging'] == 1:
			self.log_obj.log("incoming data connection: %s to port: %s" % (attIP, ownPort), 9, "debug", True, True)
		try:
			bytesTosend = len(self.shellInfo)
			while bytesTosend>0:
				sendBytes = self.socket_object.send(self.shellInfo)
				bytesTosend = bytesTosend - sendBytes
				self.shellInfo = self.shellInfo[sendBytes:]
		except socket.error, e:
			self.handle_close()
			return
		if sendBytes<=0:
			self.handle_close()
			return
		self.attIP = attIP
		self.attPort = attPort
		self.ownIP = ownIP
		self.ownPort = ownPort
		self.shellemu.setConnectionInformation(attIP,attPort,ownIP,ownPort)

	def handle_read(self):
		try:
			bytes = self.recv(1024)
		except socket.error, e:
			self.log_obj.log("handler socket error: %s" % (e), 9, "crit", True, False)
			bytes = ""
		self.collect_incoming_data(bytes)

	def collect_incoming_data(self, data):
		if data!="" and data!='local quit':
			self.log_obj.log("data received: %s (%s)" % (data.strip('\r\n'), self.attIP), 6, "warn", True, False)
			self.shellcmds.append(data)
			self.bindports[self.item['dlident']] = "%s,%s,%s" % (self.item['own_host'],self.item['port'],int(time.time()))
			try:
				closeShell = False
				(prompt,closeShell,reply) = self.shellemu.shellInterpreter(data)
				if closeShell:
					self.handle_close()
				else:
					if reply!="":
						bytesTosend = len(reply)
						while bytesTosend>0:
							sendBytes = self.socket_object.send(reply)
							bytesTosend = bytesTosend - sendBytes
							reply = reply[sendBytes:]
					bytesTosend = len(prompt)
					while bytesTosend>0:
						sendBytes = self.socket_object.send(prompt)
						bytesTosend = bytesTosend - sendBytes
						prompt = prompt[sendBytes:]
			except socket.error, e:
				self.handle_close()
				return
		elif data=='local quit':
			self.log_obj.log("received local quit", 12, "debug", True, False)
			self.handle_close()
		elif data=="":
			self.log_obj.log("no more data received", 12, "debug", False, False)
			self.handle_close()
		else:
			self.log_obj.log("wrong data received (%s)" % (data), 12, "debug", True, True)
			self.handle_close()

	def handle_expt(self):
		pass

	def handle_close(self):
		if not self.bindport_closed:
			data = "".join(self.shellcmds)
			data_length = len(data)
			if data_length>0:
				### perform regex tests
				self.check_shellcommands(data)
			self.log_obj.log("closing bindport (%s:%s)" % (self.item['own_host'],self.item['port']), 12, "debug", True, False)
			try:
				self.shutdown(socket.SHUT_RDWR)
			except socket.error, e:
				pass
			self.remove_download_entry()
			self.bindport_closed = True
		self.close()

	def check_shellcommands(self, commands):
		try:
			vulnResult = {}
			vulnResult['vulnname'] = self.item['vulnname']
			vulnResult['shellcode'] = commands
			shellCResult = self.shellcode_manager.start_shellcommand_matching(vulnResult, self.attIP, self.ownIP, self.ownPort, self.replace_locals, False)
			if len(shellCResult)>0:
				for result in shellCResult:
					if result['result']:
						dlidentifier = "%s%s%s" % (self.attIP, self.ownIP,result['path'])
						if not self.event_dict['download'].has_key(dlidentifier):
							self.event_dict['download'][dlidentifier] = result
						if result['found'] == "ftp":
							self.log_obj.log("FTP from %s:%s (User: %s Pass: %s) file(s) %s" % (result['host'],result['port'],result['username'],result['passwort'],result['path']), 12, "info", True, False)
						elif result['found'] == "tftp":
							self.log_obj.log("TFTP from %s:%s file %s" % (result['host'],result['port'],result['path']), 12, "info", True, False)
						elif result['found'] == "directfile":
							self.log_obj.log("Direct file submission detected from %s:%s" % (self.attIP,self.attPort), 12, "info", True, True)
							self.createFileEvent(vulnResult['shellcode'], len(vulnResult['shellcode']), vulnResult['vulnname'], "direct://%s:%s" % (self.attIP,self.attPort))
			else:
				self.log_obj.log("no detection by shellcode manager", 12, "crit", True, True)
		except KeyboardInterrupt:
			raise

	def createFileEvent(self, file_data, file_data_length, vulnname, downURL):
		event_item = (file_data_length, self.attIP, self.attPort, self.ownIP, "DirectFile", file_data, vulnname, downURL)
		id = "%s%s" % (self.attIP.replace('.',''), self.ownPort)
		self.event_dict['successfull_downloads'][id] = event_item

	def remove_download_entry(self):
		try:
			if self.currentDownloads.has_key(self.item['dlident']):
				del self.currentDownloads[self.item['dlident']]
			if self.bindports.has_key(self.item['dlident']):
				del self.bindports[self.item['dlident']]
		except KeyboardInterrupt:
			raise
		except:
			raise

	def check_local(self, host, attIP):
		try:
			for localAddress in self.localIPliste:
				if localAddress.contains(str(host)):
					self.log_obj.log("local ip address found %s (attacker ip: %s)" % (host, attIP), 9, "div", False, False)
					return True
			return False
		except KeyboardInterrupt:
			raise
		except:
			return False

	def handle_error(self):
		f = StringIO.StringIO()
		traceback.print_exc(file=f)
		self.log_obj.log( f.getvalue(), 9, "crit", True, True)
		self.close()
		sys.exit(1)


class bindPort(asyncore.dispatcher):
	def __init__(self, item, currentDownloads, bindports, event_dict, divLogger, config_dict, currentSockets, decodersDict):
		asyncore.dispatcher.__init__(self)
		self.divLogger = divLogger
		self.log_obj = amun_logging.amun_logging("bindport", divLogger['download'])
		self.item = item
		self.bindports = bindports
		self.currentDownloads = currentDownloads
		self.currentSockets = currentSockets
		self.event_dict = event_dict
		self.config_dict = config_dict
		self.decodersDict = decodersDict
		self.replace_locals = config_dict['replace_locals']
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.set_reuse_addr()
		self.identifier = "%s%s" % (item['own_host'],item['port'])
		try:
			self.bind( (item['own_host'], int(item['port'])) )
		except socket.error, e:
			self.log_obj.log("port already in use? (%s): %s" % (item['port'],e), 6, "crit", True, True)
			self.remove_download_entry()
			try:
				self.close()
			except:
				pass
			return
		self.listen(1)
		if not self.currentSockets.has_key(self.identifier):
			self.currentSockets[self.identifier] = (int(time.time()), self.socket)
		bindports[item['dlident']] = "%s,%s,%s" % (item['own_host'],item['port'],int(time.time()))
		self.log_obj.log("%s initialized on port %s" % (item['own_host'], item['port']), 6, "info", True, False)

	def remove_download_entry(self):
		if self.currentDownloads.has_key(self.item['dlident']):
			del self.currentDownloads[self.item['dlident']]
		if self.bindports.has_key(self.item['dlident']):
			del self.bindports[self.item['dlident']]
		if self.currentSockets.has_key(self.identifier):
			del self.currentSockets[self.identifier]

	def handle_close(self):
		try:
			self.shutdown(socket.SHUT_RDWR)
		except:
			pass
		self.close()
		self.log_obj.log("%s port closed %s" % (self.item['own_host'], self.item['port']), 6, "info", False, False)

	def handle_accept(self):
		try:
			(conn, addr) = self.accept()
			(attIP, attPort) = conn.getpeername()
			(ownIP, ownPort) = conn.getsockname()
			self.log_obj.log("incoming data connection: %s:%s to port: %s" % (attIP, attPort, ownPort), 9, "debug", True, False)
			handler = req_handler(self.divLogger, self.config_dict, self.decodersDict).handle_incoming_connection(conn, addr, self.currentDownloads, self.item, self.event_dict, self.replace_locals, attIP, attPort, ownIP, ownPort, self.bindports)
		except socket.error, e:
			self.log_obj.log("error: %s" % (e), 6, "crit", True, True)
		except KeyboardInterrupt:
			raise
		self.handle_close()
		return

	def handle_connect(self):
		pass

	def handle_expt(self):
		pass

	def handle_error(self):
		f = StringIO.StringIO()
		traceback.print_exc(file=f)
		self.log_obj.log( f.getvalue(), 9, "crit", True, True)
		self.close()
		sys.exit(1)
