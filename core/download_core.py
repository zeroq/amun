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
from StringIO import StringIO
import socket
import os
import hashlib
import traceback
import base64
import time
import re
import sys

import amun_logging
import shellcode_mgr_core
import shellemulator

#
# Handles HTTP URL downloads
#
class download_http(asyncore.dispatcher):
        def __init__(self, item, currDownl, event_dict, config_dict, currentSockets, dlLogger):
		asyncore.dispatcher.__init__(self)
		self.log_obj = amun_logging.amun_logging("http_download", dlLogger)
		self.connection_closed = False
		self.currentDownloads = currDownl
		self.currentSockets = currentSockets
		self.event_dict = event_dict
		self.config_dict = config_dict
		self.vulnName = item['vulnname']
		self.downURL = item['displayURL']
		self.dlident = item['dlident']
		self.victimIP = item['own_host']
		self.remote_ip = item['hostile_host']
		self.active = False
		self.received = StringIO()
		self.header = []
		self.content = []
		self.content_length = 0
		### check for incomplete path
		if item['path'] == '/x.' or item['path'] == '/x.e' or item['path'] == '/x.ex':
			item['path'] = '/x.exe'
		#self.buffer = 'GET %s HTTP/1.0\r\nUser-Agent: Microsoft Internet Explorer\nAccept: */*\nHost: %s\nConnection: close\r\n\r\n' % (item['path'], item['host'])
		#self.buffer = 'GET %s HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; NN4.1.0.0; .NET CLR 1.1.4322)\nAccept: */*\nHost: %s\nConnection: close\r\n\r\n' % (item['path'], item['host'])
		self.buffer = 'GET %s HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\nAccept: */*\nHost: %s\nConnection: close\r\n\r\n' % (item['path'], item['host'])
		self.path = self.buffer.strip()
		self._address = (item['host'], int(item['port']))
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		#self.bind( (item['own_host'], 0) )
		self.set_reuse_addr()
		self.identifier = "%s%s%s%s" % (self.dlident, item['host'], item['port'], item['own_host'])
		try:
			self.connect( self._address )
			self.active = True
		except socket.error, e:
			if e[0]==111:
				self.log_obj.log("failed to connect: connection refused (%s)" % (item['host']), 12, "crit", False, False)
			else:
				self.log_obj.log("failed to connect: %s (%s)" % (e, item['host']), 12, "crit", False, False)
			### add host to refused list, block connections for 3 minutes
			if config_dict['block_refused'] == 1:
				item_id = str(item['host'])
				self.event_dict['refused_connections'][item_id] = int(time.time())
			### close connection
			self.active = False
			self.handle_close()
		if not self.currentSockets.has_key(self.identifier):
			so_item = (int(time.time()), self.socket)
			self.currentSockets[self.identifier] = so_item
		if config_dict['verbose_logging']==1:
			self.log_obj.log("HTTP from %s GET %s (Display: %s)" % (item['host'], item['path'], item['displayURL']), 12, "debug", True, True)

	def handle_connect(self):
		pass

	def handle_expt(self):
		pass

	def handle_error(self):
		self.log_obj.log("http_handle_error", 0, "crit", True, True)
		f = StringIO()
		traceback.print_exc(file=f)
		self.log_obj.log(f.getvalue(), 0, "crit", True, True)
		self.close()
		raise

	def createFileEvent(self, file_data, file_data_length):
		event_item = (file_data_length, self._address[0], self._address[1], self.victimIP, "HTTP", file_data, self.vulnName, self.downURL)
		id = "%s%s" % (self._address[0].replace('.',''), self._address[1])
		self.event_dict['successfull_downloads'][id] = event_item

        def handle_close(self):
		if not self.connection_closed:
			try:
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			data = "".join(self.content)
			data_length = len(data)
			if data_length>0:
				if self.config_dict['check_http_filesize'] == 1:
					if data_length == self.content_length:
						self.createFileEvent(data, data_length)
					else:
						mess = "different size %i :: %i (%s:%s - %s)" % (data_length, self.content_length, self._address[0],self._address[1],self.path.strip())
						self.log_obj.log(mess, 12, "crit", True, False)
				else:
					self.createFileEvent(data, data_length)
			self.remove_downl_entry()
        	        self.active = False
			self.connection_closed = True
                self.close()

	def remove_downl_entry(self):
		if self.currentDownloads.has_key(self.dlident):
			del self.currentDownloads[self.dlident]
		if  self.currentSockets.has_key(self.identifier):
			del self.currentSockets[self.identifier]

	def extract_length(self, http_header):
		length_expr = re.compile('.*(Content-Length:) ([0-9]+)')
		m = length_expr.search(http_header)
		if m:
			return int(m.groups()[1])
		else:
			return 0

        def handle_read(self):
                try:
                        if self.active:
                                if not len(self.header):
                                        self.received.write(self.recv(1024))
                                        v = self.received.getvalue()
					self.content_length = self.extract_length(v)
                                        if v.find('\r\n\r\n') > -1:
                                                self.content.append(v[v.find('\r\n\r\n')+4:])
                                                self.header = v[:v.find('\r\n\r\n')].split('\r\n')
                                                line = self.header[0].split(' ',2)
                                                self.status = line[1]
                                                if not self.status in ['206','200']:
							self.log_obj.log("Unknown Response: %s (%s)" % (self.status,self.downURL), 12, "crit", True, True)
							self.log_obj.log("Unknown Header: %s (%s)" % (self.status,self.header), 12, "crit", True, True)
							self.log_obj.log("Unknown Content: %s (%s)" % (self.status,self.content), 12, "crit", True, True)
							self.active = False
							self.handle_close()
							return
						elif self.status in ['302']:
							self.log_obj.log("received content moved reply for (%s)" % (self.downURL), 12, "debug", True, False)
							for item in self.header:
								if item.startswith('Location:'):
									movedToURL = item[9:].strip()
									self.log_obj.log("moved to (%s)" % (movedToURL), 12, "debug", True, False)
									vulnResult = {}
									vulnResult['vulnname'] = self.vulnName
									vulnResult['shellcode'] = movedToURL
									shellResultList = self.shellcode_manager.start_matching( vulnResult, self.remote_ip, self.victimIP, 1, self.config_dict['replace_locals'], False)
									if len(shellResultList)>0:
										for resultSet in shellResultList:
											if resultSet['result'] and not self.event_dict['download'].has_key(resultSet['dlident']):
												self.event_dict['download'][resultSet['dlident']] = resultSet
											else:
												self.log_obj.log("Unknown: %s (%s)" % (movedToURL, self.header), 12, "crit", True, True)
									else:
										self.log_obj.log("Unknown: %s (%s)" % (movedToURL, self.header), 12, "crit", True, True)
							self.active = False
							self.handle_close()
							return
                                else:
                                        data = self.recv(1024)
					if len(data)>0:
						if len(data)<10 and len(self.content)==0:
							self.log_obj.log("received http (%s) (%s)" % (data, self.downURL), 12, "debug", True, False)
	                                        self.content.append(data)
						### successful read -> increase timeout
						item = (int(time.time()), self.socket)
						self.currentSockets[self.identifier] = item
					else:
						self.log_obj.log("received empty http (%s) (%s)" % (len(data),self.downURL), 12, "debug", False, False)
						self.handle_close()
                        else:
                                self.handle_close()
                except socket.error, e:
			if e[0]==110:
				self.log_obj.log("connection timeout (%s)" % (self.downURL), 12, "crit", False, False)
			elif e[0]==111:
				self.log_obj.log("connection refused (%s)" % (self.downURL), 12 , "crit", False, False)
			elif e[0]==113:
				self.log_obj.log("no route to host (%s)" % (self.downURL), 12 , "crit", False, False)
			else:
				self.log_obj.log("handle_read() %s %s" % (e, self.downURL), 12, "crit", False, True)
			### add host to refused list, block connections for some time
			if self.config_dict['block_refused'] == 1:
				item_id = str(self._address[0])
				self.event_dict['refused_connections'][item_id] = int(time.time())
			### close connection
			self.active = False
			self.handle_close()
		except StandardError, e:
			print "download_core.py standard error:"
			print e
			raise
		except KeyboardInterrupt:
			raise

        def writable(self):
                return (len(self.buffer) > 0)

        def handle_write(self):
                try:
                        if self.active:
				if len(self.buffer)>0:
					bytesTosend = len(self.buffer)
					while bytesTosend>0:
		                                sent = self.send(self.buffer)
						bytesTosend = bytesTosend - sent
        		                        self.buffer = self.buffer[sent:]
                        else:
                                self.handle_close()
                except socket.error, e:
                        self.log_obj.log("handle_write() %s" % (e), 12, "crit", False, True)
                        self.handle_close()


#
# Handles ConnectBack Filetransfer and Shell
#
class download_connectback(asyncore.dispatcher):
	def __init__(self, item, currDownl, currentSockets, divLogger, event_dict, config_dict, display_shell, authkey, decodersDict):
		asyncore.dispatcher.__init__(self)
		self.log_obj = amun_logging.amun_logging("connback_download", divLogger['download'])
		self.connection_closed = False
		self.shellcode_manager = shellcode_mgr_core.shell_mgr(decodersDict, divLogger['shellcode'], config_dict)
		self.currentDownloads = currDownl
		self.currentSockets = currentSockets
		self.event_dict = event_dict
		self.config_dict = config_dict
		self.vulnName = item['vulnname']
		self.downURL = item['displayURL']
		self.dlident = item['dlident']
		self.victimIP = item['own_host']
		self.display_shell = display_shell
		self.active = False
		self.authkey = authkey
		self.content = []
		if self.display_shell:
			if config_dict['verbose_logging']==1:
				self.log_obj.log("displaying shell to %s" % (item['host']), 12, "debug", True, True)
			self.shellemu = shellemulator.shellemulator(divLogger['shellemulator'])
			self.buffer = self.shellemu.getShellInfoLine()
		elif authkey!="None":
			self.authkey = base64.b64decode(authkey)
			self.buffer = self.authkey
		else:
			self.buffer = ''
		self._address = (item['host'], int(item['port']))
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		#self.bind( (item['own_host'], 0) )
		self.set_reuse_addr()
		self.identifier = "%s%s%s%s" % (self.dlident, item['host'], item['port'], item['own_host'])
		try:
			self.connect( self._address )
			self.active = True
		except socket.error, e:
			if e[0]==111:
				if config_dict['verbose_logging']==1:
					self.log_obj.log("failed to connect: connection refused (%s)" % (item['host']), 12, "crit", True, True)
				else:
					self.log_obj.log("failed to connect: connection refused (%s)" % (item['host']), 12, "crit", False, False)
			else:
				if config_dict['verbose_logging']==1:
					self.log_obj.log("failed to connect: %s (%s)" % (e, item['host']), 12, "crit", True, True)
				else:
					self.log_obj.log("failed to connect: %s (%s)" % (e, item['host']), 12, "crit", False, False)
			### add host to refused list, block connections for 3 minutes
			if self.config_dict['block_refused'] == 1:
				item_id = str(item['host'])
				self.event_dict['refused_connections'][item_id] = int(time.time())
			### close connection
			self.active = False
			self.handle_close()
		if not self.currentSockets.has_key(self.identifier):
			so_item = (int(time.time()), self.socket)
			self.currentSockets[self.identifier] = so_item
		if self.display_shell:
			(ownIP, ownPort) = self.getsockname()
			self.shellemu.setConnectionInformation(item['host'],item['port'],ownIP,ownPort)
		if config_dict['verbose_logging']==1:
			self.log_obj.log("cBACK to %s:%s (URL: %s Shell: %s)" % (item['host'], item['port'], self.downURL, self.display_shell), 12, "debug", True, True)
		else:
			self.log_obj.log("cBACK to %s:%s (URL: %s Shell: %s)" % (item['host'], item['port'], self.downURL, self.display_shell), 12, "debug", True, False)

	def handle_connect(self):
		pass

	def handle_expt(self):
		pass

	def handle_error(self):
		self.log_obj.log("connback_handle_error", 0, "crit", True, True)
		f = StringIO()
		traceback.print_exc(file=f)
		self.log_obj.log(f.getvalue(), 0, "crit", True, True)
		self.close()
		sys.exit(1)

	def createFileEvent(self, file_data, file_data_length):
		event_item = (file_data_length, self._address[0], self._address[1], self.victimIP, "ConnBack", file_data, self.vulnName, self.downURL)
		id = "%s%s" % (self._address[0].replace('.',''), self._address[1])
		self.event_dict['successfull_downloads'][id] = event_item

	def handle_close(self):
		if not self.connection_closed:
			try:
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			data = "".join(self.content)
			data_length = len(data)
			if data_length>0:
				if self.display_shell:
					### if shell we need to interpret the commands
					self.check_shellcommands( data )
				else:
					self.createFileEvent(data, data_length)
					if self.config_dict['verbose_logging']==1:
						self.log_obj.log("cBACK download complete (URL: %s)" % (self.downURL), 12, "debug", True, True)
			else:
				if self.config_dict['verbose_logging']==1:
					self.log_obj.log("cBACK no data received (URL: %s)" % (self.downURL), 12, "debug", True, True)
			self.remove_downl_entry()
			self.active = False
			self.connection_closed = True
		self.close()

	def check_shellcommands(self, commands):
		try:
			try:
				(ownIP, ownPort) =self.getsockname()
			except socket.error, e:
				self.log_obj.log("socket error: %s" % (e), 0, "crit", True, True)
				return
			vulnResult = {}
			vulnResult['vulnname'] = self.vulnName
			vulnResult['shellcode'] = commands
			shellCResult = self.shellcode_manager.start_shellcommand_matching(vulnResult, self._address[0], ownIP, ownPort, self.config_dict['replace_locals'], False)
			if len(shellCResult)>0:
				for result in shellCResult:
					if result['result']:
						identifier = "%s%s%s%s" % (self._address[0], self._address[1], ownIP, ownPort)
						### attach to download events
						if not self.event_dict['download'].has_key(result['dlident']):
							self.event_dict['download'][result['dlident']] = result
					else:
						self.log_obj.log("received unknown shell commands: (%s)" % (commands), 0, "debug", True, True)
			return
		except KeyboardInterrupt:
			raise

        def remove_downl_entry(self):
                if self.currentDownloads.has_key(self.dlident):
                        del self.currentDownloads[self.dlident]
		if  self.currentSockets.has_key(self.identifier):
			del self.currentSockets[self.identifier]

	def handle_read(self):
		try:
			if self.active:
				data = self.recv(1024)
				self.content.append(data)
				### successful read -> increase timeout
				if len(data)>0:
					item = (int(time.time()), self.socket)
					self.currentSockets[self.identifier] = item
					self.buffer = ''
				if self.display_shell:
					(prompt,closeShell,reply) = self.shellemu.shellInterpreter(data)
					if closeShell:
						self.active = False
					self.buffer = "%s%s" % (reply,prompt)
			else:
				self.handle_close()
		except socket.error, e:
			if e[0]==110:
				self.log_obj.log("connection timeout (%s)" % (self.downURL) , 12, "crit", False, False)
			elif e[0]==111:
				self.log_obj.log("connection refused (%s)" % (self.downURL) , 12, "crit", False, False)
			elif e[0]==113:
				self.log_obj.log("no route to host (%s)" % (self.downURL) , 12, "crit", False, False)
			else:
				self.log_obj.log("handle_read() %s %s" % (e, self.downURL), 12, "crit", False, True)
			### add host to refused list, block connections
			if self.config_dict['block_refused'] == 1:
				item_id = str(self._address[0])
				self.event_dict['refused_connections'][item_id] = int(time.time())
			### close connection
			self.active = False
			self.handle_close()
		except KeyboardInterrupt:
			raise

	def writeable(self):
		return (len(self.buffer) > 0)

	def handle_write(self):
		try:
			if self.active:
				bytesTosend = len(self.buffer)
				while bytesTosend>0:
					sent = self.send(self.buffer)
					bytesTosend = bytesTosend - sent
					self.buffer = self.buffer[sent:]
			else:
				self.handle_close()
		except socket.error, e:
			self.log_obj.log("handle_write() %s %s" % (e, self._address[0]), 12, "crit", False, True)
			self.handle_close()
		except KeyboardInterrupt:
			raise
