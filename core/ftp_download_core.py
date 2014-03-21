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

import StringIO
import asyncore
import asynchat
import re
import socket
import sys
import random
import hashlib
import os
import sys
import traceback
import time

import amun_logging

class req_handler(asynchat.async_chat):
	def __init__(self, dlLogger):
		self.content = []
		self.set_terminator(None)
		self.connection_closed = False
		self.log_obj = amun_logging.amun_logging("ftp_download", dlLogger)

	def handle_incoming_connection(self, socket_object, addr, event_dict, ftp_downloads, downPort, downIP, vulnName, item, currentSockets):
		asynchat.async_chat.__init__(self, socket_object)
		self.socket_object = socket_object
		self.item = item
		self.entryID = "%i%s" % (downPort,downIP)
		self.event_dict = event_dict
		self.ftp_downloads = ftp_downloads
		self.currentSockets = currentSockets
		self.downPort = downPort
		self.downIP = downIP
		self._address = addr
		self.vulnName = vulnName
		self.socket_object.settimeout(120.0)
		self.settimeout(120.0)
		self.log_obj.log("incoming data connection: %s to: %s:%s" % (self._address[0], downIP, downPort), 9, "debug", True, False)
		self.identifier = "%s%s%s%s" % (self._address[0].replace('.',''), self._address[1], downIP.replace('.','') , downPort)
		### create socket entry
		if not self.currentSockets.has_key(self.identifier):
			socket_item = (int(time.time()), self.socket)
			self.currentSockets[self.identifier] = socket_item

	def handle_read(self):
		try:
			bytes = self.recv(8192)
			#self.log_obj.log("reading ftp data (%s bytes)" % (len(bytes)), 9, "debug", True, False)
		except socket.error, e:
			self.log_obj.log("handler socket error: %s" % (e), 9, "crit", True, False)
			bytes = ""
		self.collect_incoming_data( bytes )

	def collect_incoming_data(self, data):
		if data!="" and data!='local quit':
			self.content.append( data )
			self.ftp_downloads[self.entryID] = "%i,%i,%s" % (self.downPort, int(time.time()), self.downIP)
			### increase timeout
			self.currentSockets[self.identifier] = (int(time.time()), self.socket)
			### increase general timeout
			try:
				old_socket_item = self.currentSockets[self.item['dlident']]
				new_socket_item = (int(time.time()), old_socket_item[1])
				self.currentSockets[self.item['dlident']] = new_socket_item
				del new_socket_item
				del old_socket_item
			except KeyError:
				pass
		elif data=='local quit':
			self.log_obj.log("received local quit", 12, "debug", True, False)
			self.handle_close()
		elif data=="":
			self.log_obj.log("download finished? (%s)" % (self._address[0]), 12, "debug", True, False)
			self.handle_close()

	def remove_download_entry(self):
		if self.ftp_downloads.has_key(self.entryID):
			del self.ftp_downloads[self.entryID]

	def generateNewDownloads(self, data, data_length):
		newlst = []
		lst = data.split()
		for f in lst:
			if f.endswith("exe"):
				newlst.append(f)
		if len(newlst)>0:
			resultSet = {}
			resultSet['vulnname'] = self.item['vulnname']
			resultSet['result'] = True
			resultSet['hostile_host'] = self.item['hostile_host']
			resultSet['own_host'] = self.item['own_host']
			resultSet['host'] = self.item['host']
			resultSet['port'] = int(self.item['port'])
			resultSet['found'] = "ftp"
			resultSet['username'] = self.item['username']
			resultSet['passwort'] = self.item['passwort']
			resultSet['path'] = newlst
			resultSet['dlident'] = "%s%i%s" % (self.item['host'].replace('.',''),self.item['port'],newlst[0].replace('/',''))
			resultSet['displayURL'] = self.item['displayURL']
			resultSet['shellcodeName'] = self.item['shellcodeName']
			resultSet['isLocalIP'] = self.item['isLocalIP']

			identifier = "%s%s%s%s1" % (resultSet['hostile_host'],resultSet['port'],resultSet['own_host'],resultSet['port'])
			if not self.event_dict['download'].has_key(identifier):
				self.event_dict['download'][self.identifier] = resultSet

	def handle_close(self):
		if not self.connection_closed:
			data = "".join(self.content)
			data_length = len(data)
			if data_length>0:
				if "*.exe" in self.item['path']:
					self.log_obj.log("generate new downloads from NLST returned list %s" % ([data]), 12, "debug", True, True)
					self.generateNewDownloads(data, data_length)
				else:
					self.log_obj.log("storing ftp data (%s)" % (self._address[0]), 12, "debug", True, False)
					self.createFileEvent(data, data_length)
			self.remove_download_entry()
			self.log_obj.log("closing ftp data connection", 12, "debug", True, False)
			try:
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			### remove socket entry on successfull close
			if self.currentSockets.has_key(self.identifier):
				del self.currentSockets[self.identifier]
			self.connection_closed = True
		self.close()

	def createFileEvent(self, file_data, file_data_length):
		event_item = (file_data_length, self._address[0], self._address[1], self.downIP, "FTP", file_data, self.vulnName, self.item['displayURL'])
		id = "%s%s" % (self._address[0].replace('.',''), self._address[1])
		self.event_dict['successfull_downloads'][id] = event_item

	def handle_error(self):
		f = StringIO.StringIO()
		traceback.print_exc(file=f)
		self.log_obj.log( f.getvalue(), 9, "crit", True, True)
		self.close()
		sys.exit(1)

class data_connection(asyncore.dispatcher):
	def __init__(self, item, port, event_dict, ftp_downloads, dlLogger, vulnName, currentSockets, bound_to_ip):
		asyncore.dispatcher.__init__(self)
		self.log_obj = amun_logging.amun_logging("ftp_download", dlLogger)
		self.item = item
		self.vulnName = vulnName
		self.dlLogger = dlLogger
		self.event_dict = event_dict
		self.ftp_downloads = ftp_downloads
		self.currentSockets = currentSockets
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.set_reuse_addr()
                try:
			self.bind( (bound_to_ip,port) )
		except socket.error, e:
			self.log_obj.log("port already in use?: %s - %s" % (port, e), 9, "crit", True, True)
			return
		self.listen(1)
		self.downPort = port
		self.downIP = bound_to_ip
		self.log_obj.log("ftp waiting data connection on port: %s:%i" % (bound_to_ip, port), 9, "debug", True, True)

	def writable(self):
		return False

	def handle_accept(self):
		(sock_obj, addr) = self.accept()
		handler = req_handler(self.dlLogger).handle_incoming_connection(sock_obj, addr, self.event_dict, self.ftp_downloads, self.downPort, self.downIP, self.vulnName, self.item, self.currentSockets)
		self.handle_close()

	def handle_close(self):
		try:
			self.shutdown(socket.SHUT_RDWR)
		except:
			pass
		self.log_obj.log("closing accept ftp data connection", 12, "debug", True, False)
		self.close()

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

	def readable(self):
		return self.accepting


class download_ftp(asynchat.async_chat):
	def __init__(self, item, currDownl, event_dict, config_dict, ftp_downloads, dlLogger, currentSockets):
		asynchat.async_chat.__init__(self)
		self.log_obj = amun_logging.amun_logging("ftp_download", dlLogger)
		self.currentDownloads = currDownl
		self.currentSockets = currentSockets
		self.event_dict = event_dict
		self.config_dict = config_dict
		self.dlident = item['dlident']
		self._address = (item['host'], int(item['port']))
		filename_list = item['path']
		vulnName = item['vulnname']
		self.connected = False

		bound_to_ip = item['own_host']
		if config_dict['ftp_nat_ip'] == "None":
			ftp_ip_list = item['own_host'].split('.')
		else:
			ftp_ip_list = config_dict['ftp_nat_ip'].split('.')


		(lower_port, upper_port) = config_dict['ftp_port_range'].split('-')
		self.commands = ["TYPE I"]
		for filename in filename_list:
			random_port = random.randint(int(lower_port), int(upper_port))
			p1 = random_port/256
			p2 = random_port%256
			downPort = (p1*256)+p2
			self.commands.append("PORT %s,%s,%s,%s,%i,%i" % (ftp_ip_list[0],ftp_ip_list[1],ftp_ip_list[2],ftp_ip_list[3],p1,p2))
			if filename=="*.exe" and len(filename_list)==1:
				self.log_obj.log("found wildcard download %s" %(filename_list), 9, "debug", True, True)
				self.commands.append("NLST")
			else:
				self.commands.append("RETR %s" % (filename))
			### create ftp_download entry
			entryID = "%i%s" % (downPort, bound_to_ip)
			if not ftp_downloads.has_key(entryID):
				ftp_downloads[entryID] = "%i,%i,%s" % (downPort,int(time.time()), bound_to_ip)
			### open data channel
			data_connection(item, int(downPort), self.event_dict, ftp_downloads, dlLogger, vulnName, self.currentSockets, bound_to_ip)
		self.commands.append("QUIT")

		self.user = item['username']
		self.password = item['passwort']

		self.set_terminator("\n")
		self.data = ""
		self.response = []

		self.handler = self.ftp_handle_connect

		self.log_obj.log("ftp connect to: %s %s (user: %s pass: %s)" %(item['host'],item['port'],self.user,self.password), 9, "debug", True, True)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		#self.bind( (bound_to_ip, 0) )
		try:
			### connect to ftp server
			self.connect((item['host'], int(item['port'])))
			self.settimeout(60.0)
			self.connected = True
		except socket.error, e:
			self.log_obj.log("FTP failed connect: %s" % (e), 6, "debug", True, True)
			### add host to refused list, block connections for 3 minutes
			if self.config_dict['block_refused'] == 1:
				item_id = str(item['host'])
				self.event_dict['refused_connections'][item_id] = int(time.time())
			try:
				self.remove_downl_entry()
			except:
				pass
			self.close()
			return
		### create socket entry
		if not self.currentSockets.has_key(self.dlident):
			socket_item = (int(time.time()), self.socket)
			self.currentSockets[self.dlident] = socket_item
		self.downloading = False

	def handle_connect(self):
		pass

	def handle_expt(self):
		try:
			self.remove_downl_entry()
		except:
			pass
		self.close()

	def handle_error(self):
		f = StringIO.StringIO()
		traceback.print_exc(file=f)
		self.log_obj.log( f.getvalue(), 9, "crit", True, True)
		self.close()
		sys.exit(1)

	def handle_read(self):
		try:
			bytes = self.recv(1024)
		except socket.error, e:
			if e[0]==110:
				self.log_obj.log("connection timeout (%s)" % (self._address[0]), 12, "crit", False, True)
			elif e[0]==111:
				self.log_obj.log("connection refused (%s)" % (self._address[0]), 12, "crit", False, True)
			else:
				self.log_obj.log("handle_read() %s %s" % (e, self._address[0]), 12, "crit", False, True)
			bytes = "\r\n"
			### add host to refused list, block connections for x minutes
			if self.config_dict['block_refused'] == 1:
				item_id = str(self._address[0])
				self.event_dict['refused_connections'][item_id] = int(time.time())
		self.collect_incoming_data(bytes)
		if bytes.endswith('\n'):
			self.found_terminator()

	def collect_incoming_data(self, data):
		self.data += data

	def found_terminator(self):
		### collect response
		data = self.data
		if data.endswith("\r"):
			data = data[:-1]
		self.data = ""
		self.response.append(data)

		response = self.response
		self.response = []

		for line in response:
			self.log_obj.log("Server Response: %s" % (line), 6, "debug", True, False)

		### process response
		if self.handler:
			handler = self.handler
			self.handler = None
			handler(response)

			if self.handler:
				return

		try:
			code = response[-1][:3]
		except:
			self.log_obj.log("failed reading response code", 6, "debug", True, False)
			try:
				self.remove_downl_entry()
				self.shutdown(socket.SHUT_RDWR)
				self.commands = []
			except:
				pass
			return

		### 530 - Login Failed
		if code == "530" and len(self.commands)<=0 and not self.downloading:
			try:
				self.remove_downl_entry()
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			self.commands = []
			return
		elif code != "425" and len(self.commands)<=0 and not self.downloading:
			self.log_obj.log("no commands left -> sending quit", 6, "debug", True, False)
			if len(response[-1].strip())<3:
				self.log_obj.log("socket closed -> terminating", 6, "debug", True, False)
				self.remove_downl_entry()
				return
			try:
				err = self.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
			except:
				self.remove_downl_entry()
				self.close()
				return
			try:
				self.push("QUIT\r\n")
			except:
				pass
			try:
				self.remove_downl_entry()
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			self.commands = []
			return
		elif code == "425" and not self.downloading:
			self.log_obj.log("server failed open data connection -> sending quit", 6, "debug", True, False)
			try:
				self.push("QUIT\r\n")
			except:
				pass
			try:
				self.remove_downl_entry()
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			self.commands = []
			return
		elif code == "226" and self.downloading:
			self.log_obj.log("download successful", 6, "debug", True, False)
			self.downloading = False
		elif code == "550" and self.downloading:
			self.log_obj.log("download failed", 6, "debug", True, False)
			self.downloading = False
		elif code == "421":
			self.log_obj.log("server send timeout -> sending quit", 6, "debug", True, False)
			try:
				self.push("QUIT\r\n")
			except:
				pass
			try:
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			self.commands = []
			return

		if self.commands[0].startswith("RETR") and not self.downloading:
			self.log_obj.log("Sending: %s" % (self.commands[0]), 6, "debug", True, False)
			try:
				self.push(self.commands.pop(0) + "\r\n")
			except:
				self.log_obj.log("ftp failed: error sending command (pop)" , 4, "crit", True, True)
				try:
					self.remove_downl_entry()
					self.shutdown(socket.SHUT_RDWR)
				except:
					pass
				self.commands = []
				self.close()
				return
			self.downloading = True
			return
		elif self.downloading:
			return
		elif len(self.commands)<=0:
			try:
				self.close()
			except:
				pass
			return
		else:
			try:
				self.log_obj.log("Sending: %s" % (self.commands[0]), 6, "debug", True, False)
				if self.commands[0]!="QUIT":
					try:
						self.push(self.commands.pop(0) + "\r\n")
					except:
						self.log_obj.log("ftp failed: error sending command (pop)" , 4, "crit", True, True)
						try:
							self.remove_downl_entry()
							self.shutdown(socket.SHUT_RDWR)
						except:
							pass
						self.commands = []
						self.close()
						return
				else:
					try:
						self.push("QUIT" + "\r\n")
					except:
						pass
					try:
						self.remove_downl_entry()
						self.shutdown(socket.SHUT_RDWR)
					except:
						pass
					self.commands = []
					self.close()
			except:
				self.log_obj.log("error sending: %s failed" % (self.commands[0]), 6, "crit", True, False)
				pass

	def remove_downl_entry(self):
		if self.currentDownloads.has_key(self.dlident):
			del self.currentDownloads[self.dlident]
		if self.currentSockets.has_key(self.dlident):
			del self.currentSockets[self.dlident]

	def ftp_handle_connect(self, response):
		code = response[-1][:3]
		if code == "220":
			try:
				self.push("USER " + self.user + "\r\n")
				self.log_obj.log("Sending User: %s" % (self.user), 6, "debug", True, False)
				self.handler = self.ftp_handle_user_response
			except:
				self.log_obj.log("ftp failed: error sending username" , 4, "crit", True, True)
				try:
					self.remove_downl_entry()
					self.shutdown(socket.SHUT_RDWR)
				except:
					pass
				self.commands = []
				self.close()
				return
		else:
			self.log_obj.log("ftp login failed: %s - %s" % (response,code), 6, "crit", True, False)
			try:
				self.remove_downl_entry()
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			self.commands = []
			self.close()
			return

	def ftp_handle_user_response(self, response):
		code = response[-1][:3]
		if code == "230":
			return
		elif code == "331" or code == "332":
			try:
				self.push("PASS " + self.password + "\r\n")
				self.log_obj.log("Sending Pass: %s" % (self.password), 6, "debug", True, False)
				self.handler = self.ftp_handle_pass_response
			except:
				self.log_obj.log("ftp failed: error sending password" , 4, "crit", True, True)
				try:
					self.remove_downl_entry()
					self.shutdown(socket.SHUT_RDWR)
				except:
					pass
				self.commands = []
				self.close()
				return
		elif code == "220":
			self.log_obj.log("ftp login without password (code: %s)" % (code), 4, "debug", True, True)
			self.handler = None
			return
		else:
			self.log_obj.log("ftp login failed: username not accepted (%s - %s - %s)" % (self.user,response,code), 4, "crit", True, True)
			try:
				self.remove_downl_entry()
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			self.commands = []
			self.close()
			return

	def ftp_handle_pass_response(self, response):
		code = response[-1][:3]
		if code == "230":
			self.handler = None
			return
		else:
			self.log_obj.log("ftp login failed: user/password not accepted (%s/%s - %s - %s)" % (self.user,self.password,response,code), 4, "crit", True, True)
			try:
				self.remove_downl_entry()
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			self.commands = []
			self.close()
			return

