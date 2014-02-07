"""
[Amun - low interaction honeypot]
Copyright (C) [2013]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import asynchat
import StringIO
import traceback
import time
import socket
import sys
import hashlib
import os
import random
import struct
from copy import copy

### core modules
import shellcode_mgr_core
import download_core
import amun_logging

class amun_reqhandler(asynchat.async_chat):

	def __init__(self, divLogger):
		self.remote_ip = None
		self.remote_port = None
		self.own_ip = None
		self.own_port = None
		self.identifier = None
		self.in_buffer_size = 1024
		self.in_buffer = ""
		self.out_buffer = ""
		self.connected = True
		self.set_terminator(None)
		### FIXME: configuration file
		self.enableProxy = False
		self.proxytoIP = "127.0.0.1"
		self.proxyMode = False
		self.proxyShellcode = []
		self.proxyReplies = []
		self.proxyRequests = []
		self.proxyTimedOut = False
		self.proxyResult = None
		self.sendRequest = ""
		self.log_obj = amun_logging.amun_logging("amun_request_handler", divLogger['requestHandler'])

	def __del__(self):
		pass

	def __str__(self):
		return "      .::[Amun - ReqHandler] handling connection %s:%s --> %s:%s (%s) ::."\
				% (self.remote_ip,self.remote_port,self.own_ip,self.own_port,self.identifier)

	def get_existing_connection(self):
		result = self.currentConnections[self.identifier]
		vuln_modulList = result[2]
		newItem = (int(time.time()), self.socket_object, vuln_modulList)
		self.currentConnections[self.identifier] = newItem
		return vuln_modulList

	def set_existing_connection(self):
		vuln_modulList = {}
		try:
			v_modules = self.vuln_modules[str(self.own_port)]
			for modkey in v_modules.keys():
				init_mod = v_modules[modkey]
				vuln_modulList[len(vuln_modulList)] = init_mod.vuln()
			item = (int(time.time()), self.socket_object, vuln_modulList)
			self.currentConnections[self.identifier] = item
		except KeyError, e:
			pass
		return vuln_modulList

	def update_existing_connection(self, vuln_modulList):
		newItem = (int(time.time()), self.socket_object, vuln_modulList)
		self.currentConnections[self.identifier] = newItem

	def delete_existing_connection(self):
		try:
			if self.currentSockets.has_key(self.identifier):
				del self.currentSockets[self.identifier]
			if self.currentConnections.has_key(self.identifier):
				item = self.currentConnections[self.identifier]
				del self.currentConnections[self.identifier]
				if len(item[2])>0:
					(result,state) = self.handle_vulnerabilities("", item[2])
					### check for shellcode and start download manager
					if result['shellresult']!="None":
						for resEntry in result['shellresult']:
							if resEntry['result']:
								### create exploit event
								event_item = (self.remote_ip,
										self.remote_port,
										self.own_ip,
										self.own_port,
										result['vuln_modul'],
										int(time.time()),
										resEntry)
								if not self.event_dict['exploit'].has_key(self.identifier):
									self.event_dict['exploit'][self.identifier] = event_item
								### attach to download list
								self.handle_download(resEntry)
								### attach to successful exploit list
								if self.blocksucexpl == 1:
									item_id = str(self.remote_ip)
									self.event_dict['sucexpl_connections'][item_id] = int(time.time())
		except KeyboardInterrupt:
			raise


	def setup_remote_connection(self, remote_ip=None):
		### try to setup connection to a remote system
		try:
			self.log_obj.log("establishing proxy socket", 6, "debug", False, True)
			self.origin_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.origin_socket.settimeout(10.0)
			if remote_ip==None:
				### connect to other honeypot system
				self.origin_socket.connect( (self.proxytoIP, self.own_port) )
			else:
				### connect to remote attacker
				self.proxytoIP = self.remote_ip
				self.origin_socket.connect( (remote_ip, self.own_port) )
			self.origin_socket.setblocking(0)
			return True
		except socket.error, e:
			self.log_obj.log("proxy connection setup failed: %s" % (e), 6, "crit", True, True)
			self.handle_close()
			return False
		except KeyboardInterrupt:
			raise

	def handle_close(self):
		try:
			self.connected = False
			try:
				self.shutdown(socket.SHUT_RDWR)
				self.origin_socket.close()
			except:
				pass
			self.close()
		except KeyboardInterrupt:
			raise

	def handle_incoming_connection(self, socket_object, currSockets, currConn, decodersDict, event_dict, config_dict, vuln_modules, divLogger, addr):
		""" handles incoming connections at first and inits all objects """
		asynchat.async_chat.__init__(self, socket_object)
		self.socket_object = socket_object
		self.divLogger = divLogger
		self.shellcode_manager = shellcode_mgr_core.shell_mgr(decodersDict, divLogger['shellcode'], config_dict)
		self.replace_locals = config_dict['replace_locals']
		self.blocksucexpl = config_dict['block_sucexpl']
		self.verboseLogging = config_dict['verbose_logging']
		try:
			(self.remote_ip, self.remote_port) = socket_object.getpeername()
			(self.own_ip, self.own_port) = socket_object.getsockname()
			self.identifier = "%s%s%s%s" % (self.remote_ip,self.remote_port,self.own_ip,self.own_port)
		except socket.error, e:
			### 107: Transport endpoint is not connected
			if e[0]==107:
				self.log_obj.log("Transport endpoint is not connected", 6, "crit", False, True)
			else:
				self.log_obj.log("[handle_incoming_connection] socket error: %s" % (e), 6, "crit", False, True)
			### add host to refused list, block connections for 3 minutes
			if config_dict['block_refused'] == 1:
				item_id = str(addr[0])
				event_dict['refused_connections'][item_id] = int(time.time())
			try:
				self.shutdown(socket.SHUT_RDWR)
			except:
				pass
			self.connected = False
			self.close()
			return

		if self.connected:
			self.currentSockets = currSockets
			self.currentConnections = currConn
			self.decodersDict = decodersDict
			self.event_dict = event_dict
			self.vuln_modules = vuln_modules
			self.random_reply = self.create_random_reply()
			### used sockets for timeout in amun server
			if not self.currentSockets.has_key(self.identifier):
				self.set_new_socket_connection()
			### nat or real ip
			if config_dict['ftp_nat_ip']!="None":
				self.ownIP = config_dict['ftp_nat_ip']
			else:
				self.ownIP = self.own_ip
			### initial connection event
			if not event_dict['initial_connections'].has_key(self.identifier):
				event_dict['initial_connections'][self.identifier] = [self.remote_ip, self.remote_port, self.own_ip, self.own_port, None, 0, int(time.time())]
			### handle welcome messages
			self.handle_welcome()

	def handle_welcome(self):
		### get registered vuln modules for own_port
		if not self.currentConnections.has_key(self.identifier):
			vuln_modulList = self.set_existing_connection()
		else:
			vuln_modulList = self.get_existing_connection()

		welcome_list = []
		for key in vuln_modulList.keys():
			vuln_module = vuln_modulList[key]
			welcome_message = vuln_module.getWelcomeMessage()
			if len(welcome_message)>0:
				welcome_list.append( welcome_message )

		if len(welcome_list)>0:
			self.log_obj.log("sending welcome message: %s" % ([welcome_list[0]]), 6, "crit", False, False)
			rplmess = "%s\r\n" % (welcome_list[0])
			try:
				bytesTosend = len(rplmess)
				while bytesTosend>0:
					bytes_sent = self.socket_object.send(rplmess)
					bytesTosend = bytesTosend - bytes_sent
					rplmess = rplmess[bytes_sent:]
			except socket.error, e:
				self.log_obj.log("[handle_welcome] socket error: %s" % (e), 6, "crit", False, True)
				self.delete_existing_connection()
				if self.event_dict['initial_connections'].has_key(self.identifier):
					del self.event_dict['initial_connections'][self.identifier]
				self.connected = False
				self.close()

	def set_new_socket_connection(self):
		### (0) Timestamp (1) Socket
		item = (int(time.time()), self.socket_object)
		self.currentSockets[self.identifier] = item

	def handle_connect(self):
		pass

	def found_terminator(self):
		pass

	def handle_expt(self):
		### out of band data can be ignored
		pass

	def handle_error(self):
		raise

	def handle_read(self):
		try:
			try:
				bytes = self.recv(self.in_buffer_size)
			except socket.error, e:
				if e[0]=="110":
					self.log_obj.log("connection timeout", 9, "warn", False, True)
				else:
					self.log_obj.log("[handle_read] socket error: %s" % (e), 9, "crit", False, True)
				bytes = ""
			self.collect_incoming_data( bytes )
		except KeyboardInterrupt:
			raise

	def collect_incoming_data(self, data):
		try:
			### proxy/mirror
			### TODO: move to extra function to avoid redundancy
			if self.enableProxy and self.proxyMode:
				self.proxyShellcode.append(data)
				self.proxyRequests.append(data)
				self.sendRequest = "".join(data)
				bytesTosend = len(self.sendRequest)
				if bytesTosend==0:
					shellcodeSet = {}
					shellcodeSet['vulnname'] = "ProxyCapture"
					shellcodeSet['shellcode'] = "".join(self.proxyShellcode)
					self.proxyResult = self.shellcode_manager.start_matching( shellcodeSet, self.remote_ip, self.own_ip, self.own_port, self.replace_locals, False )
					### to XML generator
					print self.proxyRequests
					print self.proxyReplies
				if not self.proxyTimedOut:
					try:
						self.log_obj.log("sending data to proxy host %s (%s)" % (self.proxytoIP, bytesTosend), 6, "debug", False, True)
						while bytesTosend>0:
							bytes_send = self.origin_socket.send(self.sendRequest)
							bytesTosend = bytesTosend - bytes_send
							self.sendRequest = self.sendRequest[bytes_send:]
					except socket.error, e:
						self.log_obj.log("sending to proxy/remote host failed %s" % (self.proxytoIP), 6, "crit", False, True)
						pass
					while True:
						try:
							self.log_obj.log("waiting for data from proxy host %s" % (self.proxytoIP), 6, "debug", False, True)
							self.origin_socket.settimeout(2.0)
							self.out_buffer = self.origin_socket.recv(1024)
							self.log_obj.log("received %s bytes from proxy" % (len(self.out_buffer)), 6, "debug", False, True)
							self.proxyReplies.append(self.out_buffer)
							if len(self.out_buffer)<1024 and len(self.out_buffer)!=0:
								try:
									bytesTosend = len(self.out_buffer)
									while bytesTosend>0:
										bytes_send = self.socket_object.send(self.out_buffer)
										bytesTosend = bytesTosend - bytes_send
										self.out_buffer = self.out_buffer[bytes_send:]
										self.log_obj.log("sending data to attacker %s (%s)" % (self.remote_ip, bytes_send), 8, "debug", False, True)
								except:
									break
								break
							elif self.out_buffer=='':
								try:
									bytesTosend = len(self.out_buffer)
									while bytesTosend>0:
										bytes_send = self.socket_object.send(self.out_buffer)
										bytesTosend = bytesTosend - bytes_send
										self.out_buffer = self.out_buffer[bytes_send:]
										self.log_obj.log("sending data to attacker %s (%s)" % (self.remote_ip, bytes_send), 8, "debug", False, True)
								except:
									break
								break
							elif len(self.out_buffer)==0:
								try:
									bytesTosend = len(self.out_buffer)
									while bytesTosend>0:
										bytes_send = self.socket_object.send(self.out_buffer)
										bytesTosend = bytesTosend - bytes_send
										self.out_buffer = self.out_buffer[bytes_send:]
										self.log_obj.log("sending data to attacker %s (%s)" % (self.remote_ip, bytes_send), 8, "debug", False, True)
								except:
									break
								break
							else:
								try:
									bytesTosend = len(self.out_buffer)
									while bytesTosend>0:
										bytes_send = self.socket_object.send(self.out_buffer)
										bytesTosend = bytesTosend - bytes_send
										self.out_buffer = self.out_buffer[bytes_send:]
										self.log_obj.log("sending data to attacker %s (%s)" % (self.remote_ip, bytes_send), 8, "debug", False, True)
								except:
									break
							time.sleep(.0001)
						except socket.error, e:
							if e[0]==11:
								pass
							else:
								self.proxyTimedOut = True
								break
						except KeyboardInterrupt:
							raise
				self.out_buffer = ""
				self.sendRequest = ""

			event_item = None
			if self.currentConnections.has_key(self.identifier):
				### existing connection
				vuln_modulList = self.get_existing_connection()
			else:
				### create new connection
				vuln_modulList = self.set_existing_connection()
			### set initial state
			state ="amun_not_set"
			### handle vulnerabilities
			if self.proxyResult == None:
				(result,state) = self.handle_vulnerabilities(data, vuln_modulList)
				### update connection entry
				self.update_existing_connection(vuln_modulList)
				self.set_new_socket_connection()
			else:
				result = shellcodeSet
				result['vuln_modul'] = "ProxyCapture"
				result['shellresult'] = self.proxyResult
			### check for shellcode and start download manager
			if result['shellresult']!="None":
				for resEntry in result['shellresult']:
					if resEntry['result']:
						for key in vuln_modulList.keys():
							del vuln_modulList[key]
						### create exploit event
						event_item = (self.remote_ip,
								self.remote_port,
								self.own_ip,
								self.own_port,
								result['vuln_modul'],
								int(time.time()),
								resEntry)
						if not self.event_dict['exploit'].has_key(self.identifier):
							self.event_dict['exploit'][self.identifier] = event_item
						### attach to download list
						self.handle_download(resEntry)
						### attach to successful exploit list
						if self.blocksucexpl == 1:
							item_id = str(self.remote_ip)
							self.event_dict['sucexpl_connections'][item_id] = int(time.time())
						try:
							self.socket_object.send("\r\n")
						except socket.error, e:
							pass
						self.delete_existing_connection()
						try:
							self.shutdown(socket.SHUT_RDWR)
						except:
							pass
						self.connected = False
						self.close()
						return
					else:
						### failed to determine shellcode
						for key in vuln_modulList.keys():
							del vuln_modulList[key]
						### create failed exploit event
						event_item = (self.remote_ip,
								self.remote_port,
								self.own_ip,
								self.own_port,
								result['vuln_modul'],
								int(time.time()),
								resEntry)
						if not self.event_dict['exploit'].has_key(self.identifier):
							self.event_dict['exploit'][self.identifier] = event_item
						### attach to successful exploit list
						if self.blocksucexpl == 1:
							item_id = str(self.remote_ip)
							self.event_dict['sucexpl_connections'][item_id] = int(time.time())
						try:
							self.socket_object.send("\r\n")
						except socket.error, e:
							pass
						self.delete_existing_connection()
						try:
							self.shutdown(socket.SHUT_RDWR)
						except:
							pass
						self.connected = False
						self.close()
						return
			### check replies and take the first
			try:
				if len(result['replies'])>0:
					reply_message = result['replies'][0]
					### calc reply message length
					bytesTosend = len(reply_message)
					try:
						while bytesTosend>0:
							bytes_send = self.socket_object.send(reply_message)
							bytesTosend = bytesTosend - bytes_send
					except socket.error, e:
						### client gone
						self.delete_existing_connection()
						try:
							self.shutdown(socket.SHUT_RDWR)
						except:
							pass
						self.connected = False
						self.close()
						return
			except:
				pass
			### TODO: proxy unknown attack to high-interaction honeypot
			### Problem: can only be done if no previous stage was used, i.e. still at STAGE1
			### possible solution: record network traffic and replay against Proxy (needs memory/disc space)
			### TODO: vuln-proxy modul to register ports for monitoring and proxying to other system
			### TODO: read and store network traffic and generate vulnerability from this data
			### TODO: every request needs to be run thru the shellcode manager and if shellcode detected then vulnerability modul is finished
			###       requires: shellcode and vulnerability name in dict vulnResult
			try:
				if len(result['stage_list'])>0:
					for entry in result['stage_list']:
						if not entry.endswith('STAGE1'):
							self.enableProxy = False
							break
			except:
				pass
			if self.enableProxy and not self.proxyMode and len(vuln_modulList)<=0 and len(data)>=0 and state!="amun_stage_finished":
				### enable proxy state
				self.proxyMode = True
				### check for proxyState earlier
				### FIXME: configuration: mirror, proxy, none
				### open socket to honeypot system or remote attacker
				proxyConnResult = self.setup_remote_connection(self.remote_ip)
				if not proxyConnResult:
					return
				self.log_obj.log("no module switching to proxy mode %s<->%s<->%s" % (self.remote_ip, self.own_ip, self.proxytoIP), 6, "debug", False, True)
				### transmit data to proxy modul
				self.sendRequest = "".join(data)
				bytesTosend = len(self.sendRequest)
				self.proxyRequests.append(data)
				try:
					self.log_obj.log("sending initial data to proxy host %s" % (self.proxytoIP), 6, "debug", False, True)
					self.log_obj.log("sending %s bytes" % (bytesTosend), 6, "debug", False, True)
					while bytesTosend>0:
						bytes_send = self.origin_socket.send(self.sendRequest)
						bytesTosend = bytesTosend - bytes_send
						self.sendRequest = self.sendRequest[bytes_send:]
				except:
					self.log_obj.log("sending to proxy/remote host failed %s" % (self.proxytoIP), 6, "crit", False, True)
					pass
				while True:
					try:
						self.log_obj.log("waiting for proxy reply %s" % (self.proxytoIP), 6, "debug", False, True)
						self.origin_socket.settimeout(2.0)
						self.out_buffer = self.origin_socket.recv(1024)
						self.log_obj.log("received %s bytes from proxy" % (len(self.out_buffer)), 6, "debug", False, True)
						self.proxyReplies.append(self.out_buffer)
						if len(self.out_buffer)<1024 and len(self.out_buffer)!=0:
							try:
								bytesTosend = len(self.out_buffer)
								while bytesTosend>0:
									bytes_send = self.socket_object.send(self.out_buffer)
									bytesTosend = bytesTosend - bytes_send
									self.out_buffer = self.out_buffer[bytes_send:]
									self.log_obj.log("1 sending data to attacker %s (%s)" % (self.remote_ip, bytes_send), 8, "debug", False, True)
							except:
								break
							break
						elif self.out_buffer=='':
							try:
								bytesTosend = len(self.out_buffer)
								while bytesTosend>0:
									bytes_send = self.socket_object.send(self.out_buffer)
									bytesTosend = bytesTosend - bytes_send
									self.out_buffer = self.out_buffer[bytes_send:]
									self.log_obj.log("2 sending data to attacker %s (%s)" % (self.remote_ip, bytes_send), 8, "debug", False, True)
							except:
								break
							break
						elif len(self.out_buffer)==0:
							try:
								bytesTosend = len(self.out_buffer)
								while bytesTosend>0:
									bytes_send = self.socket_object.send(self.out_buffer)
									bytesTosend = bytesTosend - bytes_send
									self.out_buffer = self.out_buffer[bytes_send:]
									self.log_obj.log("3 sending data to attacker %s (%s)" % (self.remote_ip, bytes_send), 8, "debug", False, True)
							except:
								break
							break
						else:
							try:
								bytesTosend = len(self.out_buffer)
								while bytesTosend>0:
									bytes_send = self.socket_object.send(self.out_buffer)
									bytesTosend = bytesTosend - bytes_send
									self.out_buffer = self.out_buffer[bytes_send:]
									self.log_obj.log("4 sending data to attacker %s (%s)" % (self.remote_ip, bytes_send), 8, "debug", False, True)
							except:
								break
						time.sleep(.0001)
					except socket.error, e:
						if e[0]==11:
							pass
						else:
							self.proxyTimedOut = True
							break
					except KeyboardInterrupt:
						raise
				self.out_buffer = ""
				self.sendRequest = ""
			### connection finished but modules left
			if len(vuln_modulList)>0 and len(data)<=0:
				for key in vuln_modulList.keys():
					modul = vuln_modulList[key]
					self.log_obj.log("%s leaving communication (stage: %s bytes: %s)"\
							% (modul.getVulnName(),modul.getCurrentStage(),len(data)), 6, "debug", False, True)
					result['stage_list'].append(modul.getCurrentStage())
					del vuln_modulList[key]
				if self.event_dict['initial_connections'].has_key(self.identifier):
					del self.event_dict['initial_connections'][self.identifier]
			### modules left?
			if len(vuln_modulList)<=0 and not self.proxyMode:
				if self.verboseLogging:
					self.log_obj.log("no vulnerability modul left (%s) -> closing connection" % (self.own_port), 6, "debug", False, True)
				if not event_item and len(data)>0 and state!="amun_stage_finished":
					self.log_obj.log("unknown vuln (Attacker: %s Port: %s, Mess: %s (%i) Stages: %s)" % (self.remote_ip, self.own_port, [data], len(data), result['stage_list']), 6, "crit", True, False)
				elif not event_item and len(data)>0:
					self.log_obj.log("incomplete vuln (Attacker: %s Port: %s, Mess: %s (%i) Stages: %s)" % (self.remote_ip, self.own_port, [data], len(data), result['stage_list']), 6, "crit", True, False)
				elif not event_item and len(data)==0 and state!="amun_stage_finished":
					self.log_obj.log("PortScan Detected on Port: %s (%s)" % (self.own_port, self.remote_ip), 6, "div", True, False)
					pass
				try:
					self.socket_object.send("\r\n")
				except socket.error, e:
					pass
				self.delete_existing_connection()
				try:
					self.shutdown(socket.SHUT_RDWR)
				except:
					pass
				if self.event_dict['initial_connections'].has_key(self.identifier):
					del self.event_dict['initial_connections'][self.identifier]
				self.connected = False
				self.close()
				return
		except KeyboardInterrupt:
			raise

	def create_random_reply(self):
		random_reply = []
		random_reply = [struct.pack("B", random.randint(0,255)) for i in xrange(0,62)]
		return random_reply

	def handle_vulnerabilities(self, data, vuln_modulList):
		try:
			keysToRemove = []
			state = "amun_not_set"
			result =  {}
			result['replies'] = []
			result['shellresult'] = "None"
			result['vuln_modul'] = "None"
			result['stage_list'] = []

			for key in vuln_modulList.keys():
				vuln_modul = vuln_modulList[key]
				vulnResult = vuln_modul.incoming(data, len(data), self.remote_ip, self.divLogger['vulnerability'], self.random_reply, self.ownIP)
				### not accepted -> remove from vuln list
				if not vulnResult['accept']:
					self.log_obj.log("%s leaving communication (stage: %s bytes: %s)" % (vulnResult['vulnname'],vulnResult['stage'],len(data)), 6, "debug", False, False)
					result['stage_list'].append(vulnResult['stage'])
					keysToRemove.append(key)
				else:
					### if result true and we have a reply -> send reply
					if vulnResult['result'] and vulnResult['reply']!="None":
						if vulnResult['reply'].endswith('#'):
							rplmess = "%s" % (vulnResult['reply'])
						if vulnResult['reply'].endswith('*'):
							rplmess = "%s" % (vulnResult['reply'][:-1])
						else:
							rplmess = "%s\r\n" % (vulnResult['reply'])
						if rplmess not in result['replies']:
							result['replies'].append(rplmess)
					### if result false, shellcode present and not a direct file -> run shellcode manager
					if not vulnResult['result'] and vulnResult['shellcode']!="None" and not vulnResult['isFile']:
						result['shellresult'] = self.handle_shellcode(vulnResult)
						result['vuln_modul'] = vulnResult['vulnname']
						state = "amun_stage_finished"
						break
					### if result false, shellcode present but a direct file -> add to download list
					if not vulnResult['result'] and vulnResult['shellcode']!="None" and vulnResult['isFile']:
						self.log_obj.log("Vuln: %s requested file check" % (vulnResult['vulnname']), 6, "crit", False, False)
						data = vulnResult['shellcode']
						data_len = len(data)
						if data_len>0:
							downURL = "%s://%s:%s/" % (vulnResult['vulnname'].replace(' Vulnerability','').lower(), self.remote_ip, self.remote_port)
							self.createFileEvent(data, data_len, vulnResult['vulnname'], downURL)
							result['shellresult'] = [self.setMyDoomShellResult(downURL)]
							result['vuln_modul'] = vulnResult['vulnname']
						state = "amun_stage_finished"
						break
					### check for requested connection shutdown
					if vulnResult['shutdown']:
						self.log_obj.log("%s requested shutdown" % (vulnResult['vulnname']), 6, "crit", False, True)
						self.delete_existing_connection()
						try:
							self.shutdown(socket.SHUT_RDWR)
						except:
							pass
						if self.event_dict['initial_connections'].has_key(self.identifier):
							del self.event_dict['initial_connections'][self.identifier]
						self.connected = False
						self.close()
					### set state
					state = "amun_stage_finished"
			### remove entries
			for key in keysToRemove:
				del vuln_modulList[key]
			del keysToRemove
			return result,state
		except KeyboardInterrupt:
			raise
		except:
			print "Port: %s" % (self.own_port)
			raise

	def setMyDoomShellResult(self, downURL):
		resultSet = {}
		resultSet['vulnname'] = 'MYDOOM'
		resultSet['result'] = True
		resultSet['hostile_host'] = self.remote_ip
		resultSet['own_host'] = self.own_ip
		resultSet['found'] = "mydoom"
		resultSet['path'] = "None"
		resultSet['host'] = "None"
		resultSet['port'] = "None"
		resultSet['xorkey'] = "None"
		resultSet['username'] = "None"
		resultSet['passwort'] = "None"
		resultSet['dlident'] = "%s%s" % (self.remote_ip.replace('.',''), self.remote_port)
		resultSet['displayURL'] = downURL
		resultSet['isLocalIP'] = False
		resultSet['shellcodeName'] = "mydoom"
		return resultSet

	def handle_shellcode(self, vulnResult):
		try:
			return self.shellcode_manager.start_matching( vulnResult, self.remote_ip, self.own_ip, self.own_port, self.replace_locals, False )
		except KeyboardInterrupt:
			raise

	def handle_download(self, result):
		### attach to download events
		if not self.event_dict['download'].has_key(result['dlident']):
			self.event_dict['download'][result['dlident']] = result

	def createFileEvent(self, file_data, file_data_length, vulnname, downURL):
		event_item = (file_data_length, self.remote_ip, self.remote_port, self.own_ip, "MyDOOM", file_data, vulnname, downURL)
		id = "%s%s" % (self.remote_ip.replace('.',''), self.own_port)
		self.event_dict['successfull_downloads'][id] = event_item
