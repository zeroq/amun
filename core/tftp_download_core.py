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

import socket
import struct
import asyncore
import time
import hashlib
import os
import random

import amun_logging

class tftp(asyncore.dispatcher):
	def __init__(self, item, currDownl, tftp_downloads, event_dict, dlLogger, config_dict):
		asyncore.dispatcher.__init__(self)
		self.log_obj = amun_logging.amun_logging("tftp_download", dlLogger)
		self.file = item['path']
		self._address = (item['host'], int(item['port']))
		self.tftp_downloads = tftp_downloads
		self.currentDownloads = currDownl
		self.event_dict = event_dict
		self.item = item
		self.active = True

		if config_dict['store_unfinished_tftp']:
			self.complete = True
		else:
			self.complete = False

		### send buffer
		self.buffer = ''
		self.max_retries = config_dict['tftp_max_retransmissions']
		self.tmp_max_retries = self.max_retries

		### receive parameters
		self.rcv_packet = []
		self.blk_size = 516

		### setup socket
		self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
		try:
			udp_port = random.randint(5062,62535)
			self.bind( (item['own_host'], udp_port) )
		except socket.error, e:
			self.log_obj.log("UDP Port busy: %i" % (udp_port), 6, "crit", True, True)
			self.handle_close()
			return
		self.set_reuse_addr()

		### current block to ack
		self.curBlock = 0

		### request packet
		self.packet = '\x00\x01%s\x00octet\x00blksize\x00%s\x00' % (self.file, self.blk_size)
		#self.packet = '\x00\x01%s\x00octet\x00' % (self.file)

		self.sendto(self.packet, self._address)
		(self.own_ip, self.own_port) = self.getsockname()
		self.tftp_downloads[item['dlident']] = "%s,%s,%s" % (self.own_port, int(time.time()), self.own_ip)
		self.active = True
		self.log_obj.log("%s Sending TFTP Request Package (%s)" % (self.own_ip,[self.packet.strip()]), 6, "debug", True, False)

	def remove_download_entry(self):
		if self.currentDownloads.has_key(self.item['dlident']):
			del self.currentDownloads[self.item['dlident']]
		if self.tftp_downloads.has_key(self.item['dlident']):
			del self.tftp_downloads[self.item['dlident']]

	def handle_connect(self):
		pass

	def handle_error(self):
		raise

	def handle_expt(self):
		pass

	def handle_close(self):
		data = "".join(self.rcv_packet)
		data_length = len(data)
		if self.complete and data!='quit' and data_length>0:
			self.log_obj.log("tftp writing download event (%s)" % (self.item['displayURL']), 6, "debug", True, False)
			self.createFileEvent(data, data_length)
		elif data=='quit':
			self.log_obj.log("received local quit", 6, "div", True, False)
		else:
			self.log_obj.log("tftp did not quit", 6, "div", True, False)
		self.remove_download_entry()
		self.close()

	def createFileEvent(self, file_data, file_data_length):
		event_item = (file_data_length, self._address[0], self._address[1], self.item['own_host'], "TFTP", file_data, self.item['vulnname'], self.item['displayURL'])
		id = "%s%s" % (self._address[0].replace('.',''), self._address[1])
		self.event_dict['successfull_downloads'][id] = event_item

	def handle_read(self):
		try:
			if self.active:
				try:
					(buffer, (raddress, rport)) = self.recvfrom(self.blk_size)
				except socket.error, e:
					self.log_obj.log("udp socket error: %s" % (e), 6, "crit", True, False)
					buffer = 'resend'
					self.max_retries += 1
				if buffer=='resend':
					if self.max_retries <= 0:
						self.log_obj.log("%s tried %i times, now closing" % (self.own_ip,self.tmp_max_retries), 6, "debug", True, False)
						self.active = False
						self.handle_close()
						return
					else:
						### resend last packet
						self.sendto(self.packet, self._address)
						self.max_retries -= 1
						self.tftp_downloads[self.item['dlident']] = "%s,%s,%s" % (self.own_port, int(time.time()), self.own_ip)
						self.log_obj.log("resending last packet (%s)" % ([self.packet]), 6, "debug", False, False)
						return
				### ignore incoming data from a different host or port than requested
				if raddress!=self._address[0] and rport!=self._address[1]:
					self.log_obj.log("ignoring received %d bytes from different source %s:%s" % (len(buffer), raddress, rport), 6, "debug", True, False)
					return
				self.log_obj.log("Received %d bytes from %s:%s" % (len(buffer), raddress, rport), 6, "debug", True, False)
				self._address = (raddress, int(rport))
				self.rcv_packet.append(buffer[4:])
				self.tftp_downloads[self.item['dlident']] = "%s,%s,%s" % (self.own_port, int(time.time()), self.own_ip)
				### done
				if len(buffer)<self.blk_size:
					self.log_obj.log("tftp last packet received", 6, "debug", True, False)
					self.active = False
					self.complete = True
					self.handle_close()
				else:
					opcode = 4
					expt_number = self.curBlock + 1
					blocknumber = struct.unpack("!H", buffer[2:4])[0]
					if blocknumber == expt_number:
						self.packet = struct.pack("!HH", opcode, blocknumber)
						self.log_obj.log("sending ACK for block %s - %s" % (blocknumber,[self.packet]), 6, "debug", True, False)
						self.sendto(self.packet, self._address)
						self.curBlock = expt_number
						self.max_retries = self.tmp_max_retries
					else:
						if self.max_retries <= 0:
							self.log_obj.log("tried %i times (packet out of order), now closing" % (self.tmp_max_retries), 6, "debug", True, False)
							self.active = False
							self.handle_close()
							return
						else:
							self.log_obj.log("packet out of order (%s :: %s), resending last ACK" % (blocknumber,expt_number), 6, "debug", True, False)
							self.packet = struct.pack("!HH", opcode, expt_number)
							self.sendto(self.packet, self._address)
							self.max_retries -= 1
							return
			else:
				handle_close()
		except KeyboardInterrupt:
			raise

	def writeable(self):
		return (len(self.buffer) > 0)

	def handle_write(self):
		try:
			if len(self.buffer)>1:
				sent = self.sendto(self.buffer, self._address)
				self.buffer = self.buffer[sent:]
		except KeyboardInterrupt:
			raise

