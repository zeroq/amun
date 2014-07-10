#!/usr/bin/python -O
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
import sys
import time
import copy

class amun_rdp_prot:
	def __init__(self):
		self.debug = False
		self.showRequests = False
		### variables
		### reply packet
		self.reply = []
		### vulnName
		self.vulnName = "RDP (Unknown)"
		self.shellcode = []

	def genBitvector(self, integer, count=16):
		return [str((integer >> y) & 1) for y in range(count-1, -1, -1)]

	def getShellcode(self):
		return "".join(self.shellcode)

	def getVulnName(self):
		return self.vulnName

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
		return

	def checkConnectionRequest(self, data):
		tpktVersion = struct.unpack('B', data[0])[0]
		tpktReserved = struct.unpack('B', data[1])[0]
		tpktPLengthHigh = struct.unpack('B', data[2])[0]
		tpktPLengthLow = struct.unpack('B', data[3])[0]
		pktLength = struct.unpack('>H', data[2:4])[0]

		x224length = struct.unpack('B', data[4])[0]
		if x224length < 5:
			return False
		x224type = struct.unpack('B', data[5])[0]
		x224destref = struct.unpack('2B', data[6:8])[0]
		x224sourceref = struct.unpack('2B', data[8:10])[0]
		x224class = struct.unpack('B', data[10])[0]
		
		if self.debug:
			print "TPKT Header: version = %s" % (tpktVersion)
			print "TPKT Header: Reserved = %s" % (tpktReserved)
			print "TPKT Header: Packet length - high part = %s" % (tpktPLengthHigh)
			print "TPKT Header: Packet length - low part = %s" % (tpktPLengthLow)
			print "Packet Length: %s (%s)" % (pktLength, len(data))
			print "X.224: Length indicator = %s" % (x224length)
			print "X.224: Type = %s" % (x224type)
			print "X.224: Destination reference = %s" % (x224destref)
			print "X.224: Source reference = %s" % (x224sourceref)
			print "X.224: Class and options = %s" % (x224class)

		cookie = []
		pos = False
		for pos in range(11, len(data)):
			byte = data[pos]
			if byte == '\x0d' and data[pos+1]=='\x0a':
				cookie.append(byte)
				pos += 1
				cookie.append(data[pos])
				break
			cookie.append(byte)
		if self.debug:
			print "%s" % (["".join(cookie)])
			if pos:
				print "%s" % ([data[pos:]])

		if tpktVersion == 3 and tpktPLengthLow == len(data) and x224class == 0:
			return True
		return False

	def createConnectionResponse(self):
		self.reply = []
		self.reply.append('\x03') # tpkt version
		self.reply.append('\x00')
		self.reply.append('\x00')
		self.reply.append('\x13') # packet length
		self.reply.append('\x0e') # x244 length
		self.reply.append('\xd0')
		self.reply.append('\x00')
		self.reply.append('\x00')
		self.reply.append('\x12')
		self.reply.append('\x34')
		self.reply.append('\x00')

		self.reply.append('\x02') # rdp neg resp
		self.reply.append('\x00')
		self.reply.append('\x08')
		self.reply.append('\x00')
		self.reply.append('\x00') # protocol: PROTOCOL_RDP
		self.reply.append('\x00')
		self.reply.append('\x00')
		self.reply.append('\x00')
		return

	def checkForConferenceRequest(self, data):		
		tpktVersion = struct.unpack('B', data[0])[0]
		tpktReserved = struct.unpack('B', data[1])[0]
		tpktPLengthHigh = struct.unpack('B', data[2])[0]
		tpktPLengthLow = struct.unpack('B', data[3])[0]
		pktLength = struct.unpack('>H', data[2:4])[0]

		x224length = struct.unpack('B', data[4])[0]
		x224type = struct.unpack('B', data[5])[0]
		x224eot = struct.unpack('B', data[6])[0]

		posi = 9	
		bertypeLength = data[9:11]
		if bertypeLength[-1] == '\x01':
			bertypeLength += data[11]
			posi = 12
		elif bertypeLength[-1] == '\x02':
			bertypeLength += data[11:13]
			posi = 13

		callingDomainSelector = data[posi:posi+2]
		if callingDomainSelector[-1] == '\x01':
			callingDomainSelector += data[posi+2]
			posi = posi + 3
		elif callingDomainSelector[-1] == '\x02':
			callingDomainSelector += data[posi+2:posi+4]
			posi = posi + 4
			
		calledDomainSelector = data[posi:posi+2]
		if calledDomainSelector[-1] == '\x01':
			calledDomainSelector += data[posi+2]
			posi = posi + 3
		elif calledDomainSelector[-1] == '\x02': 
			calledDomainSelector += data[posi+2:posi+4]
			posi = posi + 4

		upwardFlag = data[posi:posi+2]
		if upwardFlag[-1] == '\x01':
			upwardFlag += data[posi+2]
			posi = posi + 3
		elif upwardFlag[-1] == '\x02':
			upwardFlag += data[posi+2:posi+4]
			posi = posi + 4
		# is two bytes long
		targetParameters = data[posi:posi+2]
		posi = posi + 2

		maxChannelIds = data[posi:posi+2]
		if maxChannelIds[-1] == '\x01':
			maxChannelIds += data[posi+2]
			posi = posi + 3
		elif maxChannelIds[-1] == '\x02':
			maxChannelIds += data[posi+2:posi+4]
			posi = posi + 4

		maxUserIds = data[posi:posi+2]
		if maxUserIds[-1] == '\x01':
			maxUserIds += data[posi+2]
			posi = posi + 3
		elif maxUserIds[-1] == '\x02':
			maxUserIds += data[posi+2:posi+4]
			posi = posi + 4

		maxTokenIds = data[posi:posi+2]
		if maxTokenIds[-1] == '\x01':
			maxTokenIds += data[posi+2]
			posi = posi + 3
		elif maxTokenIds[-1] == '\x02':
			maxTokenIds += data[posi+2:posi+4]
			posi = posi + 4
	
		numPriorities = data[posi:posi+2]
		if numPriorities[-1] == '\x01':
			numPriorities += data[posi+2]
			posi = posi + 3
		elif numPriorities[-1] == '\x02':
			numPriorities += data[posi+2:posi+4]
			posi = posi + 4

		minThroughput = data[posi:posi+2]
		if minThroughput[-1] == '\x01':
			minThroughput += data[posi+2]
			posi = posi + 3
		elif minThroughput[-1] == '\x02':
			minThroughput += data[posi+2:posi+4]
			posi = posi + 4

		maxHeight = data[posi:posi+2]
		if maxHeight[-1] == '\x01':
			maxHeight += data[posi+2]
			posi = posi + 3
		elif maxHeight[-1] == '\x02':
			maxHeight += data[posi+2:posi+4]
			posi = posi + 4

		maxMCSPDUsize = data[posi:posi+2]
		if maxMCSPDUsize[-1] == '\x01':
			maxMCSPDUsize += data[posi+2]
			posi = posi + 3
		elif maxMCSPDUsize[-1] == '\x02':
			maxMCSPDUsize += data[posi+2:posi+4]
			posi = posi + 4
		
		protocolVersion = data[posi:posi+2]
		if protocolVersion[-1] == '\x01':
			protocolVersion += data[posi+2]
			posi = posi + 3
		elif protocolVersion[-1] == '\x02':
			protocolVersion += data[posi+2:posi+4]
			posi = posi + 4

		if self.debug:
			print "TPKT Header: version = %s" % (tpktVersion)
			print "TPKT Header: Reserved = %s" % (tpktReserved)
			print "TPKT Header: Packet length - high part = %s" % (tpktPLengthHigh)
			print "TPKT Header: Packet length - low part = %s" % (tpktPLengthLow)
			print "Packet Length: %s (%s)" % (pktLength, len(data))
			print "X.224: Length indicator = %s" % (x224length)
			print "X.224: Type = %s (%s)" % (x224type, hex(x224type))
			if hex(x224type)=='0xf0':
				print "\t Data TPDU"
			print "X.224: EOT = %s (%s)" % (x224eot, hex(x224eot))
			if data[8]=='\x65':
				print "MCS_TYPE_CONNECTINITIAL"
			print "BER: Type Length:", [bertypeLength]
			print "Connect-Initial::callingDomainSelector", [callingDomainSelector]
			print "Connect-Initial::calledDomainSelector", [calledDomainSelector]
			print "Connect-Initial::upwardFlag", [upwardFlag]
			print "Connect-Initial::targetParameters", [targetParameters]
			print "DomainParameters::maxChannelIds", [maxChannelIds]
			print "DomainParameters::maxUserIds", [maxUserIds]
			print "DomainParameters::maxTokenIds", [maxTokenIds]
			print "DomainParameters::numPriorities", [numPriorities]
			print "DomainParameters::minThroughput", [minThroughput]
			print "DomainParameters::maxHeight", [maxHeight]
			print "DomainParameters::maxMCSPDUsize", [maxMCSPDUsize]
			print "DomainParameters::protocolVersion", [protocolVersion]
			print [data[posi:]]

		if x224length == 2 and data[7]=='\x7f' and data[8]=='\x65':
			return True
		return False

	def createConferenceResponse(self):
		self.reply = []
		self.reply.append('\x03\x00\x01\x51') # tpkt header
		self.reply.append('\x02\xf0\x80')
		self.reply.append('\x7f\x66') # ber connect-respone
		self.reply.append('\x82\x01\x45')
		self.reply.append('\x0a\x01\x00')
		self.reply.append('\x02\x01\x00')
		self.reply.append('\x30\x1a')
		self.reply.append('\x02\x01\x22')
		self.reply.append('\x02\x01\x02')
		self.reply.append('\x02\x01\x00')
		self.reply.append('\x02\x01\x01')
		self.reply.append('\x02\x01\x00')
		self.reply.append('\x02\x01\x01')
		self.reply.append('\x02\x03\x00\xff\xf8')
		self.reply.append('\x02\x01\x02')
		self.reply.append('\x04\x82\x01\x1f')
		self.reply.append('\x00\x05\x00\x14\x7c\x00\x01\x2a\x14\x76\x0a\x01\x01\x00\x01\xc0')
		self.reply.append('\x00\x4d\x63\x44\x6e\x81\x08')
		self.reply.append('\x00\x05')
		self.reply.append('\x00\x14\x7c\x00\x01')
		self.reply.append('\x2a') #
		self.reply.append('\x14\x76\x0a\x01\x01\x00\x01\xc0\x00\x00\x4d\x63\x44\x6e\x81\x08')
		self.reply.append('\x4d\x63\x44\x6e')
		self.reply.append('\x81\x08')
		self.reply.append('\x01\x0c\x0c\x00')
		self.reply.append('\x04\x00\x08\x00')
		self.reply.append('\x00\x00\x00\x00')
		self.reply.append('\x03\x0c\x10\x00')
		self.reply.append('\xeb\x03')
		self.reply.append('\x03\x00') # TS_UD_SC_NET::channelCount
		self.reply.append('\xec\x03')
		self.reply.append('\xed\x03')
		self.reply.append('\xee\x03')
		self.reply.append('\x00\x00') # padding
		# SC_SECURITY, length
		
		
		return

	def consume(self, data, ownIP):
		#if self.debug:
		#	self.print_message(data)
		if len(data)==0:
			### client disconnected
			return None, None
		elif len(data)<10:
			if self.showRequests:
				print ">> received too short data (<10)"
				print [data]
				print
			return None, None
		### check for  x.224 connection request PDU
		if self.checkConnectionRequest(data):
			if self.debug:
				print ">> valid connection request received"
				print
			self.createConnectionResponse()
			return "".join(self.reply), None
		### check for conference request
		elif self.checkForConferenceRequest(data):
			if self.debug:
				print ">> valid conference request received"
				print
			self.createConferenceResponse()
			return "".join(self.reply), None
		else:
			self.print_message(data)


		### failover
		return None, None
