#!/usr/bin/python -O
"""
[Amun - low interaction honeypot]
Copyright (C) [2014]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>

SMB Emulation supported Exploits (Metasploit):
	- MS03049 (netapi)
	- MS04007 (asn1)
	- MS04011 (lsass)
	- MS04031 (netdde)
	- MS05039 (pnp)
	- MS06025 (rasmans)
	- MS06070 (netpmanageipcconnect)
	- MS08067 (netapi)
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

class amun_smb_prot:
	def __init__(self):
		self.debug = False
		self.showRequests = False
		### variables
		self.findDialect = '\x02NT LM 0.12'
		self.SMB_LEN0 = 2
		self.SMB_LEN1 = 3
		self.SMB_COMMAND = 8
		self.SMB_ERRCLASS = 9
		self.SMB_ERR_RESERVED = 10
		self.SMB_ERRCODE0 = 11
		self.SMB_ERRCODE1 = 12
		self.SMB_FLAG = 13
		self.SMB_FLAG0 = 14
		self.SMB_FLAG1 = 15
		self.SMB_TREEID0 = 28
		self.SMB_TREEID1 = 29
		self.SMB_PID0 = 30
		self.SMB_PID1 = 31
		self.SMB_UID0 = 32
		self.SMB_UID1 = 33
		self.SMB_MID0 = 34
		self.SMB_MID1 = 35
		self.SMB_WORDCOUNT = 36
		self.SMB_PACKETTYPE = 62
		### session variables
		self.sess_pid0 = '\x00'
		self.sess_pid1 = '\x00'
		self.sess_mid0 = '\x00'
		self.sess_mid1 = '\x00'
		### session stuff
		self.NUM_COUNT_ITEMS = None
		self.CALL_ID = None
		self.NTErrorCodes = True
		### fragmentation
		self.fragmentation = False
		self.fragments = []
		### writeAndX
		self.writtenBytes = ""
		self.readAndXOffset = 0
		self.NextReadWithError = False
		self.readCounter = 0
		### initial FID counter
		self.init_fid = 16384
		self.pipe_fid = {}
		### known windows pipes
		self.knownPipes = ["LANMAN","srvsvc","samr","wkssvc","NETLOGON","ntlsa","ntsvcs","lsass","lsarpc","winreg","spoolss","netdfs","rpcecho","svcctl","eventlog","unixinfo"]
		self.samr_data = "\x00\x00\x00\x01\x00\x00\x00\x00\x00\x50\xd2\x6f\x4e\xae\x4e\xd7\x11\xb3\x9d\x00\x05\x69\x9b\x01\x12\x00\x9b\x01\x12\x00\x00\x00"
		self.svcctl_data = "\x0c\x00\x0c\x00\x66\x00\x00\x00\x10\x00\x10\x00\xa2\x00\x00\x00\x15\x82\x88\xe0\x53\x00\xff\x01\x1f\x00\x9b\x01\x12\x00\x31\x00"
		self.lsarpc_data = "\x06\x00\x06\x00\x40\x00\x00\x00\x10\x00\x10\x00\x47\x00\x00\x00\x15\x8a\x88\xe0\x48\x00\x9b\x01\x12\x00\x9b\x01\x12\x00\x7a\xf2"
		self.other_data = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9b\x01\x12\x00\x9b\x01\x12\x00\x00\x00"
		### netbios header (byte 3 und 4 bestimmen die smb length)
		self.net_header = "\x00\x00\x00\x57"
		### smb header - flag[13]=\x98
		self.smb_header = "\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x98\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		### read andx data
		self.read_andx_data = "\x00\x05\x00\x0c\x03\x10\x00\x00\x00D\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10Cz\x01\x00\x0e\x00\\PIPE\\browser\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04]\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00+\x10H`\x02\x00\x00\x00"
		self.read_data_contextitem = "\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		self.read_last_data_contextitem = "\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
		### reply packet
		self.reply = []
		### vulnName
		self.vulnName = "SMB (Unknown)"
		self.shellcode = []
		self.trans2counter = 0

	def genBitvector(self, integer, count=16):
		return [str((integer >> y) & 1) for y in range(count-1, -1, -1)]

	def getShellcode(self):
		return "".join(self.shellcode)

	def getContent(self, message):
		try:
			smbWordCount = message[self.SMB_WORDCOUNT]
			lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
			ByteCountPosition = 36+1+lengthWordBlock
			smbByteCount = message[ByteCountPosition:ByteCountPosition+2]
			smbDataBlock = message[ByteCountPosition+2:]
			return smbDataBlock
		except:
			return message

	def getVulnName(self):
		return self.vulnName

	def setDialect(self, type):
		if type=='ntlm':
			self.findDialect = '\x02NT LM 0.12'
		elif type=='lanman':
			self.findDialect = '\x02LANMAN1.0'
		else:
			self.findDialect = '\x02NT LM 0.12'
		return

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

	def checkForNetbiosSessionRequest(self, data):
		try:
			type = data[0]
			flags = data[1]
			size = struct.unpack('2B', data[2:4])[1]
			rest = data[4:]
			### session request
			if type=='\x81' and len(rest)==size:
				return True
			else:
				return False
		except:
			return False
		return False

	def checkForNetbiosSessionRetargetRequest(self, data):
		try:
			type = data[0]
			flags = data[1]
			size = struct.unpack('2B', data[2:4])[1]
			rest = data[4:]
			### retarget request
			if type=='\x85' and len(rest)==size:
				return True
			else:
				return False
		except:
			return False
		return False

	def NetbiosRetargetReply(self, mesdata, ownIP):
		self.reply = []
		self.reply.append('\x84')
		self.reply.append('\x00')
		self.reply.append('\x00')
		self.reply.append('\x00')
		fill = ['\x00'] * 6
		self.reply.extend(fill)

		iprepr = socket.inet_aton(ownIP)
		self.reply[4:8] = iprepr

		self.reply[8] = '\x00'
		self.reply[9] = '\x8b'

		return

	def NetbiosSessionReply(self, mesdata):
		self.reply = []
		self.reply.append('\x82')
		self.reply.append('\x00')
		self.reply.append('\x00')
		self.reply.append('\x00')
		return

	def checkForSMBPacket(self, data):
		try:
			smbPart = data[4:8]
			if smbPart == '\xff\x53\x4d\x42':
				return True, data
			else:
				smbPart = data[:4]
				if smbPart == '\xff\x53\x4d\x42':
					data = '\x82\x00\x00\x00'+data
					return True, data
				else:
					return False, data
		except Exception as e:
			if self.debug:
				print e
			return False, data
		return False, data

	def getsmbNegotInfo(self, message):
		wordCount = struct.unpack('!B', message[self.SMB_WORDCOUNT])[0]
		if wordCount==0:
			bytePosition = self.SMB_WORDCOUNT+1
			byteCount = struct.unpack('!H', message[bytePosition:bytePosition+2])[0]
		else:
			bytePosition = self.SMB_WORDCOUNT+wordCount+1
			byteCount = struct.unpack('!H', message[bytePosition:bytePosition+2])[0]
		allDialects = message[bytePosition+2:].split('\x00')
		for item in allDialects:
			if item == '':
				allDialects.remove(item)
		for i in range(0, len(allDialects)):
			#if allDialects[i] == '\x02LANMAN1.0':
			#	return i
			if allDialects[i] == '\x02NT LM 0.12':
				if self.debug:
					print ">> setting Dialect to NT LM 0.12"
				return i
		return None

	def NegotiationReplyAnonymous(self, message, dialectIndex):
		self.reply = []
		self.reply.extend(list(self.net_header))
		self.reply.extend(list(self.smb_header))

		self.reply[self.SMB_ERRCLASS] = '\x00'
		self.reply[self.SMB_ERRCODE0] = '\x00'
		self.reply[self.SMB_ERRCODE1] = '\x00'

		self.reply[self.SMB_FLAG] = '\x98'
		self.reply[self.SMB_FLAG0] = '\x01'
		self.reply[self.SMB_FLAG1] = '\x28' #\xc8 - with extended security

		self.reply[self.SMB_PID0] = message[self.SMB_PID0]
		self.reply[self.SMB_PID1] = message[self.SMB_PID1]

		self.reply[self.SMB_MID0] = message[self.SMB_MID0]
		self.reply[self.SMB_MID1] = message[self.SMB_MID1]

		fill = ['\x00'] * 75
		self.reply.extend(fill)

		### word count - \x11 = NT LM 0.12
		### \x0d = LAN Manager
		###
		self.reply[self.SMB_WORDCOUNT] = "\x11"
		###### parameter block
		### dialect
		if dialectIndex == None:
			self.reply[37] = "\x05"
			self.reply[38] = "\x00"
		else:
			dialectHex = struct.pack('H', dialectIndex)
			self.reply[37:39] = dialectHex
		### securityMode
		self.reply[39] = "\x03"
		### max mpx count
		self.reply[40] = "\x32"
		self.reply[41] = "\x00"
		### max vcs
		self.reply[42] = "\x01"
		self.reply[43] = "\x00"
		### max buffer size
		self.reply[44] = "\x04"
		self.reply[45] = "\x11"
		#self.reply[45] = "\x00"
		self.reply[46] = "\x00"
		self.reply[47] = "\x00"
		### max raw
		self.reply[48] = "\x00"
		self.reply[49] = "\x00"
		self.reply[50] = "\x01"
		self.reply[51] = "\x00"
		### session key
		self.reply[52] = "\x00"
		self.reply[53] = "\x00"
		self.reply[54] = "\x00"
		self.reply[55] = "\x00"
		### capabilities
		self.reply[56] = "\xfd"
		self.reply[57] = "\xe3"
		self.reply[58] = "\x00"
		self.reply[59] = "\x80"
		### system time high
		### generate time string
		smbtime = struct.pack('Q' , ( (time.time()+11644473600)*10000000 ) )
		self.reply[60:68] = smbtime
		### server time zone
		self.reply[68] = "\x88"
		self.reply[69] = "\xfe"
		### encryptedkey lenght
		self.reply[70] = "\x08"
		### byte count
		self.reply[71] = "\x00"
		self.reply[72] = "\x00"
		### testme
		self.reply[73] = "\xd3"
		self.reply[74] = "\x62"
		self.reply[75] = "\xfe"
		self.reply[76] = "\xb4"
		self.reply[77] = "\x4b"
		self.reply[78] = "\x2c"
		self.reply[79] = "\xbc"
		self.reply[80] = "\x9a"
		self.reply[81] = "\x57" # W
		self.reply[82] = "\x00"
		self.reply[83] = "\x4f" # O
		self.reply[84] = "\x00"
		self.reply[85] = "\x52" # R
		self.reply[86] = "\x00"
		self.reply[87] = "\x4b" # K
		self.reply[88] = "\x00"
		self.reply[89] = "\x47" # G
		self.reply[90] = "\x00"
		self.reply[91] = "\x52" # R
		self.reply[92] = "\x00"
		self.reply[93] = "\x4f" # O
		self.reply[94] = "\x00"
		self.reply[95] = "\x55" # U
		self.reply[96] = "\x00"
		self.reply[97] = "\x50" # P
		self.reply[98] = "\x00"
		self.reply[99] = "\x00"
		self.reply[100] = "\x00"
		self.reply[101] = "\x50" # P
		self.reply[102] = "\x00"
		self.reply[103] = "\x43" # C
		self.reply[104] = "\x00"
		self.reply[105] = "\x58" # X
		self.reply[106] = "\x00"
		self.reply[107] = "\x50" # P
		self.reply[108] = "\x00"
		self.reply[109] = "\x00"
		self.reply[110] = "\x00"
		### calc byte count
		bytecount = struct.pack('H', len(self.reply[73:]))
		self.reply[71:73] = bytecount
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def emptyTransaction(self, message):
		self.genSMBHeader(smbCommand="\x25", err="\x05", errRes="\x02", err0="\x00", err1="\xc0", pid0=self.sess_pid0, pid1=self.sess_pid1, mid0=self.sess_mid0, mid1=self.sess_mid1, uid0='\x01', uid1='\x08', tree0='\x00', tree1='\x08')

		fill = ['\x00'] * 96
		self.reply.extend(fill)

		smbWordCount = message[36]
		lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
		if lengthWordBlock>0:
			wordBlock = message[37:37+lengthWordBlock]
			totalParamCount = wordBlock[0:2]
			totalDataCount = wordBlock[2:4]
			paramCount = wordBlock[18:20]
			dataCount = wordBlock[22:24]
		else:
			totalParamCount = '\x00\x00'
			totalDataCount = '\x48\x00'

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x0a'
		### totalparametercount
		self.reply[37:39] = totalParamCount
		### totaldatacount
		self.reply[39:41] = totalDataCount
		## reserved1 must be zero
		self.reply[41] = '\x00'
		self.reply[42] = '\x00'
		### parametercount - one transaction then equal to totalparametercount
		if not self.fragmentation:
			self.reply[43:45] = totalParamCount
		else:
			self.reply[43:45] = paramCount
		### parameteroffset bytes to transactionparameterbytes (parameters)
		self.reply[45] = '\x38'
		self.reply[46] = '\x00'
		### parameterdisplacement
		self.reply[47] = '\x00'
		self.reply[48] = '\x00'
		### DataCount -one transaction then equal to totaldatacount
		if not self.fragmentation:
			self.reply[49:51] = totalDataCount
		else:
			self.reply[49:51] = dataCount
		### DataOffset bytes to data
		self.reply[51] = '\x38'
		self.reply[52] = '\x00'
		### DataDisplacement
		self.reply[53] = '\x00'
		self.reply[54] = '\x00'
		### SetupCount
		self.reply[55] = '\x00'
		### reserved2
		self.reply[56] = '\x00'
		### byte count
		self.reply[57] = '\x49'
		self.reply[58] = '\x00'
		### padding
		self.reply[59] = '\x48'
		### dcerp version
		self.reply[60] = '\x05'
		### dcerp version minor
		self.reply[61] = '\x00'
		### packet type - ack
		self.reply[62] = '\x0c'
		### packet flags
		self.reply[63] = '\x03'
		### data representation
		self.reply[64] = '\x10'
		self.reply[65] = '\x00'
		self.reply[66] = '\x00'
		self.reply[67] = '\x00'
		### frag length
		self.reply[68] = '\x48'
		self.reply[69] = '\x00'
		### auth length
		self.reply[70] = '\x00'
		self.reply[71] = '\x00'
		### call id
		self.reply[72:76] = '\x01\x00\x00\x00'
		### max xmit frag
		self.reply[76] = '\xb8'
		self.reply[77] = '\x10'
		### max recv frag
		self.reply[78] = '\xb8'
		self.reply[79] = '\x10'
		### assoc group
		self.reply[80] = '\xa2'
		self.reply[81] = '\x55'
		self.reply[82] = '\x00'
		self.reply[83] = '\x00'
		### sec addr len
		self.reply[84] = '\x0f'
		self.reply[85] = '\x00'
		### sec addr
		self.reply[86] = '\x5c'
		self.reply[87] = '\x70'
		self.reply[88] = '\x69'
		self.reply[89] = '\x70'
		self.reply[90] = '\x65'
		self.reply[91] = '\x5c'
		self.reply[92] = '\x65'
		self.reply[93] = '\x70'
		self.reply[94] = '\x6d'
		self.reply[95] = '\x61'
		self.reply[96] = '\x70'
		self.reply[97] = '\x70'
		self.reply[98] = '\x65'
		self.reply[99] = '\x72'
		self.reply[100] = '\x00'
		###
		self.reply[101] = '\x00'
		self.reply[102] = '\x00'
		self.reply[103] = '\x00'
		### num results
		self.reply[104] = '\x01'
		###
		self.reply[105] = '\x00'
		self.reply[106] = '\x00'
		self.reply[107] = '\x00'

		### context
		self.reply[108] = '\x00'
		self.reply[109] = '\x00'
		self.reply[110] = '\x00'
		self.reply[111] = '\x00'
		self.reply[112] = '\x04'
		self.reply[113] = '\x5d'
		self.reply[114] = '\x88'
		self.reply[115] = '\x8a'
		self.reply[116] = '\xeb'
		self.reply[117] = '\x1c'
		self.reply[118] = '\xc9'
		self.reply[119] = '\x11'
		self.reply[120] = '\x9f'
		self.reply[121] = '\xe8'
		self.reply[122] = '\x08'
		self.reply[123] = '\x00'
		self.reply[124] = '\x2b'
		self.reply[125] = '\x10'
		self.reply[126] = '\x48'
		self.reply[127] = '\x60'
		self.reply[128] = '\x02'
		self.reply[129] = '\x00'
		self.reply[130] = '\x00'
		self.reply[131] = '\x00'
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return


	def smbTransaction(self, message, callid):
		self.genSMBHeader(smbCommand="\x25", pid0=self.sess_pid0, pid1=self.sess_pid1, mid0=self.sess_mid0, mid1=self.sess_mid1, uid0='\x01', uid1='\x08', tree0='\x00', tree1='\x08', flag='\x80', flag0='\x00', flag1='\x01')

		fill = ['\x00'] * 96
		self.reply.extend(fill)

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x0a'
		### totalparametercount
		self.reply[37] = '\x00'
		self.reply[38] = '\x00'
		### totaldatacount
		self.reply[39] = '\x48'
		self.reply[40] = '\x00'
		## reserved1 must be zero
		self.reply[41] = '\x00'
		self.reply[42] = '\x00'
		### parametercount - one transaction then equal to totalparametercount
		self.reply[43] = '\x00'
		self.reply[44] = '\x00'
		### parameteroffset bytes to transactionparameterbytes (parameters)
		self.reply[45] = '\x38'
		self.reply[46] = '\x00'
		### parameterdisplacement
		self.reply[47] = '\x00'
		self.reply[48] = '\x00'
		### DataCount -one transaction then equal to totaldatacount
		self.reply[49] = '\x48'
		self.reply[50] = '\x00'
		### DataOffset bytes to data
		self.reply[51] = '\x38'
		self.reply[52] = '\x00'
		### DataDisplacement
		self.reply[53] = '\x00'
		self.reply[54] = '\x00'
		### SetupCount
		self.reply[55] = '\x00'
		### reserved2
		self.reply[56] = '\x00'
		### byte count
		self.reply[57] = '\x49'
		self.reply[58] = '\x00'
		### padding
		self.reply[59] = '\x48'
		### dcerp version
		self.reply[60] = '\x05'
		### dcerp version minor
		self.reply[61] = '\x00'
		### packet type - ack
		self.reply[62] = '\x0c'
		### packet flags
		self.reply[63] = '\x03'
		### data representation
		self.reply[64] = '\x10'
		self.reply[65] = '\x00'
		self.reply[66] = '\x00'
		self.reply[67] = '\x00'
		### frag length
		self.reply[68] = '\x48'
		self.reply[69] = '\x00'
		### auth length
		self.reply[70] = '\x00'
		self.reply[71] = '\x00'
		### call id
		self.reply[72:76] = callid
		### max xmit frag
		self.reply[76] = '\xb8'
		self.reply[77] = '\x10'
		### max recv frag
		self.reply[78] = '\xb8'
		self.reply[79] = '\x10'
		### assoc group
		self.reply[80] = '\xa2'
		self.reply[81] = '\x55'
		self.reply[82] = '\x00'
		self.reply[83] = '\x00'
		### sec addr len
		self.reply[84] = '\x0f'
		self.reply[85] = '\x00'
		### sec addr
		self.reply[86] = '\x5c'
		self.reply[87] = '\x70'
		self.reply[88] = '\x69'
		self.reply[89] = '\x70'
		self.reply[90] = '\x65'
		self.reply[91] = '\x5c'
		self.reply[92] = '\x65'
		self.reply[93] = '\x70'
		self.reply[94] = '\x6d'
		self.reply[95] = '\x61'
		self.reply[96] = '\x70'
		self.reply[97] = '\x70'
		self.reply[98] = '\x65'
		self.reply[99] = '\x72'
		self.reply[100] = '\x00'
		###
		self.reply[101] = '\x00'
		self.reply[102] = '\x00'
		self.reply[103] = '\x00'
		### num results
		self.reply[104] = '\x01'
		###
		self.reply[105] = '\x00'
		self.reply[106] = '\x00'
		self.reply[107] = '\x00'

		### context
		self.reply[108] = '\x00'
		self.reply[109] = '\x00'
		self.reply[110] = '\x00'
		self.reply[111] = '\x00'
		self.reply[112] = '\x04'
		self.reply[113] = '\x5d'
		self.reply[114] = '\x88'
		self.reply[115] = '\x8a'
		self.reply[116] = '\xeb'
		self.reply[117] = '\x1c'
		self.reply[118] = '\xc9'
		self.reply[119] = '\x11'
		self.reply[120] = '\x9f'
		self.reply[121] = '\xe8'
		self.reply[122] = '\x08'
		self.reply[123] = '\x00'
		self.reply[124] = '\x2b'
		self.reply[125] = '\x10'
		self.reply[126] = '\x48'
		self.reply[127] = '\x60'
		self.reply[128] = '\x02'
		self.reply[129] = '\x00'
		self.reply[130] = '\x00'
		self.reply[131] = '\x00'

		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def smbLookUpReq(self, message, ownIP, callid):
		self.reply = []
		self.reply.extend(list(self.net_header))
		self.reply.extend(list(self.smb_header))

		self.reply[self.SMB_COMMAND] = "\x25"

		self.reply[self.SMB_ERRCLASS] = "\x00"
		self.reply[self.SMB_ERRCODE1] = "\x00"

		self.reply[self.SMB_FLAG] = '\x98'
		self.reply[self.SMB_FLAG0] = "\x07"
		self.reply[self.SMB_FLAG1] = "\xc8"

		self.reply[self.SMB_TREEID0] = "\x00"
		self.reply[self.SMB_TREEID1] = "\x08"

		self.reply[self.SMB_PID0] = message[self.SMB_PID0]
		self.reply[self.SMB_PID1] = message[self.SMB_PID1]

		self.reply[self.SMB_UID0] = "\x01"
		self.reply[self.SMB_UID1] = "\x08"

		self.reply[self.SMB_MID0] = message[self.SMB_MID0]
		self.reply[self.SMB_MID1] = message[self.SMB_MID1]

		fill = ['\x00'] * 220
		self.reply.extend(fill)

		### word count
		self.reply[36] = '\x0a'
		### totalparametercount
		self.reply[37] = '\x00'
		self.reply[38] = '\x00'
		### totaldatacount
		self.reply[39] = '\x44'
		self.reply[40] = '\x03'
		## reserved1 must be zero
		self.reply[41] = '\x00'
		self.reply[42] = '\x00'
		### parametercount - one transaction then equal to totalparametercount
		self.reply[43] = '\x00'
		self.reply[44] = '\x00'
		### parameteroffset bytes to transactionparameterbytes (parameters)
		self.reply[45] = '\x08'
		self.reply[46] = '\x00'
		### parameterdisplacement
		self.reply[47] = '\x00'
		self.reply[48] = '\x00'
		### DataCount -one transaction then equal to totaldatacount
		self.reply[49] = '\x44'
		self.reply[50] = '\x03'
		### DataOffset bytes to data
		self.reply[51] = '\x08'
		self.reply[52] = '\x00'
		### DataDisplacement
		self.reply[53] = '\x00'
		self.reply[54] = '\x00'
		### SetupCount
		self.reply[55] = '\x00'
		### reserved2
		self.reply[56] = '\x00'

		### byte count
		self.reply[57] = '\xc5'
		self.reply[58] = '\x00'
		### padding
		self.reply[59] = '\x64'
		### dcerp version
		self.reply[60] = '\x05'
		### dcerp version minor
		self.reply[61] = '\x00'
		### packet type - ack
		self.reply[62] = '\x02'
		### packet flags
		self.reply[63] = '\x03'
		### data representation
		self.reply[64] = '\x10'
		self.reply[65] = '\x00'
		self.reply[66] = '\x00'
		self.reply[67] = '\x00'
		### frag length
		self.reply[68] = '\xc4'
		self.reply[69] = '\x00'
		### auth length
		self.reply[70] = '\x00'
		self.reply[71] = '\x00'
		### call id
		self.reply[72:76] = callid
		### alloc hint
		self.reply[76] = '\xac'
		self.reply[77] = '\x00'
		self.reply[78] = '\x00'
		self.reply[79] = '\x00'
		### context id
		self.reply[80] = '\x00'
		self.reply[81] = '\x00'
		### cancel count
		self.reply[82] = '\x00'
		### opnum
		self.reply[83] = '\x00'
		### handle
		self.reply[84] = '\x00'
		self.reply[85] = '\x00'
		self.reply[86] = '\x00'
		self.reply[87] = '\x00'
		self.reply[88] = '\xf4'
		self.reply[89] = '\xfa'
		self.reply[90] = '\xc5'
		self.reply[91] = '\x8a'
		self.reply[92] = '\xa7'
		self.reply[93] = '\x51'
		self.reply[94] = '\xde'
		self.reply[95] = '\x11'
		self.reply[96] = '\xa6'
		self.reply[97] = '\x8c'
		self.reply[98] = '\x00'
		self.reply[99] = '\x0c'
		self.reply[100] = '\x29'
		self.reply[101] = '\xe0'
		self.reply[102] = '\x69'
		self.reply[103] = '\x22'
		### num entries
		self.reply[104] = '\x01'
		self.reply[105] = '\x00'
		self.reply[106] = '\x00'
		self.reply[107] = '\x00'
		### max count
		self.reply[108] = '\x01'
		self.reply[109] = '\x00'
		self.reply[110] = '\x00'
		self.reply[111] = '\x00'
		### offset
		self.reply[112] = '\x00'
		self.reply[113] = '\x00'
		self.reply[114] = '\x00'
		self.reply[115] = '\x00'
		### actual count
		self.reply[116] = '\x01'
		self.reply[117] = '\x00'
		self.reply[118] = '\x00'
		self.reply[119] = '\x00'
		### object
		self.reply[120] = '\x00'
		self.reply[121] = '\x00'
		self.reply[122] = '\x00'
		self.reply[123] = '\x00'
		self.reply[124] = '\x00'
		self.reply[125] = '\x00'
		self.reply[126] = '\x00'
		self.reply[127] = '\x00'
		self.reply[128] = '\x00'
		self.reply[129] = '\x00'
		self.reply[130] = '\x00'
		self.reply[131] = '\x00'
		self.reply[132] = '\x00'
		self.reply[133] = '\x00'
		self.reply[134] = '\x00'
		self.reply[135] = '\x00'
		### reference id
		self.reply[136] = '\x03'
		self.reply[137] = '\x00'
		self.reply[138] = '\x00'
		self.reply[139] = '\x00'
		### annotation offset
		self.reply[140] = '\x00'
		self.reply[141] = '\x00'
		self.reply[142] = '\x00'
		self.reply[143] = '\x00'
		### annotation length
		self.reply[144] = '\x12'
		self.reply[145] = '\x00'
		self.reply[146] = '\x00'
		self.reply[147] = '\x00'
		### annotation
		self.reply[148] = '\x4d'
		self.reply[149] = '\x65'
		self.reply[150] = '\x73'
		self.reply[151] = '\x73'
		self.reply[152] = '\x65'
		self.reply[153] = '\x6e'
		self.reply[154] = '\x67'
		self.reply[155] = '\x65'
		self.reply[156] = '\x72'
		self.reply[157] = '\x20'
		self.reply[158] = '\x53'
		self.reply[159] = '\x65'
		self.reply[160] = '\x72'
		self.reply[161] = '\x76'
		self.reply[162] = '\x69'
		self.reply[163] = '\x63'
		self.reply[164] = '\x65'
		self.reply[165] = '\x00'
		####
		self.reply[166] = '\x52'
		self.reply[167] = '\x8e'
		### length
		self.reply[168] = '\x4b'
		self.reply[169] = '\x00'
		self.reply[170] = '\x00'
		self.reply[171] = '\x00'
		### length
		self.reply[172] = '\x4b'
		self.reply[173] = '\x00'
		self.reply[174] = '\x00'
		self.reply[175] = '\x00'
		#### floors
		self.reply[176] = '\x05'
		self.reply[177] = '\x00'
		### lhs length
		self.reply[178] = '\x13'
		self.reply[179] = '\x00'
		### protocol
		self.reply[180] = '\x0d'
		### uuid
		### this is vuln 50 AB C2 A4 - 57 4D - 40 B3 - 9D 66- EE 4F D5 FB A0 76 (milworm)
		self.reply[181] = '\xa4'
		self.reply[182] = '\xc2'
		self.reply[183] = '\xab'
		self.reply[184] = '\x50'
		self.reply[185] = '\x4d'
		self.reply[186] = '\x57'
		self.reply[187] = '\xb3'
		self.reply[188] = '\x40'
		self.reply[189] = '\x9d'
		self.reply[190] = '\x66'
		self.reply[191] = '\xee'
		self.reply[192] = '\x4f'
		self.reply[193] = '\xd5'
		self.reply[194] = '\xfb'
		self.reply[195] = '\xa0'
		self.reply[196] = '\x76'
		### version
		self.reply[197] = '\x01'
		self.reply[198] = '\x00'
		### rhs length
		self.reply[199] = '\x02'
		self.reply[200] = '\x00'
		### version minor
		self.reply[201] = '\x00'
		self.reply[202] = '\x00'
		### lhs length
		self.reply[203] = '\x13'
		self.reply[204] = '\x00'
		### protocol
		self.reply[205] = '\x0d'
		### uuid
		self.reply[206] = '\x04'
		self.reply[207] = '\x5d'
		self.reply[208] = '\x88'
		self.reply[209] = '\x8a'
		self.reply[210] = '\xeb'
		self.reply[211] = '\x1c'
		self.reply[212] = '\xc9'
		self.reply[213] = '\x11'
		self.reply[214] = '\x9f'
		self.reply[215] = '\xe8'
		self.reply[216] = '\x08'
		self.reply[217] = '\x00'
		self.reply[218] = '\x2b'
		self.reply[219] = '\x10'
		self.reply[220] = '\x48'
		self.reply[221] = '\x60'
		### version
		self.reply[222] = '\x02'
		self.reply[223] = '\x00'
		### rhs length
		self.reply[224] = '\x02'
		self.reply[225] = '\x00'
		### version minor
		self.reply[226] = '\x00'
		self.reply[227] = '\x00'
		### lhs length
		self.reply[228] = '\x01'
		self.reply[229] = '\x00'
		### protocol
		self.reply[230] = '\x0a'
		### rhs length
		self.reply[231] = '\x02'
		self.reply[232] = '\x00'
		### version minor
		self.reply[233] = '\x00'
		self.reply[234] = '\x00'
		### lhs length
		self.reply[235] = '\x01'
		self.reply[236] = '\x00'
		### dod udp
		self.reply[237] = '\x08'
		### rhs length
		self.reply[238] = '\x02'
		self.reply[239] = '\x00'
		### udp port
		self.reply[240] = '\x00'
		self.reply[241] = '\x8b'
		### lhs length
		self.reply[242] = '\x01'
		self.reply[243] = '\x00'
		### dod ip
		self.reply[244] = '\x09'
		### rhs length
		self.reply[245] = '\x04'
		self.reply[246] = '\x00'
		### IP -
		self.reply[247] = '\x00'
		self.reply[248] = '\x00'
		self.reply[249] = '\x00'
		self.reply[250] = '\x00'
		####
		self.reply[251] = '\x00'
		self.reply[252] = '\x00'
		self.reply[253] = '\x00'
		self.reply[254] = '\x00'
		self.reply[255] = '\x00'

		###
		iprepr = socket.inet_aton(ownIP)
		self.reply[248:252] = iprepr

		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def disectWriteAndX(self, message):
		try:
			opnumber = -1
			if self.debug:
				print
				print '--- SMB Write AndX ---'
			smbWordCount = message[36]
			if self.debug:
				print "Word Count: ",[smbWordCount]," - ",struct.unpack('!B', smbWordCount)[0]
			lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
			if self.debug:
				print "WordsBlock Length: ",lengthWordBlock
			if lengthWordBlock>0:
				wordBlock = message[37:37+lengthWordBlock]
				if self.debug:
					print "\tWordBlock: ",[wordBlock]," - ",len(wordBlock)
					print "\tAndXCommand: ",[wordBlock[0]]
					print "\tReserved: ",[wordBlock[1]]
					print "\tAndXOffset: ",[wordBlock[2:4]]
					print "\tFID: ",[wordBlock[4:6]]
					print "\tOffset: ",[wordBlock[6:10]],struct.unpack('2H', wordBlock[6:10])[0]
					print "\tReserved: ",[wordBlock[10:14]],struct.unpack('2H', wordBlock[10:14])[0]
					print "\tWrite Mode: ",[wordBlock[14:16]],struct.unpack('H', wordBlock[14:16])[0]
					print "\tRemaining: ",[wordBlock[16:18]],struct.unpack('H', wordBlock[16:18])[0]
					print "\tData Length High: ",[wordBlock[18:20]],struct.unpack('H', wordBlock[18:20])[0]
					print "\tData Length Low: ",[wordBlock[20:22]],struct.unpack('H', wordBlock[20:22])[0]
					print "\tData Offset: ",[wordBlock[22:24]],struct.unpack('H', wordBlock[22:24])[0]
					### only included in wordcount 0x0e and not in 0x0c
					if smbWordCount == '\x0e':
						print "\tHigh Offset: ",[wordBlock[24:28]]
			if self.debug:
				print "--- Data Block ---"
			ByteCountPosition = 37+lengthWordBlock
			smbByteCount = message[ByteCountPosition:ByteCountPosition+2]
			### check for padding byte
			if message[ByteCountPosition+2:ByteCountPosition+5] != '\x05\x00\x0b' and message[ByteCountPosition+3:ByteCountPosition+6] == '\x05\x00\x0b':
				if self.debug:
					print "WriteAndX with Padding"
					print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
					print "Padding: ",[message[ByteCountPosition+2]]
				smbDataBlock = message[ByteCountPosition+3:]
			elif message[ByteCountPosition+2:ByteCountPosition+5] != '\x05\x00\x00' and message[ByteCountPosition+3:ByteCountPosition+6] == '\x05\x00\x00':
				if self.debug:
					print "WriteAndX with Padding"
					print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
					print "Padding: ",[message[ByteCountPosition+2]]
				smbDataBlock = message[ByteCountPosition+3:]
			else:
				if self.debug:
					print "WriteAndX without Padding"
					print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
				smbDataBlock = message[ByteCountPosition+2:]
			if self.debug:
				print "\tData Block: ",[smbDataBlock]," - ",len(smbDataBlock)
			### broken header
			if len(smbDataBlock)<10 and not self.fragmentation:
				if len(self.fragments)>0 and len("".join(self.fragments))+len(smbDataBlock)>=10:
					self.fragments.append(smbDataBlock)
					smbDataBlock = "".join(self.fragments)
				else:
					self.fragments.append(smbDataBlock)
					if self.debug:
						print "\tOut of Band (Broken Header): ",[smbDataBlock]
					return opnumber, ""
			### determine fragmentation by getting the fragmentation length field of the header part (8:10)
			if len(smbDataBlock)>=10 and not self.fragmentation:
				if len(self.fragments)>0:
					self.fragments.append(smbDataBlock)
					smbDataBlock = "".join(self.fragments)
				fragLength = struct.unpack('H', smbDataBlock[8:10])[0]
				if self.debug:
					print "\tFragmentationLength: ",fragLength
				if len(smbDataBlock)<fragLength:
					if self.debug:
						print "\tFragmentation Detected (1)"
					self.fragmentation = True
					self.fragments.append(smbDataBlock)
					return opnumber, ""
				else:
					if smbDataBlock[2] == '\x0b': # bind request
						numCTXItems = struct.unpack('B', smbDataBlock[24])[0]
						self.NUM_COUNT_ITEMS = smbDataBlock[24]
						self.CALL_ID = smbDataBlock[12:16]
						if self.debug:
							print "\tCall ID: ",[self.CALL_ID]
							print "\tNum Ctx Items: ", [self.NUM_COUNT_ITEMS], struct.unpack('B', self.NUM_COUNT_ITEMS)[0]
						counter = struct.unpack('B', self.NUM_COUNT_ITEMS)[0]
						startposition = 28
						if counter>0:
							#### 44 byte ein item
							for item in range(0, counter):
								if self.debug:
									print "\tCtx Item ",item,": ",[smbDataBlock[startposition:startposition+44]], len(smbDataBlock[startposition:startposition+44])
								startposition += 44
						return opnumber, smbDataBlock
					elif smbDataBlock[2] == '\x00': # write request
						packetFlag = struct.unpack('B', smbDataBlock[3])[0]
						opnumber = struct.unpack('H', smbDataBlock[22:24])[0]
						self.writtenBytes = copy.copy(smbDataBlock)
						if self.debug:
							print "\tPacketFlag: ",packetFlag
							print "\tOperationNumber: ",opnumber
							print "\tTotal Written Bytes: ",[self.writtenBytes],len(self.writtenBytes)
						return opnumber, smbDataBlock
			elif self.fragmentation:
				self.fragments.append(smbDataBlock)
				smbDataBlock = "".join(self.fragments)
				fragLength = struct.unpack('H', smbDataBlock[8:10])[0]
				if len(smbDataBlock)<fragLength:
					if self.debug:
						print "\tFragmentation Detected: ", fragLength, " ", len(smbDataBlock)
					return opnumber, ""
				elif len(smbDataBlock)<3:
					if self.debug:
						print "\tBroken Fragmentation: ", len(smbDataBlock)
					self.fragmentation = False
					self.fragments = []
					return opnumber, ""
				else:
					if self.debug:
						print "\tFragments found -> trying reassemble"
					if len(smbDataBlock)==fragLength:
						self.fragmentation = False
						self.fragments = []
					else:
						if self.debug:
							print "\tfound more than expected -> new fragmentation created"
						overhead = smbDataBlock[fragLength:]
						smbDataBlock = smbDataBlock[:fragLength]
						self.fragments = [overhead]
					if smbDataBlock[2] == '\x0b': # bind request
						numCTXItems = struct.unpack('B', smbDataBlock[24])[0]
						self.NUM_COUNT_ITEMS = smbDataBlock[24]
						self.CALL_ID = smbDataBlock[12:16]
						if self.debug:
							print "\tCall ID: ",[self.CALL_ID]
							print "\tNum Ctx Items: ", [self.NUM_COUNT_ITEMS], struct.unpack('B', self.NUM_COUNT_ITEMS)[0]
						counter = struct.unpack('B', self.NUM_COUNT_ITEMS)[0]
						startposition = 28
						if counter>0:
							#### 44 byte ein item
							for item in range(0, counter):
								if self.debug:
									print "\tCtx Item ",item,": ",[smbDataBlock[startposition:startposition+44]], len(smbDataBlock[startposition:startposition+44])
								startposition += 44
						return opnumber, smbDataBlock
					elif smbDataBlock[2] == '\x00': # write request
						packetFlag = struct.unpack('B', smbDataBlock[3])[0]
						opnumber = struct.unpack('H', smbDataBlock[22:24])[0]
						self.writtenBytes = copy.copy(smbDataBlock)
						if self.debug:
							print "\tPacketFlag: ",packetFlag
							print "\tOperationNumber: ",opnumber
							print "\tTotal Written Bytes: ",[self.writtenBytes],len(self.writtenBytes)
						return opnumber, smbDataBlock
					else:
						if self.debug:
							print "\tData Block: ",[smbDataBlock]," - ",len(smbDataBlock)
							print "\tFragments: ",[self.fragments]
							print "\tRequest Byte: ", [smbDataBlock[2]]
						### MZ header in fragmentation
						if self.debug and (smbDataBlock[2] == 'Z' or smbDataBlock[0] == 'M'):
							print "\tFound MZ header of executable file -> appending"
						### fixme append to shellcode?
						self.shellcode = []
						self.shellcode.append(smbDataBlock)
						self.shellcode.extend(self.fragments)
						return -2, smbDataBlock
						### fixme append to fragments?
						### fixme create new list to append file uploads?
		except KeyboardInterrupt:
			raise

	def emptyWriteAndX(self, message):
		self.genSMBHeader(smbCommand="\x2f", pid0=self.sess_pid0, pid1=self.sess_pid1, mid0=self.sess_mid0, mid1=self.sess_mid1, uid0='\x01', uid1='\x08', tree0='\x00', tree1='\x08')

		fill = ['\x00'] * 3
		self.reply.extend(fill)

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x00'
		### byte count
		self.reply[37] = '\x00'
		self.reply[38] = '\x00'
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def WriteAndX(self, message):
		self.reply = []
		self.reply.extend(list(self.net_header))
		self.reply.extend(list(self.smb_header))

		self.reply[self.SMB_COMMAND] = "\x2f"

		self.reply[self.SMB_ERRCLASS] = "\x00"
		self.reply[self.SMB_ERRCODE1] = "\x00"

		self.reply[self.SMB_FLAG] = '\x98'
		self.reply[self.SMB_FLAG0] = "\x07"
		self.reply[self.SMB_FLAG1] = "\xc8"

		self.reply[self.SMB_TREEID0] = "\x00"
		self.reply[self.SMB_TREEID1] = "\x08"

		self.reply[self.SMB_PID0] = message[self.SMB_PID0]
		self.reply[self.SMB_PID1] = message[self.SMB_PID1]

		self.reply[self.SMB_UID0] = "\x01"
		self.reply[self.SMB_UID1] = "\x08"

		self.reply[self.SMB_MID0] = message[self.SMB_MID0]
		self.reply[self.SMB_MID1] = message[self.SMB_MID1]

		fill = ['\x00'] * 15
		self.reply.extend(fill)

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x06'
		### andx command
		self.reply[37] = '\xff'
		### andx reserved
		self.reply[38] = '\x00'
		### andx offset
		self.reply[39] = '\x2f'
		self.reply[40] = '\x00'
		### count
		self.reply[41] = message[36+21]
		self.reply[42] = message[36+22]
		### remaining
		self.reply[43] = '\xff'
		self.reply[44] = '\xff'
		### reserved
		self.reply[45] = '\x00'
		self.reply[46] = '\x00'
		self.reply[47] = '\x00'
		self.reply[48] = '\x00'
		### byte count
		self.reply[49] = '\x00'
		self.reply[50] = '\x00'
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def disectReadAndX(self, message):
		try:
			if self.debug:
				print
				print '--- SMB Read AndX ---'
			smbWordCount = message[36]
			wordCount = struct.unpack('!B', smbWordCount)[0]
			if self.debug:
				print "Word Count: ",[smbWordCount]," - ",struct.unpack('!B', smbWordCount)[0]
			lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
			if self.debug:
				print "WordsBlock Length: ",lengthWordBlock
			if lengthWordBlock>0:
				wordBlock = message[37:37+lengthWordBlock]
				if self.debug:
					print "\tWordBlock: ",[wordBlock]," - ",len(wordBlock)
					print "\tAndXCommand: ",[wordBlock[0]]
					print "\tReserved: ",[wordBlock[1]]
					print "\tAndXOffset: ",[wordBlock[2:4]]
					print "\tFID: ",[wordBlock[4:6]],struct.unpack('H', wordBlock[4:6])[0]
					print self.pipe_fid
					print "\tOffset: ",[wordBlock[6:10]],struct.unpack('2H', wordBlock[6:10])[0]
				offset = struct.unpack('2H', wordBlock[6:10])[0]
				if self.debug:
					print "\tMax Count: ",[wordBlock[10:12]],struct.unpack('H', wordBlock[10:12])[0]
				maxcount = struct.unpack('H', wordBlock[10:12])[0]
				if self.debug:
					print "\tMin Count: ",[wordBlock[12:14]]
					print "\tMaxCountHigh: ",[wordBlock[14:18]]
					print "\tRemaining: ",[wordBlock[18:20]]
					print "\tOffsetHigh: ",[wordBlock[20:24]]
			if self.debug:
				print "--- Data Block ---"
			ByteCountPosition = 36+1+lengthWordBlock
			smbByteCount = message[ByteCountPosition:ByteCountPosition+2]
			if self.debug:
				print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
			smbDataBlock = message[ByteCountPosition+2:]
			if self.debug:
				print "\tData Block: ",[smbDataBlock]," - ",len(smbDataBlock)
			return wordCount, maxcount, offset
		except KeyboardInterrupt:
			raise
		return None, None, None

	def ReadAndXBrokenPipe(self, message):
		self.genSMBHeader(smbCommand="\x2e", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1], flag0='\x01', flag1='\x60', err='\x4b', errRes='\x01', err0='\x00', err1='\xc0')

		fill = ['\x00'] * 3
		self.reply.extend(fill)

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x00'
		### byte count
		self.reply[37] = '\x00'
		self.reply[38] = '\x00'
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return


	def ReadAndX(self, message, maxcount, dataToRead):
		if self.NTErrorCodes:
			self.genSMBHeader(smbCommand="\x2e", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1], err='\x05', err1='\x80')
		else:
			self.genSMBHeader(smbCommand="\x2e", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1], err='\x00', err1='\x00')

		fill = ['\x00'] * 28
		self.reply.extend(fill)

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x0c'
		### andx command
		self.reply[37] = '\xff'
		### andx reserved
		self.reply[38] = '\x00'
		### andx offset
		self.reply[39] = '\x00'
		self.reply[40] = '\x00'
		### remaining
		self.reply[41] = '\x00'
		self.reply[42] = '\x00'
		### data compation mode
		self.reply[43] = '\x00'
		self.reply[44] = '\x00'
		### reserved
		self.reply[45] = '\x00'
		self.reply[46] = '\x00'
		### data length
		#self.reply[47] = '\x2a'
		#self.reply[48] = '\x00'
		self.reply[47:49] = struct.pack('H', maxcount)
		### dataoffset
		self.reply[49] = '\x3c'
		self.reply[50] = '\x00'
		## datalengthhigh
		self.reply[51] = '\x00'
		self.reply[52] = '\x00'
		self.reply[53] = '\x00'
		self.reply[54] = '\x00'
		### reserved
		self.reply[55] = '\x00'
		self.reply[56] = '\x00'
		self.reply[57] = '\x00'
		self.reply[58] = '\x00'
		self.reply[59] = '\x00'
		self.reply[60] = '\x00'
		### byte count
		self.reply[61] = '\x2b'
		self.reply[62] = '\x00'
		### padding
		self.reply[63] = '\x00' #28
		### data
		self.reply.extend(list(dataToRead))
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def smbReadAndX2(self, message):
		self.genSMBHeader(smbCommand="\x2e", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1])

		fill = ['\x00'] * 27
		self.reply.extend(fill)

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x0c'
		### andx command
		self.reply[37] = '\xff'
		### andx reserved
		self.reply[38] = '\x00'
		### andx offset
		self.reply[39] = '\x00'
		self.reply[40] = '\x00'
		### remaining
		self.reply[41] = '\x00'
		self.reply[42] = '\x00'
		### data compation mode
		self.reply[43] = '\x00'
		self.reply[44] = '\x00'
		### reserved
		self.reply[45] = '\x00'
		self.reply[46] = '\x00'
		###
		self.reply[47] = '\x44'
		self.reply[48] = '\x00'
		self.reply[49] = '\x3c'
		self.reply[50] = '\x00'
		self.reply[51] = '\x00'
		self.reply[52] = '\x00'
		self.reply[53] = '\x00'
		self.reply[54] = '\x00'
		self.reply[55] = '\x00'
		self.reply[56] = '\x00'
		self.reply[57] = '\x00'
		self.reply[58] = '\x00'
		self.reply[59] = '\x00'
		self.reply[60] = '\x00'
		### byte count
		self.reply[61] = '\x00'
		self.reply[62] = '\x00'
		###
		self.reply.extend(list(self.read_andx_data))
		### calc byte count
		bytecount = struct.pack('H', len(self.reply[63:]))
		self.reply[61:63] = bytecount
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def smbReadAndX(self, message):
		if self.debug:
			print ">> With CTX: ",[self.NUM_COUNT_ITEMS]
		self.genSMBHeader(smbCommand="\x2e", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1])

		if self.pipe_fid.has_key('samr'):
			fill = ['\x00'] * 68
		else:
			fill = ['\x00'] * 72
		self.reply.extend(fill)

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x0c'
		### andx command
		self.reply[37] = '\xff'
		### andx reserved
		self.reply[38] = '\x00'
		### andx offset
		self.reply[39] = '\x00'
		self.reply[40] = '\x00'
		### remaining
		self.reply[41] = '\x00'
		self.reply[42] = '\x00'
		### data compation mode
		self.reply[43] = '\x00'
		self.reply[44] = '\x00'
		### reserved
		self.reply[45] = '\x00'
		self.reply[46] = '\x00'
		### data length
		self.num = struct.unpack('B', self.NUM_COUNT_ITEMS)[0]
		datalength = struct.pack('H', (44 + (self.num*24)))
		self.reply[47:49] = datalength
		### data offset
		self.reply[49] = '\x3c'
		self.reply[50] = '\x00'
		### reserved2
		self.reply[51] = '\x00'
		self.reply[52] = '\x00'
		### reserved3
		self.reply[53] = '\x00'
		self.reply[54] = '\x00'
		self.reply[55] = '\x00'
		self.reply[56] = '\x00'
		self.reply[57] = '\x00'
		self.reply[58] = '\x00'
		self.reply[59] = '\x00'
		self.reply[60] = '\x00'
		### byte count
		self.reply[61] = '\xad'
		self.reply[62] = '\x01'
		### padding
		self.reply[63] = '\x00'
		### DCERPC Data
		### version
		self.reply[64] = '\x05'
		self.reply[65] = '\x00'
		### packet type
		self.reply[66] = '\x0c' # bind_ack
		### packet flags
		self.reply[67] = '\x03'
		### data representation
		self.reply[68] = '\x10'
		self.reply[69] = '\x00'
		self.reply[70] = '\x00'
		self.reply[71] = '\x00'
		### frag length
		self.reply[72:74] = datalength
		### auth length
		self.reply[74] = '\x00'
		self.reply[75] = '\x00'
		### call id
		self.reply[76:80] = self.CALL_ID
		### max xmit
		self.reply[80] = '\xb8'
		self.reply[81] = '\x10'
		#### max recv
		self.reply[82] = '\xb8'
		self.reply[83] = '\x10'
		### assoc group
		if self.pipe_fid.has_key('lsarpc'):
			self.reply[84] = '\xc9' # '\x46'
			self.reply[85] = '\x3a' # '\x58'
			self.reply[86] = '\x00'
			self.reply[87] = '\x00'
		else:
			self.reply[84] = '\x7f'
			self.reply[85] = '\x28'
			self.reply[86] = '\x00'
			self.reply[87] = '\x00'
		if self.pipe_fid.has_key('lsarpc'):
			### scndry len
			self.reply[88] = '\x0c'
			self.reply[89] = '\x00'
			### scndry addr
			self.reply[90] = '\x5c' # \
			self.reply[91] = '\x50' # P
			self.reply[92] = '\x49' # I
			self.reply[93] = '\x50' # P
			self.reply[94] = '\x45' # E
			self.reply[95] = '\x5c' # \
			self.reply[96] = '\x6c' # l
			self.reply[97] = '\x73' # s
			self.reply[98] = '\x61' # a
			self.reply[99] = '\x73' # s
			self.reply[100] = '\x73' # s
			self.reply[101] = '\x00'
			self.reply[102] = '\xcd'
			self.reply[103] = '\xab'
			###CTX_Items Anzahl
			self.reply[104] = self.NUM_COUNT_ITEMS
			self.reply[105] = '\x00'
			self.reply[106] = '\x00'
			self.reply[107] = '\x00'
			for i in range(self.num,1,-1):
				self.reply.extend(list(self.read_data_contextitem))
			self.reply.extend(list(self.read_last_data_contextitem))
		elif self.pipe_fid.has_key('srvsvc'):
			### scndry len
			self.reply[88] = '\x0d'
			self.reply[89] = '\x00'
			### scndry addr
			self.reply[90] = '\x5c' # \
			self.reply[91] = '\x50' # P
			self.reply[92] = '\x49' # I
			self.reply[93] = '\x50' # P
			self.reply[94] = '\x45' # E
			self.reply[95] = '\x5c' # \
			self.reply[96] = '\x73' # s
			self.reply[97] = '\x72' # r
			self.reply[98] = '\x76' # v
			self.reply[99] = '\x73' # s
			self.reply[100] = '\x76' # v
			self.reply[101] = '\x63' # c
			self.reply[102] = '\x00' #
			self.reply[103] = '\x00'
			###CTX_Items Anzahl
			print "HERE -> [%s]" % (self.pipe_fid)
			self.reply[104] = self.NUM_COUNT_ITEMS
			self.reply[105] = '\x00'
			self.reply[106] = '\x00'
			self.reply[107] = '\x00'
			for i in range(self.num,1,-1):
				self.reply.extend(list(self.read_data_contextitem))
			self.reply.extend(list(self.read_last_data_contextitem))
		elif self.pipe_fid.has_key('samr'):
			### scndry len
			self.reply[88] = '\x0a'
			self.reply[89] = '\x00'
			### scndry addr
			self.reply[90] = '\x5c' # \
			self.reply[91] = '\x50' # P
			self.reply[92] = '\x49' # I
			self.reply[93] = '\x50' # P
			self.reply[94] = '\x45' # E
			self.reply[95] = '\x5c' # \
			self.reply[96] = '\x73' # s
			self.reply[97] = '\x61' # a
			self.reply[98] = '\x6d' # m
			self.reply[99] = '\x72' # r
			###CTX_Items Anzahl
			self.reply[100] = self.NUM_COUNT_ITEMS
			self.reply[101] = '\x00'
			self.reply[102] = '\x00'
			self.reply[103] = '\x00'
			for i in range(self.num,1,-1):
				self.reply.extend(list(self.read_data_contextitem))
			self.reply.extend(list(self.read_last_data_contextitem))
		elif self.pipe_fid.has_key('svcctl'):
			### scndry len
			self.reply[88] = '\x0d'
			self.reply[89] = '\x00'
			### scndry addr
			self.reply[90] = '\x5c' # \
			self.reply[91] = '\x50' # P
			self.reply[92] = '\x49' # I
			self.reply[93] = '\x50' # P
			self.reply[94] = '\x45' # E
			self.reply[95] = '\x5c' # \
			self.reply[96] = '\x73' # s
			self.reply[97] = '\x76' # v
			self.reply[98] = '\x63' # c
			self.reply[99] = '\x63' # c
			self.reply[100] = '\x74' # t
			self.reply[101] = '\x6c' # l
			self.reply[102] = '\x00' #
			self.reply[103] = '\x00'
			###CTX_Items Anzahl
			self.reply[104] = self.NUM_COUNT_ITEMS
			self.reply[105] = '\x00'
			self.reply[106] = '\x00'
			self.reply[107] = '\x00'
			for i in range(self.num,1,-1):
				self.reply.extend(list(self.read_data_contextitem))
			self.reply.extend(list(self.read_last_data_contextitem))
		else:
			### scndry len
			self.reply[88] = '\x0e'
			self.reply[89] = '\x00'
			### scndry addr
			self.reply[90] = '\x5c' # \
			self.reply[91] = '\x50' # P
			self.reply[92] = '\x49' # I
			self.reply[93] = '\x50' # P
			self.reply[94] = '\x45' # E
			self.reply[95] = '\x5c' # \
			self.reply[96] = '\x62' # b
			self.reply[97] = '\x72' # r
			self.reply[98] = '\x6f' # o
			self.reply[99] = '\x77' # w
			self.reply[100] = '\x73' # s
			self.reply[101] = '\x65' # e
			self.reply[102] = '\x72' # r
			self.reply[103] = '\x00'
			###CTX_Items Anzahl
			self.reply[104] = self.NUM_COUNT_ITEMS
			self.reply[105] = '\x00'
			self.reply[106] = '\x00'
			self.reply[107] = '\x00'
			for i in range(self.num,1,-1):
				self.reply.extend(list(self.read_data_contextitem))
			self.reply.extend(list(self.read_last_data_contextitem))

		bcc = struct.pack('H', (45 + (self.num*24)))
		self.reply[61:63] = bcc
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def genSMBHeader(self, smbCommand, err='\x00', errRes='\x00', err0='\x00', err1='\x00', flag='\x98', flag0=None, flag1=None, tree0='\x00', tree1='\x00', pid0='\x00', pid1='\x00', uid0='\x00', uid1='\x00', mid0='\x00', mid1='\x00'):
		self.reply = []
		self.reply.extend(list(self.net_header))
		self.reply.extend(list(self.smb_header))

		self.reply[self.SMB_COMMAND] = smbCommand

		self.reply[self.SMB_ERRCLASS] = err
		self.reply[self.SMB_ERR_RESERVED] = errRes
		self.reply[self.SMB_ERRCODE0] = err0
		self.reply[self.SMB_ERRCODE1] = err1

		self.reply[self.SMB_FLAG] = flag

		if self.NTErrorCodes and flag0==None:
			self.reply[self.SMB_FLAG0] = '\xc8'
		elif self.NTErrorCodes and flag0!=None:
			self.reply[self.SMB_FLAG0] = flag0

		if self.NTErrorCodes and flag1==None:
			self.reply[self.SMB_FLAG1] = '\x53'
		elif self.NTErrorCodes and flag1!=None:
			self.reply[self.SMB_FLAG1] = flag1

		if not self.NTErrorCodes and flag0==None:
			self.reply[self.SMB_FLAG0] = '\x01'
		elif not self.NTErrorCodes and flag0!=None:
			self.reply[self.SMB_FLAG0] = flag0

		if not self.NTErrorCodes and flag1==None:
			self.reply[self.SMB_FLAG1] = '\x20'
		elif not self.NTErrorCodes and flag1!=None:
			self.reply[self.SMB_FLAG1] = flag1


		self.reply[self.SMB_TREEID0] = tree0
		self.reply[self.SMB_TREEID1] = tree1

		self.reply[self.SMB_PID0] = pid0
		self.reply[self.SMB_PID1] = pid1

		self.reply[self.SMB_UID0] = uid0
		self.reply[self.SMB_UID1] = uid1

		self.reply[self.SMB_MID0] = mid0
		self.reply[self.SMB_MID1] = mid1

		return

	def disectNegotiateRequest(self, message):
		try:
			multiplexID = 0
			if self.debug:
				print
				print '--- SMB Negotiation ---'
			flags2Vect = self.genBitvector(struct.unpack('H', message[self.SMB_FLAG0:self.SMB_FLAG1+1])[0], count=16)
			if flags2Vect[1] == '1':
				self.NTErrorCodes = True
			else:
				self.NTErrorCodes = False
			if self.debug:
				print "FlagsVector: ",flags2Vect
				print "NT Error Codes: ",self.NTErrorCodes
			multiplexID = struct.unpack('H', message[self.SMB_MID0:self.SMB_MID1+1])[0]
			if self.debug:
				print "MultiplexID: ",multiplexID
			smbWordCount = message[self.SMB_WORDCOUNT]
			if self.debug:
				print "Word Count: ",[smbWordCount]," - ",struct.unpack('!B', smbWordCount)[0]
			lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
			if self.debug:
				print "WordsBlock Length: ",lengthWordBlock
			if lengthWordBlock>0:
				wordBlock = message[37:37+lengthWordBlock]
			ByteCountPosition = 36+1+lengthWordBlock
			smbByteCount = message[ByteCountPosition:ByteCountPosition+2]
			if self.debug:
				print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
			smbDataBlock = message[ByteCountPosition+2:]
			if self.debug:
				print "Data Block: ",[smbDataBlock]," - ",len(smbDataBlock)
			return multiplexID
		except KeyboardInterrupt:
			raise
		return multiplexID

	def NegotiationReply(self, message, dialectIndex):
		if self.NTErrorCodes:
			self.genSMBHeader(smbCommand="\x72", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1])
		else:
			self.genSMBHeader(smbCommand="\x72", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], flag0='\x01', flag1='\x28')

		fill = ['\x00'] * 37
		self.reply.extend(fill)

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x11'
		###  dialect index
		if dialectIndex == None:
			self.reply[37] = "\x00"
			self.reply[38] = "\x00"
		else:
			dialectHex = struct.pack('H', dialectIndex)
			self.reply[37:39] = dialectHex
		### security mode
		self.reply[39] = "\x03"
		### maxnmpxcount
		self.reply[40] = "\x0a"
		self.reply[41] = "\x00"
		### maxnumbervcs
		self.reply[42] = "\x01"
		self.reply[43] = "\x00"
		### maxbuffersize
		self.reply[44] = "\x04"
		self.reply[45] = "\x11"
		#self.reply[45] = "\x00"
		self.reply[46] = "\x00"
		self.reply[47] = "\x00"
		### maxrawsize
		self.reply[48] = "\x00"
		self.reply[49] = "\x00"
		self.reply[50] = "\x01"
		self.reply[51] = "\x00"
		### sessionkey
		self.reply[52] = "\x00"
		self.reply[53] = "\x00"
		self.reply[54] = "\x00"
		self.reply[55] = "\x00"
		### capabilities
		self.reply[56] = "\xfd"
		self.reply[57] = "\xe3"
		self.reply[58] = "\x00"
		self.reply[59] = "\x80"
		### systemtimelow
		### generate time string
		smbtime = struct.pack('Q' , ( (time.time()+11644473600)*10000000 ) )
		self.reply[60:68] = smbtime
		### servertimezone
		self.reply[68] = "\xf0"
		self.reply[69] = "\x00"
		### encryptionkeylength
		self.reply[70] = "\x00"
		### byte count
		self.reply[71] = "\x10"
		self.reply[72] = "\x00"
		### guid[16]
		self.reply.extend(list(',\xcb\xcf\x9c\xafU\xb9J\xb9\xe2\x14\xb6\xdc\xa5\x1b('))
		### securityblob
		### missing
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def smbEcho(self, message):
		try:
			self.genSMBHeader(smbCommand="\x2b", tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1], pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], uid0=message[self.SMB_UID0], uid1=message[self.SMB_UID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1])
		except IndexError:
			self.genSMBHeader(smbCommand="\x2b")

		fill = ['\x00'] * 5
		self.reply.extend(fill)

		### word count
		self.reply[self.SMB_WORDCOUNT] = '\x01'
		self.reply[37] = "\x01"
		self.reply[38] = "\x00"
		### byte count
		self.reply[39] = "\x00"
		self.reply[40] = "\x00"

		### data to echo
		data = self.getContent(message)
		### echo data
		self.reply.extend(list(data))
		### calc byte count
		bytecount = struct.pack('H', len(self.reply[41:]))
		self.reply[39:41] = bytecount
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def TreeDisconnect(self, message):
		self.genSMBHeader(smbCommand="\x71", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], uid0=message[self.SMB_UID0], uid1=message[self.SMB_UID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1])

		fill = ['\x00'] * 3
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x00"
		### byte count
		self.reply[37] = "\x00"
		self.reply[38] = "\x00"
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def LogOffAndX(self, message):
		self.genSMBHeader(smbCommand="\x74", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1])

		fill = ['\x00'] * 7
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x02"
		### andxcommand
		self.reply[37] = "\xff"
		### reserved
		self.reply[38] = "\x00"
		### andx offset
		self.reply[39] = "\x00"
		self.reply[40] = "\x00"
		### byte count
		self.reply[41] = "\x00"
		self.reply[42] = "\x00"
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def disectSetupAndX(self, message):
		try:
			if self.debug:
				print
				print '--- SMB Session Setup AndX ---'
			smbWordCount = message[36]
			if struct.unpack('!B', smbWordCount)[0]==12:
				if self.debug:
					print "\t--client supports extended security"
			if self.debug:
				print "Word Count: ",[smbWordCount]," - ",struct.unpack('!B', smbWordCount)[0]
			lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
			if self.debug:
				print "WordsBlock Length: ",lengthWordBlock
			if lengthWordBlock>0:
				wordBlock = message[37:37+lengthWordBlock]
				if self.debug:
					print "\tWordBlock: ",[wordBlock]," - ",len(wordBlock)
					print "\tAndXCommand: ",[wordBlock[0]]," - ",struct.unpack('B', wordBlock[0])[0]
					print "\tReserved: ",[wordBlock[1]]," - ",struct.unpack('B', wordBlock[1])[0]
					print "\tAndXOffset: ",[wordBlock[2:4]]," - ",struct.unpack('H', wordBlock[2:4])[0]
					print "\tMaxBuffer: ",[wordBlock[4:6]]," - ",struct.unpack('H', wordBlock[4:6])[0]
					print "\tMaxMpxCount: ",[wordBlock[6:8]]," - ",struct.unpack('H', wordBlock[6:8])[0]
					print "\tVcNumber: ",[wordBlock[8:10]]," - ",struct.unpack('H', wordBlock[8:10])[0]
					print "\tSessionKey: ",[wordBlock[10:14]]," - ",struct.unpack('2H', wordBlock[10:14])[0]
					print "\tSecurityBlobLength: ",[wordBlock[14:16]]," - ",struct.unpack('H', wordBlock[14:16])[0]
				secBloblength = struct.unpack('H', wordBlock[14:16])[0]
				if self.debug:
					print "\tReserved: ",[wordBlock[16:20]]
					print "\tCapabilities: ",[wordBlock[20:24]]," - ",struct.unpack('2H', wordBlock[20:24])[0]
			if self.debug:
				print "--- Data Block ---"
			ByteCountPosition = 36+1+lengthWordBlock
			smbByteCount = message[ByteCountPosition:ByteCountPosition+2]
			if self.debug:
				print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
			smbDataBlock = message[ByteCountPosition+2:]
			if self.debug:
				print "\tData Block: ",[smbDataBlock]," - ",len(smbDataBlock)
				print "\tSecurityBlob[]: ",[smbDataBlock[0:0+secBloblength]]
			secBlobData = smbDataBlock[0:0+secBloblength]
			rest = smbDataBlock[0+secBloblength:]
			pos1 = rest.find('\x00\x00\x00')
			if self.debug:
				print "\tNativeOS[]: ",[rest[:pos1+1]],[rest[:pos1+1].replace('\x00','')]
				print "\tNativeLanMan[]: ",[rest[pos1+1:]],[rest[pos1+1:].replace('\x00','')]
				print
			pos1 = secBlobData.find('NTLMSSP')
			ntlmsspBlock = secBlobData[pos1:]
			ntlmsspNego = 0
			ntlmsspChallenge = 0
			NTLMSSP_NEGOTIATE_VERSION = 0
			NTLMSSP_NEGOTIATE_TARGET_INFO = 0
			NTLMSSP_REQUEST_TARGET = 0
			if pos1!=-1:
				if self.debug:
					print "\tSignature: ",[ntlmsspBlock[0:8]]
					print "\tMessageType: ",[ntlmsspBlock[8:12]]," - ",struct.unpack('2H', ntlmsspBlock[8:12])[0]
					#print "\tMessageDependent: ",[ntlmsspBlock[12:24]]
				if struct.unpack('2H', ntlmsspBlock[8:12])[0] == 1:
					ntlmsspNego = 1
					if self.debug:
						print "\t\tNTLMSSP Negotiate"
						print "\t\tNegotiateFlags: ",[ntlmsspBlock[12:16]]
					#bitv = self.genBitvector(struct.unpack('i', ntlmsspBlock[12:16])[0])[1:]
					bitv = self.genBitvector(struct.unpack('i', ntlmsspBlock[12:16])[0], count=32)
					if self.debug:
						print "\t\tBitVector: ",bitv
					try:
						if bitv[6]=='1':
							NTLMSSP_NEGOTIATE_VERSION = 1
						if bitv[8]=='1':
							#print "\t\tTargetInfo Requested"
							NTLMSSP_NEGOTIATE_TARGET_INFO = 1
						if bitv[30]=='1':
							NTLMSSP_REQUEST_TARGET = 1
					except:
						pass
					if self.debug:
						print "\t\tDomainNameFields: ",[ntlmsspBlock[16:24]]
						#print "\t\tDomainNameMaxLen: ",[ntlmsspBlock[12:24][2:4]]," - ",struct.unpack('H', ntlmsspBlock[12:24][2:4])[0]
						#print "\t\tDomainNameBufferOffset: ",[ntlmsspBlock[12:24][4:8]]," - ",struct.unpack('2H', ntlmsspBlock[12:24][4:8])[0]
						print "\t\tWorkstationFields: ",[ntlmsspBlock[24:32]]
					### Only if version flag is set
					if NTLMSSP_NEGOTIATE_VERSION:
						if self.debug:
							print "\t\tVersion: ",[ntlmsspBlock[32:40]]
							print "\tPayload: ",[ntlmsspBlock[40:]]
					else:
						if self.debug:
							print "\tPayload: ",[ntlmsspBlock[32:]]
				elif struct.unpack('2H', ntlmsspBlock[8:12])[0] == 3:
					if self.debug:
						print "\t\tNTLMSSP Challenge Response"
					ntlmsspChallenge = 1
			else:
				if struct.unpack('H', smbByteCount)[0]>len(secBlobData):
					self.vulnName = "MS04007 (ASN1)"
				print ">> ntlmssp not found"
				print [secBlobData],len(secBlobData)
			return ntlmsspNego, ntlmsspChallenge, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_NEGOTIATE_TARGET_INFO, NTLMSSP_REQUEST_TARGET
		except KeyboardInterrupt:
			raise
		return None, None, None, None, None


	def generatePCName(self, ownIP, upCase=True):
		lastItem = ownIP.split('.')[-1]
		while len(lastItem)<3:
			lastItem = "\x30%s" % (lastItem)
		if upCase:
			name = ['\x50','\x00','\x43','\x00','\x30','\x00']
		else:
			name = ['\x70','\x00','\x63','\x00','\x30','\x00']
		for item in lastItem:
			name.append(item)
			name.append('\x00')
		return "".join(name)


	def SessionSetupAndX(self, message, ownIP):
		ntlmsspNego, ntlmsspChallenge, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_NEGOTIATE_TARGET_INFO, NTLMSSP_REQUEST_TARGET = self.disectSetupAndX(message)

		if ntlmsspNego:
			if self.NTErrorCodes:
				self.genSMBHeader(smbCommand="\x73", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1], err="\x16", err1="\xc0")
			else:
				self.genSMBHeader(smbCommand="\x73", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1], err="\x16", err1="\xc0", flag0='\x01', flag1='\x68')
		else:
			self.genSMBHeader(smbCommand="\x73", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1])

		fill = ['\x00'] * 11
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x04"
		### andxcommand
		self.reply[37] = "\xff"
		self.reply[38] = "\x00"
		### andx offset
		if ntlmsspNego:
			self.reply[39] = "\xf5"
			self.reply[40] = "\x00"
		else:
			self.reply[39] = "\x75"
			self.reply[40] = "\x00"
		### action
		self.reply[41] = "\x00"
		self.reply[42] = "\x00"
		### security blob length
		self.reply[43] = "\x00"
		self.reply[44] = "\x00"
		### byte count
		self.reply[45] = "\x00"
		self.reply[46] = "\x00"
		### securityblob[]
		if ntlmsspNego:
			### ntlmssp challenge reply
			secBlobPart = '\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00'
			#if NTLMSSP_REQUEST_TARGET == 0:
			#	secBlobPart += '\x00\x00\x00\x00\x38\x00\x00\x00'
			#else:
			secBlobPart += '\x0c\x00\x0c\x00\x30\x00\x00\x00'
			### flags
			secBlobPart += '\x15\x82\x8a\xe0'
			### challenge
			secBlobPart += '\x23\x2b\xb5\xf6\x5b\x11\x73\xa9'
			### reserved
			secBlobPart += '\x00\x00\x00\x00\x00\x00\x00\x00'
			### target info field
			#if NTLMSSP_NEGOTIATE_TARGET_INFO == 0:
			#	secBlobPart += '\x00\x00\x00\x00\x3c\x00\x00\x00'
			#else:
			secBlobPart += '\x44\x00\x44\x00\x3c\x00\x00\x00'
			### version ignored
			### payload
			## domain netbios
			#secBlobPart += '\x50\x00\x43\x00\x30\x00\x31\x00\x39\x00\x31\x00'
			ownDomainName = self.generatePCName(ownIP)
			secBlobPart += ownDomainName
			secBlobPart += '\x02\x00\x0c\x00'
			#secBlobPart += '\x50\x00\x43\x00\x30\x00\x31\x00\x39\x00\x31\x00'
			secBlobPart += ownDomainName
			## server netbios
			secBlobPart += '\x01\x00\x0c\x00'
			#secBlobPart += '\x50\x00\x43\x00\x30\x00\x31\x00\x39\x00\x31\x00'
			secBlobPart += ownDomainName
			## domain dns
			ownDomainNameLower = self.generatePCName(ownIP, upCase=False)
			secBlobPart += '\x04\x00\x0c\x00'
			#secBlobPart += '\x70\x00\x63\x00\x30\x00\x31\x00\x39\x00\x31\x00'
			secBlobPart += ownDomainNameLower
			## server dns
			secBlobPart += '\x03\x00\x0c\x00'
			#secBlobPart += '\x70\x00\x63\x00\x30\x00\x31\x00\x39\x00\x31\x00'
			secBlobPart += ownDomainNameLower
			## list terminator
			secBlobPart += '\x00\x00\x00\x00'
			###
			secBlobLength = struct.pack('H', len(secBlobPart))
			self.reply[43:45] = secBlobLength
			self.reply.extend(list(secBlobPart))
		### nativeOS
		if self.NTErrorCodes:
			#self.reply.extend(list('\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x005\x00.\x001\x00\x00'))
			self.reply.extend(list('Windows 5.1\x00'))
		else:
			self.reply.extend(list('Windows 5.1\x00'))
		### nativelanman
		if self.NTErrorCodes:
			#self.reply.extend(list('\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x002\x000\x000\x000\x00 \x00L\x00A\x00N\x00 \x00M\x00a\x00n\x00a\x00g\x00e\x00r\x00\x00'))
			self.reply.extend(list('Windows 2000 LAN Manager\x00'))
		else:
			self.reply.extend(list('Windows 2000 LAN Manager\x00'))
		### primarydomain
		#self.reply.extend(list('\x00W\x00O\x00R\x00K\x00G\x00R\x00O\x00U\x00P\x00\x00\x00'))
		#self.reply.extend(list('WORKGROUP\x00'))
		### calc byte count
		bytecount = struct.pack('H', len(self.reply[47:]))
		self.reply[45:47] = bytecount
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def SessionSetupAndxNoCap(self, message):
		self.genSMBHeader(smbCommand="\x73", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1])

		fill = ['\x00'] * 9
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x03"
		### andxcommand
		self.reply[37] = "\xff"
		self.reply[38] = "\x00"
		### andx offset
		self.reply[39] = "\x00"
		self.reply[40] = "\x00"
		### action
		self.reply[41] = "\x01"
		self.reply[42] = "\x00"
		### byte count
		self.reply[43] = "\x00"
		self.reply[44] = "\x00"
		### nativeOS
		self.reply.extend(list('Windows 5.1\x00'))
		### nativelanman
		self.reply.extend(list('Windows 2000 LAN Manager\x00'))
		### primarydomain
		self.reply.extend(list('WORKGROUP\x00'))

		### calc byte count
		bytecount = struct.pack('H', len(self.reply[45:]))
		self.reply[43:45] = bytecount
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def disectTreeAndx(self, message):
		try:
			if self.debug:
				print
				print '--- SMB Tree AndX Connect ---'
			smbWordCount = message[36]
			if self.debug:
				print "Word Count: ",[smbWordCount]," - ",struct.unpack('!B', smbWordCount)[0]
			lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
			if self.debug:
				print "WordsBlock Length: ",lengthWordBlock
			if lengthWordBlock>0:
				wordBlock = message[37:37+lengthWordBlock]
				if self.debug:
					print "\tWordBlock: ",[wordBlock]," - ",len(wordBlock)
					print "\tAndXCommand: ",[wordBlock[0]]
					print "\tReserved: ",[wordBlock[1]]
					print "\tAndXOffset: ",[wordBlock[2:4]]
					print "\tFlags: ",[wordBlock[4:6]]
					print "\tPasswordLength: ",[wordBlock[6:8]],struct.unpack('H', wordBlock[6:8])[0]
				passLen = struct.unpack('H', wordBlock[6:8])[0]
			if self.debug:
				print "--- Data Block ---"
			ByteCountPosition = 36+1+lengthWordBlock
			smbByteCount = message[ByteCountPosition:ByteCountPosition+2]
			if self.debug:
				print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
			smbDataBlock = message[ByteCountPosition+2:]
			if self.debug:
				print "\tData Block: ",[smbDataBlock]," - ",len(smbDataBlock)
				print "\tPassword[]: ",[smbDataBlock[0:0+passLen]]
			rest = smbDataBlock[passLen:].split('\x00')
			path = []
			counter = 0
			for item in rest:
				if item=='':
					break
				else:
					path.append(item)
				counter +=1
			if self.debug:
				print "\tPath[]: ",["".join(path)]
			rest = rest[counter:]
			service = []
			for item in rest:
				service.append(item)
			if self.debug:
				print "\tService[]: ",["".join(service)]
			return "".join(path)
		except KeyboardInterrupt:
			raise
		return None

	def NTTrans2Response(self, message):
		self.genSMBHeader(smbCommand="\x33", err="\x0d", errRes="\x00", err1="\xc0", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0='\x00', tree1='\x08')
		fill = ['\x00'] * 9
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x00"
		### andxcommand
		self.reply[37] = "\x00"
		self.reply[38] = "\xff"
		### andx offset
		self.reply[39] = "\x00"
		self.reply[40] = "\xff"
		### action
		self.reply[41] = "\x00"
		self.reply[42] = "\xff"
		### byte count
		self.reply[43] = "\x00"
		self.reply[44] = "\xff"
		fill = ['\xa0'] * 900
		self.reply.extend(fill)
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def NTTransResponse(self, message):
		self.genSMBHeader(smbCommand="\xa0", err="\x05", errRes="\x02", err1="\xc0", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0='\x00', tree1='\x08')
		fill = ['\x00'] * 9
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x00"
		### andxcommand
		self.reply[37] = "\x00"
		self.reply[38] = "\x00"
		### andx offset
		self.reply[39] = "\x00"
		self.reply[40] = "\x00"
		### action
		self.reply[41] = "\x00"
		self.reply[42] = "\x00"
		### byte count
		self.reply[43] = "\x00"
		self.reply[44] = "\x00"
		fill = ['\x00'] * 9
		self.reply.extend(fill)
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def TreeConnectAndX(self, message):
		### disect message
		ConnectToService = self.disectTreeAndx(message)
		self.genSMBHeader(smbCommand="\x75", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0='\x00', tree1='\x08')
		### store pid and mid
		self.sess_mid0 = message[self.SMB_MID0]
		self.sess_mid1 = message[self.SMB_MID1]
		self.sess_pid0 = message[self.SMB_PID0]
		self.sess_pid1 = message[self.SMB_PID1]

		if self.NTErrorCodes:
			fill = ['\x00'] * 17
		else:
			fill = ['\x00'] * 9
		self.reply.extend(fill)

		### word count
		if self.NTErrorCodes:
			self.reply[self.SMB_WORDCOUNT] = "\x07"
		else:
			self.reply[self.SMB_WORDCOUNT] = "\x03"
		### andxcommand
		self.reply[37] = "\xff"
		### reserved
		self.reply[38] = "\x00"
		### andxoffset
		self.reply[39] = "\x38"
		self.reply[40] = "\x00"
		### optionalsupport
		self.reply[41] = "\x01"
		self.reply[42] = "\x00"
		if self.NTErrorCodes:
			### word parameter
			self.reply[43] = "\xff"
			self.reply[44] = "\x01"
			### word parameter
			self.reply[45] = "\x00"
			self.reply[46] = "\x00"
			### word parameter
			self.reply[47] = "\xff"
			self.reply[48] = "\x01"
			### word parameter
			self.reply[49] = "\x00"
			self.reply[50] = "\x00"
			### byte count
			self.reply[51] = "\x00"
			self.reply[52] = "\x00"
		else:
			### byte count
			self.reply[43] = "\x00"
			self.reply[44] = "\x00"
		### service[]
		#pos1 = ConnectToService.rfind('\\')
		if ConnectToService.lower().count('ipc')>0:
			#finConnService = ConnectToService[pos1:]
			if self.NTErrorCodes:
				finConnService = "IPC\x00\x00\x00\x00"
			else:
				finConnService = 'IPC\x00\x00'
			self.reply.extend(list(finConnService))
		else:
			self.reply.extend(list(ConnectToService))
			self.reply.extend(['\x00','F','\x00','A','\x00','T','\x00'])

		if self.NTErrorCodes:
			### calc byte count
			bytecount = struct.pack('H', len(self.reply[53:]))
			self.reply[51:53] = bytecount
		else:
			### calc byte count
			bytecount = struct.pack('H', len(self.reply[45:]))
			self.reply[43:45] = bytecount
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def disectNtCreateAndX(self, message):
		try:
			if self.debug:
				print
				print '--- SMB NT Create AndX  ---'
			smbWordCount = message[36]
			if self.debug:
				print "Word Count: ",[smbWordCount]," - ",struct.unpack('!B', smbWordCount)[0]
			lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
			if self.debug:
				print "WordsBlock Length: ",lengthWordBlock
			if lengthWordBlock>0:
				wordBlock = message[37:37+lengthWordBlock]
				if self.debug:
					print "\tWordBlock: ",[wordBlock]," - ",len(wordBlock)
					print "\tAndXCommand: ",[wordBlock[0]]
					print "\tReserved: ",[wordBlock[1]]
					print "\tAndXOffset: ",[wordBlock[2:4]],struct.unpack('H', wordBlock[2:4])[0]
				oversizedAndXOffset = struct.unpack('H', wordBlock[2:4])[0]
				if self.debug:
					print "\tReserved: ",[wordBlock[4]]
					print "\tNameLength: ",[wordBlock[5:7]],struct.unpack('H', wordBlock[5:7])[0]
					print "\tFlags: ",[wordBlock[7:11]]
					print "\tRootDirFid: ",[wordBlock[11:15]]
					print "\tAccessMask: ",[wordBlock[15:19]]
					print "\tAllocationSize: ",[wordBlock[19:27]]
					print "\tExtFileAttr: ",[wordBlock[27:31]]
					print "\tShareAccess: ",[wordBlock[31:35]]
					print "\tCreateDisposition: ",[wordBlock[35:39]]
					print "\tCreateOptions: ",[wordBlock[39:43]],struct.unpack('2H', wordBlock[39:43])[0]
				createOptions = struct.unpack('2H', wordBlock[39:43])[0]
				if self.debug:
					print "\tImpersonationLevel: ",[wordBlock[43:47]]
					print "\tSecurityFlags: ",[wordBlock[47]]
			if self.debug:
				print "--- Data Block ---"
			ByteCountPosition = 36+1+lengthWordBlock
			smbByteCount = message[ByteCountPosition:ByteCountPosition+2]
			if self.debug:
				print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
			smbDataBlock = message[ByteCountPosition+2:]
			if self.debug:
				print "\tData Block: ",[smbDataBlock]," - ",len(smbDataBlock)
			nameToOpen = smbDataBlock.replace('\x00','').replace('\\','')
			if self.debug:
				print ">> BIND TO: ",[nameToOpen]
			if self.debug:
				print "\tName[]: ",[smbDataBlock],[smbDataBlock.replace('\x00','')]
			return nameToOpen, createOptions, oversizedAndXOffset
		except KeyboardInterrupt:
			raise
		return None, None, None

	def NTCreateAndX(self, message):
		nameToOpen, createOptions, oversizedAndXOffset = self.disectNtCreateAndX(message)

		self.genSMBHeader(smbCommand="\xa2", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1])

		#if oversizedAndXOffset >= 57054:
		#	fill = ['\x00'] * 3
		#	self.reply.extend(fill)
		#	### word count
		#	self.reply[self.SMB_WORDCOUNT] = "\x00"
		#	### byte count
		#	self.reply[37] = "\x00"
		#	self.reply[38] = "\x00"
		#else:
		if True:
			fill = ['\x00'] * 71
			self.reply.extend(fill)
			### word count
			self.reply[self.SMB_WORDCOUNT] = "\x2a"
			### andxcommand
			self.reply[37] = "\xff"
			self.reply[38] = "\x00"
			### andxoffset
			self.reply[39] = "\x87"
			self.reply[40] = "\x00"
			### oplocklevel
			self.reply[41] = "\x00"
			### fid
			self.reply[42:44] = struct.pack('H', self.init_fid)
			self.pipe_fid[nameToOpen] = self.init_fid
			self.init_fid += 1
			### createAction
			self.reply[44] = "\x01"
			self.reply[45] = "\x00"
			self.reply[46] = "\x00"
			self.reply[47] = "\x00"
			### creationTime
			self.reply[48:56] = "\x00\x00\x00\x00\x00\x00\x00\x00"
			### lastaccess
			self.reply[56:64] = "\x00\x00\x00\x00\x00\x00\x00\x00"
			### lastwrite
			self.reply[64:72] = "\x00\x00\x00\x00\x00\x00\x00\x00"
			### changetime
			self.reply[72:80] = "\x00\x00\x00\x00\x00\x00\x00\x00"
			### extFileAttributes
			self.reply[80:84] = "\x80\x00\x00\x00"
			### allocationsize
			self.reply[84:92] = "\x00\x10\x00\x00\x00\x00\x00\x00"
			### endoffile
			self.reply[92:100] = "\x00\x00\x00\x00\x00\x00\x00\x00"
			### filetype
			if nameToOpen in self.knownPipes:
				self.reply[100] = "\x02"
				self.reply[101] = "\x00"
			else:
				self.reply[100] = "\xff"
				self.reply[101] = "\xff"
			### device state
			self.reply[102] = "\xff"
			self.reply[103] = "\x05"
			### directory
			self.reply[104] = "\x00"
			### byte count
			self.reply[105] = "\x00"
			self.reply[106] = "\x00"
			if nameToOpen.count('samr')>0:
				self.reply.extend(list(self.samr_data))
			elif nameToOpen.count('svcctl')>0:
				self.reply.extend(list(self.svcctl_data))
			elif nameToOpen.count('lsarpc')>0:
				self.reply.extend(list(self.lsarpc_data))
			else:
				self.reply.extend(list(self.other_data))
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def disectSMBClose(self, message):
		try:
			if self.debug:
				print
				print '--- SMB Close ---'
			smbWordCount = message[36]
			if self.debug:
				print "Word Count: ",[smbWordCount]," - ",struct.unpack('!B', smbWordCount)[0]
			lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
			if self.debug:
				print "WordsBlock Length: ",lengthWordBlock
			if lengthWordBlock>0:
				wordBlock = message[37:37+lengthWordBlock]
				if self.debug:
					print "\tWordBlock: ",[wordBlock]," - ",len(wordBlock)
				fid = struct.unpack('H', wordBlock[0:2])[0]
			#ByteCountPosition = 36+1+lengthWordBlock
			#smbByteCount = message[ByteCountPosition:ByteCountPosition+2]
			#actualDataBytes = struct.unpack('H', smbByteCount)[0] - dataCount
			#print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
			#smbDataBlock = message[ByteCountPosition+2:actualDataBytes]
			#print "\tData Block: ",[smbDataBlock]," - ",len(smbDataBlock)
			return fid
		except KeyboardInterrupt:
			raise
		return None

	def SMBClose(self, message):

		self.NUM_COUNT_ITEMS = None
		killFID = self.disectSMBClose(message)

		#print ">> REMOVING TREE CONNECT FID: ", killFID
		fidKeys = self.pipe_fid.keys()
		for key in fidKeys:
			if self.pipe_fid[key] == killFID:
				#print ">> REMOVING ..."
				del self.pipe_fid[key]
				break

		self.genSMBHeader(smbCommand="\x04", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0='\x00', tree1='\x00')
		fill = ['\x00'] * 3
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x00"
		### byte count
		self.reply[37] = "\x00"
		self.reply[38] = "\x00"
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def disectTransaction(self, message):
		try:
			if self.debug:
				print
				print '--- SMB Transaction ---'
			smbWordCount = message[36]
			if self.debug:
				print "Word Count: ",[smbWordCount]," - ",struct.unpack('!B', smbWordCount)[0]
			lengthWordBlock = 2*struct.unpack('!B', smbWordCount)[0]
			if self.debug:
				print "WordsBlock Length: ",lengthWordBlock
			if lengthWordBlock>0:
				wordBlock = message[37:37+lengthWordBlock]
				if self.debug:
					print "\tWordBlock: ",[wordBlock]," - ",len(wordBlock)
					print "\tTotalParamCount: ",[wordBlock[0:2]]
					print "\tTotalDataCount: ",[wordBlock[2:4]]," - ",struct.unpack('H', wordBlock[2:4])[0]
					print "\tMaxParameterCount: ",[wordBlock[4:6]]
					print "\tMaxDataCount: ",[wordBlock[6:8]]," - ",struct.unpack('H', wordBlock[6:8])[0]
					print "\tMaxSetupCount: ",[wordBlock[8:10]]
					print "\tFlags: ",[wordBlock[10:12]]
					print "\tTimeout: ",[wordBlock[12:16]]
					print "\tReserved: ",[wordBlock[16:18]]," - ",struct.unpack('H', wordBlock[16:18])[0]
					print "\tParameterCount: ",[wordBlock[18:20]]," - ",struct.unpack('H', wordBlock[18:20])[0]
				paramCount = struct.unpack('H', wordBlock[18:20])[0]
				if self.debug:
					print "\tParameterOffset: ",[wordBlock[20:22]]," - ",struct.unpack('H', wordBlock[20:22])[0]
				paramOffSet = struct.unpack('H', wordBlock[20:22])[0]
				if self.debug:
					print "\tDataCount: ",[wordBlock[22:24]]," - ",struct.unpack('H', wordBlock[22:24])[0]
				dataCount = struct.unpack('H', wordBlock[22:24])[0]
				if self.debug:
					print "\tDataOffset: ",[wordBlock[24:26]]," - ",struct.unpack('H', wordBlock[24:26])[0]
				dataOffSet = struct.unpack('H', wordBlock[24:26])[0]
				if self.debug:
					print "\tSetupCount: ",[wordBlock[26:27]]," - ",struct.unpack('B', wordBlock[26:27])[0]
				setupCountVal = struct.unpack('B', wordBlock[26:27])[0]
				if setupCountVal == 2:
					if self.debug:
						print "\t\tNamed Pipe Transaction"
				if self.debug:
					print "\tReserved: ",[wordBlock[27:28]]," - ",struct.unpack('B', wordBlock[27:28])[0]
					print "\tSetup[]",[wordBlock[28:]]
				setupBlock = wordBlock[28:]
				if setupCountVal == 2 and setupBlock[0] == '\x01':
					if self.debug:
						print "\t\tSet Pipe Handle Modes"
				elif len(setupBlock)>0 and setupBlock[0] == '\x26':
					if self.debug:
						print "\t\tTransactNmPipe 0x26 write/read operation on pipe requested"
				else:
					if self.debug:
						print "\t\tWrong or Missing SetupBlock (%s)" % ([setupBlock])
			ByteCountPosition = 36+1+lengthWordBlock
			smbByteCount = message[ByteCountPosition:ByteCountPosition+2]
			actualDataBytes = struct.unpack('H', smbByteCount)[0] - dataCount
			if self.debug:
				print "Byte Count: ",[smbByteCount]," - ",struct.unpack('H', smbByteCount)[0]
			smbDataBlock = message[ByteCountPosition+2:actualDataBytes]
			if self.debug:
				print "\tData Block: ",[smbDataBlock]," - ",len(smbDataBlock)
				print "\tName[]: ",[message[ByteCountPosition+2:paramOffSet]]
				print "\tParameters[]: ",[message[paramOffSet:paramOffSet+paramCount]]," - ",len(message[paramOffSet:paramOffSet+paramCount])
				### Data[] equals DataCount bytes
				print "\tData[]: ",[message[dataOffSet:dataOffSet+dataCount]]," - ",len(message[dataOffSet:dataOffSet+dataCount])
				#print self.pipe_fid
				if len(message[dataOffSet:dataOffSet+dataCount])>=940 and struct.unpack('H', message[ByteCountPosition+2+actualDataBytes:][22:24])[0]==9 and self.pipe_fid.has_key('lsarpc'):
					self.vulnName = 'MS04011 (LSASS)'
					self.NextReadWithError = True
			rest = message[ByteCountPosition+2+actualDataBytes:]
			if len(rest)>=24 and not self.fragmentation:
				if self.debug:
					print "\t\tDCERPC Version ",[rest[0:2]]
					print "\t\tPacket Type: ",[rest[2]]
				DCEpacketType = rest[2]
				fragLength = struct.unpack('H', rest[8:10])[0]
				if self.debug:
					print "\t\tPacket Flags: ",[rest[3]]
					print "\t\tData Representation: ",[rest[4:8]]
					print "\t\tFrag Length: ",[rest[8:10]]
					print "\t\tAuth Length: ",[rest[12:12]]
					print "\t\tCall ID: ",[rest[12:16]]
				callid = rest[12:16]
				if self.debug:
					print "\t\tAlloc Hint: ",[rest[16:20]]
					print "\t\tContext ID: ",[rest[20:22]]
					print "\t\tOpnum: ",[rest[22:24]],struct.unpack('H', rest[22:24])[0]
				opnumber = struct.unpack('H', rest[22:24])[0]
				if self.debug:
					if DCEpacketType=='\x00' and opnumber == 0:
						print "\t\tlsa_Close"
					elif DCEpacketType=='\x00' and opnumber == 6:
						print "\t\tlsa_OpenPolicy"
					elif DCEpacketType=='\x00' and opnumber == 7:
						print "\t\tlsa_QueryInfoPolicy"
					elif DCEpacketType=='\x00' and opnumber == 9:
						print "\t\tDsRoleUpgradeDownlevelServer"
					elif DCEpacketType=='\x00' and opnumber == 27:
						print "\t\tOpenSCManagerA"
					elif DCEpacketType=='\x00' and opnumber == 31:
						print "\t\tNetPathCanonicalize"
					elif DCEpacketType=='\x00' and opnumber == 32:
						print "\t\tNetPathCompare"
					elif DCEpacketType=='\x00' and opnumber == 54:
						print "\t\tPNP_QueryResConfList"
					elif DCEpacketType=='\x00' and opnumber == 62:
						print "\t\tConnect4"
					elif DCEpacketType=='\x00' and opnumber == 64:
						print "\t\tConnect5"
				if len(rest)>=fragLength:
					return setupCountVal, DCEpacketType, opnumber, callid
				else:
					if self.debug:
						print "\tTransaction Fragmentation Detected"
					self.fragmentation = True
					self.fragments.append(rest)
					return setupCountVal, None, -1, None
			elif self.fragmentation:
				self.fragments.append(rest)
				rest = "".join(self.fragments)
				fragLength = struct.unpack('H', rest[8:10])[0]
				if len(rest)>=fragLength:
					if self.debug:
						print "\tTransaction Fragmentation Finished"
					self.fragmentation = False
					self.fragments = []
					DCEpacketType = rest[2]
					opnumber = struct.unpack('H', rest[22:24])[0]
					callid = rest[12:16]
					return setupCountVal, DCEpacketType, opnumber, callid
				else:
					self.fragments.append(rest)
					return setupCountVal, None, -1, None
			else:
				DCEpacketType = None
				opnumber = -1
				callid = None
			return setupCountVal, DCEpacketType, opnumber, callid
		except KeyboardInterrupt:
			raise
		return None, None, None, None

	def lsaClose(self, message, callid):
		self.genSMBHeader(smbCommand="\x25", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1])
		fill = ['\x00'] * 72
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x0a"
		### total param count
		self.reply[37] = "\x00"
		self.reply[38] = "\x00"
		### total data count
		self.reply[39] = "\x30"
		self.reply[40] = "\x00"
		### reserved
		self.reply[41] = "\x00"
		self.reply[42] = "\x00"
		### parameter count
		self.reply[43] = "\x00"
		self.reply[44] = "\x00"
		### param offset
		self.reply[45] = "\x38"
		self.reply[46] = "\x00"
		### displacement
		self.reply[47] = "\x00"
		self.reply[48] = "\x00"
		### data count
		self.reply[49] = "\x30"
		self.reply[50] = "\x00"
		### data offset
		self.reply[51] = "\x38"
		self.reply[52] = "\x00"
		### displacement
		self.reply[53] = "\x00"
		self.reply[54] = "\x00"
		### setup count
		self.reply[55] = "\x00"
		### reserved
		self.reply[56] = "\x00"
		### byte count
		self.reply[57] = "\x31"
		self.reply[58] = "\x00"
		### padding
		self.reply[59] = "\x00"
		### dce bind_ack
		### version
		self.reply[60] = "\x05"
		self.reply[61] = "\x00"
		### packet type
		self.reply[62] = "\x02"
		### packet flags
		self.reply[63] = "\x03"
		### data representation
		self.reply[64] = "\x10"
		self.reply[65] = "\x00"
		self.reply[66] = "\x00"
		self.reply[67] = "\x00"
		### frag length
		self.reply[68] = "\x30"
		self.reply[69] = "\x00"
		### auth length
		self.reply[70] = "\x00"
		self.reply[71] = "\x00"
		### call id
		self.reply[72:76] = callid
		### alloc hint
		self.reply[76] = "\x18"
		self.reply[77] = "\x00"
		self.reply[78] = "\x00"
		self.reply[79] = "\x00"
		### context id
		self.reply[80] = "\x00"
		self.reply[81] = "\x00"
		### cancel count
		self.reply[82] = "\x00"
		###
		self.reply[83] = "\x00"
		self.reply[84] = "\x00"
		self.reply[85] = "\x00"
		self.reply[86] = "\x00"
		self.reply[87] = "\x00"
		###
		self.reply[88] = "\x00"
		self.reply[89] = "\x00"
		self.reply[90] = "\x00"
		self.reply[91] = "\x00"
		self.reply[92] = "\x00"
		self.reply[93] = "\x00"
		###
		self.reply[94] = "\x00"
		self.reply[95] = "\x00"
		self.reply[96] = "\x00"
		self.reply[97] = "\x00"
		self.reply[98] = "\x00"
		self.reply[99] = "\x00"
		self.reply[100] = "\x00"
		self.reply[101] = "\x00"
		###
		self.reply[102] = "\x00"
		self.reply[103] = "\x00"
		self.reply[104] = "\x00"
		self.reply[105] = "\x00"
		self.reply[106] = "\x00"
		self.reply[107] = "\x00"
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def lsaQueryInfoPolicy(self, message, callid):
		self.genSMBHeader(smbCommand="\x25", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1])
		fill = ['\x00'] * 120
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x0a"
		### total param count
		self.reply[37] = "\x00"
		self.reply[38] = "\x00"
		### total data count
		self.reply[39] = "\x60"
		self.reply[40] = "\x00"
		### reserved
		self.reply[41] = "\x00"
		self.reply[42] = "\x00"
		### parameter count
		self.reply[43] = "\x00"
		self.reply[44] = "\x00"
		### param offset
		self.reply[45] = "\x38"
		self.reply[46] = "\x00"
		### displacement
		self.reply[47] = "\x00"
		self.reply[48] = "\x00"
		### data count
		self.reply[49] = "\x60"
		self.reply[50] = "\x00"
		### data offset
		self.reply[51] = "\x38"
		self.reply[52] = "\x00"
		### displacement
		self.reply[53] = "\x00"
		self.reply[54] = "\x00"
		### setup count
		self.reply[55] = "\x00"
		### reserved
		self.reply[56] = "\x00"
		### byte count
		self.reply[57] = "\x61"
		self.reply[58] = "\x00"
		### padding
		self.reply[59] = "\x00"
		### dce bind_ack
		### version
		self.reply[60] = "\x05"
		self.reply[61] = "\x00"
		### packet type
		self.reply[62] = "\x02"
		### packet flags
		self.reply[63] = "\x03"
		### data representation
		self.reply[64] = "\x10"
		self.reply[65] = "\x00"
		self.reply[66] = "\x00"
		self.reply[67] = "\x00"
		### frag length
		self.reply[68] = "\x60"
		self.reply[69] = "\x00"
		### auth length
		self.reply[70] = "\x00"
		self.reply[71] = "\x00"
		### call id
		self.reply[72:76] = callid
		### alloc hint
		self.reply[76] = "\x48"
		self.reply[77] = "\x00"
		self.reply[78] = "\x00"
		self.reply[79] = "\x00"
		### context id
		self.reply[80] = "\x00"
		self.reply[81] = "\x00"
		### cancel count
		self.reply[82] = "\x00"
		###
		self.reply[83] = "\x00"
		### pointer to info
		### referent id
		self.reply[84] = "\x08"
		self.reply[85] = "\x42"
		self.reply[86] = "\x0a"
		self.reply[87] = "\x00"
		### info
		self.reply[88] = "\x05"
		self.reply[89] = "\x00"
		### account domain
		self.reply[90] = "\x1b"
		self.reply[91] = "\xb8"
		### length
		self.reply[92] = "\x08"
		self.reply[93] = "\x00"
		### size
		self.reply[94] = "\x0a"
		self.reply[95] = "\x00"
		### referent id
		self.reply[96] = "\xa8"
		self.reply[97] = "\x47"
		self.reply[98] = "\x0a"
		self.reply[99] = "\x00"
		### referent id
		self.reply[100] = "\x58"
		self.reply[101] = "\x75"
		self.reply[102] = "\x0a"
		self.reply[103] = "\x00"
		### max count
		self.reply[104] = "\x05"
		self.reply[105] = "\x00"
		self.reply[106] = "\x00"
		self.reply[107] = "\x00"
		### offset
		self.reply[108] = "\x00"
		self.reply[109] = "\x00"
		self.reply[110] = "\x00"
		self.reply[111] = "\x00"
		### actual count
		self.reply[112] = "\x04"
		self.reply[113] = "\x00"
		self.reply[114] = "\x00"
		self.reply[115] = "\x00"
		### string
		self.reply[116] = "\x54" #T
		self.reply[117] = "\x00"
		self.reply[118] = "\x45" #E
		self.reply[119] = "\x00"
		self.reply[120] = "\x53" #S
		self.reply[121] = "\x00"
		self.reply[122] = "\x54" #T
		self.reply[123] = "\x00"
		### count
		self.reply[124] = "\x04"
		self.reply[125] = "\x00"
		self.reply[126] = "\x00"
		self.reply[127] = "\x00"
		### revision
		self.reply[128] = "\x01"
		### num auth
		self.reply[129] = "\x04"
		### authority
		self.reply[130] = "\x00"
		self.reply[131] = "\x00"
		self.reply[132] = "\x00"
		self.reply[133] = "\x00"
		self.reply[134] = "\x00"
		self.reply[135] = "\x05"
		### sub-authorities
		self.reply[136] = "\x15"
		self.reply[137] = "\x00"
		self.reply[138] = "\x00"
		self.reply[139] = "\x00"
		self.reply[140] = "\x79"
		self.reply[141] = "\xe3"
		self.reply[142] = "\xfc"
		self.reply[143] = "\x53"
		self.reply[144] = "\x11"
		self.reply[145] = "\xc3"
		self.reply[146] = "\x5f"
		self.reply[147] = "\x73"
		self.reply[148] = "\x43"
		self.reply[149] = "\x17"
		self.reply[150] = "\x0a"
		self.reply[151] = "\x32"
		### nt status
		self.reply[152] = "\x00"
		self.reply[153] = "\x00"
		self.reply[154] = "\x00"
		self.reply[155] = "\x00"
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def lsaOpenPolicy(self, message, callid):
		self.genSMBHeader(smbCommand="\x25", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1])
		fill = ['\x00'] * 72
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x0a"
		### total param count
		self.reply[37] = "\x00"
		self.reply[38] = "\x00"
		### total data count
		self.reply[39] = "\x30"
		self.reply[40] = "\x00"
		### reserved
		self.reply[41] = "\x00"
		self.reply[42] = "\x00"
		### parameter count
		self.reply[43] = "\x00"
		self.reply[44] = "\x00"
		### param offset
		self.reply[45] = "\x38"
		self.reply[46] = "\x00"
		### displacement
		self.reply[47] = "\x00"
		self.reply[48] = "\x00"
		### data count
		self.reply[49] = "\x30"
		self.reply[50] = "\x00"
		### data offset
		self.reply[51] = "\x38"
		self.reply[52] = "\x00"
		### displacement
		self.reply[53] = "\x00"
		self.reply[54] = "\x00"
		### setup count
		self.reply[55] = "\x00"
		### reserved
		self.reply[56] = "\x00"
		### byte count
		self.reply[57] = "\x31"
		self.reply[58] = "\x00"
		### padding
		self.reply[59] = "\x00"
		### dce bind_ack
		### version
		self.reply[60] = "\x05"
		self.reply[61] = "\x00"
		### packet type
		self.reply[62] = "\x02"
		### packet flags
		self.reply[63] = "\x03"
		### data representation
		self.reply[64] = "\x10"
		self.reply[65] = "\x00"
		self.reply[66] = "\x00"
		self.reply[67] = "\x00"
		### frag length
		self.reply[68] = "\x30"
		self.reply[69] = "\x00"
		### auth length
		self.reply[70] = "\x00"
		self.reply[71] = "\x00"
		### call id
		self.reply[72:76] = callid
		### alloc hint
		self.reply[76] = "\x18"
		self.reply[77] = "\x00"
		self.reply[78] = "\x00"
		self.reply[79] = "\x00"
		### context id
		self.reply[80] = "\x00"
		self.reply[81] = "\x00"
		### cancel count
		self.reply[82] = "\x00"
		###
		self.reply[83] = "\x00"
		self.reply[84] = "\x00"
		self.reply[85] = "\x00"
		self.reply[86] = "\x00"
		self.reply[87] = "\x00"
		###
		self.reply[88] = "\x08"
		self.reply[89] = "\xa7"
		self.reply[90] = "\x1b"
		self.reply[91] = "\xb8"
		self.reply[92] = "\x43"
		self.reply[93] = "\x8f"
		###
		self.reply[94] = "\xdf"
		self.reply[95] = "\x11"
		self.reply[96] = "\xa6"
		self.reply[97] = "\x93"
		self.reply[98] = "\x00"
		self.reply[99] = "\x0c"
		self.reply[100] = "\x29"
		self.reply[101] = "\xe0"
		###
		self.reply[102] = "\x69"
		self.reply[103] = "\x22"
		self.reply[104] = "\x00"
		self.reply[105] = "\x00"
		self.reply[106] = "\x00"
		self.reply[107] = "\x00"
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def SetNamedPipeHandleState(self, message, callid):
		self.genSMBHeader(smbCommand="\x25", pid0=message[self.SMB_PID0], pid1=message[self.SMB_PID1], mid0=message[self.SMB_MID0], mid1=message[self.SMB_MID1], uid0='\x01', uid1='\x08', tree0=message[self.SMB_TREEID0], tree1=message[self.SMB_TREEID1])

		fill = ['\x00'] * 92
		self.reply.extend(fill)
		### word count
		self.reply[self.SMB_WORDCOUNT] = "\x0a"
		### total param count
		self.reply[37] = "\x00"
		self.reply[38] = "\x00"
		### total data count
		self.reply[39] = "\x44"
		self.reply[40] = "\x00"
		### reserved
		self.reply[41] = "\x00"
		self.reply[42] = "\x00"
		### parameter count
		self.reply[43] = "\x00"
		self.reply[44] = "\x00"
		### param offset
		self.reply[45] = "\x38"
		self.reply[46] = "\x00"
		### displacement
		self.reply[47] = "\x00"
		self.reply[48] = "\x00"
		### data count
		self.reply[49] = "\x44"
		self.reply[50] = "\x00"
		### data offset
		self.reply[51] = "\x38"
		self.reply[52] = "\x00"
		### displacement
		self.reply[53] = "\x00"
		self.reply[54] = "\x00"
		### setup count
		self.reply[55] = "\x00"
		### reserved
		self.reply[56] = "\x00"
		### byte count
		self.reply[57] = "\x45"
		self.reply[58] = "\x00"
		### padding
		self.reply[59] = "\x00"
		### dce bind_ack
		### version
		self.reply[60] = "\x05"
		self.reply[61] = "\x00"
		### packet type
		self.reply[62] = "\x0c" # 27
		### packet flags
		self.reply[63] = "\x03"
		### data representation
		self.reply[64] = "\x10"
		self.reply[65] = "\x00"
		self.reply[66] = "\x00"
		self.reply[67] = "\x00"
		### frag length
		self.reply[68] = "\x44"
		self.reply[69] = "\x00"
		### auth length
		self.reply[70] = "\x00"
		self.reply[71] = "\x00"
		### call id
		self.reply[72:76] = callid
		### max xmit frag
		self.reply[76] = "\xb8"
		self.reply[77] = "\x10"
		### max recv frag
		self.reply[78] = "\xb8"
		self.reply[79] = "\x10"
		### assoc group
		self.reply[80] = "\xf7"
		self.reply[81] = "\x41"
		self.reply[82] = "\x00"
		self.reply[83] = "\x00"
		### scndry addr len
		self.reply[84] = "\x0c"
		self.reply[85] = "\x00"
		### scndry addr
		self.reply[86] = "\x5c"
		self.reply[87] = "\x50"
		self.reply[88] = "\x49"
		self.reply[89] = "\x50"
		self.reply[90] = "\x45"
		self.reply[91] = "\x5c"
		if self.pipe_fid.has_key('lsarpc'):
			self.reply[92] = "\x6c" # l
			self.reply[93] = "\x73" # s
			self.reply[94] = "\x61" # a
			self.reply[95] = "\x73" # s
			self.reply[96] = "\x73" # s
			self.reply[97] = "\x00"
			self.reply[98] = "\x00"
			self.reply[99] = "\x00"
		### num result
		self.reply[100] = "\x01" # 65
		### reserved
		self.reply[101] = "\x00"
		self.reply[102] = "\x00"
		self.reply[103] = "\x00"
		### context id
		### ack result
		self.reply[104] = "\x00"
		self.reply[105] = "\x00"
		### reserved
		self.reply[106] = "\x00"
		self.reply[107] = "\x00"
		### transfer syntax
		self.reply[108] = "\x04"
		self.reply[109] = "\x5d"
		self.reply[110] = "\x88"
		self.reply[111] = "\x8a"
		self.reply[112] = "\xeb"
		self.reply[113] = "\x1c"
		self.reply[114] = "\xc9"
		self.reply[115] = "\x11"
		self.reply[116] = "\x9f"
		self.reply[117] = "\xe8"
		self.reply[118] = "\x08"
		self.reply[119] = "\x00"
		self.reply[120] = "\x2b"
		self.reply[121] = "\x10"
		self.reply[122] = "\x48"
		self.reply[123] = "\x60"
		### syntax version
		self.reply[124] = "\x02"
		self.reply[125] = "\x00"
		self.reply[126] = "\x00"
		self.reply[127] = "\x00" # 92
		###
		pktlength = struct.pack('!H', (len(self.reply)-4))
		self.reply[2:4] = pktlength
		return

	def checkOperationNumber(self, opnumber, smbDataBlock):
		try:
			if opnumber == 9: # and self.pipe_fid.has_key('lsarpc'):
				self.vulnName = "MS04011 (LSASS)"
				self.shellcode.append(smbDataBlock)
				return "".join(self.reply), 'shellcode'
			elif opnumber == 10:
				self.vulnName = "MS06025 (Rasmans)"
				self.shellcode.append(smbDataBlock)
				return "".join(self.reply), 'shellcode'
			elif opnumber == 12:
				self.vulnName = "MS04031 (NetDDE)"
				self.shellcode.append(smbDataBlock)
				return "".join(self.reply), 'shellcode'
			elif opnumber == 22:
				self.vulnName = "MS06070 (NetpManageIPCConnect)"
				self.shellcode.append(smbDataBlock)
				return "".join(self.reply), 'shellcode'
			elif opnumber == 27:
				self.vulnName = "MS03049 (NetAPI)"
				self.shellcode.append(smbDataBlock)
				return "".join(self.reply), 'shellcode'
			elif opnumber == 31:
				self.vulnName = "MS08067 (NetAPI)"
				self.shellcode.append(smbDataBlock)
				return "".join(self.reply), 'shellcode'
			elif opnumber == 54:
				self.vulnName = "MS05039 (PNP)"
				self.shellcode.append(smbDataBlock)
				return "".join(self.reply), 'shellcode'
			elif opnumber == -2:
				if self.debug:
					print "shellcode contains executable"
				self.vulnName = "SMB File Upload"
				return "".join(self.reply), 'shellcode'
			else:
				return "".join(self.reply), None
		except KeyboardInterrupt:
			raise

	def consume(self, data, ownIP):
		if len(data)==0:
			### client disconnected
			if len(self.fragments)>0:
				remainingData = "".join(self.fragments)
				self.shellcode.append(remainingData)
				if remainingData.startswith('\x05\x00\x00') and len(remainingData)>24 and struct.unpack('H', remainingData[22:24])[0]==22:
					self.vulnName = "MS06070 (NetpManageIPCConnect)"
					return None, 'shellcode'
				elif remainingData.startswith('\x05\x00\x00') and len(remainingData)>24 and struct.unpack('H', remainingData[22:24])[0]==12:
					self.vulnName = "MS04031 (NetDDE)"
					return None, 'shellcode'
			return None, None
		elif len(data)<10:
			if self.showRequests:
				print ">> received too short data (<10)"
				print [data]
			return None, None
		elif len(data)<35:
			if self.showRequests:
				print ">> received too short data (<35)"
				print [data]
			if self.fragmentation:
				self.fragments.append(data)
				return None, 'noreply'
			return None, None
		### check for netbios session request packet
		if self.checkForNetbiosSessionRequest(data):
			if self.showRequests:
				print ">> received netbios session request"
			self.NetbiosSessionReply(data)
			return "".join(self.reply), None
		elif self.checkForNetbiosSessionRetargetRequest(data):
			if self.showRequests:
				print ">> received netbios session retarget request"
			self.NetbiosRetargetReply(data, ownIP)
			return "".join(self.reply), None
		### check smb packet
		smbCheckResult, data = self.checkForSMBPacket(data)
		if smbCheckResult:
			commandByte = data[8]
			if commandByte == '\x72':
				if self.showRequests:
					print ">> received smb negotiate request", len(data)
				multiplexID = self.disectNegotiateRequest(data)
				dialectIndex = self.getsmbNegotInfo(data)
				if self.debug:
					print "MutliplexID: %s" % (multiplexID)
					print "DialectIndex: %s" % (dialectIndex)
				if multiplexID!=0:
					self.NegotiationReply(data, dialectIndex)
				else:
					if self.debug:
						print "Anonymous Negotiation Reply"
					self.NegotiationReplyAnonymous(data, dialectIndex)
				return "".join(self.reply), None
			elif commandByte == '\x73':
				if self.showRequests:
					print ">> received session setup andX request", len(data)
				### check client for security capability
				if data[36] == '\x0c':
					self.SessionSetupAndX(data, ownIP)
				else: #data[36] == '\x0d':
					self.SessionSetupAndxNoCap(data)
				if self.vulnName == "MS04007 (ASN1)":
					self.shellcode.append(self.getContent(data))
					return "".join(self.reply), 'shellcode'
				else:
					return "".join(self.reply), None
			elif commandByte == '\x75':
				if self.showRequests:
					print ">> received tree connect andX request", len(data)
				self.TreeConnectAndX(data)
				return "".join(self.reply), None
			elif commandByte == '\xa2':
				if self.showRequests:
					print ">> received nt create andX request", len(data)
				self.NTCreateAndX(data)
				return "".join(self.reply), None
			elif commandByte == '\x25' or commandByte == '\x32':
				setupCountVal, packetType, opnumber, callid = self.disectTransaction(data)
				if packetType=='\x00' and opnumber == 6:
					if self.showRequests:
						print ">> received lsa_openpolicy request"
					self.lsaOpenPolicy(data, callid)
					return "".join(self.reply), None
				elif packetType=='\x00' and opnumber == 7:
					if self.showRequests:
						print ">> received lsa_queryinfopolicy request"
					self.lsaQueryInfoPolicy(data, callid)
					return "".join(self.reply), None
				elif packetType=='\x00' and opnumber == 0:
					if self.showRequests:
						print ">> received lsa_close request"
					self.lsaClose(data, callid)
					return "".join(self.reply), None
				if setupCountVal == 2 and packetType == '\x0b':
					if self.showRequests:
						print ">> received set named pipe handle state (BIND)"
					self.SetNamedPipeHandleState(data, callid)
					return "".join(self.reply), None
				else:
					if packetType == '\x0b':
						if self.showRequests:
							print ">> received smb transaction bind request", len(data)
						self.smbTransaction(data, callid)
						return "".join(self.reply), None
					elif packetType == '\x00':
						if self.showRequests:
							print ">> received smb lookup request", len(data)
						self.smbLookUpReq(data, ownIP, callid)
						messageData = self.getContent(data)
						return self.checkOperationNumber(opnumber, messageData)
					elif packetType == None:
						self.emptyTransaction(data)
						return "".join(self.reply), None
					else:
						if self.showRequests:
							print ">> Unknown SMB Packet Type Request: %s" % ([packetType])
							print ">> %s" % ([data])
						return None, None
			elif commandByte == '\x2f':
				if self.showRequests:
					print ">> received smb write andx request", len(data)
				opnumber, smbDataBlock = self.disectWriteAndX(data)
				self.WriteAndX(data)
				return self.checkOperationNumber(opnumber, smbDataBlock)
			elif commandByte == '\x2e':
				if self.showRequests:
					print ">> received smb read andx request", len(data)
				wordCount, maxcount, offset = self.disectReadAndX(data)
				if self.vulnName == "MS08067 (NetAPI)":
					self.smbReadAndX2(data)
				else:
					### if amount of written data equals data to read
					if self.debug:
						print "MaxCount: ",maxcount
						print "AndXRead: ",self.readAndXOffset
						print "Wr Bytes: ",len(self.writtenBytes)
						print "Items: ",[self.NUM_COUNT_ITEMS]
						print "Fragm.: ",self.fragmentation
					if self.NextReadWithError:
						if self.debug:
							print ">> reply with broken pipe"
						self.NextReadWithError = False
						self.ReadAndXBrokenPipe(data)
					elif (maxcount+offset)>=len(self.writtenBytes) and self.NUM_COUNT_ITEMS != None and self.fragmentation == False:
						if self.debug:
							print ">> finish read"
						self.readCounter += 1
						if self.readCounter>=15:
							self.writtenBytes = ""
							self.NextReadWithError = True
						self.readAndXOffset = 0
						self.smbReadAndX(data)
					else:
						if self.debug:
							print ">> continue read"
						dataToRead = self.writtenBytes[self.readAndXOffset:self.readAndXOffset+maxcount]
						self.readAndXOffset += maxcount
						self.ReadAndX(data, maxcount, dataToRead)
				return "".join(self.reply), None
			elif commandByte == '\x2b':
				if self.showRequests:
					print ">> received smb echo request", len(data)
				self.smbEcho(data)
				return "".join(self.reply), None
			elif commandByte == '\x71':
				if self.showRequests:
					print ">> received tree disconnect connection request", len(data)
				self.TreeDisconnect(data)
				return "".join(self.reply), 'quit'
			elif commandByte == '\x04':
				if self.showRequests:
					print ">> received smb close request", len(data)
				self.SMBClose(data)
				return "".join(self.reply), None
			elif commandByte == '\x74':
				if self.showRequests:
					print ">> received logoff andx request", len(data)
				self.LogOffAndX(data)
				return "".join(self.reply), None
			elif commandByte == '\xa0':
				if self.showRequests:
					print ">> received nt trans request", len(data)
				self.NTTransResponse(data)
				return "".join(self.reply), None
			elif commandByte == '\x33':
				self.trans2counter = 1
				if self.showRequests:
					print ">> received trans2 secondary request", len(data)
				totalDataCount = struct.unpack('H', data[39:41])[0]
				if self.debug:
					print ">> Trans2 Data Count: %s" % totalDataCount
					print ">> Trans2 Counter: %s" % self.trans2counter
				self.vulnName = 'MS17010 (EternalBlue)'
				self.NTTrans2Response(data)
				return "".join(self.reply), 'shellcode'
			else:
				print ">> Unknown SMB Request: %s (%s)" % ([commandByte], len(data))
				return None, None
		else:
			if self.vulnName == "MS04007 (ASN1)":
				self.shellcode.append(self.getContent(data))
				return None, 'shellcode'
			if self.vulnName == 'MS17010 (EternalBlue)':
				self.trans2counter += 1
				if self.trans2counter >=61:
					self.NTTrans2Response(data)
					return "".join(self.reply), 'shellcode'
			if self.fragmentation:
				if self.debug:
					print ">> still in fragmentation mode"
				#print [data]
				self.fragments.append(data)
				dataBlock = "".join(self.fragments)
				if dataBlock.startswith('\x05\x00\x00') and len(dataBlock)>=10:
					fragLength = struct.unpack('H', dataBlock[8:10])[0]
					if len(dataBlock)>24:
						opnumber = struct.unpack('H', dataBlock[22:24])[0]
					else:
						opnumber = -1
					if len(dataBlock)==fragLength:
						self.fragments = []
						self.fragmentation = False
						### reply with empty write andx
						self.emptyWriteAndX(data)
						return self.checkOperationNumber(opnumber, dataBlock)
					elif len(dataBlock)>fragLength:
						newBlock = dataBlock[fragLength:]
						self.fragments = [newBlock]
						self.fragmentation = True
						### reply with empty write andx
						self.emptyWriteAndX(data)
						return self.checkOperationNumber(opnumber, dataBlock)
				return None, 'noreply'
			if self.debug:
				print ">> no answer"
				print self.trans2counter
			#	print [data[:10]]
				print self.vulnName
			#if self.showRequests:
			#	print [data]
			self.shellcode.append(data)
			return None, 'shellcode'
