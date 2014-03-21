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

import random

import amun_logging

class shellemulator:
	def __init__(self, emuLogger):
		self.log_obj = amun_logging.amun_logging("shellemulator", emuLogger)
		os_id = random.randint(0,1)
		if os_id==0:
			self.shellInfo = "Microsoft Windows XP [Version 5.1.2600]\n(C) Copyright 1985-2001 Microsoft Corp.\n\nC:\\WINNT\\System32>"
			self.prompt = "C:\\WINNT\\System32>"
		else:
			self.shellInfo = "Microsoft Windows 2000 [Version 5.00.2195]\n(C) Copyright 1985-2000 Microsoft Corp.\n\nC:\\WINDOWS\\System32>"
			self.prompt = "C:\\WINDOWS\\System32>"
		self.randomNumber = random.randint(255,5100)
		self.computerName = "DESKTOP-%i" % (self.randomNumber)
		self.attackerIP = None
		self.ownIP = None
		self.attackerPort = None
		self.ownPort = None
		self.defaultGW = None

	def setConnectionInformation(self, aIP, aPort, oIP, oPort):
		self.attackerIP = aIP
		self.attackerPort = aPort
		self.ownIP = oIP
		self.ownPort = oPort

	def setAttackerIP(self, ip):
		self.attackerIP = ip

	def setAttackerPort(self, port):
		self.attackerPort = port

	def setOwnIP(self, ip):
		self.ownIP = ip
		pointpos = ip.rfind('.')
		self.defaultGW = ip[:pointpos]+".4"

	def setOwnPort(self, port):
		self.ownPort = port

	def getShellInfoLine(self):
		return self.shellInfo

	def getPrompt(self):
		return self.prompt

	def shellInterpreter(self, data):
		""" Interpret Incoming Shellcommands """
		data = data.strip()
		closeShell = False
		reply = ""
		self.log_obj.log("%s incoming shellcommand: %s" % (self.attackerIP, data), 9, "crit", True, False)
		try:
			if data=="exit":
				closeShell = True
			elif data.startswith('cd'):
				self.changeDirectory(data)
			elif data.startswith('netstat'):
				reply = self.netstat(data)
			elif data.startswith('net '):
				reply = self.net(data)
			elif data.startswith('dir'):
				reply = self.dir(data)
			elif data.startswith('ipconfig'):
				reply = self.ipconfig(data)
		except:
			pass
		### return modified prompt
		return self.prompt,closeShell,reply

	def dir(self, data):
		""" emulate dir command """
		reply = ""
		try:
			if data=="dir":
				reply = "\nVolume in drive C has no label\n"
				reply+= "Volume Serial Number is %i-FAB8\n\n" % (self.randomNumber)
				reply+= "Directory of %s\n\n" % (self.prompt.strip('>'))
				reply+= "06/11/2007  05:01p    <DIR>\t\t.\n"
				reply+= "06/11/2007  05:01p    <DIR>\t\t..\n"
				reply+= "               0 File(s)\t\t0 bytes\n"
				reply+= "               2 Dir(s)\t1,627,193,344 bytes free\n\n"
				return reply
		except:
			pass
		return reply

	def net(self, data):
		""" emulate the net command """
		reply = ""
		try:
			if data=="net user":
				reply = "\nUser accounts for \\\\%s\n\n" % (self.computerName)
				reply+= "--------------------------------------------------------------------------------\n"
				reply+= "admin\t\t\tAdministrator\t\t\tGuest\n"
				reply+= "HelpAssistant\t\tSUPPORT_%ia0\n" % (self.randomNumber)
				reply+= "The command completed successfully\n\n"
				return reply
		except:
			pass
		return reply

	def netstat(self, data):
		""" emulate the netstat command """
		reply = ""
		try:
			if data=="netstat -anp tcp" or data=="netstat -nap tcp":
				reply = "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State\n"
				reply+= "  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    0.0.0.0:25             0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    0.0.0.0:110            0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    0.0.0.0:139            0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    0.0.0.0:2967           0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    0.0.0.0:2968           0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    0.0.0.0:5000           0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    0.0.0.0:6129           0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    127.0.0.1:8118         0.0.0.0:0              LISTENING\n"
				reply+= "  TCP    127.0.0.1:62514        0.0.0.0:0              LISTENING\n"
				if self.attackerIP!=None and self.attackerPort!=None and self.ownIP!=None and self.ownPort!=None:
					reply+= "  TCP    %s:%s         %s:%s              ESTABLISHED\n" % (self.ownIP,self.ownPort,self.attackerIP,self.attackerPort)
				reply+= "\n"
				return reply
		except:
			pass
		return reply

	def ipconfig(self, data):
		""" emulate ipconfig command """
		reply = ""
		try:
			if data=="ipconfig":
				reply = "\nWindows IP Configuration\n\n"
				reply+= "Ethernet adapter Local Area Connection 3:\n\n"
				reply+= "\tConnection-specific DNS Suffix  . :\n"
				reply+= "\tIP Address. . . . . . . . . . . . : %s\n" % (self.ownIP)
				reply+= "\tSubnet Mask . . . . . . . . . . . : 255.255.255.0\n"
				reply+= "\tDefault Gateway . . . . . . . . . : %s\n" % (self.defaultGW)
				reply+= "\n"
				return reply
		except:
			pass
		return reply

	def changeDirectory(self, data):
		""" emulate directory changing """
		try:
			if data=="cd ..":
				data="cd.."
			if data=="cd.." and self.prompt!="C:\\>":
				position = self.prompt.rfind('\\')
				newPrompt = self.prompt[:position]
				if newPrompt=="C:":
					newPrompt = "C:\\"
				self.prompt = "%s>" % (newPrompt)
			elif data=="cd\\":
				self.prompt = "C:\\>"
			elif data.startswith('cd '):
				position = data.find(' ')
				newdir = data[position+1:]
				newPrompt = self.prompt[:-1]
				if newPrompt[-1] == '\\':
					self.prompt = "%s%s>" % (newPrompt,newdir)
				else:
					self.prompt = "%s\\%s>" % (newPrompt,newdir)
		except:
			pass
