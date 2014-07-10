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

import re
import struct
import socket
import subprocess

class utilities(object):
	__slots__ = ("ipReg", "ipRange", "ipCIDR", "deviceIP", "resultIPlist")

	def __init__(self):
		self.ipReg = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
		self.ipRange = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
		self.ipCIDR = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{2})")
		self.deviceIP = re.compile("inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/");
		self.resultIPlist = []

	def genIPList(self, IPentry):
		IPentryList = []
		### check for comma and split
		if IPentry.count(',')>0:
			IPentryList = IPentry.split(',')
		else:
			IPentryList.append(IPentry)

		for entry in IPentryList:
			match = self.ipRange.search(entry)
			if match:
				self.getIPsFromRange(match.groups())
				continue
			match = self.ipCIDR.search(entry)
			if match:
				self.getIPsFromCIDR(match.groups())
				continue
			match = self.ipReg.search(entry)
			if match:
				self.getSingleIP(match.groups())
				continue
			if entry.startswith('eth') or entry.startswith('ppp') or entry.startswith('lo'):
				self.getIPsFromDevice(IPentry)
				continue
		return self.resultIPlist

	def getSingleIP(self, ipGroup):
		### 192.168.0.1
		self.resultIPlist.append(ipGroup[0].strip())
		return

	def getIPsFromDevice(self, device):
		### "ip addr show <device>"
		command = "ip addr show %s" % (device)
		child = subprocess.Popen([command], shell=True, bufsize=1024, stdout=subprocess.PIPE, close_fds=True)
		line = child.stdout.readline()
		while line:
			line = str(line).strip()
			m = self.deviceIP.search(line)
			if m:
				self.resultIPlist.append(m.groups()[0].strip())
			line = child.stdout.readline()
		child.wait()

	def getIPsFromRange(self, rangeStr):
		### 192.168.0.1 - 192.168.0.255
		startIP = rangeStr[0]
		stopIP = rangeStr[1]
		curIP = startIP
		curIPSplitted = map(int, curIP.split('.'))
		invalid = False
		self.resultIPlist.append(curIP)
		while curIP!=stopIP and not invalid:
			curIPSplitted[3] += 1
			curIP = "%i.%i.%i.%i" % (curIPSplitted[0],curIPSplitted[1],curIPSplitted[2],curIPSplitted[3])
			self.resultIPlist.append(curIP)
			if curIPSplitted[3] > 255:
				curIPSplitted[3] = 0
				curIPSplitted[2] += 1
			if curIPSplitted[2] > 255:
				curIPSplitted[2] = 0
				curIPSplitted[1] += 1
			if curIPSplitted[1] > 255:
				curIPSplitted[1] = 0
				curIPSplitted[0] += 1
			if curIPSplitted[0] > 255:
				invalid = True
		return

	def getIPsFromCIDR(self, networkCIDR):
		### 192.168.0.0/24
		baseIP = networkCIDR[0]
		netmask = networkCIDR[1]
		ip = struct.unpack('>L', socket.inet_aton(baseIP))[0]
		diff1 = int(ip & int(netmask))
		diff2 = 32-int(netmask)
		if diff1==0:
			startip = ip-diff1
			numHosts = pow(2,diff2)
			for i in xrange(numHosts):
				self.resultIPlist.append(socket.inet_ntoa(struct.pack('>L', startip+i)))
		else:
			self.resultIPlist.append(socket.inet_ntoa(struct.pack('>L', ip)))
		return

class fifoqueue(object):
	__slots__ = ("list", "size")

	def __init__(self, size):
		self.list = []
		self.size = size

	def insert(self, value):
		if len(self.list)>=self.size:
			self.remove()
		self.list.append(value)

	def remove(self):
		test = self.list
		test.reverse()
		test.pop()
		test.reverse()
		self.list = test
		if not self.list:
			self.list = []

	def contains(self, value):
		if value in self.list:
			return True
		return False
