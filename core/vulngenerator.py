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

class vulngenerator:

	def __init__(self):
		self.receivedData = []
		self.replyData = []
		### maybe hash from first stage?
		self.vulnName = None
		self.stages = 0
		self.welcomeMessage = None
		self.port = None
		### self.stagesDict[1] = [ReadBytes, RequestBytes, ReplyBytes, DefaultReply=random]
		self.stagesDict = {}

	def writeReceived(self, data):
		self.receivedData.append(data)

	def writeReply(self, data):
		self.replyData.append(data)

	def writeXMLfile(self):
		pass
