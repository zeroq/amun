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
import os.path

class AmunConfigParser:
	def __init__(self, filename):
		if os.path.exists(filename):
			try:
				self.filename = filename
				fp = open(filename, 'r')
				content = fp.read()
				fp.close()
				self.contentList = content.split('\n')
			except IOError:
				self.contentList = None
				return None
		else:
			self.contentList = None
			return None

	def getSingleValue(self, attribute):
		regString = '^(%s)\s*(:|=)\s*(.*)' % (attribute)
		lookup = re.compile(regString)
		for line in self.contentList:
			match = lookup.search(line)
			if match:
				if len(match.groups()[2])>0:
					return match.groups()[2]
				return None
		return None

	def getListValues(self, attribute):
		attrList = []
		begin = False
		regString = '^(%s)\s*(:|=)\s*' % (attribute)
		lookup = re.compile(regString, re.S )
		for item in self.contentList:
			line = item.strip()
			if not begin:
				match = lookup.search(line)
				if match:
					begin = True
					continue
			if begin and line.startswith('#') and not line.startswith('###'):
				continue
			if begin and line.startswith('###'):
				begin = False
				break
			if begin and not line.endswith(',') and len(line)>0:
				attrList.append(line)
				begin = False
				break
			if begin and len(line)>0:
				attrList.append(line.strip(','))
		return attrList


	def reloadConfig(self):
		if os.path.exists(self.filename):
			try:
				fp = open(self.filename, 'r')
				content = fp.read()
				fp.close()
				self.contentList = content.split('\n')
				return True, None
			except IOError, e:
				self.contentList = None
				return False, e
		else:
			self.contentList = None
			return False, None

