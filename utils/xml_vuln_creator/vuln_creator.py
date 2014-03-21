#!/usr/bin/python

"""
[Amun - low interaction honeypot]
Copyright (C) [2014]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

from xml.sax import saxutils
from xml.sax import ContentHandler
from xml.sax import make_parser
from xml.sax.handler import feature_namespaces

import optparse
import sys

__version__ = "0.2"

vuln_dict = {}
vuln_dict['vuln_name'] = ""
vuln_dict['num_stages'] = 0
vuln_dict['welcome_mess'] = ""
vuln_dict['default_reply'] = "\x00"

class createVuln(ContentHandler):
	def __init__(self):
		self.stage = {}
		self.stage['reply'] = ""
		self.stage['rpl_position'] = ""
		self.stage['request'] = ""
		self.stage['bytes_to_read'] = []
		self.ports = []
		self.stages = {}
		### Init Section
		self.inInit = False
		self.inName = False
		self.inNumStages = False
		self.inWelcome = False
		self.inPorts = False
		self.inPort = False
		self.inDefaultReply = False
		### Stages Section
		self.inStages = False
		self.inStage = False
		self.inReadBytes = False
		self.inReply = False
		self.inRequest = False
		self.currentStage = "0"

	def startElement(self, name, attrs):
		if name=="Init":
			self.inInit = True
		elif self.inInit and name=="Name":
			self.inName = True
		elif self.inInit and name=="Stages":
			self.inNumStages = True
		elif self.inInit and name=="WelcomeMess":
			self.inWelcome = True
		elif self.inInit and name=="Ports":
			self.inPorts = True
		elif self.inInit and self.inPorts and name=="Port":
			self.inPort = True
		elif self.inInit and name=="DefaultReply":
			self.inDefaultReply = True
		elif not self.inInit and name=="Stages":
			self.inStages = True
		elif not self.inInit and self.inStages and name=="Stage":
			self.inStage = True
			self.currentStage = attrs.get('stage', "")
			self.stage['stage_num'] = attrs.get('stage', "")
		elif not self.inInit and self.inStages and self.inStage and name=="ReadBytes":
			self.inReadBytes = True
		elif not self.inInit and self.inStages and self.inStage and name=="Reply":
			self.inReply = True
			self.stage['rpl_position'] = attrs.get('position', "")
		elif not self.inInit and self.inStages and self.inStage and name=="Request":
			self.inRequest = True

	def characters(self, ch):
		if self.inInit and self.inName:
			vuln_dict['vuln_name'] += ch
		if self.inInit and self.inNumStages:
			vuln_dict['num_stages'] = ch
		if self.inInit and self.inWelcome:
			vuln_dict['welcome_mess'] += ch
		if self.inInit and self.inPorts and self.inPort:
			self.ports.append(ch)
		if self.inInit and self.inDefaultReply:
			vuln_dict['default_reply'] = ch
		if self.inReadBytes:
			self.stage['bytes_to_read'].append(ch)
		if self.inReply:
			self.stage['reply'] = ch
		if self.inRequest:
			self.stage['request'] = ch

	def endElement(self, name):
		if self.inInit and name=="Name":
			self.inName = False
		elif self.inInit and name=="Stages":
			self.inNumStages = False
		elif self.inInit and name=="WelcomeMess":
			self.inWelcome = False
		elif self.inInit and self.inPorts and name=="Port":
			self.inPort = False
		elif self.inInit and name=="Ports":
			self.inPorts = False
		elif self.inInit and name=="DefaultReply":
			self.inDefaultReply = False
		elif name=="Init":
			self.inInit = False
		elif not self.inInit and self.inStages and name=="Stage":
			self.inStage = False
			self.stages[int(self.currentStage)] = self.stage
			self.stage = {}
			self.stage['reply'] = ""
			self.stage['rpl_position'] = ""
			self.stage['request'] = ""
			self.stage['bytes_to_read'] = []
		elif not self.inInit and self.inStages and self.inStage and name=="ReadBytes":
			self.inReadBytes = False
		elif not self.inInit and self.inStages and self.inStage and name=="Reply":
			self.inReply = False
		elif not self.inInit and self.inStages and self.inStage and name=="Request":
			self.inRequest = False
		elif not self.inInit and name=="Stages":
			self.inStages = False

	def endDocument(self):
		vuln_dict['ports'] = self.ports
		vuln_dict['stages'] = self.stages


class constructFile:
	def __init__(self, vuln_dictionary):
		self.vdict = vuln_dictionary
		self.v_name = self.vdict['vuln_name']
		self.module_name = "%s_modul.py" % (self.v_name.lower())
		self.shellc_name = "%s_shellcodes.py" % (self.v_name.lower())
		self.write_imports()
		self.write_class_init()
		self.write_print_func()
		self.write_utility_func()
		self.write_incoming()
		self.write_stages()
		self.write_shellcode_stage()
		self.write_requests()

	def write_requests(self):
		fp = open(self.shellc_name, 'w')
		number_of_stages = int(self.vdict['num_stages'])
		list_of_stages = self.vdict['stages']
		for i in range(1, number_of_stages+1):
			try:
				req_line = '%s_request_stage%i = "%s"\n\n' % (self.v_name.lower(), i, list_of_stages[i]['request'])
				fp.write(req_line)
			except:
				pass
		fp.close()

	def write_imports(self):
		#fp = open(self.module_name, 'a+')
		fp = open(self.module_name, 'w')
		fp.write("try:\n")
		fp.write("\timport psyco ; psyco.full()\n")
		fp.write("\tfrom psyco.classes import *\n")
		fp.write("except ImportError:\n")
		fp.write("\tpass\n")
		fp.write("\n")
		fp.write("import traceback\n")
		fp.write("import StringIO\n")
		fp.write("import sys\n")
		fp.write("import struct\n")
		fp.write("import amun_logging\n")
		fp.write("import random\n")
		fp.write("import %s_shellcodes\n\n" % (self.v_name.lower()))
		fp.close()

	def write_class_init(self):
		fp = open(self.module_name, 'a+')
		fp.write('class vuln(object):\n')
		fp.write('\t__slots__ = ("vuln_name", "stage", "welcome_message", "shellcode", "reply", "log_obj")\n\n')
		fp.write('\tdef __init__(self):\n')
		fp.write('\t\ttry:\n')
		fp.write('\t\t\tself.vuln_name = "%s Vulnerability"\n' % (self.v_name))
		if int(self.vdict['num_stages'])>0:
			fp.write('\t\t\tself.stage = "%s_STAGE1"\n' % (self.v_name))
		else:
			fp.write('\t\t\tself.stage = "SHELLCODE"\n')
		fp.write('\t\t\tself.welcome_message = "%s"\n' % (self.vdict['welcome_mess']))
		fp.write('\t\t\tself.shellcode = []\n')
		fp.write('\t\texcept KeyboardInterrupt:\n')
		fp.write('\t\t\traise\n\n')
		fp.close()
	
	def write_print_func(self):
		fp = open(self.module_name, 'a+')
		fp.write('\tdef print_message(self, data):\n')
		fp.write('\t\tprint "\\n"\n')
		fp.write('\t\tcounter = 1\n')
		fp.write('\t\tfor byte in data:\n')
		fp.write('\t\t\tif counter==16:\n')
		fp.write('\t\t\t\tausg = hex(struct.unpack("B",byte)[0])\n')
		fp.write('\t\t\t\tif len(ausg) == 3:\n')
		fp.write('\t\t\t\t\tlist = str(ausg).split("x")\n')
		fp.write('\t\t\t\t\tausg = "%sx0%s" % (list[0],list[1])\n')
		fp.write('\t\t\t\t\tprint ausg\n')
		fp.write('\t\t\t\telse:\n')
		fp.write('\t\t\t\t\tprint ausg\n')
		fp.write('\t\t\t\tcounter = 0\n')
		fp.write('\t\t\telse:\n')
		fp.write('\t\t\t\tausg = hex(struct.unpack("B",byte)[0])\n')
		fp.write('\t\t\t\tif len(ausg) == 3:\n')
		fp.write('\t\t\t\t\tlist = str(ausg).split("x")\n')
		fp.write('\t\t\t\t\tausg = "%sx0%s" % (list[0],list[1])\n')
		fp.write('\t\t\t\t\tprint ausg,\n')
		fp.write('\t\t\t\telse:\n')
		fp.write('\t\t\t\t\tprint ausg,\n')
		fp.write('\t\t\tcounter += 1\n')
		fp.write('\t\tprint "\\n>> Incoming Codesize: %s\\n\\n" % (len(data))\n\n')
		fp.close()


	def write_utility_func(self):
		fp = open(self.module_name, 'a+')
		fp.write('\tdef getVulnName(self):\n')
		fp.write('\t\treturn self.vuln_name\n\n')
		fp.write('\tdef getCurrentStage(self):\n')
		fp.write('\t\treturn self.stage\n\n')
		fp.write('\tdef getWelcomeMessage(self):\n')
		fp.write('\t\treturn self.welcome_message\n\n')
		fp.close()

	def write_incoming(self):
		fp = open(self.module_name, 'a+')
		fp.write('\tdef incoming(self, message, bytes, ip, vuLogger, random_reply, ownIP):\n')
		fp.write('\t\ttry:\n')
		fp.write('\t\t\t### logging object\n')
		fp.write('\t\t\tself.log_obj = amun_logging.amun_logging("vuln_%s", vuLogger)\n' % (self.v_name.lower()))
		fp.write('\t\t\t### construct standard reply\n')
		if self.vdict['default_reply']=="random" or self.vdict['default_reply']==None:
			fp.write('\t\t\tself.reply = random_reply\n')
		else:
			fp.write('\t\t\tself.reply = []\n')
			fp.write('\t\t\tfor i in range(0,510):\n')
			fp.write('\t\t\t\ttry:\n')
			fp.write('\t\t\t\t\tself.reply.append("%s")\n' % (self.vdict['default_reply']))
			fp.write('\t\t\t\texcept KeyboardInterrupt:\n')
			fp.write('\t\t\t\t\traise\n\n')
		fp.write('\t\t\t### prepare default resultSet\n')
		fp.write('\t\t\tresultSet = {}\n')
		fp.write('\t\t\tresultSet["vulnname"] = self.vuln_name\n')
		fp.write('\t\t\tresultSet["accept"] = False\n')
		fp.write('\t\t\tresultSet["result"] = False\n')
		fp.write('\t\t\tresultSet["shutdown"] = False\n')
		fp.write('\t\t\tresultSet["reply"] = "None"\n')
		fp.write('\t\t\tresultSet["stage"] = self.stage\n')
		fp.write('\t\t\tresultSet["shellcode"] = "None"\n')
		fp.write('\t\t\tresultSet["isFile"] = False\n\n')
		fp.close()

	def write_stages(self):
		fp = open(self.module_name, 'a+')
		number_of_stages = int(self.vdict['num_stages'])
		list_of_stages = self.vdict['stages']
		for i in range(1, number_of_stages+1):
			try:
				if i == 1:
					if len(list_of_stages[i]['bytes_to_read'])>0:
						bytesString = "bytes == %s" % (list_of_stages[i]['bytes_to_read'].pop())
						for bStr in list_of_stages[i]['bytes_to_read']:
							bytesString += " or bytes == %s" % (bStr)
						fp.write('\t\t\tif self.stage == "%s_STAGE%i" and (%s):\n' % (self.v_name, i, bytesString))
					else:
						fp.write('\t\t\tif self.stage == "%s_STAGE%i":\n' % (self.v_name, i))
				else:
					if len(list_of_stages[i]['bytes_to_read'])>0:
						bytesString = "bytes == %s" % (list_of_stages[i]['bytes_to_read'].pop())
						for bStr in list_of_stages[i]['bytes_to_read']:
							bytesString += " or bytes == %s" % (bStr)
						fp.write('\t\t\telif self.stage == "%s_STAGE%i" and (%s):\n' % (self.v_name, i, bytesString))
					else:
						fp.write('\t\t\telif self.stage == "%s_STAGE%i":\n' % (self.v_name, i))
				if list_of_stages[i]['request']!="":
					fp.write('\t\t\t\tif %s_shellcodes.%s_request_stage%i == message:\n' % (self.v_name.lower(), self.v_name.lower(), i))
					fp.write('\t\t\t\t\tresultSet["result"] = True\n')
					fp.write('\t\t\t\t\tresultSet["accept"] = True\n')
					if list_of_stages[i]['reply']!="":
						try:
							start_pos = list_of_stages[i]['rpl_position']
							if list_of_stages[i]['reply'].find('\\x')!=-1:
								stop_pos = int(start_pos) + int(list_of_stages[i]['reply'].count('\\x'))
							else:
								stop_pos = int(start_pos) + len(list_of_stages[i]['reply'])
							fp.write('\t\t\t\t\tself.reply[%s:%i] = "%s"\n' % (start_pos, stop_pos, list_of_stages[i]['reply']))
							fp.write('\t\t\t\t\tresultSet["reply"] = "".join(self.reply)\n')
						except:
							print "no position"
							fp.write('\t\t\t\t\tself.reply = "%s"\n' % (list_of_stages[i]['reply']))
							fp.write('\t\t\t\t\tresultSet["reply"] = self.reply\n')
							#sys.exit(1)
					else:
						fp.write('\t\t\t\t\tresultSet["reply"] = "".join(self.reply)\n')
					if i == number_of_stages:
						wr_st = "SHELLCODE"
					else:
						wr_st = "%s_STAGE%i" % (self.v_name, i+1)
					fp.write('\t\t\t\t\tself.stage = "%s"\n' % (wr_st))
					fp.write('\t\t\t\t\treturn resultSet\n')
				else:
					fp.write('\t\t\t\tresultSet["result"] = True\n')
					fp.write('\t\t\t\tresultSet["accept"] = True\n')
					if list_of_stages[i]['reply']!="":
						try:
							start_pos = list_of_stages[i]['rpl_position']
							if list_of_stages[i]['reply'].find('\\x')!=-1:
								stop_pos = int(start_pos) + int(list_of_stages[i]['reply'].count('\\x'))
							else:
								stop_pos = int(start_pos) + len(list_of_stages[i]['reply'])
							fp.write('\t\t\t\tself.reply[%s:%i] = "%s"\n' % (start_pos, stop_pos, list_of_stages[i]['reply']))
							fp.write('\t\t\t\tresultSet["reply"] = "".join(self.reply)\n')
						except:
							print "no position"
							fp.write('\t\t\t\t\tself.reply = "%s"\n' % (list_of_stages[i]['reply']))
							fp.write('\t\t\t\t\tresultSet["reply"] = self.reply\n')
							#sys.exit(1)
					else:
						fp.write('\t\t\t\tresultSet["reply"] = "".join(self.reply)\n')
					if i == number_of_stages:
						wr_st = "SHELLCODE"
					else:
						wr_st = "%s_STAGE%i" % (self.v_name, i+1)
					fp.write('\t\t\t\tself.stage = "%s"\n' % (wr_st))
					fp.write('\t\t\t\treturn resultSet\n')
			except KeyError, e:
				print "default stage: %s" % (e)
				if i == 1:
					fp.write('\t\t\tif self.stage == "%s_STAGE%i":\n' % (self.v_name, i))
				else:
					fp.write('\t\t\telif self.stage == "%s_STAGE%i":\n' % (self.v_name, i))
				fp.write('\t\t\t\tresultSet["result"] = True\n')
				fp.write('\t\t\t\tresultSet["accept"] = True\n')
				fp.write('\t\t\t\tresultSet["reply"] = "".join(self.reply)\n')
				if i == number_of_stages:
					wr_st = "SHELLCODE"
				else:
					wr_st = "%s_STAGE%i" % (self.v_name, i+1)
				fp.write('\t\t\t\tself.stage = "%s"\n' % (wr_st))
				fp.write('\t\t\t\treturn resultSet\n')
		fp.close()

	def write_shellcode_stage(self):
		fp = open(self.module_name, 'a+')
		number_of_stages = int(self.vdict['num_stages'])
		print "Number of stages %i" % (number_of_stages)
		if number_of_stages<=0:
			fp.write('\t\t\tif self.stage == "SHELLCODE":\n')
		else:
			fp.write('\t\t\telif self.stage == "SHELLCODE":\n')
		fp.write('\t\t\t\tif bytes>0:\n')
		fp.write('\t\t\t\t\tresultSet["result"] = True\n')
		fp.write('\t\t\t\t\tresultSet["accept"] = True\n')
		fp.write('\t\t\t\t\tresultSet["reply"] = "".join(self.reply)\n')
		fp.write('\t\t\t\t\tself.shellcode.append(message)\n')
		fp.write('\t\t\t\t\tself.stage = "SHELLCODE"\n')
		fp.write('\t\t\t\t\treturn resultSet\n')
		fp.write('\t\t\t\telse:\n')
		fp.write('\t\t\t\t\tresultSet["result"] = False\n')
		fp.write('\t\t\t\t\tresultSet["accept"] = True\n')
		fp.write('\t\t\t\t\tresultSet["reply"] = "None"\n')
		fp.write('\t\t\t\t\tself.shellcode.append(message)\n')
		fp.write('\t\t\t\t\tresultSet["shellcode"] = "".join(self.shellcode)\n')
		fp.write('\t\t\t\t\treturn resultSet\n')
		fp.write('\t\t\telse:\n')
		fp.write('\t\t\t\tresultSet["result"] = False\n')
		fp.write('\t\t\t\tresultSet["accept"] = False\n')
		fp.write('\t\t\t\tresultSet["reply"] = "None"\n')
		fp.write('\t\t\t\treturn resultSet\n')
		fp.write('\t\t\treturn resultSet\n')
		fp.write('\t\texcept KeyboardInterrupt:\n')
		fp.write('\t\t\traise\n')
		fp.write('\t\texcept StandardError, e:\n')
		fp.write('\t\t\tprint e\n')
		fp.write('\t\t\tf = StringIO.StringIO()\n')
		fp.write('\t\t\ttraceback.print_exc(file=f)\n')
		fp.write('\t\t\tprint f.getvalue()\n')
		fp.write('\t\t\tsys.exit(1)\n')
		fp.write('\t\texcept:\n')
		fp.write('\t\t\tprint "%s fatal error"\n' % (self.v_name))
		fp.close()


def readOptions():
	usage = """
	%prog -f filename
	"""

	parser = optparse.OptionParser(usage=usage, version = "%prog v"+__version__)

	parser.add_option("-f", "--file",
			action="store", type="string", dest="filename", default=None,
			help="build vulnerability from xml file")

	return parser.parse_args()

if __name__ == '__main__':
	(opts, args) = readOptions()
	if opts.filename:
		file = open(opts.filename, 'r')
		parser = make_parser()
		parser.setFeature(feature_namespaces, 0)
		dh = createVuln()
		parser.setContentHandler(dh)
		parser.parse(file)
		file.close()
		obj = constructFile(vuln_dict)
	else:
		print "no/wrong options read help (-h)"
