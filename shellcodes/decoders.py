"""
[Amun - low interaction honeypot]
Copyright (C) [2014]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

### collection of known shellcode decoders

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import re

class decoders:
	def __init__(self):
		self.decodersDict = {}

		### CheckIP
		self.log("compiling CheckIP Expression", 0, "info")
		self.decodersDict['checkIP'] = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

		### MZ Header
		self.log("compiling MZ header detection", 0, "info")
		self.decodersDict['directfile'] = re.compile('^MZ.*?This program cannot be run in DOS mode')

		### HTTP/HTTPS/FTP
		self.log("compiling URL decoder", 0, "info")
		self.decodersDict['url'] = re.compile('((https?|ftp):((\/\/)|(\\\\))+[\d\w:@\/()~_?\+\-=\\\.&]*)')

		### TFTP 1
		self.log("compiling TFTP 1 decoder", 0, "info")
		self.decodersDict['tftp1'] = re.compile("tftp(\.exe)?\s*(\-i)?\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*(GET).*?&\s*(\S*?\.exe)|tftp(\.exe)?\s*(\-i)?\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*(GET).*?\s*(\S*?\.exe)", re.S|re.I)

		### TFTP 2
		self.log("compiling TFTP decoder", 0, "info")
		self.decodersDict['tftp'] = re.compile('.*(tftp(.exe)? -i) ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) (get) (.*?\.(exe|com)).*', re.S|re.I)

		### FTP cmd
		self.log("compiling Windows CMD FTP 1", 0, "info")
		self.decodersDict['ftpcmd'] = re.compile('.*cmd /[c|k].*echo open ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-z0-9\.]*) ([0-9]+).*[>|>>]\s*.+&echo user (.*?) (.*?) >>.*&echo get (.*?) >>.*', re.S|re.I)

		### FTP command 2
		self.log("compiling Windows CMD FTP 2", 0, "info")
		self.decodersDict['ftpcmd2'] = re.compile('.*echo open ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-z0-9\.]+).([0-9]+)?>>.*?echo (.*?)>>.*?echo (.*?)>>.*?(.*?get (.*?)>>).*?(.*?get (.*?)>>)?.*?(.*?get (.*?)>>)?', re.S|re.I)

		### FTP command 3
		self.log("compiling Windows CMD FTP 3", 0, "info")
		self.decodersDict['ftpcmd3ip'] = re.compile('(?:echo open|open|echo)\s*([@a-zA-Z0-9\-\/\\\.\+:]+)\s*([0-9]+)?.*', re.S|re.I)
		self.decodersDict['ftpcmd3userpass'] = re.compile('>.*?&echo user (.*?) (.*?)>>|>>.*?&echo (.*?)>>.*?&echo (.*?)&|.*?@echo (.*?)>>.*?@echo (.*?)>>|>.*?echo (.*?)>>.*?echo (.*?)>>', re.S|re.I)
		self.decodersDict['ftpcmd3binary'] = re.compile('echo m?get (.*?)>>', re.S|re.I)

		### FTP command 4
		self.log("compiling Windows CMD FTP 4", 0, "info")
		self.decodersDict['ftpcmd4'] = re.compile('echo ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})>.*?echo (.*?)>>.*?echo (.*?)>>.*?echo binary(.*?get (.*?)>>).*?(.*?get (.*?)>>)?.*?(.*?get (.*?)>>)?', re.S|re.I)

		### Unnamed Bindshell 1
		self.log("compiling bindshell1 pattern", 0, "info")
		self.decodersDict['bindshell1'] = re.compile('\\x58\\x99\\x89\\xe1\\xcd\\x80\\x96\\x43\\x52\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x6a\\x66\\x58\\x50\\x51\\x56', re.S)

		### Unnamed Bindshell 2
		self.log("compiling bindshell2 pattern", 0, "info")
		self.decodersDict['bindshell2'] = re.compile('\\x53\\x53\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95\\x68\\xa4\\x1a', re.S)

		### Unnamed Bindshell 3
		self.log("compiling bindshell3 pattern", 0, "info")
		self.decodersDict['bindshell3'] = re.compile('\\x89\\xc3\\x31\\xff\\x57\\x57\\x68\\x02\\x00(..)\\x89\\xe6\\x6a', re.S)

		### Unnamed Bindshell 4
		self.log("compiling bindshell4 pattern", 0, "info")
		self.decodersDict['bindshell4'] = re.compile('\\xc0\\x33\\xdb\\x50\\x50\\x50\\xb8\\x02\\x01(..)\\xfe\\xcc\\x50', re.S)

		### Unnamed Bindshell 5
		self.log("compiling bindshell5 pattern",0 , "info")
		self.decodersDict['bindshell5'] = re.compile('\\x89\\xc7\\x31\\xdb\\x53\\x68\\x02\\x00(..)\\x89\\xe6\\x6a', re.S)

		### Unnamed Bindshell 6
		self.log("compiling bindshell6 pattern",0 , "info")
		self.decodersDict['bindshell6'] = re.compile('\\xc0\\x50\\x50\\x50\\xb8\\x02\\xff(..)\\x80\\xf4\\xff\\x50', re.S)

		### Rothenburg Shellcode
		self.log("compiling rothenburg/schoenborn xor decoder", 0, "info")
		self.decodersDict['rothenburg'] = re.compile('\\xd9\\x74\\x24\\xf4\\x5b\\x81\\x73\\x13(.)(.)(.)(.)\\x83\\xeb\\xfc\\xe2\\xf4', re.S)
		self.decodersDict['rothenburg_bindport'] = re.compile('\\x53\\x53\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1', re.S)
		self.decodersDict['rothenburg_bindport2'] = re.compile('\\x96\\x43\\x52\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x6a', re.S)
		### Schoenborn Shellcode
		self.decodersDict['schoenborn_bindport'] = re.compile('\\x89\\xc7\\x31\\xdb\\x53\\x68\\x02\\x00(..)\\x89\\xe6\\x6a', re.S)
		self.decodersDict['schoenborn_connback'] = re.compile('\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x68(....)\\x66\\x68(..)\\x66\\x53\\x89\\xe1', re.S)
		self.decodersDict['schoenborn_connback2'] = re.compile('\\xff\\xd5\\x89\\xc7\\x68(....)\\x68\\x02\\x00(..)\\x89\\xe6\\x6a', re.S)
		self.decodersDict['schoenborn_portopening'] = re.compile('firewall add portopening TCP (\d*) spools', re.S)

		### Aachen Shellcode
		self.log("compiling aachen xor decoder", 0, "info")
		self.decodersDict['aachen'] = re.compile('\\x8b\\x45\\x04\\x35(....)\\x89\\x45\\x04\\x66\\x8b\\x45\\x02\\x66\\x35(..)\\x66\\x89\\x45\\x02', re.S)
		self.decodersDict['aachen_connback'] = re.compile('\\x90\\xeb\\x25(..)(....)\\x02\\x06\\x6c', re.S)

		### Adenau Shellcode
		self.log("compiling adenau xor decoder", 0, "info")
		self.decodersDict['adenau'] = re.compile('\\xeb\\x19\\x5e\\x31\\xc9\\x81\\xe9....\\x81\\x36(.)(.)(.)(.)\\x81\\xee\\xfc\\xff\\xff\\xff', re.S)
		self.decodersDict['adenau_bindport'] = re.compile('\\x50\\x50\\x50\\x40\\x50\\x40\\x50\\xff\\x56\\x1c\\x8b\\xd8\\x57\\x57\\x68\\x02\\x00(..)\\x8b\\xcc\\x6a', re.S)

		### Heidelberg
		self.log("compiling heidelberg xor decoder", 0, "info")
		self.decodersDict['heidelberg'] = re.compile('\\x33\\xc9\\x66\\xb9..\\x80\\x34.(.)\\xe2.\\x42\\xff\\xe2\\xe8\\xea\\xff\\xff', re.S)

		### Mainz / Bielefeld Shellcode
		self.log("compiling mainz/bielefeld xor decoder", 0, "info")
		self.decodersDict['mainz'] = re.compile('\\x33\\xc9\\x66\\xb9..\\x80\\x34.(.)\\xe2.\\xeb\\x05\\xe8\\xeb\\xff\\xff\\xff', re.S)
		### bind 1
		self.decodersDict['mainz_bindport1'] = re.compile('\\x6a\\x01\\x6a\\x02\\xff\\x57\\xec\\x8b\\xd8\\xc7\\x07\\x02\\x00(..)\\x33\\xc0\\x89\\x47\\x04', re.S)
		### bind 2
		self.decodersDict['mainz_bindport2'] = re.compile('\\x6a\\x01\\x6a\\x02\\xff\\x57\\xec\\x8b\\xd8\\xc7\\x07\\x02\\x00(..)\\xc0\\x89\\x47\\x04', re.S)
		### bind 3
		self.decodersDict['mainz_bindport3'] = re.compile('\\x52\\x50\\xff\\x57\\xe8\\xc7\\x07\\x02\\x00(..).\\x47\\x04', re.S)
		### connback 1
		self.decodersDict['mainz_connback1'] = re.compile('\\xc7\\x02\\x63\\x6d\\x64\\x00\\x52\\x50\\xff\\x57\\xe8\\xc7\\x07\\x02\\x00(..)\\xc7\\x47\\x04(....)\\x6a\\x10\\x57\\x53\\xff\\x57\\xf8\\x53\\xff\\x57\\xfc\\x50\\xff\\x57\\xec', re.S)
		### connback 2
		self.decodersDict['mainz_connback2'] = re.compile('\\x50\\x50\\x50\\x40\\x50\\x40\\x50\\xff\\x56.\\x8b\\xd8\\x68(....)\\x68\\x02\\x00(..)\\x8b\\xcc\\x6a.\\x51\\x53', re.S)
		### connback 3
		self.decodersDict['mainz_connback3'] = re.compile('\\x50\\x50\\x8d\\x57\\x3c\\xc7\\x02....\\x52\\x50\\xff\\x57\\xe8\\xc7\\x07\\x02\\x00(..)\\xc7\\x47\\x04(....)\\x10\\x57.\\xff\\x57.\\x53\\xff\\x57.\\x50', re.S)

		### Wuerzburg Shellcode
		self.log("compiling wuerzburg xor decoder", 0, "info")
		self.decodersDict['wuerzburg'] = re.compile('\\xeb\\x27(..)(....)\\x5d\\x33\\xc9\\x66\\xb9..\\x8d\\x75\\x05\\x8b\\xfe\\x8a\\x06\\x3c.\\x75\\x05\\x46\\x8a\\x06..\\x46\\x34(.)\\x88\\x07\\x47\\xe2\\xed\\xeb\\x0a\\xe8\\xda\\xff\\xff\\xff', re.S)
		self.decodersDict['wuerzburg_file'] = re.compile('\\x00\\x50\\x00\\x50\\x2e(.*?)\\x00\\x50\\x00\\x50', re.S)

		### Schauenburg Shellcode
		self.log("compiling schauenburg xor decoder", 0, "info")
		self.decodersDict['schauenburg'] = re.compile('\\xeb\\x0f\\x8b\\x34\\x24\\x33\\xc9\\x80\\xc1.\\x80\\x36(.)\\x46\\xe2\\xfa\\xc3\\xe8\\xec', re.S)
		self.decodersDict['schauenburg_bindport'] = re.compile('\\xff\\xd0\\x93\\x6a.\\x68\\x02\\x00(..)\\x8b\\xc4\\x6a.\\x50\\x53', re.S)
		self.decodersDict['schauenburg_connback'] = re.compile('\\x00\\x57\\xff\\x16\\xff\\xd0\\x93\\x68(....)\\x68\\x02\\x00(..)\\x8b\\xc4\\x6a.\\x50\\x53', re.S)

		### Koeln Shellcode
		self.log("compiling koeln xor decoder", 0, "info")
		self.decodersDict['koeln'] = re.compile('\\xd9\\xee\\xd9\\x74\\x24\\xf4\\x5b\\x31\\xc9\\xb1.\\x81\\x73\\x17(.)(.)(.)(.)\\x83\\xeb.\\xe2', re.S)
		self.decodersDict['koeln_bindport'] = re.compile('\\x40\\x50\\x40\\x50\\xff\\x55.\\x89\\xc7\\x31\\xdb\\x53\\x53\\x68\\x02\\x00(..)\\x89\\xe0\\x6a.\\x50\\x57', re.S)

		### Lichtenfels Shellcode
		self.log("compiling lichtenfels xor decoder", 0, "info")
		self.decodersDict['lichtenfels'] = re.compile('\\x01\\xfc\\xff\\xff\\x83\\xe4\\xfc\\x8b\\xec\\x33\\xc9\\x66\\xb9..\\x80\\x30(.)\\x40\\xe2\\xfA', re.S)
		self.decodersDict['lichtenfels_connback'] = re.compile('\\x83\\xf8.\\x74.\\x8b\\xd8\\x66\\xc7\\x45...\\x66\\xc7\\x45\\x02(..)\\xc7\\x45\\x04(....)\\x6a.\\x55\\x53', re.S)

		### Mannheim Shellcode
		self.log("compiling mannheim xor decoder", 0, "info")
		self.decodersDict['mannheim'] = re.compile('\\x80\\x73\\x0e(.)\\x43\\xe2.*\\x73\\x73\\x73(.+)\\x81\\x86\\x8c\\x81', re.S)

		### Berlin Shellcode
		self.log("compiling berlin xor decorder", 0, "info")
		self.decodersDict['berlin'] = re.compile('\\x31\\xc9\\xb1\\xfc\\x80\\x73\\x0c(.)\\x43\\xe2.\\x8b\\x9f....\\xfc', re.S)

		### Leimbach Shellcode
		self.log("compiling leimbach xor decoder", 0, "info")
		self.decodersDict['leimbach'] = re.compile('\\x5b\\x31\\xc9\\xb1.\\x80\\x73.(.)\\x43\\xe2.[\\x21|\\x20][\\xd3|\\xd2][\\x77|\\x76]', re.S)

		### Alpha_Upper Metasploit
		self.log("compiling Metasploit Alpha_Upper", 0, "info")
		self.decodersDict['alphaupper'] = re.compile('(VTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJ(.*?)AA)', re.S)
		self.decodersDict['alphaupper2'] = re.compile('(VTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BXP8ACJJ(.*?)AA)', re.S)
		self.decodersDict['alphaupper_generic'] = re.compile('(VTX30VX4AP.*?BXP8ACJJ(.*?)AA)', re.S)
		self.decodersDict['alphaupper_bindport'] = re.compile('\\x31\\xdb\\x53\\x68\\x02\\x00(..)\\x89\\xe6\\x6a.\\x56\\x57\\x68', re.S)
		self.decodersDict['alphaupper_connback'] = re.compile('\\xff\\xd5\\x97\\x6a.\\x68(....)\\x68\\x02\\x00(..)\\x89\\xe6\\x6a', re.S)

		### PexAlphaNumeric Shellcode (Augsburg)
		self.log("compiling Metasploit PexAlphaNumeric", 0, "info")
		self.decodersDict['pexalphanum'] = re.compile('(VTX630VX4A0B6HH0B30BCVX2BDBH4A2AD0ADTBDQB0ADAVX4Z8BDJOM(.*)Z)', re.S)
		self.decodersDict['pexalphanum_bindport'] = re.compile('\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95\\x68\\xa4\\x1a\\x70\\xc7', re.S)

		### Base64Encoded PexAlphaNumeric Shellcode (Augsburg)
		self.log("compiling Base64Encoded PexAlphaNumeric", 0, "info")
		self.decodersDict['alphaNum'] = re.compile('LoadTestPassword: (.*)==rrr', re.S)

		### Base64Encoded PexAlphaNumeric Shellcode 2 (Augsburg)
		self.log("compiling Base64Encoded PexAlphaNumeric 2", 0, "info")
		self.decodersDict['alphaNum2'] = re.compile('LoadTestPassword: (.*)=rrr', re.S)

		### alpha2 zero-tolerance
		self.log("compiling alpha2 zero-tolerance", 0, "info")
		self.decodersDict['alpha2endchar'] = re.compile('\\x51\\x5a\\x6a(.)\\x58.(.*)', re.S)
		self.decodersDict['alpha2connback'] = re.compile('\\x53\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x68(....)\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95', re.S)
		self.decodersDict['alpha2bind'] = re.compile('\\x53\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95', re.S)

		### Lindau Shellcode
		self.log("compiling lindau (linkbot) xor decoder", 0, "info")
		self.decodersDict['linkbot'] = re.compile('\\xeb\\x15\\xb9....\\x81\\xf1.....\\x80\\x74\\x31\\xff(.)\\xe2\\xf9\\xeb\\x05\\xe8\\xe6\\xff\\xff\\xff', re.S)
		self.decodersDict['linkbot_connback'] = re.compile('\\x53\\x53\\x68(....)\\x68\\x02\\x00(..)\\x8b\\xd4\\x8b\\xd8\\x6a\\x10\\x52\\x53\\xba\\x63\\x30\\x60\\x5a\\xff\\xd6\\x50\\xb4\\x02\\x50\\x55\\x53\\xba\\x00\\x58\\x60\\xe2\\xff\\xd6\\xbf(....)\\xff\\xe5', re.S)
		self.decodersDict['linkbot_connback2'] = re.compile('\\x50\\x50\\x68(....)\\x68\\x02\\x00(..)\\x8b\\xfc\\x50\\x6a.\\x6a.\\xff\\x55.\\x8b\\xd8\\x6a.\\x57\\x53\\xff\\x55.\\x85\\xc0\\x75.\\xc7\\x45.....\\x50\\x6a.\\x55\\x53\\xff\\x55.\\x8b\\xf4\\xc7\\x45.....\\x68....\\x68(....)\\x8b\\xfc\\x55\\x57', re.S)
		self.decodersDict['linkbot_connback3'] = re.compile('\\x5e\\x5b\\xff\\xe0\\x5e\\x68(..)\\x00\\x00\\x68(....)\\x54\\xba(....)\\xff\\xd6', re.S)

		### Furth Shellcode
		self.log("compiling furth xor decoder", 0, "info")
		self.decodersDict['furth'] = re.compile('\\x5b\\x31\\xc9\\x66\\xb9..\\x80\\x73.(.)\\x43\\xe2..', re.S)

		### Duesseldorf Shellcode
		self.log("compiling duesseldorf xor decoder",0, "info")
		self.decodersDict['duesseldorf'] = re.compile('\\xd9\\x74..\\x5b\\x80\\x73.(.)\\x80\\x73.(.)\\x83..\\xe2.\\x78.\\x18', re.S)

		### Bergheim Shellcode
		self.log("compiling bergheim xor decoder",0, "info")
		self.decodersDict['bergheim'] = re.compile('\\x31\\xc9\\x66\\x81\\xe9..\\x80\\x33(.)\\x43\\xe2\\xfa', re.S)
		self.decodersDict['bergheim_connback'] = re.compile('\\x50\\xff\\xd6\\x66\\x53\\x66\\x68(..)\\x68(....)\\x54\\xff\\xd0\\x68', re.S)

		### Langenfeld Shellcode
		self.log("compiling langenfeld xor decoder",0, "info")
		self.decodersDict['langenfeld'] = re.compile('\\xeb\\x0f\\x5b\\x33\\xc9\\x66\\xb9..\\x80\\x33(.)\\x43\\xe2\\xfa\\xeb', re.S)
		self.decodersDict['langenfeld_connback'] = re.compile('\\x52\\x50\\xff..\\xc7\\x07\\x02\\x00(..)\\xc7\\x47.(....)\\x6a.\\x57\\x53\\xff', re.S)
		self.decodersDict['langenfeld_connback2'] = re.compile('\\x52\\x50\\xff..\\xc7\\x07\\x02\\x00(..)\\xc7\\x47.(....)\\xf4\\xf4\\xf4\\xf4', re.S)

		### Bonn Shellcode
		self.log("compiling bonn xor decoder",0, "info")
		self.decodersDict['bonn'] = re.compile('\\x31\\xc9\\x81\\xe9....\\x83\\xeb.\\x80\\x73.(.)\\x43\\xe2\\xf9', re.S)

		### Siegburg Shellcode
		self.log("compiling siegburg xor decoder", 0, "info")
		self.decodersDict['siegburg'] = re.compile('\\x31\\xeb\\x80\\xeb.\\x58\\x80\\x30(.)\\x40\\x81\\x38....\\x75.\\xeb', re.S)
		self.decodersDict['siegburg_bindshell'] = re.compile('\\x89\\xc7\\x31\\xdb\\x53\\x53\\x68\\x02\\x00(..)\\x89\\xe0\\x6a.\\x50\\x57', re.S)

		### Ulm Shellcode
		self.log("compiling ulm xor decoder", 0, "info")
		self.decodersDict['ulm'] = re.compile('\\xff\\xc0\\x5e\\x81\\x76\\x0e(.)(.)(.)(.)\\x83\\xee\\xfc', re.S)
		self.decodersDict['ulm_bindshell'] = re.compile('\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95', re.S)
		#self.decodersDict['ulm_bindshell2'] = re.compile('\\x89\\xc7\\x31\\xdb\\x53\\x68\\x02\\00(..)\\x89\\xe6\\x6a', re.S)
		self.decodersDict['ulm_bindshell2'] = re.compile('\\x31\\xdb\\x53\\x68\\x02\\00(..)\\x89\\xe6\\x6a', re.S)
		self.decodersDict['ulm_connback'] = re.compile('\\x6a.\\xff\\x55.\\x93\\x68(....)\\x68\\x02\\x00(..)\\x89\\xe2\\x6a.\\x6a.\\x6a', re.S)
		self.decodersDict['ulm_connback2'] = re.compile('\\xff\\xd5\\x97\\x6a\\x05\\x68(....)\\x68\\x02\\x00(..)\\x89\\xe6\\x6a.\\x56\\x57', re.S)

		### Conficker Shellcode
		self.log("compiling conficker xor decoder", 0, "info")
		self.decodersDict['conficker'] = re.compile('.\\x8d..\\x80\\x31(.)\\x41\\x66\\x81\\x39..\\x75\\xf5', re.S)

		### Plain1 Shellcode
		self.log("compiling plain1 shellcode", 0, "info")
		self.decodersDict['plain1'] = re.compile('\\x89\\xe1\\xcd.\\x5b\\x5d\\x52\\x66\\xbd(..)\\x0f\\xcd\\x09\\xdd\\x55\\x6a.\\x51\\x50', re.S)

		### Plain2 Shellcode
		self.log("compiling plain2 shellcode", 0, "info")
		self.decodersDict['plain2'] = re.compile('\\x50\\x50\\x50\\x50\\x40\\x50\\x40\\x50\\xff\\x56\\x1c\\x8b\\xd8\\x57\\x57\\x68\\x02(..)\\x8b\\xcc\\x6a.\\x51\\x53', re.S)

		### HTTP GET TFTP Command
		self.log("compiling http embedded tftp command", 0, "info")
		self.decodersDict['cmdtftp'] = re.compile('GET /scripts/.*?/cmd.exe.*?tftp.*?%20([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})%20GET%20(.*?)%20.*?HTTP/1\.')

	def getDecoders(self):
		return self.decodersDict

	def log(self, message, tabs=0, type="normal"):
		empty = ""
		for i in range(0, tabs):
			empty += " "

		if type=="debug":
			print "\033[0;34m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="warn":
			print "\033[0;33m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="info":
			print "\033[0;32m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="crit":
			print "\033[0;31m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="fade":
			print "\033[0;37m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="div":
			print "\033[0;36m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		else:
			print "\033[0m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
