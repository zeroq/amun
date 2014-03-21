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

import time
import amun_logging
import sha
import socket

class log(object):
	__slots__ = ("log_name", "log_obj")

	def __init__(self):
		try:
			self.log_name = "Log Blast-o-Mat"
		except KeyboardInterrupt:
			raise

	def initialConnection(self, attackerIP, attackerPort, victimIP, victimPort, identifier, initialConnectionsDict, loLogger):
		pass

	def incoming(self, attackerIP, attackerPort, victimIP, victimPort, vulnName, timestamp, downloadMethod, loLogger, attackerID, shellcodeName):
		try:
			if shellcodeName=="None":
				return
			self.log_obj = amun_logging.amun_logging("log_blastomat", loLogger)
			tstart = timestamp
			tend = timestamp
			proceed = "Kick"
			type = "Exploit"
			secret = "testing"
			blastHost = "127.0.0.1"
			blastPort = 12345

			mess = "%s%s%s%s%s%s" % (type,attackerIP,tstart,tend,proceed,secret)
			shahash = sha.sha(mess).hexdigest()

			message = '<?xml version="1.0" encoding="UTF-8"?>'
			message += '<!DOCTYPE BlastEvent SYSTEM "xmlblast.dtd">'
			message += '<BlastEvent>'
			message += '<Type>%s</Type>' % (type)
			message += '<IP>%s</IP>' % (attackerIP)
			message += '<TStart>%s</TStart>' % (tstart)
			message += '<TEnd>%s</TEnd>' % (tend)
			message += '<Proceed>%s</Proceed>' % (proceed)
			message += '<Ports>%s</Ports>' % (victimPort)
			message += '<Module>%s</Module>' % (vulnName)
			message += '<Hash>%s</Hash>' % (shahash)
			message += '</BlastEvent>'

			addr = (blastHost, blastPort)
			UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			if(UDPSock.sendto(message,addr)):
				self.log_obj.log("blast-o-mat message for %s send (%s)" % (attackerIP,shellcodeName), 12, "crit", Log=True, display=True)
			else:
				self.log_obj.log("failed sending message to blast-o-mat", 12, "crit", Log=True, display=False)
			UDPSock.close()
			self.log_obj.log("blast-o-mat: %s" % (message), 12, "crit", Log=True, display=False)
		except KeyboardInterrupt:
			raise

	def successfullSubmission(self, attackerIP, attackerPort, victimIP, downloadURL, md5hash, data, filelength, downMethod, loLogger, vulnName, fexists):
		pass
