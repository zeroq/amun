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
import syslog


class log:
	def __init__(self):
		try:
			self.log_name = "Log Syslog"
		except KeyboardInterrupt:
			raise

	def initialConnection(self, attackerIP, attackerPort, victimIP, victimPort, identifier, initialConnectionsDict, loLogger):
		pass

	def incoming(self, attackerIP, attackerPort, victimIP, victimPort, vulnName, timestamp, downloadMethod, loLogger, attackerID, shellcodeName):
		try:
			self.log_obj = amun_logging.amun_logging("log_syslog", loLogger)
			syslog_message = "Exploit: %s -> %s:%s %s (%s)" % (attackerIP,victimIP,victimPort,vulnName,downloadMethod)
			syslog.openlog('Amun',syslog.LOG_PID,syslog.LOG_LOCAL4)
			syslog.syslog(syslog.LOG_WARNING, syslog_message)
			syslog.closelog()
		except KeyboardInterrupt:
			raise

	def successfullSubmission(self, attackerIP, attackerPort, victimIP, downloadURL, md5hash, data, filelength, downMethod, loLogger, vulnName, fexists):
		pass
