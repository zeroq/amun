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
import smtplib
import amun_config_parser

class log:
	def __init__(self):
		try:
			self.log_name = "Log eMail"
			conffile = "conf/log-mail.conf"
			config = amun_config_parser.AmunConfigParser(conffile)
			self.smtpServer = config.getSingleValue("smtpServer")
			self.smtpPort = int(config.getSingleValue("smtpPort"))
			self.mailFrom = config.getSingleValue("mailFrom")
			self.mailReplyTo = config.getSingleValue("mailReplyTo")
			if self.mailReplyTo == "None":
				self.mailReplyTo = ""
			self.RecipientList = config.getSingleValue("recipientList").split(',')
			if self.RecipientList == "None":
				self.RecipientList = ""
			self.mailCCList = config.getSingleValue("mailCCList").split(',')
			if self.mailCCList == "None":
				self.mailCCList = ""
			self.mailBody = config.getSingleValue("mailBody").replace('\\n','\n').replace('\\t','\t')
			del config
		except KeyboardInterrupt:
			raise

	def initialConnection(self, attackerIP, attackerPort, victimIP, victimPort, identifier, initialConnectionsDict, loLogger):
		pass

	def incoming(self, attackerIP, attackerPort, victimIP, victimPort, vulnName, timestamp, downloadMethod, loLogger, attackerID, shellcodeName):
		try:
			self.log_obj = amun_logging.amun_logging("log_mail", loLogger)
			### construct message header
			### From, To, and Subject
			Subject = "Amun Exploit from: %s" % (attackerIP)
			RecipientRow = ",".join(self.RecipientList)
			MessageHeader = "From: %s\r\nTo: %s\r\nSubject: %s \r\n" % (self.mailFrom,RecipientRow,Subject)
			### If ReplyTo is set, add to header
			if self.mailReplyTo!="":
				MessageHeader += "ReplyTo: %s\r\n" % (self.mailReplyTo)
			if len(self.mailCCList)>0:
				MessageHeader += "CC: %s\r\n" % (",".join(self.mailCCList))
			### set character encoding
			charencode = "Content-Type: text/plain; charset=iso-8859-1"
			MessageHeader += "%s\r\n" % (charencode)
			### finalize Message Header
			MessageHeader += "\r\n"
			### eMail Body
			MailBody = self.mailBody
			ExploitLine = "\n\nTimestamp: %s\nExploit: %s:%s -> %s:%s %s (%s)" % (time.ctime(int(timestamp)),attackerIP,attackerPort,victimIP,victimPort,vulnName,downloadMethod)
			### construct final eMail
			Message = str(MessageHeader) + str(MailBody) + str(ExploitLine)
			### connect to mailserver and send email
			try:
				Server = smtplib.SMTP(self.smtpServer,int(self.smtpPort))
				Server.set_debuglevel(0)
				Server.sendmail(self.mailFrom, self.RecipientList, Message)
				Server.quit()
			except:
				self.log_obj.log("failed sending email message", 12, "crit", Log=True, display=True)
		except KeyboardInterrupt:
			raise

	def successfullSubmission(self, attackerIP, attackerPort, victimIP, downloadURL, md5hash, data, filelength, downMethod, loLogger, vulnName, fexists):
		pass
