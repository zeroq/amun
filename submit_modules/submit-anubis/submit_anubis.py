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

import amun_logging
import amun_config_parser

from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.MIMEBase import MIMEBase

import httplib
import urlparse
import socket

class submit(object):
	__slots__ = ("submit_name", "reportToEmail", "anubisURL", "anubisResultURL", "alwaysLog", "log_obj")

	def __init__(self):
		try:
			self.submit_name = "Submit Anubis"
			conffile = "conf/submit-anubis.conf"
			config = amun_config_parser.AmunConfigParser(conffile)
			self.reportToEmail = config.getSingleValue("reportToEmail")
			self.anubisURL = config.getSingleValue("anubisURL")
			self.anubisResultURL = config.getSingleValue("anubisResultURL")
			self.alwaysLog = config.getSingleValue("alwaysLog")
			del config
		except KeyboardInterrupt:
			raise

	def incoming(self, file_data, file_data_length, downMethod, attIP, victimIP, smLogger, md5hash, attackedPort, vulnName, downURL, fexists):
		try:
			self.log_obj = amun_logging.amun_logging("submit_anubis", smLogger)
			### check if already stored to disc than do not submit
			if not fexists:
				### submit to anubis for analysis
				postdata = {}
				if self.reportToEmail!='None':
					postdata["notification"] = "email"
					postdata["email"] = self.reportToEmail
				else:
					postdata["notification"] = "browser"
					postdata["email"] = ""
				filename = "amun-%s.exe" % (md5hash)
				postdata['analysisType'] = "file"
				postdata["executable"] = {"content" : file_data, "filename" : filename}

				response = self.httprequest(postdata)

				if (response.status == 200 and response.getheader("taskid", "DEFAULT") != "DEFAULT"):
					self.log_obj.log("submit anubis successfull", 12, "div", Log=False, display=True)
					if postdata["notification"] == "browser" or self.alwaysLog:
						self.log_obj.log("anubis result: %s&task_id=%s" % (self.anubisResultURL, response.getheader('taskid')), 12, "div", Log=True, display=False)
				else:
					self.log_obj.log("could not submit sample to anubis: %s %s" % (response.status, response.getheader("taskid", "DEFAULT")), 12, "crit", Log=True, display=True)
		except KeyboardInterrupt:
			raise
		except StandardError, e:
			self.log_obj.log("could not submit sample to anubis: %s" % (e), 12, "crit", Log=True, display=True)
		except Exception:
			self.log_obj.log("could not submit sample to anubis", 12, "crit", Log=True, display=True)
			import traceback
			import sys
			import StringIO
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
			sys.exit(1)

	def httprequest(self, postdata):
		if not self.anubisURL.startswith("http://"):
			raise Exception("Invalid URL, only http:// URLs are allowed: url='%s'" % (self.anubisURL))
		if  not postdata:
			raise Exception("Invalid/No POST data supplied: postdata='%s'" % (postdata))

		headers = {}
		headers["Content-Type"] = "multipart/form-data"
		message = MIMEMultipart(_subtype="form-data")
		### notification element
		part = MIMEText(None)
		part.set_payload(postdata["notification"], "us-ascii")
		part.add_header("Content-Disposition", "form-data", name="notification")
		message.attach(part)
		### email element
		part = MIMEText(None)
		part.set_payload(postdata["email"], "us-ascii")
		part.add_header("Content-Disposition", "form-data", name="email")
		message.attach(part)
		### type element
		part = MIMEText(None)
		part.set_payload(postdata["analysisType"], "us-ascii")
		part.add_header("Content-Disposition", "form-data", name="analysisType")
		message.attach(part)
		### file data element
		part = MIMEBase('application', "octet-stream")
		part.set_payload(postdata['executable']['content'])
		### Add content-disposition header.
		dispHeaders = postdata["executable"].get("headers", {})
		part.add_header("Content-Disposition", "form-data", name="executable", filename=postdata["executable"]["filename"])
		for dhName, dhValue in dispHeaders:
			part.add_header(dhName, dhValue)
		message.attach(part)
		message.epilogue = ""
		headerBlock, body = message.as_string().split("\n\n",1)
		for hName, hValue in message.items():
			headers[hName] = hValue
		### Make the HTTP request and get the response.
		### Precondition: 'url', 'method', 'headers', 'body' are all setup properly.
		scheme, netloc, path, parameters, query, fragment = urlparse.urlparse(self.anubisURL)
		if parameters or query or fragment:
			raise Exception("Unexpected URL: parameters=%r, query=%r, fragment=%r" % (parameters, query, fragment))
		try:
			conn = httplib.HTTPConnection(netloc)
			conn.request("POST", path, body, headers)
			response = conn.getresponse()
		except socket.error, e:
			response = ConnRes(404, e)
		return response

class ConnRes(object):
	__slots__ = ("status", "msg")

	def __init__(self, status, msg):
		self.status = status
		self.msg = msg

	def getheader(self, taskid, defaults):
		return "%s" % (self.msg)
