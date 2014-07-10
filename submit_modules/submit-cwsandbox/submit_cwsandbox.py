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

import httplib
import mimetypes
import urlparse
import socket

import re

class submit(object):
	__slots__ = ("submit_name", "reportToEmail", "cwsandboxURL", "resultRex", "resultRex2", "log_obj" )

	def __init__(self):
		try:
			self.submit_name = "Submit CWSandbox"
			self.resultRex = re.compile('page=samdet.*?>(.*?)</a>', re.S)
			self.resultRex2 = re.compile('href=".(page=details.*?)">.*?</a>', re.S)
			conffile = "conf/submit-cwsandbox.conf"
			config = amun_config_parser.AmunConfigParser(conffile)
			self.reportToEmail = config.getSingleValue("reportToEmail")
			self.cwsandboxURL = config.getSingleValue("cwsandboxURL")
			del config
		except KeyboardInterrupt:
			raise

	def incoming(self, file_data, file_data_length, downMethod, attIP, victimIP, smLogger, md5hash, attackedPort, vulnName, downURL, fexists):
		try:
			self.log_obj = amun_logging.amun_logging("submit_cwsandbox", smLogger)
			### check if already stored to disc than do not submit
			if not fexists:
				### submit to CWSandbox for analysis
				fields = []
				fields.append( ("email", self.reportToEmail) )

				filename = "amun-%s.exe" % (md5hash)
				files = []
				files.append( ("upfile", filename, file_data) )

				(status, reason, response) = self.httprequest(fields, files)

				if (status == 200 and reason != "DEFAULT"):
					self.log_obj.log("submit cwsandbox successfull", 12, "div", Log=False, display=True)
					self.log_obj.log("cwsandbox result: %s" % (response), 12, "div", Log=True, display=False)
					#resultURL = self.evaluateReply(response)
					#if len(resultURL)>0:
					#	self.log_obj.log("cwsandbox result: %s" % (resultURL), 12, "div", Log=True, display=False)
					#else:
					#	self.log_obj.log("cwsandbox result url not found: %s" % (response), 12, "div", Log=True, display=True)
				else:
					self.log_obj.log("could not submit sample to cwsandbox: %s %s" % (status, reason), 12, "crit", Log=True, display=True)
		except KeyboardInterrupt:
			raise
		except StandardError, e:
			self.log_obj.log("could not submit sample to cwsandbox: %s" % (e), 12, "crit", Log=True, display=True)
		except Exception:
			self.log_obj.log("could not submit sample to cwsandbox", 12, "crit", Log=True, display=True)
			import traceback
			import sys
			import StringIO
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
			sys.exit(1)

	def httprequest(self, fields, files):
		if not self.cwsandboxURL.startswith("http://"):
			raise Exception("Invalid URL, only http:// URLs are allowed: url='%s'" % (self.cwsandboxURL))
		if  not fields or not files:
			raise Exception("Invalid/No POST data supplied: fields='%s' files='%s'" % (fields, files))
		(scheme, netloc, path, parameters, query, fragment) = urlparse.urlparse(self.cwsandboxURL)
		content_type, body = self.encode_multipart_formdata(fields, files)

		h = httplib.HTTPConnection(netloc)
		headers = {
			'User-Agent': 'Internet Explorer',
			'Content-Type': content_type
		}
		try:
			h.request('POST', path+'?'+query, body, headers)
			#currentTimeout = socket.gettimeout()
			#socket.settimeout(5.0)
			res = h.getresponse()
		except:
			#socket.settimeout(currentTimeout)
			return "404", "time out", "time out"
		#socket.settimeout(currentTimeout)
		return res.status, res.reason, res.read()

	def encode_multipart_formdata(self, fields, files):
		boundaryLine = '----------boundary_$'
		linebreak = '\r\n'
		postdata = []
		for (key, value) in fields:
			postdata.append('--' + boundaryLine)
			postdata.append('Content-Disposition: form-data; name="%s"' % key)
			postdata.append('')
			postdata.append(value)
		for (key, filename, value) in files:
			postdata.append('--' + boundaryLine)
			postdata.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
			postdata.append('Content-Type: %s' % self.get_content_type(filename))
			postdata.append('')
			postdata.append(value)
		postdata.append('--' + boundaryLine + '--')
		postdata.append('')
		body = linebreak.join(postdata)
		content_type = 'multipart/form-data; boundary=%s' % boundaryLine
		return content_type, body

	def get_content_type(self, filename):
		return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

	def evaluateReply(self, response):
		match = self.resultRex.search(response)
		if match:
			url =  match.groups()[0]
			return "http://"+url.replace("&amp;","&")
		match = self.resultRex2.search(response)
		if match:
			url = match.groups()[0]
			return "http://mwanalysis.org/?"+url.replace("&amp;", "&")
		return ""

