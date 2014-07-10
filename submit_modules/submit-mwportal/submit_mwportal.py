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
    __slots__ = ("submit_name", "token", "mwportalURL", "log_obj" )

    def __init__(self):
        try:
            self.submit_name = "Submit MWPortal"
            conffile = "conf/submit-mwportal.conf"
            config = amun_config_parser.AmunConfigParser(conffile)
            self.token = config.getSingleValue("token")
            self.mwportalURL = config.getSingleValue("mwportalURL")
            del config
        except KeyboardInterrupt:
            raise Exception("KeyboardError")

    def incoming(self, file_data, file_data_length, downMethod, attIP, victimIP, smLogger, md5hash, attackedPort, vulnName, downURL, fexists):
        try:
            self.log_obj = amun_logging.amun_logging("submit_mwportal", smLogger)
            ### check if already stored to disc than do not submit
            if not fexists:
                ### submit to MWPortal for analysis
                filename = "amun-%s.exe" % (md5hash)
                files = []
                files.append( ("fileselect", filename, file_data) )

                (status, reason, response) = self.httprequest(files)

                if (status == 200 and reason != "DEFAULT"):
                    self.log_obj.log("submit mwportal successfull", 12, "div", Log=False, display=True)
                    #self.log_obj.log("mwportal result: %s" % (response), 12, "div", Log=True, display=False)
                else:
                    self.log_obj.log("could not submit sample to mwportal: %s %s (%s)" % (status, reason, response), 12, "crit", Log=True, display=True)
        except KeyboardInterrupt:
            raise Exception("KeyboardError")
        except StandardError as e:
            self.log_obj.log("could not submit sample to mwportal: %s" % (e), 12, "crit", Log=True, display=True)
        except:
            self.log_obj.log("could not submit sample to mwportal", 12, "crit", Log=True, display=True)
            import traceback
            import sys
            import StringIO
            f = StringIO.StringIO()
            traceback.print_exc(file=f)
            print f.getvalue()
            sys.exit(1)

    def httprequest(self, files):
        if not self.mwportalURL.startswith("http://"):
            raise Exception("Invalid URL, only http:// URLs are allowed: url='%s'" % (self.mwportalURL))
        if not files:
            raise Exception("Invalid/No POST data supplied: files='%s'" % (files))
        (scheme, netloc, path, parameters, query, fragment) = urlparse.urlparse(self.mwportalURL)
        content_type, body = self.encode_multipart_formdata(files)

        h = httplib.HTTPConnection(netloc)
        headers = {
            'User-Agent': 'Internet Explorer',
            'Content-Type': content_type
        }


        try:
            if not path.endswith('/'):
                path += '/'
            h.request('POST', path+self.token+'/upload', body, headers)
            res = h.getresponse()
        except StandardError as e:
            return "404", "time out", "time out"
        return res.status, res.reason, res.read()

    def encode_multipart_formdata(self, files):
        boundaryLine = '----------boundary_$'
        linebreak = '\r\n'
        postdata = []
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
