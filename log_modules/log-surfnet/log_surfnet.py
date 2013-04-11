"""
[Amun - low interaction honeypot]
Copyright (C) [2013]  [Jan Goebel]

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
import amun_config_parser
import psycopg2
from re import escape

class log:
	def __init__(self):
		try:
			self.log_name = "Log SurfNet"
			conffile = "conf/log-surfnet.conf"

			self.AS_POSSIBLE_MALICIOUS_CONNECTION = 0
			self.AS_DEFINITLY_MALICIOUS_CONNECTION = 1
			self.AS_DOWNLOAD_OFFER = 16
			self.AS_DOWNLOAD_SUCCESS = 32

			self.DT_DIALOGUE_NAME = 1
			self.DT_SHELLCODEHANDLER_NAME = 2

			self.ATYPE = 4

			config = amun_config_parser.AmunConfigParser(conffile)
			self.sensorIP = config.getSingleValue("sensorIP")
			self.pghost = config.getSingleValue("PGHost")
			self.pgport = int(config.getSingleValue("PGPort"))
			self.pguser = config.getSingleValue("PGUser")
			self.pgpass = config.getSingleValue("PGPass")
			self.pgdb = config.getSingleValue("PGDB")
			self.conn = psycopg2.connect("dbname='%s' user='%s' host='%s' password='%s' port=%s" % (self.pgdb,self.pguser,self.pghost,self.pgpass, self.pgport))
			self.cur = self.conn.cursor()
			del config
		except KeyboardInterrupt:
			raise

	def __del__(self):
		try:
			self.conn.close()
			self.cur.close()
		except:
			pass

	def initialConnection(self, attackerIP, attackerPort, victimIP, victimPort, identifier, initialConnectionsDict, loLogger):
		""" log incoming initial connections """
		# query = "SELECT surfnet_attack_add('%s','%s','%s','%s','%s',NULL,'%s');" % (self.AS_POSSIBLE_MALICIOUS_CONNECTION, attackerIP, attackerPort, victimIP, victimPort, victimIP)
		query = "SELECT surfids3_attack_add('%s','%s','%s','%s','%s',NULL,'%s');" % (self.AS_POSSIBLE_MALICIOUS_CONNECTION, attackerIP, attackerPort, victimIP, victimPort, self.ATYPE)
		if self.conn!=None and not self.conn.closed:
			try:
				self.conn.set_isolation_level(0)
				self.cur.execute(query)
				result = self.cur.fetchall()
				attackerID = result[0][0]
			except:
				attackerID = None
		else:
			try:
				self.conn = psycopg2.connect("dbname='%s' user='%s' host='%s' password='%s'" % (self.pgdb,self.pguser,self.pghost,self.pgpass))
				self.conn.set_isolation_level(0)
				self.cur = self.conn.cursor()
				self.cur.execute(query)
				result = self.cur.fetchall()
				attackerID = result[0][0]
			except:
				attackerID = None
		### the attackID in the socket list
		if initialConnectionsDict.has_key(identifier) and attackerID!=None:
			initialConnectionsDict[identifier][4] = attackerID

	def incoming(self, attackerIP, attackerPort, victimIP, victimPort, vulnName, timestamp, downloadMethod, loLogger, attackerID, shellcodeName):
		""" log successfull exploit and download offer """
		if self.conn!=None and not self.conn.closed:
			try:
				self.conn.set_isolation_level(0)
				# query = "SELECT surfnet_attack_add('%s','%s','%s','%s','%s',NULL,'%s');" % (self.AS_DEFINITLY_MALICIOUS_CONNECTION, attackerIP, attackerPort, victimIP, victimPort, victimIP)
				query = "SELECT surfids3_attack_add('%s','%s','%s','%s','%s',NULL,'%s');" % (self.AS_DEFINITLY_MALICIOUS_CONNECTION, attackerIP, attackerPort, victimIP, victimPort, self.ATYPE)
				self.cur.execute(query)
				result = self.cur.fetchall()
				attackerID = result[0][0]
				if attackerID:
					if vulnName != None:
						# query1 = "SELECT surfnet_detail_add('%s','%s','%s','%s')" % (attackerID, victimIP, self.DT_DIALOGUE_NAME, vulnName)
						query1 = "SELECT surfids3_detail_add('%s','%s','%s','%s')" % (attackerID, victimIP, self.DT_DIALOGUE_NAME, vulnName)
						self.cur.execute(query1)

					if shellcodeName != None:
						# query3 = "SELECT surfnet_detail_add('%s','%s','%s','%s')" % (attackerID, victimIP, self.DT_SHELLCODEHANDLER_NAME, shellcodeName)
						query3 = "SELECT surfids3_detail_add('%s','%s','%s','%s')" % (attackerID, victimIP, self.DT_SHELLCODEHANDLER_NAME, shellcodeName)
						self.cur.execute(query3)

					if downloadMethod != None:
						# query4 = "SELECT surfnet_detail_add_offer('%s','%s','%s')" % (attackerIP, victimIP, downloadMethod)
						query4 = "SELECT surfids3_detail_add_offer('%s','%s','%s','%s')" % (attackerIP, victimIP, downloadMethod, self.ATYPE)
						self.cur.execute(query4)

			except:
				pass
		else:
			try:
				self.conn = psycopg2.connect("dbname='%s' user='%s' host='%s' password='%s'" % (self.pgdb,self.pguser,self.pghost,self.pgpass))
				# query = "SELECT surfnet_attack_add('%s','%s','%s','%s','%s',NULL,'%s');" % (self.AS_DEFINITLY_MALICIOUS_CONNECTION, attackerIP, attackerPort, victimIP, victimPort, victimIP)
				query = "SELECT surfids3_attack_add('%s','%s','%s','%s','%s',NULL,'%s');" % (self.AS_DEFINITLY_MALICIOUS_CONNECTION, attackerIP, attackerPort, victimIP, victimPort, self.ATYPE)
				self.cur.execute(query)
				result = self.cur.fetchall()
				attackerID = result[0][0]
				if attackerID:
					if vulnName != None:
						# query1 = "SELECT surfnet_detail_add('%s','%s','%s','%s')" % (attackerID, victimIP, self.DT_DIALOGUE_NAME, vulnName)
						query1 = "SELECT surfids3_detail_add('%s','%s','%s','%s')" % (attackerID, victimIP, self.DT_DIALOGUE_NAME, vulnName)
						self.cur.execute(query1)

					if shellcodeName != None:
						# query3 = "SELECT surfnet_detail_add('%s','%s','%s','%s')" % (attackerID, victimIP, self.DT_SHELLCODEHANDLER_NAME, shellcodeName)
						query3 = "SELECT surfids3_detail_add('%s','%s','%s','%s')" % (attackerID, victimIP, self.DT_SHELLCODEHANDLER_NAME, shellcodeName)
						self.cur.execute(query3)

					if downloadMethod != None:
						# query4 = "SELECT surfnet_detail_add_offer('%s','%s','%s')" % (attackerIP, victimIP, downloadMethod)
						query4 = "SELECT surfids3_detail_add_offer('%s','%s','%s','%s')" % (attackerIP, victimIP, downloadMethod, self.ATYPE)
						self.cur.execute(query4)
			except:
				pass

	def successfullSubmission(self, attackerIP, attackerPort, victimIP, downloadURL, md5hash, data, filelength, downMethod, loLogger, vulnName, fexists):
		""" log successfull download """
		# query = "SELECT surfnet_detail_add_download('%s','%s','%s','%s')" % (attackerIP, victimIP, escape(downloadURL), md5hash)
		query = "SELECT surfids3_detail_add_download('%s','%s','%s','%s','%s')" % (attackerIP, victimIP, escape(downloadURL), md5hash, self.ATYPE)
		if self.conn!=None and not self.conn.closed:
			try:
				self.conn.set_isolation_level(0)
				self.cur.execute(query)
			except:
				pass
		else:
			try:
				self.conn = psycopg2.connect("dbname='%s' user='%s' host='%s' password='%s'" % (self.pgdb,self.pguser,self.pghost,self.pgpass))
				self.conn.set_isolation_level(0)
				self.cur = self.conn.cursor()
				self.cur.execute(query)
			except:
				pass
		pass
