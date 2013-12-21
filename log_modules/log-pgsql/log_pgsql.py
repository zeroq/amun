"""
[Amun - low interaction honeypot]
Copyright (C) [2008]  [Jan Goebel]

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
import MySQLdb
import base64

class log:
	def __init__(self):
		try:
			self.log_name = "Log pgSQL"
			conffile = "conf/log-pgsql.conf"
			config = amun_config_parser.AmunConfigParser(conffile)
			self.pgHost = config.getSingleValue("pgSQLHost")
			self.pgUser = config.getSingleValue("pgSQLUser")
			self.pgPass = config.getSingleValue("pgSQLPass")
			self.pgDB = config.getSingleValue("pgSQLDB")
			del config
		except KeyboardInterrupt:
			raise

	def connectDB(self, logger):
		try:
			self.db = psycopg2.connect("host='%s' dbname='%s' user='%s' password='%s'" % (self.pgHost, self.pgDB, self.pgUser, self.pgPass))
			self.cursor = self.db.cursor()
			return True
		except psycopg2.Error, e:
			logger.log("log-pgsql failed: %s" % (e), 12, "crit", Log=True, display=True)
			raise
		except KeyboardInterrupt:
			raise

	def closeDB(self, logger):
		try:
			self.db.close()
			try:
				self.cursor.close()
			except:
				pass
			return True
		except psycopg2.Error, e:
			logger.log("log-pgsql failed: %s" % (e), 12, "crit", Log=True, display=True)
			raise
		except KeyboardInterrupt:
			raise

	def query(self, query):
		try:
			self.cursor.execute(query)
			result = self.cursor.fetchall()
			self.db.commit()
			return result
		except psycopg2.Error, e:
			self.log_obj.log("log-pgsql failed: %s" % (e), 12, "crit", Log=True, display=True)
		except KeyboardInterrupt:
			raise
		return False

	def initialConnection(self, attackerIP, attackerPort, victimIP, victimPort, identifier, initialConnectionsDict, loLogger):
		pass

	def incoming(self, attackerIP, attackerPort, victimIP, victimPort, vulnName, timestamp, downloadMethod, loLogger, attackerID, shellcodeName):
		try:
			self.log_obj = amun_logging.amun_logging("log_pgsql", loLogger)
			### current table
			tableName = time.strftime('%Y%m%d')
			if self.connectDB(self.log_obj):
				### insert new connection
				self.insertConnection(tableName, attackerIP, attackerPort, victimIP, victimPort, vulnName)
				self.closeDB(self.log_obj)
			else:
				self.log_obj.log("log-pgsql failed connection", 12, "crit", Log=True, display=True)

		except KeyboardInterrupt:
			raise

	def insertConnection(self, tableName, attackerIP, attackerPort, victimIP, victimPort, vulnName):
		try:
			### check for already existing entry
			query = "SELECT id FROM honeypot_amun.amun_connections WHERE hostileip='%s' AND targetip='%s' AND targetport='%s'" % (attackerIP, victimIP, victimPort)
			result = self.query(query)
			if result and (len(result) > 0):
				### existing connection
				updateID = str(result[0][0])
				query = "UPDATE honeypot_amun.amun_connections SET count=count+1 WHERE id='%s' RETURNING count" % (updateID)
				self.query(query)
			else:
				### new connection
				curTimestamp = psycopg2.TimestampFromTicks(time.time())
				query = "INSERT INTO honeypot_amun.amun_connections (timestamp,hostileip,hostileport,targetip,targetport,DialogueName) VALUES (%s,'%s','%s','%s','%s','%s') RETURNING id" % (curTimestamp, attackerIP, attackerPort, victimIP, victimPort, vulnName)
				self.query(query)
			### return from insert connection
			return True
		except KeyboardInterrupt:
			raise

	def successfullSubmission(self, attackerIP, attackerPort, victimIP, downloadURL, md5hash, data, filelength, downMethod, loLogger, vulnName, fexists):
		try:
			self.log_obj = amun_logging.amun_logging("log_pgsql", loLogger)
			### current table
			tableName = time.strftime('%Y%m%d')
			if self.connectDB(self.log_obj):
				### insert binary
				self.insertBinary(tableName, md5hash, attackerIP, victimIP, downloadURL, filelength, data)
				self.closeDB(self.log_obj)
			else:
				self.log_obj.log("log-pgsql failed connection", 12, "crit", Log=True, display=True)
		except KeyboardInterrupt:
			raise

	def insertBinary(self, tableName, md5hash, attIP, victimIP, downURL, file_data_length, file_data):
		try:
			### current timestamp
			curTimestamp = psycopg2.TimestampFromTicks(time.time())
			### check if binary exists
			query = "SELECT id, md5hash FROM honeypot_amun.amun_storage WHERE md5hash='%s'" % (md5hash)
			result = self.query(query)
			if len(result)>0:
				### binary exists
				binaryID = str(result[0][0])
				query = "SELECT eventid FROM honeypot_amun.amun_hits WHERE hostileip='%s' AND targetip='%s' AND downurl='%s'" % (attIP, victimIP, MySQLdb.escape_string(downURL))
				result = self.query(query)
				if len(result)>0:
					### entry exists
					pass
				else:
					### create incident entry
					query = "INSERT INTO honeypot_amun.amun_hits (hostileip, targetip, timestamp, downurl, binaryid) VALUES ('%s','%s','%s','%s','%s') RETURNING id" % (attIP, victimIP, curTimestamp, MySQLdb.escape_string(downURL), binaryID)
					self.query(query)
			else:
				### new binary
				query = "INSERT INTO honeypot_amun.amun_hits (hostileip,targetip,timestamp,downurl) VALUES ('%s','%s','%s','%s') RETURNING id" % (attIP, victimIP, curTimestamp, MySQLdb.escape_string(downURL))
				self.query(query)
				### insert common data
				query = "INSERT INTO honeypot_amun.amun_storage (md5hash,filesize,comment) VALUES ('%s','%s','None')RETURNING id" % (md5hash, file_data_length)
				result = self.query(query)
				### id of last insert
				eventID = result[0][0]
				query = "UPDATE honeypot_amun.amun_hits SET binaryid='%s' WHERE eventid='%s' RETURING eventid" % (eventID, eventID)
				self.query(query)
				if file_data_length<2000000:
					encodedBin = base64.encodestring(file_data)
					query = "INSERT INTO honeypot_amun.amun_binaries (id,binary_data) VALUES ('%s','%s') RETURNING id" % (eventID, MySQLdb.escape_string(encodedBin))
					self.query(query)
					query = "INSERT INTO honeypot_amun.amun_cwsandbox (id,cwanalyse,flag,comment) VALUES ('%s','None','0','None') RETURNING id" % (eventID)
					self.query(query)
				else:
					query = "UPDATE honeypot_amun.amun_storage SET comment='binary too big' WHERE id='%s' RETURNING id" % (eventID)
					self.query(query)
		except KeyboardInterrupt:
			raise
