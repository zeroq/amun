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
import amun_config_parser
import MySQLdb
import base64

class log:
	def __init__(self):
		try:
			self.log_name = "Log MySQL"
			conffile = "conf/log-mysql.conf"
			config = amun_config_parser.AmunConfigParser(conffile)
			self.myHost = config.getSingleValue("MySQLHost")
			self.myUser = config.getSingleValue("MySQLUser")
			self.myPass = config.getSingleValue("MySQLPass")
			self.myDB = config.getSingleValue("MySQLDB")
			del config
		except KeyboardInterrupt:
			raise

	def connectDB(self, logger):
		try:
			self.db = MySQLdb.connect(self.myHost, self.myUser, self.myPass, self.myDB)
			self.cursor = self.db.cursor()
			return True
		except MySQLdb.Error, e:
			logger.log("log-mysql failed: %s" % (e), 12, "crit", Log=True, display=True)
			raise
		except KeyboardInterrupt:
			raise

	def closeDB(self, logger):
		try:
			self.db.close()
			self.cursor.close()
			return True
		except MySQLdb.Error, e:
			logger.log("log-mysql failed: %s" % (e), 12, "crit", Log=True, display=True)
			raise
		except KeyboardInterrupt:
			raise

	def query(self, query):
		try:
			self.cursor.execute(query)
			return self.cursor.fetchall()
		except MySQLdb.Error, e:
			self.log_obj.log("log-mysql failed: %s" % (e), 12, "crit", Log=True, display=True)
		except KeyboardInterrupt:
			raise
		return False

	def initialConnection(self, attackerIP, attackerPort, victimIP, victimPort, identifier, initialConnectionsDict, loLogger):
		pass

	def incoming(self, attackerIP, attackerPort, victimIP, victimPort, vulnName, timestamp, downloadMethod, loLogger, attackerID, shellcodeName):
		try:
			self.log_obj = amun_logging.amun_logging("log_mysql", loLogger)
			### current table
			tableName = time.strftime('%Y%m%d')
			if self.connectDB(self.log_obj):
				### insert new connection
				self.insertConnection(tableName, attackerIP, attackerPort, victimIP, victimPort, vulnName)
				self.closeDB(self.log_obj)
			else:
				self.log_obj.log("log-mysql failed connection", 12, "crit", Log=True, display=True)

		except KeyboardInterrupt:
			raise

	def insertConnection(self, tableName, attackerIP, attackerPort, victimIP, victimPort, vulnName):
		try:
			### create new table for connections if not exists (daily-basis)
			query = "CREATE TABLE IF NOT EXISTS amun_connections_%s ( id INT(11) NOT NULL AUTO_INCREMENT, timestamp INT(11) NOT NULL, hostileip VARCHAR(255) NOT NULL, hostileport VARCHAR(255) NOT NULL, targetip VARCHAR(255) NOT NULL, targetport VARCHAR(255) NOT NULL, DialogueName VARCHAR(255) NOT NULL, count int(11) NOT NULL DEFAULT '1', warned INT(11) NOT NULL DEFAULT '0', PRIMARY KEY (id), KEY hostileip (hostileip), KEY targetip (targetip), KEY DialogueName (DialogueName) ) ENGINE = MYISAM" % (tableName)
			self.query(query)
			### check for already existing entry
			query = "SELECT id FROM amun_connections_%s WHERE hostileip='%s' AND targetip='%s' AND targetport='%s'" % (tableName, attackerIP, victimIP, victimPort)
			result = self.query(query)
			if len(result)>0:
				### existing connection
				updateID = str(result[0][0])
				query = "UPDATE amun_connections_%s SET count=count+1 WHERE id='%s'" % (tableName, updateID)
				self.query(query)
			else:
				### new connection
				curTimestamp = int(time.time())
				query = "INSERT INTO amun_connections_%s (timestamp,hostileip,hostileport,targetip,targetport,DialogueName) VALUES ('%s','%s','%s','%s','%s','%s')" % (tableName, curTimestamp, attackerIP, attackerPort, victimIP, victimPort, vulnName)
				self.query(query)
			### return from insert connection
			return True
		except KeyboardInterrupt:
			raise

	def successfullSubmission(self, attackerIP, attackerPort, victimIP, downloadURL, md5hash, data, filelength, downMethod, loLogger, vulnName, fexists):
		try:
			self.log_obj = amun_logging.amun_logging("log_mysql", loLogger)
			### current table
			tableName = time.strftime('%Y%m%d')
			if self.connectDB(self.log_obj):
				### insert binary
				self.insertBinary(tableName, md5hash, attackerIP, victimIP, downloadURL, filelength, data)
				self.closeDB(self.log_obj)
			else:
				self.log_obj.log("log-mysql failed connection", 12, "crit", Log=True, display=True)
		except KeyboardInterrupt:
			raise

	def insertBinary(self, tableName, md5hash, attIP, victimIP, downURL, file_data_length, file_data):
		try:
			### current timestamp
			curTimestamp = int(time.time())
			### create table if not exists
			query = "CREATE TABLE IF NOT EXISTS amun_hits_%s ( eventid INT(11) NOT NULL AUTO_INCREMENT, hostileip VARCHAR(255) NOT NULL, targetip VARCHAR(255) NOT NULL, timestamp INT(11) NOT NULL, downurl TINYTEXT NOT NULL, binaryid INT(11) NOT NULL DEFAULT '0', PRIMARY KEY (eventid), KEY hostileip (hostileip), KEY targetip (targetip), KEY binaryid (binaryid), KEY downurl (downurl(250)) ) ENGINE = MYISAM" % (tableName)
			self.query(query)
			### check if binary exists
			query = "SELECT id,md5hash FROM amun_storage WHERE md5hash='%s'" % (md5hash)
			result = self.query(query)
			if len(result)>0:
				### binary exists
				binaryID = str(result[0][0])
				query = "SELECT eventid FROM amun_hits_%s WHERE hostileip='%s' AND targetip='%s' AND downurl='%s'" % (tableName, attIP, victimIP, MySQLdb.escape_string(downURL))
				result = self.query(query)
				if len(result)>0:
					### entry exists
					pass
				else:
					### create incident entry
					query = "INSERT INTO amun_hits_%s (hostileip,targetip,timestamp,downurl,binaryid) VALUES ('%s','%s','%s','%s','%s')" % (tableName, attIP, victimIP, curTimestamp, MySQLdb.escape_string(downURL), binaryID)
					self.query(query)
			else:
				### new binary
				query = "INSERT INTO amun_hits_%s (hostileip,targetip,timestamp,downurl) VALUES ('%s','%s','%s','%s')" % (tableName, attIP, victimIP, curTimestamp, MySQLdb.escape_string(downURL))
				self.query(query)
				### insert common data
				query = "INSERT INTO amun_storage (md5hash,filesize,comment) VALUES ('%s','%s','None')" % (md5hash, file_data_length)
				self.query(query)
				### id of last insert
				eventID = int(self.db.insert_id())
				query = "UPDATE amun_hits_%s SET binaryid='%s' WHERE eventid='%s'" % (tableName, eventID, eventID)
				self.query(query)
				if file_data_length<2000000:
					encodedBin = base64.encodestring(file_data)
					query = "INSERT INTO amun_binaries (id,binary_data) VALUES ('%s','%s')" % (eventID, MySQLdb.escape_string(encodedBin))
					self.query(query)
					query = "INSERT INTO amun_cwsandbox (id,cwanalyse,flag,comment) VALUES ('%s','None','0','None')" % (eventID)
					self.query(query)
				else:
					query = "UPDATE amun_storage SET comment='binary too big' WHERE id='%s'" % (eventID)
					self.query(query)
		except KeyboardInterrupt:
			raise
