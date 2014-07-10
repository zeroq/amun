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

import time
import MySQLdb
import base64

###
### OBSOLETE: USE THE LOG_MYSQL INSTEAD !
###

class submit(object):
	__slots__ = ("submit_name", "myHost", "myUser", "myPass", "myTable", "db", "cursor", "log_obj")

	def __init__(self):
		try:
			self.submit_name = "Submit MySQL"
			self.myHost = "127.0.0.1"
			self.myUser = ""
			self.myPass = ""
			self.myTable = ""
		except KeyboardInterrupt:
			raise

	def connectDB(self, logger):
		try:
			self.db = MySQLdb.connect(self.myHost, self.myUser, self.myPass, self.myTable)
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

	def incoming(self, file_data, file_data_length, downMethod, attIP, victimIP, smLogger, md5hash, attackedPort, vulnName, downURL, fexists):
		try:
			self.log_obj = amun_logging.amun_logging("submit_mysql", smLogger)
			### current table
			tableName = time.strftime('%Y%m%d')
			if self.connectDB(self.log_obj):
				### insert binary
				self.insertBinary(tableName, md5hash, attIP, victimIP, downURL, file_data_length, file_data)
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
				query = "SELECT eventid FROM amun_hits_%s WHERE hostileip='%s' AND targetip='%s' AND downurl='%s'" % (tableName, attIP, victimIP, downURL)
				result = self.query(query)
				if len(result)>0:
					### entry exists
					pass
				else:
					### create incident entry
					query = "INSERT INTO amun_hits_%s (hostileip,targetip,timestamp,downurl,binaryid) VALUES ('%s','%s','%s','%s','%s')" % (tableName, attIP, victimIP, curTimestamp, downURL, binaryID)
					self.query(query)
			else:
				### new binary
				query = "INSERT INTO amun_hits_%s (hostileip,targetip,timestamp,downurl) VALUES ('%s','%s','%s','%s')" % (tableName, attIP, victimIP, curTimestamp, downURL)
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
