

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import amun_logging
import amun_config_parser
import psycopg2
from datetime import datetime
from re import escape
import hashlib

class log:
	def __init__(self):
		try:
			self.log_name = "Log Sarcophagus"
			conffile = "conf/log-sarcophagus.conf"
			self.config = amun_config_parser.AmunConfigParser(conffile)
			self.sensor_id = self.config.getSingleValue("sensorID")
		except KeyboardInterrupt:
			raise

	def connectDB(self, logger):
		try:
			self.db = psycopg2.connect("host='%s' dbname='%s' user='%s' password='%s'" %
					(
						self.config.getSingleValue("pgSQLHost"),
						self.config.getSingleValue("pgSQLDB"),
						self.config.getSingleValue("pgSQLUser"),
						self.config.getSingleValue("pgSQLPass")
					))
			self.cursor = self.db.cursor()
			return True
		except psycopg2.Error as e:
			logger.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
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
		except psycopg2.Error as e:
			logger.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
			raise
		except KeyboardInterrupt:
			raise

	def initialConnection(self, attackerIP, attackerPort, victimIP, victimPort, identifier, initialConnectionsDict, loLogger):
		try:
			update_id = None
			log_obj = amun_logging.amun_logging("log_sarcophagus", loLogger)
			if self.connectDB(log_obj):
				""" check for existing connection of attacker to victim """
				try:
					self.cursor.execute("SELECT id FROM public.amun_initial_connection WHERE attacker_ip = %s AND victim_ip = %s AND victim_port = %s AND sensor_id=%s", (attackerIP, victimIP, victimPort, self.sensor_id))
					result = self.cursor.fetchall()
					self.db.commit()
				except psycopg2.Error as e:
					log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
					result = False
				if result and (len(result) > 0):
					""" update existing connection entry """
					update_id = str(result[0][0])
					try:
						self.cursor.execute("UPDATE public.amun_initial_connection SET count=count+1, last_seen=%s WHERE id=%s", (datetime.utcnow(), update_id))
						self.db.commit()
						""" store attacker identifier with socket dictionary """
						if initialConnectionsDict.has_key(identifier) and update_id!=None:
							initialConnectionsDict[identifier][4] = update_id
						return True
					except psycopg2.Error as e:
						log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
						return False
				else:
					""" insert new connection """
					connection_id = None
					try:
						self.cursor.execute("INSERT INTO public.amun_initial_connection (attacker_ip, attacker_port, victim_ip, victim_port, count, first_seen, last_seen, sensor_id) VALUES (%s, %s, %s, %s, 1, %s, %s, %s) RETURNING id", (attackerIP, attackerPort, victimIP, victimPort, datetime.utcnow(), datetime.utcnow(), self.sensor_id))
						connection_id = self.cursor.fetchone()[0]
						self.db.commit()
						""" store attacker identifier with socket dictionary """
						if initialConnectionsDict.has_key(identifier) and connection_id!=None:
							initialConnectionsDict[identifier][4] = connection_id
						return True
					except psycopg2.Error as e:
						log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
						return False
			else:
				log_obj.log("log-sarcophagus failed connection", 12, "crit", Log=True, display=True)
				return False
		except KeyboardInterrupt:
			raise
		return True

	def incoming(self, attackerIP, attackerPort, victimIP, victimPort, vulnName, timestamp, downloadMethod, loLogger, attackerID, shellcodeName):
		try:
			log_obj = amun_logging.amun_logging("log_sarcophagus", loLogger)
			if self.connectDB(log_obj):
				""" get ID for attacker based on his initial connection """
				try:
					self.cursor.execute("SELECT id FROM public.amun_initial_connection WHERE attacker_ip = %s AND victim_ip = %s AND victim_port = %s AND sensor_id=%s", (attackerIP, victimIP, victimPort, self.sensor_id))
					attacker_result = self.cursor.fetchall()
					self.db.commit()
				except psycopg2.Error as e:
					log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
					attacker_result = False
					return False
				if attacker_result and (len(attacker_result)>0):
					attacker_id = str(attacker_result[0][0])
					try:
						self.cursor.execute("SELECT id FROM public.amun_successful_exploit WHERE attacker_id=%s AND vulnerability_name=%s AND download_method=%s AND shellcode_name=%s", (attacker_id, vulnName, downloadMethod, shellcodeName))
						exploit_result = self.cursor.fetchall()
						self.db.commit()
					except psycopg2.Error as e:
						log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
						exploit_result = False
					if exploit_result and (len(exploit_result)>0):
						""" update existing exploit """
						exploit_id = str(exploit_result[0][0])
						try:
							self.cursor.execute("UPDATE public.amun_successful_exploit SET count=count+1, last_seen=%s WHERE id=%s", (datetime.utcnow(), exploit_id))
							self.db.commit()
							return True
						except psycopg2.Error as e:
							log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
							return False
					else:
						""" create new exploit entry """
						try:
							self.cursor.execute("INSERT INTO public.amun_successful_exploit (attacker_id, vulnerability_name, download_method, shellcode_name, count, first_seen, last_seen) VALUES (%s, %s, %s, %s, 1, %s, %s)", (attacker_id, vulnName, downloadMethod, shellcodeName, datetime.utcnow(), datetime.utcnow()))
							self.db.commit()
							return True
						except psycopg2.Error as e:
							log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
							return False
				else:
					log_obj.log("no initial connection entry for incoming attacker!", 12, "crit", Log=True, display=True)
					return False
			else:
				log_obj.log("log-sarcophagus failed connection", 12, "crit", Log=True, display=True)
				return False
		except KeyboardInterrupt:
			raise
		return True

	def successfullSubmission(self, attackerIP, attackerPort, victimIP, downloadURL, md5hash, data, filelength, downMethod, loLogger, vulnName, fexists):
		try:
			log_obj = amun_logging.amun_logging("log_sarcophagus", loLogger)
			if self.connectDB(log_obj):
				try:
					""" get exploit ID """
					self.cursor.execute("SELECT x.id FROM public.amun_successful_exploit x JOIN public.amun_initial_connection i ON x.attacker_id=i.id WHERE i.attacker_ip=%s AND i.victim_ip=%s AND x.vulnerability_name=%s ORDER BY x.last_seen LIMIT 1", (attackerIP, victimIP, vulnName))
					exploit_result = self.cursor.fetchall()
					self.db.commit()
				except psycopg2.Error as e:
					log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
					attacker_result = False
					return False
				if exploit_result and (len(exploit_result)>0):
					exploit_id = str(exploit_result[0][0])
					sha256hash = hashlib.sha256(data).hexdigest()
					try:
						self.cursor.execute("SELECT id FROM public.amun_successful_submission WHERE exploit_id=%s AND download_url=%s AND md5_hash=%s AND sha256_hash=%s", (exploit_id, downloadURL, md5hash, sha256hash))
						submission_result = self.cursor.fetchall()
						self.db.commit()
					except psycopg2.Error as e:
						log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
						submission_result = False
					if submission_result and (len(submission_result)>0):
						""" update existing submission """
						submission_id = str(submission_result[0][0])
						try:
							self.cursor.execute("UPDATE public.amun_successful_submission SET count=count+1, last_seen=%s WHERE id=%s", (datetime.utcnow(), submission_id))
							self.db.commit()
							return True
						except psycopg2.Error as e:
							log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
							return False
					else:
						""" create new submission entry """
						try:
							self.cursor.execute("INSERT INTO public.amun_successful_submission (exploit_id, download_url, download_method, md5_hash, sha256_hash, count, first_seen, last_seen) VALUES (%s, %s, %s, %s, %s, 1, %s, %s)", (exploit_id, downloadURL, downMethod, md5hash, sha256hash, datetime.utcnow(), datetime.utcnow()))
							self.db.commit()
							return True
						except psycopg2.Error as e:
							log_obj.log("log-sarcophagus failed: %s" % (e), 12, "crit", Log=True, display=True)
							return False
				else:
					log_obj.log("no exploit entry for incoming attacker! (%s:%s -> %s [%s|%s|%s])" % (attackerIP, attackerPort, victimIP, vulnName, downloadURL, downMethod), 12, "crit", Log=True, display=True)
					return False
			else:
				log_obj.log("log-sarcophagus failed connection", 12, "crit", Log=True, display=True)
				return False
		except KeyboardInterrupt:
			raise
		return True
