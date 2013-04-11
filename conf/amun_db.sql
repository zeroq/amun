-- MySQL dump 10.11
--
-- Host: localhost    Database: amun_db
-- ------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `amun_db`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `amun_db` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `amun_db`;

--
-- Table structure for table `amun_binaries`
--

DROP TABLE IF EXISTS `amun_binaries`;
CREATE TABLE `amun_binaries` (
  `id` bigint(20) NOT NULL,
  `binary_data` longblob NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Table structure for table `amun_cwsandbox`
--

DROP TABLE IF EXISTS `amun_cwsandbox`;
CREATE TABLE `amun_cwsandbox` (
  `id` int(11) NOT NULL,
  `cwanalyse` longtext NOT NULL,
  `flag` int(11) NOT NULL,
  `comment` varchar(255) NOT NULL,
  `timestamp` timestamp NULL default NULL,
  `priority` smallint(6) NOT NULL default '0',
  `notification_email` text,
  `binary_data` mediumblob,
  PRIMARY KEY  (`id`),
  KEY `priority` (`priority`,`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Table structure for table `amun_storage`
--

DROP TABLE IF EXISTS `amun_storage`;
CREATE TABLE `amun_storage` (
  `id` int(11) NOT NULL auto_increment,
  `md5hash` varchar(32) NOT NULL,
  `filesize` int(11) NOT NULL,
  `comment` varchar(255) NOT NULL,
  PRIMARY KEY  (`id`),
  UNIQUE KEY `md5hash` (`md5hash`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


CREATE TABLE IF NOT EXISTS `amun_connections_currentDate` ( 
	id INT(11) NOT NULL AUTO_INCREMENT, 
	timestamp INT(11) NOT NULL, 
	hostileip VARCHAR(255) NOT NULL, 
	hostileport VARCHAR(255) NOT NULL, 
	targetip VARCHAR(255) NOT NULL, 
	targetport VARCHAR(255) NOT NULL, 
	DialogueName VARCHAR(255) NOT NULL, 
	count int(11) NOT NULL DEFAULT '1', 
	warned INT(11) NOT NULL DEFAULT '0', 
	PRIMARY KEY (id), 
	KEY hostileip (hostileip), 
	KEY targetip (targetip), 
	KEY DialogueName (DialogueName) 
) ENGINE = MYISAM;

CREATE TABLE IF NOT EXISTS amun_hits_currentDate ( 
	eventid INT(11) NOT NULL AUTO_INCREMENT, 
	hostileip VARCHAR(255) NOT NULL, 
	targetip VARCHAR(255) NOT NULL, 
	timestamp INT(11) NOT NULL, 
	downurl TINYTEXT NOT NULL, 
	binaryid INT(11) NOT NULL DEFAULT '0', 
	PRIMARY KEY (eventid), 
	KEY hostileip (hostileip), 
	KEY targetip (targetip), 
	KEY binaryid (binaryid), 
	KEY downurl (downurl(250)) 
) ENGINE = MYISAM;
