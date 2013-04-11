#!/usr/bin/python

import popen2
import re


if __name__ == '__main__':
	print "Try to get all assigned IP addresses:"
	try:
		t = re.compile("inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/");
		counter = 0
		ipListe = []
		command = "ip addr show eth0"
		child = popen2.Popen4(command)
		line = child.fromchild.readline()
		while line:
			line = str(line).strip()
			match = t.search(line)
			if match:
				#print "\t%s" % (match.groups()[0])
				ipListe.append(str(match.groups()[0]).strip())
				counter += 1
			line = child.fromchild.readline()
		child.wait()
		print counter
		print ipListe[0]
	except KeyboardInterrupt:
		pass
