#!/usr/bin/python

import sys
import os
import subprocess

if len(sys.argv) != 5:
    print "Usage: dirbust.py <target url> <port> <scan name> <log directory>"
    sys.exit(0)

url = str(sys.argv[1])
port = str(sys.argv[2])
name = str(sys.argv[3])
log_dir = str(sys.argv[4])
folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]

directory = "%s/%s/dirb/%s" % (log_dir, name, port)
if not os.path.exists(directory):
    os.makedirs(directory)

found = []
print "INFO: Starting dirb scan for " + url
for folder in folders:
    for filename in os.listdir(folder):

		outfile = "-o %s/%s/dirb/%s/%s_dirb_%s" % (log_dir, name, port, name, filename)
		#outfile = " -o " + "results/exam/" + name + "_dirb_" + filename
		DIRBSCAN = "dirb %s:%s %s/%s %s -S -r" % (url, port, folder, filename, outfile)
		print DIRBSCAN
		try:
			results = subprocess.check_output(DIRBSCAN, shell=True)
			resultarr = results.split("\n")
			for line in resultarr:
				if "+" in line:
					if line not in found:
						found.append(line)
		except:
			pass

try:
    if found[0] != "":
        print "[*] Dirb found the following items..."
        for item in found:
            print "   " + item
except:
    print "INFO: No items found during dirb scan of " + url		
