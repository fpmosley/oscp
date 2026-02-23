#!/usr/bin/python3

import sys
import os
import subprocess

if len(sys.argv) != 5:
    print("Usage: dirbust.py <target url> <port> <scan name> <log directory>")
    sys.exit(0)

url = sys.argv[1]
port = sys.argv[2]
name = sys.argv[3]
log_dir = sys.argv[4]
folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns",
           "/usr/local/share/dirb/wordlists", "/usr/local/share/dirb/wordlists/vulns"]

directory = f"{log_dir}/{name}/dirb/{port}"
os.makedirs(directory, exist_ok=True)

found = []
print(f"INFO: Starting dirb scan for {url}")
for folder in folders:
    if not os.path.exists(folder):
        continue
    for filename in os.listdir(folder):
        outfile = f"-o {log_dir}/{name}/dirb/{port}/{name}_dirb_{filename}"
        cmd = f"dirb {url}:{port} {folder}/{filename} {outfile} -S -r"
        print(cmd)
        try:
            results = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True).stdout
            for line in results.splitlines():
                if "+" in line and line not in found:
                    found.append(line)
        except subprocess.CalledProcessError:
            pass

if found:
    print("[*] Dirb found the following items...")
    for item in found:
        print(f"   {item}")
else:
    print(f"INFO: No items found during dirb scan of {url}")
