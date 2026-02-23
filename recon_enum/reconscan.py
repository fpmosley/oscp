#!/usr/bin/env python3
import subprocess
import multiprocessing
import os
import re
import shutil
import socket
import sys
from pathlib import Path

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

ENUM_TYPE_PLACEHOLDERS = {
    "portscan":    "INSERTTCPSCAN",
    "dirb":        "INSERTDIRBSCAN",
    "nikto":       "INSERTNIKTOSCAN",
    "ftp-connect": "INSERTFTPTEST",
    "smtp-connect":"INSERTSMTPCONNECT",
    "ssh-connect": "INSERTSSHCONNECT",
    "pop3-connect":"INSERTPOP3CONNECT",
    "curl":        "INSERTCURLHEADER",
    "nfs":         "INSERTRPCBIND",
}

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True).stdout

def multProc(targetin, scanip, port):
    p = multiprocessing.Process(target=targetin, args=(scanip, port))
    p.start()

def connect_to_port(ip_address, port, service):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip_address, int(port)))
        banner = s.recv(1024).decode('utf-8', errors='replace')

        if service == "ftp":
            s.send(b"USER anonymous\r\n")
            user = s.recv(1024).decode('utf-8', errors='replace')
            s.send(b"PASS anonymous\r\n")
            password = s.recv(1024).decode('utf-8', errors='replace')
            write_to_file(ip_address, "ftp-connect", f"{banner}\r\n{user}\r\n{password}")
        elif service == "smtp":
            write_to_file(ip_address, "smtp-connect", f"{banner}\r\n")
        elif service == "ssh":
            write_to_file(ip_address, "ssh-connect", banner)
        elif service == "pop3":
            s.send(b"USER root\r\n")
            user = s.recv(1024).decode('utf-8', errors='replace')
            s.send(b"PASS root\r\n")
            password = s.recv(1024).decode('utf-8', errors='replace')
            write_to_file(ip_address, "pop3-connect", f"{banner}{user}{password}")

def write_to_file(ip_address, enum_type, data):
    paths = [
        Path(f"../reports/{ip_address}/mapping-linux.md"),
        Path(f"../reports/{ip_address}/mapping-windows.md"),
    ]
    print(f"{bcolors.OKGREEN}INFO: Writing {enum_type} to template files:{bcolors.ENDC}")
    for path in paths:
        print(f"  {path}")

    search_string = ENUM_TYPE_PLACEHOLDERS.get(enum_type, '')
    for path in paths:
        path.write_text(path.read_text().replace(search_string, data))

def dirb(ip_address, port, url_start, wordlist="/usr/share/wordlists/dirb/common.txt"):
    print(f"{bcolors.HEADER}INFO: Starting dirb scan for {ip_address}:{port}{bcolors.ENDC}")
    cmd = f"dirb {url_start}://{ip_address}:{port} {wordlist} -o ../reports/{ip_address}/dirb-{ip_address}-{port}.txt -r"
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results_dirb = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with dirb scan for {ip_address}{bcolors.ENDC}")
    print(results_dirb)
    write_to_file(ip_address, "dirb", results_dirb)

def nikto(ip_address, port, url_start):
    print(f"{bcolors.HEADER}INFO: Starting nikto scan for {ip_address}:{port}{bcolors.ENDC}")
    cmd = f"nikto -h {url_start}://{ip_address}:{port} -o ../reports/{ip_address}/nikto-{ip_address}-{port}.txt"
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results_nikto = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with NIKTO-scan for {ip_address}{bcolors.ENDC}")
    print(results_nikto)
    write_to_file(ip_address, "nikto", results_nikto)

def httpEnum(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected http on {ip_address}:{port}{bcolors.ENDC}")
    print(f"{bcolors.HEADER}INFO: Performing nmap web script scan for {ip_address}:{port}{bcolors.ENDC}")

    multiprocessing.Process(target=dirb, args=(ip_address, port, "http")).start()
    multiprocessing.Process(target=nikto, args=(ip_address, port, "http")).start()

    curl_cmd = f"curl -I http://{ip_address}"
    print(f"{bcolors.HEADER}{curl_cmd}{bcolors.ENDC}")
    curl_results = run(curl_cmd)
    write_to_file(ip_address, "curl", curl_results)

    http_cmd = (f"nmap -n -sV -Pn -p {port} --script=http-vhosts,http-userdir-enum,http-apache-negotiation,"
                f"http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,"
                f"http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,"
                f"http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635"
                f" -oN ../reports/{ip_address}/{ip_address}_http.nmap {ip_address}")
    print(f"{bcolors.HEADER}{http_cmd}{bcolors.ENDC}")
    http_results = run(http_cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with HTTP-SCAN for {ip_address}{bcolors.ENDC}")
    print(http_results)

    if "Drupal" in http_results:
        print(f"{bcolors.HEADER}INFO: Detected Drupal on {ip_address}:{port}{bcolors.ENDC}")
        print(f"{bcolors.HEADER}INFO: Performing Drupal scan for {ip_address}:{port}{bcolors.ENDC}")
        drupal_cmd = f"droopescan scan drupal -u http://{ip_address}:{port} | tee ../reports/{ip_address}/droopescan_{port}.txt"
        drupal_results = run(drupal_cmd)
        print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with DRUPAL-SCAN for {ip_address}{bcolors.ENDC}")
        print(drupal_results)

def httpsEnum(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected https on {ip_address}:{port}{bcolors.ENDC}")
    print(f"{bcolors.HEADER}INFO: Performing nmap web script scan for {ip_address}:{port}{bcolors.ENDC}")

    multiprocessing.Process(target=dirb, args=(ip_address, port, "https")).start()
    multiprocessing.Process(target=nikto, args=(ip_address, port, "https")).start()

    ssl_cmd = f"sslscan {ip_address}:{port} >> ../reports/{ip_address}/ssl_scan_{ip_address}_{port}.txt"
    print(f"{bcolors.HEADER}{ssl_cmd}{bcolors.ENDC}")
    subprocess.run(ssl_cmd, shell=True)
    print(f"{bcolors.OKGREEN}INFO: CHECK FILE - Finished with SSLSCAN for {ip_address}:{port}{bcolors.ENDC}")

    https_cmd = (f"nmap -n -sV -Pn -p {port} --script=http-vhosts,http-userdir-enum,http-apache-negotiation,"
                 f"http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,"
                 f"http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,"
                 f"http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635"
                 f" -oN ../reports/{ip_address}/{ip_address}_http.nmap {ip_address}")
    print(f"{bcolors.HEADER}{https_cmd}{bcolors.ENDC}")
    https_results = run(https_cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with HTTPS-scan for {ip_address}{bcolors.ENDC}")
    print(https_results)

def mssqlEnum(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected MS-SQL on {ip_address}:{port}{bcolors.ENDC}")
    print(f"{bcolors.HEADER}INFO: Performing nmap mssql script scan for {ip_address}:{port}{bcolors.ENDC}")
    cmd = (f"nmap -n -sV -Pn -p {port} --script=ms-sql-empty-password,ms-sql-info,ms-sql-config,"
           f"ms-sql-hasdbaccess,ms-sql-dump-hashes --script-args=mssql.instance-port={port}"
           f" -oN ../reports/{ip_address}/mssql_{ip_address}.nmap {ip_address}")
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with MSSQL-scan for {ip_address}{bcolors.ENDC}")
    print(results)

def mysqlEnum(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected MySQL on {ip_address}:{port}{bcolors.ENDC}")
    print(f"{bcolors.HEADER}INFO: Performing nmap mysql script scan for {ip_address}:{port}{bcolors.ENDC}")
    cmd = (f"nmap -n -sV -Pn -p {port} --script=mysql-empty-password,mysql-enum,mysql-users,"
           f"mysql-variables,mysql-vuln-cve2012-2122 -oN ../reports/{ip_address}/mysql_{ip_address}.nmap {ip_address}")
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with MySQL-scan for {ip_address}{bcolors.ENDC}")
    print(results)

def oracleEnum(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected Oracle on {ip_address}:{port}{bcolors.ENDC}")
    print(f"{bcolors.HEADER}INFO: Performing nmap oracle script scan for {ip_address}:{port}{bcolors.ENDC}")
    cmd = (f"nmap -n -sV -Pn -p {port} --script=oracle-tns-version,oracle-sid-brute,oracle-enum-users"
           f" -oN ../reports/{ip_address}/oracle_{ip_address}.nmap {ip_address}")
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with Oracle-scan for {ip_address}{bcolors.ENDC}")
    print(results)

def smtpEnum(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected smtp on {ip_address}:{port}{bcolors.ENDC}")
    connect_to_port(ip_address, port, "smtp")
    cmd = (f"nmap -n -sV -Pn -p {port} --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,"
           f"smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 {ip_address} -oN ../reports/{ip_address}/smtp_{ip_address}.nmap")
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with SMTP-scan for {ip_address}:{port}{bcolors.ENDC}")
    print(results)

def smbNmap(ip_address, ports):
    print(f"{bcolors.HEADER}INFO: Detected SMB on {ip_address} on {ports}")
    cmd = (f"nmap -n -p {ports} --script=smb-enum-shares,smb-ls,smb-enum-users,smb-mbenum,smb-os-discovery,"
           f"smb-security-mode,msrpc-enum,smb-vuln-cve2009-3103,smb-vuln-cve-2017-7494,smb-vuln-ms06-025,"
           f"smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010"
           f" {ip_address} -oN ../reports/{ip_address}/smb_{ip_address}_{ports.replace(',', '_')}.nmap")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with SMB-Nmap-scan for {ip_address} for ports {ports}{bcolors.ENDC}")
    print(results)

def smbEnum(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected SMB on {ip_address}")
    enum4linux_results = run(f"enum4linux -a {ip_address} > ../reports/{ip_address}/enum4linux_{ip_address}.txt 2>/dev/null")
    print(f"{bcolors.OKGREEN}INFO: CHECK FILE - Finished with SMB-enum4linux for {ip_address}{bcolors.ENDC}")
    print(enum4linux_results)
    smbmap_results = run(f"smbmap -H {ip_address}")
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with SMB-smbmap for {ip_address}{bcolors.ENDC}")
    print(smbmap_results)
    nbtresults = run(f"nbtscan -r {ip_address}/32")
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with SMB-nbtscan for {ip_address}{bcolors.ENDC}")
    print(nbtresults)

def ftpEnum(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected ftp on {ip_address}:{port}{bcolors.ENDC}")
    connect_to_port(ip_address, port, "ftp")
    cmd = (f"nmap -n -sV -Pn -p {port} --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,"
           f"ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '../reports/{ip_address}/ftp_{ip_address}.nmap' {ip_address}")
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with FTP-Nmap-scan for {ip_address}{bcolors.ENDC}")
    print(results)

def udpScan(ip_address, ports):
    print(f"{bcolors.HEADER}INFO: Detecting UDP on {ip_address}{bcolors.ENDC}")
    cmd = f"nmap -n -Pn -A -sC -sU -T 3 -p {ports} -oA '../reports/{ip_address}/udp_{ip_address}' {ip_address}"
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with UDP-Nmap scan for {ip_address}{bcolors.ENDC}")
    print(results)
    #UNICORNSCAN = f"unicornscan -mU -I {ip_address} > ../reports/{ip_address}/unicorn_udp_{ip_address}.txt"
    #run(UNICORNSCAN)
    #print(f"{bcolors.OKGREEN}INFO: CHECK FILE - Finished with UNICORNSCAN for {ip_address}{bcolors.ENDC}")

def udpTopScan(ip_address):
    print(f"{bcolors.HEADER}INFO: Detecting UDP on Top 200 ports on {ip_address}{bcolors.ENDC}")
    cmd = f"nmap -n -Pn -A -sC -sU -T 3 --top-ports 200 -oA '../reports/{ip_address}/udp_{ip_address}_200' {ip_address}"
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with UDP-Nmap Top 200 scan for {ip_address}{bcolors.ENDC}")
    print(results)

def sshScan(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected SSH on {ip_address}:{port}{bcolors.ENDC}")
    connect_to_port(ip_address, port, "ssh")
    cmd = (f"nmap -n -sV -Pn -p {port} --script=ssh-auth-methods,ssh-hostkey,ssh-run,sshv1"
           f" -oN '../reports/{ip_address}/ssh_{ip_address}.nmap' {ip_address}")
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with SSH-Nmap-scan for {ip_address}{bcolors.ENDC}")
    print(results)

def pop3Scan(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected POP3 on {ip_address}:{port}{bcolors.ENDC}")
    connect_to_port(ip_address, port, "pop3")
    cmd = (f"nmap -n -sV -Pn -p {port} --script=pop3-brute,pop3-capabilities,pop3-ntlm-info"
           f" -oN '../reports/{ip_address}/pop3_{ip_address}.nmap' {ip_address}")
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with POP3-Nmap-scan for {ip_address}:{port}{bcolors.ENDC}")
    print(results)

def snmpEnum(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected SNMP on {ip_address}:{port}{bcolors.ENDC}")
    onesixtyone_results = run(f"onesixtyone {ip_address} > ../reports/{ip_address}/onesixtyone_{ip_address}.txt 2>/dev/null")
    snmpdetect = 0
    if onesixtyone_results:
        if "Windows" in onesixtyone_results:
            results = onesixtyone_results.split("Software: ")[1]
            snmpdetect = 1
        elif "Linux" in onesixtyone_results:
            results = onesixtyone_results.split("[public] ")[1]
            snmpdetect = 1
        if snmpdetect == 1:
            print(f"{bcolors.OKGREEN}[*] SNMP running on {ip_address}; OS Detect: {results}")
            run(f"snmpwalk -c public -v1 {ip_address} 1 > ../reports/{ip_address}/snmpwalk_{ip_address}.txt 2>/dev/null")

    snmp_cmd = (f"nmap -n -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes"
                f" -oN '../reports/{ip_address}/snmp_{ip_address}.nmap' {ip_address}")
    results_snmp = run(snmp_cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with SNMP-Nmap-scan for {ip_address}:{port}{bcolors.ENDC}")
    print(results_snmp)

def nfsScan(ip_address, port):
    print(f"{bcolors.HEADER}INFO: Detected RPCBIND on {ip_address}:{port}{bcolors.ENDC}")
    cmd = f"nmap -n -sS -Pn -p {port} --script=nfs* -oN '../reports/{ip_address}/nfs_{ip_address}.nmap' {ip_address}"
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with NFS-Nmap-scan for {ip_address}:{port}{bcolors.ENDC}")
    print(results)
    write_to_file(ip_address, "nfs", results)

def masscan(ip_address):
    ip_address = ip_address.strip()
    print(f"{bcolors.OKGREEN}INFO: Running masscan for {ip_address}{bcolors.ENDC}")

    #cmd = f"masscan -e tun0 -p1-65535,U:1-65535 --rate 300 --interactive {ip_address} -oG '../reports/{ip_address}/masscan.txt'"
    #cmd = f"masscan -e eth0 --router-mac 8c-85-90-00-1c-88 -p1-65535,U:1-65535 --rate 1000 {ip_address} | tee '../reports/{ip_address}/masscan.txt'"
    cmd = f"masscan -e tun0 -p1-65535,U:1-65535 --rate 1000 {ip_address} | tee '../reports/{ip_address}/masscan.txt'"
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    output = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with masscan for {ip_address}{bcolors.ENDC}")
    print(output)

    # Get discovered TCP ports from the masscan output, sort them and run nmap for those
    tcp_results = re.findall(r'port (\d*)/tcp', output)
    if tcp_results:
        tcp_ports = ','.join(str(p) for p in sorted({int(p) for p in tcp_results}))
        multiprocessing.Process(target=nmapScan, args=(ip_address, tcp_ports)).start()

    # Get discovered UDP ports from the masscan output, sort them and run nmap for those
    udp_results = re.findall(r'port (\d*)/udp', output)
    if udp_results:
        udp_ports = ','.join(str(p) for p in sorted({int(p) for p in udp_results}))
        multiprocessing.Process(target=udpScan, args=(ip_address, udp_ports)).start()
    else:
        multiprocessing.Process(target=udpTopScan, args=(ip_address,)).start()

def nmapScan(ip_address, ports):
    ip_address = ip_address.strip()
    print(f"{bcolors.OKGREEN}INFO: Running general TCP nmap scans for {ip_address}{bcolors.ENDC}")

    cmd = f"nmap -n -A -p {ports} {ip_address} -oA '../reports/{ip_address}/tcp_{ip_address}'"
    print(f"{bcolors.HEADER}{cmd}{bcolors.ENDC}")
    results = run(cmd)
    print(f"{bcolors.OKGREEN}INFO: RESULT BELOW - Finished with Nmap scan for {ip_address}{bcolors.ENDC}")
    print(results)

    write_to_file(ip_address, "portscan", results)
    serv_dict = {}
    for line in results.splitlines():
        line = line.strip()
        if "tcp" in line and "open" in line and "Discovered" not in line:
            line = re.sub(r' +', ' ', line)
            parts = line.split(" ")
            service = parts[2]
            port = parts[0]
            serv_dict.setdefault(service, []).append(port)

    # go through the service dictionary to call additional targeted enumeration functions
    called_smbEnum = False
    for serv, ports in serv_dict.items():
        port_nums = [p.split("/")[0] for p in ports]
        if serv == "http":
            for port in port_nums:
                multProc(httpEnum, ip_address, port)
        elif serv in ("https", "ssl/https"):
            for port in port_nums:
                multProc(httpsEnum, ip_address, port)
        elif "smtp" in serv:
            for port in port_nums:
                multProc(smtpEnum, ip_address, port)
        elif "ftp" in serv:
            for port in port_nums:
                multProc(ftpEnum, ip_address, port)
        elif "microsoft-ds" in serv or serv == "netbios-ssn":
            multProc(smbNmap, ip_address, ",".join(port_nums))
            if not called_smbEnum:
                multProc(smbEnum, ip_address, "445")
                called_smbEnum = True
        elif "ms-sql" in serv:
            for port in port_nums:
                multProc(mssqlEnum, ip_address, port)
        elif "mysql" in serv:
            for port in port_nums:
                multProc(mysqlEnum, ip_address, port)
        elif "ssh" in serv:
            for port in port_nums:
                multProc(sshScan, ip_address, port)
        elif "pop3" in serv:
            for port in port_nums:
                multProc(pop3Scan, ip_address, port)
        elif "snmp" in serv:
            for port in port_nums:
                multProc(snmpEnum, ip_address, port)
        elif "rpcbind" in serv:
            for port in port_nums:
                multProc(nfsScan, ip_address, port)
        elif "oracle" in serv:
            for port in port_nums:
                multProc(oracleEnum, ip_address, port)


if __name__ == '__main__':
    print(bcolors.HEADER)
    print("------------------------------------------------------------")
    print("!!!!                      RECON SCAN                   !!!!!")
    print("!!!!            A multi-process service scanner        !!!!!")
    print("!!!!        dirb, nikto, ftp, ssh, mssql, pop3, tcp    !!!!!")
    print("!!!!                    udp, smtp, smb                 !!!!!")
    print("------------------------------------------------------------")
    print(bcolors.ENDC)

    if len(sys.argv) < 2:
        print("\nUsage: python reconscan.py <ip> <ip> <ip>")
        print("Example: python reconscan.py 192.168.1.101 192.168.1.102\n")
        print("############################################################")
        sys.exit()

    targets = sys.argv[1:]
    existing_dirs = os.listdir("../reports/")

    for scanip in targets:
        scanip = scanip.strip()
        if scanip not in existing_dirs:
            print(f"{bcolors.HEADER}INFO: No folder was found for {scanip}. Setting up folder.{bcolors.ENDC}")
            os.makedirs(f"../reports/{scanip}/exploits")
            os.makedirs(f"../reports/{scanip}/privesc")
            print(f"{bcolors.OKGREEN}INFO: Folder created here: ../reports/{scanip}{bcolors.ENDC}")

        for template, dest in [("windows-template.md", "mapping-windows.md"),
                                ("linux-template.md",   "mapping-linux.md")]:
            dest_path = Path(f"../reports/{scanip}/{dest}")
            shutil.copy(f"../templates/{template}", dest_path)
            dest_path.write_text(dest_path.read_text().replace("INSERTIPADDRESS", scanip))

        print(f"{bcolors.OKGREEN}INFO: Added pentesting templates: ../reports/{scanip}{bcolors.ENDC}")
        multiprocessing.Process(target=masscan, args=(scanip,)).start()
