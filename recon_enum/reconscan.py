#!/usr/bin/env python
import subprocess
import multiprocessing
import os
import sys
import socket
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Creates a function for multiprocessing. Several things at once.
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip, port))
    jobs.append(p)
    p.start()
    return

def connect_to_port(ip_address, port, service):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, int(port)))
    banner = s.recv(1024)

    if service == "ftp":
        s.send("USER anonymous\r\n")
        user = s.recv(1024)
        s.send("PASS anonymous\r\n")
        password = s.recv(1024)
        total_communication = banner + "\r\n" + user + "\r\n" + password
        write_to_file(ip_address, "ftp-connect", total_communication)
    elif service == "smtp":
        total_communication = banner + "\r\n"
        write_to_file(ip_address, "smtp-connect", total_communication)
    elif service == "ssh":
        total_communication = banner
        write_to_file(ip_address, "ssh-connect", total_communication)
    elif service == "pop3":
        s.send("USER root\r\n")
        user = s.recv(1024)
        s.send("PASS root\r\n")
        password = s.recv(1024)
        total_communication = banner +  user +  password
        write_to_file(ip_address, "pop3-connect", total_communication)
    s.close()

def write_to_file(ip_address, enum_type, data):

    file_path_linux = '../reports/%s/mapping-linux.md' % (ip_address)
    file_path_windows = '../reports/%s/mapping-windows.md' % (ip_address)
    paths = [file_path_linux, file_path_windows]
    print bcolors.OKGREEN + "INFO: Writing " + enum_type + " to template files:\n" + file_path_linux + "\n" + file_path_windows + bcolors.ENDC

    search_string = ''
    if enum_type == "portscan":
        search_string = "INSERTTCPSCAN"
    if enum_type == "dirb":
        search_string = "INSERTDIRBSCAN"
    if enum_type == "nikto":
        search_string = "INSERTNIKTOSCAN"
    if enum_type == "ftp-connect":
        search_string = "INSERTFTPTEST"
    if enum_type == "smtp-connect":
        search_string = "INSERTSMTPCONNECT"
    if enum_type == "ssh-connect":
        search_string = "INSERTSSHCONNECT"
    if enum_type == "pop3-connect":
        search_string = "INSERTPOP3CONNECT"
    if enum_type == "curl":
        search_string = "INSERTCURLHEADER"
    if enum_type == "nfs":
        search_string = "INSERTRPCBIND"

    # Search and replace
    for path in paths:
        f = open(path, 'r')
        filedata = f.read()
        f.close()

        newdata = filedata.replace(search_string, data)

        f = open(path, 'w')
        f.write(newdata)
        f.close()

    return

def dirb(ip_address, port, url_start, wordlist="/usr/share/wordlists/dirb/common.txt"):
    print bcolors.HEADER + "INFO: Starting dirb scan for " + ip_address + ":" + port + bcolors.ENDC
    DIRBSCAN = "dirb %s://%s:%s %s -o ../reports/%s/dirb-%s-%s.txt -r" % (url_start, ip_address, port, wordlist, ip_address, ip_address, port)
    print bcolors.HEADER + DIRBSCAN + bcolors.ENDC
    results_dirb = subprocess.check_output(DIRBSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with dirb scan for " + ip_address + bcolors.ENDC
    print results_dirb
    write_to_file(ip_address, "dirb", results_dirb)
    return

def nikto(ip_address, port, url_start):
    print bcolors.HEADER + "INFO: Starting nikto scan for " + ip_address + ":" + port + bcolors.ENDC
    NIKTOSCAN = "nikto -h %s://%s:%s -o ../reports/%s/nikto-%s-%s.txt" % (url_start, ip_address, port, ip_address, ip_address, port)
    print bcolors.HEADER + NIKTOSCAN + bcolors.ENDC
    results_nikto = subprocess.check_output(NIKTOSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with NIKTO-scan for " + ip_address + bcolors.ENDC
    print results_nikto
    write_to_file(ip_address, "nikto", results_nikto)
    return

def httpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected http on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC

    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address, port, "http"))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address, port, "http"))
    nikto_process.start()

    CURLSCAN = "curl -I http://%s" % (ip_address)
    print bcolors.HEADER + CURLSCAN + bcolors.ENDC
    curl_results = subprocess.check_output(CURLSCAN, shell=True)
    write_to_file(ip_address, "curl", curl_results)
    HTTPSCAN = "nmap -n -sV -Pn -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN ../reports/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + HTTPSCAN + bcolors.ENDC

    http_results = subprocess.check_output(HTTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTP-SCAN for " + ip_address + bcolors.ENDC
    print http_results
    
    if "Drupal" in http_results:
        print bcolors.HEADER + "INFO: Detected Drupal on " + ip_address + ":" + port + bcolors.ENDC
        print bcolors.HEADER + "INFO: Performing Drupal scan for " + ip_address + ":" + port + bcolors.ENDC
        DRUPALSCAN = "droopescan scan drupal -u http://%s:%s | tee ../reports/%s/droopescan_%s.txt" % (ip_address, port, ip_address, port)
        drupal_results = subprocess.check_output(DRUPALSCAN, shell=True)
        print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with DRUPAL-SCAN for " + ip_address + bcolors.ENDC
        print drupal_results

    return

def httpsEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected https on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC

    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address, port, "https"))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address, port, "https"))
    nikto_process.start()

    SSLSCAN = "sslscan %s:%s >> ../reports/%s/ssl_scan_%s_%s.txt" % (ip_address, port, ip_address, ip_address, port)
    print bcolors.HEADER + SSLSCAN + bcolors.ENDC
    subprocess.check_output(SSLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with SSLSCAN for " + ip_address + ":" + port + bcolors.ENDC

    HTTPSCANS = "nmap -n -sV -Pn -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN ../reports/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + HTTPSCANS + bcolors.ENDC
    https_results = subprocess.check_output(HTTPSCANS, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTPS-scan for " + ip_address + ":" + port + bcolors.ENDC
    print https_results
    return

def mssqlEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected MS-SQL on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port + bcolors.ENDC
    MSSQLSCAN = "nmap -n -sV -Pn -p %s --script=ms-sql-empty-password,ms-sql-info,ms-sql-config,ms-sql-hasdbaccess,ms-sql-dump-hashes --script-args=mssql.instance-port=%s -oN ../reports/%s/mssql_%s.nmap %s" % (port, port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + MSSQLSCAN + bcolors.ENDC
    mssql_results = subprocess.check_output(MSSQLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with MSSQL-scan for " + ip_address + ":" + port + bcolors.ENDC
    print mssql_results
    return

def mysqlEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected MySQL on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap mysql script scan for " + ip_address + ":" + port + bcolors.ENDC
    MYSQLSCAN = "nmap -n -sV -Pn -p %s --script=mysql-empty-password,mysql-enum,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oN ../reports/%s/mysql_%s.nmap %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + MYSQLSCAN + bcolors.ENDC
    mysql_results = subprocess.check_output(MYSQLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with MySQL-scan for " + ip_address + ":" + port + bcolors.ENDC
    print mysql_results
    return

def oracleEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected Oracle on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap oracle script scan for " + ip_address + ":" + port + bcolors.ENDC
    ORACLESCAN = "nmap -n -sV -Pn -p %s --script=oracle-tns-version,oracle-sid-brute,oracle-enum-users -oN ../reports/%s/oracle_%s.nmap %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + ORACLESCAN + bcolors.ENDC
    oracle_results = subprocess.check_output(ORACLESCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with Oracle-scan for " + ip_address + ":" + port + bcolors.ENDC
    print oracle_results
    return

def smtpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected smtp on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "smtp")
    SMTPSCAN = "nmap -n -sV -Pn -p %s --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 %s -oN ../reports/%s/smtp_%s.nmap" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + SMTPSCAN + bcolors.ENDC
    smtp_results = subprocess.check_output(SMTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMTP-scan for " + ip_address + ":" + port + bcolors.ENDC
    print smtp_results
    return

def smbNmap(ip_address, ports):
    print bcolors.HEADER + "INFO: Detected SMB on " + ip_address + " on " + ports
    smb_nmap = "nmap -n -p %s --script=smb-enum-shares,smb-ls,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,msrpc-enum,smb-vuln-cve2009-3103,smb-vuln-cve-2017-7494,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010 %s -oN ../reports/%s/smb_%s_%s.nmap" % (ports, ip_address, ip_address, ip_address, ports.replace(",", "_"))
    smbNmap_results = subprocess.check_output(smb_nmap, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMB-Nmap-scan for " + ip_address + " for ports " + ports + bcolors.ENDC
    print smbNmap_results
    return

def smbEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected SMB on " + ip_address
    enum4linux = "enum4linux -a %s > ../reports/%s/enum4linux_%s.txt 2>/dev/null" % (ip_address, ip_address, ip_address)
    enum4linux_results = subprocess.check_output(enum4linux, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with SMB-enum4linux for " + ip_address + bcolors.ENDC
    print enum4linux_results
    smbmap = "smbmap -H %s" % (ip_address)
    smbmap_results = subprocess.check_output(smbmap, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMB-smbmap for " + ip_address + bcolors.ENDC
    print smbmap_results
    NBTSCAN = "nbtscan -r %s/32" % (ip_address)
    nbtresults = subprocess.check_output(NBTSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMB-nbtscan for " + ip_address + bcolors.ENDC
    print nbtresults
    return

def ftpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected ftp on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "ftp")
    FTPSCAN = "nmap -n -sV -Pn -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '../reports/%s/ftp_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + FTPSCAN + bcolors.ENDC
    results_ftp = subprocess.check_output(FTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with FTP-Nmap-scan for " + ip_address + bcolors.ENDC
    print results_ftp
    return

def udpScan(ip_address, ports):
    print bcolors.HEADER + "INFO: Detecting UDP on " + ip_address + bcolors.ENDC
    UDPSCAN = "nmap -n -Pn -A -sC -sU -T 3 -p %s -oA '../reports/%s/udp_%s' %s"  % (ports, ip_address, ip_address, ip_address)
    print bcolors.HEADER + UDPSCAN + bcolors.ENDC
    udpscan_results = subprocess.check_output(UDPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with UDP-Nmap scan for " + ip_address + bcolors.ENDC
    print udpscan_results
    #UNICORNSCAN = "unicornscan -mU -I %s > ../reports/%s/unicorn_udp_%s.txt" % (ip_address, ip_address, ip_address)
    #subprocess.check_output(UNICORNSCAN, shell=True)
    #print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with UNICORNSCAN for " + ip_address + bcolors.ENDC

def udpTopScan(ip_address):
    print bcolors.HEADER + "INFO: Detecting UDP on Top 200 ports on " + ip_address + bcolors.ENDC
    UDPSCAN = "nmap -n -Pn -A -sC -sU -T 3 --top-ports 200 -oA '../reports/%s/udp_%s_200' %s"  % (ip_address, ip_address, ip_address)
    print bcolors.HEADER + UDPSCAN + bcolors.ENDC
    udpscan_results = subprocess.check_output(UDPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with UDP-Nmap Top 200 scan for " + ip_address + bcolors.ENDC
    print udpscan_results

def sshScan(ip_address, port):
    print bcolors.HEADER + "INFO: Detected SSH on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "ssh")
    SSHSCAN = "nmap -n -sV -Pn -p %s --script=ssh-auth-methods,ssh-hostkey,ssh-run,sshv1 -oN '../reports/%s/ssh_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + SSHSCAN + bcolors.ENDC
    results_ssh = subprocess.check_output(SSHSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SSH-Nmap-scan for " + ip_address + bcolors.ENDC
    print results_ssh
    return

def pop3Scan(ip_address, port):
    print bcolors.HEADER + "INFO: Detected POP3 on " + ip_address + ":" + port + bcolors.ENDC
    connect_to_port(ip_address, port, "pop3")
    POP3SCAN = "nmap -n -sV -Pn -p %s --script=pop3-brute,pop3-capabilities,pop3-ntlm-info -oN '../reports/%s/pop3_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + POP3SCAN + bcolors.ENDC
    results_pop3 = subprocess.check_output(POP3SCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with POP3-Nmap-scan for " + ip_address + ":" + port + bcolors.ENDC
    print results_pop3
    return

def snmpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected SNMP on " + ip_address + ":" + port + bcolors.ENDC
    onesixtyone = "onesixtyone %s > ../reports/%s/onesixtyone_%s.txt 2>/dev/null" % (ip_address, ip_address, ip_address)
    onesixtyone_results = subprocess.check_output(onesixtyone, shell=True)
    if onesixtyone_results != "":
        if "Windows" in onesixtyone_results:
            results = onesixtyone_results.split("Software: ")[1]
            snmpdetect = 1
        elif "Linux" in onesixtyone_results:
            results = onesixtyone_results.split("[public] ")[1]
            snmpdetect = 1
        if snmpdetect == 1:
            print bcolors.OKGREEN + "[*] SNMP running on " + ip_address + "; OS Detect: " + results
            SNMPWALK = "snmpwalk -c public -v1 %s 1 > ../reports/%s/snmpwalk_%s.txt 2>/dev/null" % (ip_address, ip_address, ip_address)
            results = subprocess.check_output(SNMPWALK, shell=True)

    SNMPSCAN = "nmap -n -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes -oN '../reports/%s/snmp_%s.nmap' %s" % (ip_address, ip_address, ip_address)
    results_snmp = subprocess.check_output(SNMPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SNMP-Nmap-scan for " + ip_address + ":" + port + bcolors.ENDC
    print results_snmp
    return

def nfsScan(ip_address, port):
    print bcolors.HEADER + "INFO: Detected RPCBIND on " + ip_address + ":" + port + bcolors.ENDC
    NFSSCAN = "nmap -n -sS -Pn -p %s --script=nfs* -oN '../reports/%s/nfs_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + NFSSCAN + bcolors.ENDC
    results_nfs = subprocess.check_output(NFSSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with NFS-Nmap-scan for " + ip_address + ":" + port + bcolors.ENDC
    print results_nfs

    write_to_file(ip_address, "nfs", results_nfs)
    return

def masscan(ip_address):
    ip_address = ip_address.strip()
    print bcolors.OKGREEN + "INFO: Running masscan for " + ip_address + bcolors.ENDC

    #MASSCAN = "masscan -e tun0 -p1-65535,U:1-65535 --rate 300 --interactive %s -oG '../reports/%s/masscan.txt'" % (ip_address, ip_address)
    #MASSCAN = "masscan -e eth0 --router-mac 8c-85-90-00-1c-88  -p1-65535,U:1-65535 --rate 1000 %s | tee '../reports/%s/masscan.txt'" % (ip_address, ip_address)
    MASSCAN = "masscan -e tun0 -p1-65535,U:1-65535 --rate 1000 %s | tee '../reports/%s/masscan.txt'" % (ip_address, ip_address)
    print bcolors.HEADER + MASSCAN + bcolors.ENDC
    output = subprocess.check_output(MASSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with masscan for " + ip_address + bcolors.ENDC
    print output
    
    # Get discovered TCP ports from the masscan output, sort them and run nmap for those
    results = re.findall('port (\d*)/tcp', output)
    if results:
        tcp_ports = list({int(port) for port in results})
        tcp_ports.sort()
        tcp_ports = ''.join(str(tcp_ports)[1:-1].split())
        
        # Running nmap
        p = multiprocessing.Process(target=nmapScan, args=(ip_address, tcp_ports))
        p.start()

    # Get discovered UDP ports from the masscan output, sort them and run nmap for those
    results = re.findall('port (\d*)/udp', output)
    if results:
        udp_ports = list({int(port) for port in results})
        udp_ports.sort()
        udp_ports = ''.join(str(udp_ports)[1:-1].split())
        
        # Running nmap
        p = multiprocessing.Process(target=udpScan, args=(ip_address, udp_ports))
        p.start()
    else:
        # Running nmap
        p = multiprocessing.Process(target=udpTopScan, args=(ip_address,))
        p.start()

def nmapScan(ip_address, ports):
    ip_address = ip_address.strip()
    print bcolors.OKGREEN + "INFO: Running general TCP nmap scans for " + ip_address + bcolors.ENDC

    TCPSCAN = "nmap -n -A -p %s %s -oA '../reports/%s/tcp_%s'"  % (ports, ip_address, ip_address, ip_address)
    print bcolors.HEADER + TCPSCAN + bcolors.ENDC
    results = subprocess.check_output(TCPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with Nmap scan for " + ip_address + bcolors.ENDC
    print results

    #p = multiprocessing.Process(target=udpScan, args=(ip_address,))
    #p.start()

    write_to_file(ip_address, "portscan", results)
    lines = results.split("\n")
    serv_dict = {}
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not "Discovered" in line:
            # print line
            while "  " in line:
                line = line.replace("  ", " ")
            linesplit = line.split(" ")
            service = linesplit[2] # grab the service name

            port = line.split(" ")[0] # grab the port/proto

            if service in serv_dict:
                ports = serv_dict[service] # if the service is already in the dict, grab the port list

            ports.append(port)
            serv_dict[service] = ports # add service to the dictionary along with the associated port(2)

    # go through the service dictionary to call additional targeted enumeration functions
    called_smbEnum = False
    for serv in serv_dict:
        ports = serv_dict[serv]
        if serv == "http":
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif (serv == "https") or (serv == "ssl/https"):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpsEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum, ip_address, port)
        elif ("microsoft-ds" in serv) or (serv == "netbios-ssn"):
            multProc(smbNmap, ip_address, ",".join(port.split("/")[0] for port in ports))
            if not called_smbEnum:
                # call SMB enum only once
                multProc(smbEnum, ip_address, "445")
                called_smbEnum = True
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssqlEnum, ip_address, port)
        elif "mysql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mysqlEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshScan, ip_address, port)
        elif "pop3" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(pop3Scan, ip_address, port)
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(snmpEnum, ip_address, port)
        elif "rpcbind" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(nfsScan, ip_address, port)
        elif "oracle" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(oracleEnum, ip_address, port)

    return


print bcolors.HEADER
print "------------------------------------------------------------"
print "!!!!                      RECON SCAN                   !!!!!"
print "!!!!            A multi-process service scanner        !!!!!"
print "!!!!        dirb, nikto, ftp, ssh, mssql, pop3, tcp    !!!!!"
print "!!!!                    udp, smtp, smb                 !!!!!"
print "------------------------------------------------------------"



if len(sys.argv) < 2:
    print ""
    print "Usage: python reconscan.py <ip> <ip> <ip>"
    print "Example: python reconscan.py 192.168.1.101 192.168.1.102"
    print ""
    print "############################################################"
    sys.exit()

print bcolors.ENDC

if __name__ == '__main__':

    # Setting ip targets
    targets = sys.argv
    targets.pop(0)

    dirs = os.listdir("../reports/")
    for scanip in targets:
        scanip = scanip.rstrip()
        if not scanip in dirs:
            print bcolors.HEADER + "INFO: No folder was found for " + scanip + ". Setting up folder." + bcolors.ENDC
            subprocess.check_output("mkdir ../reports/" + scanip, shell=True)
            subprocess.check_output("mkdir ../reports/" + scanip + "/exploits", shell=True)
            subprocess.check_output("mkdir ../reports/" + scanip + "/privesc", shell=True)
            print bcolors.OKGREEN + "INFO: Folder created here: " + "../reports/" + scanip + bcolors.ENDC
        subprocess.check_output("cp ../templates/windows-template.md ../reports/" + scanip + "/mapping-windows.md", shell=True)
        subprocess.check_output("cp ../templates/linux-template.md ../reports/" + scanip + "/mapping-linux.md", shell=True)
        print bcolors.OKGREEN + "INFO: Added pentesting templates: " + "../reports/" + scanip + bcolors.ENDC
        subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' ../reports/" + scanip + "/mapping-windows.md", shell=True)
        subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' ../reports/" + scanip + "/mapping-linux.md", shell=True)

        p = multiprocessing.Process(target=masscan, args=(scanip,))
        p.start()
