# oscp

OSCP exam preparation toolkit containing automated recon scripts and attack checklists.

> **Warning:** These scripts include invasive scans (dirb, nikto, nmap vulnerability scripts). Only run them against machines you have explicit permission to attack.

## Scripts

### reconscan.py

The main entry point. Based on the script by [Mike Czumak](http://www.securitysift.com/offsec-pwb-oscp/), but heavily rewritten. Runs multithreaded recon against one or more target hosts using masscan, nmap, dirb, nikto, and a range of service-specific enumeration tools.

Requires sudo for UDP scanning.

```bash
cd recon_enum
sudo python reconscan.py <ip> [<ip> ...]
```

**Services enumerated:** HTTP/S, FTP, SSH, SMTP, SMB, MySQL, MSSQL, Oracle, POP3, SNMP, NFS/RPC

**Tools used:** masscan, nmap, dirb, nikto, curl, sslscan, enum4linux, smbmap, nbtscan, onesixtyone, snmpwalk, droopescan (optional)

### dirbust.py

Standalone web directory brute-forcer. Runs dirb against a target URL across multiple wordlists and collects discovered paths.

```bash
python dirbust.py <url> <port> <scan-name> <log-dir>
```

Example:
```bash
python dirbust.py http://192.168.57.4 80 metasploitable "../reports"
```

### sshrecon.py

Standalone SSH credential brute-forcer. Uses hydra with the bundled wordlists to test SSH credentials against a target.

```bash
python sshrecon.py <ip> <port> <log-dir>
```

Example:
```bash
python sshrecon.py 192.168.57.4 22 "../reports"
```

## Setup

```bash
sudo bash setup.sh
```

This installs `reconscan` as a system command so it can be run from anywhere.

## Reports

Each target gets its own folder under `reports/<ip>/` containing:

- `mapping-linux.md` / `mapping-windows.md` — populated from templates, used as attack checklists
- Nmap, dirb, nikto, and other scan output files
- `exploits/` and `privesc/` subdirectories for notes

The `reports/` directory is gitignored.

## Templates

Two markdown checklists (`linux-template.md`, `windows-template.md`) divided into three sections: **recon**, **privilege escalation**, and **loot**. `reconscan.py` automatically populates them with the target IP and scan results.

## Requirements

- Python
- nmap, masscan, dirb, nikto, hydra, curl, sslscan
- enum4linux, smbmap, nbtscan, onesixtyone, snmpwalk
- droopescan (optional, for Drupal detection)

### macOS notes

- `dirb` is not in Homebrew — build from source: https://github.com/v0re/dirb
- `masscan` can be installed via `brew install masscan`
- Metasploitable 2's SSH requires legacy algorithm support in `~/.ssh/config`:

```
Host <target-ip>
  MACs hmac-sha1,hmac-md5
  KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
  HostKeyAlgorithms +ssh-rsa
```
