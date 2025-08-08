# [Attacking Enterprise Networks](https://academy.hackthebox.com/module/details/163)

## Table of Contents

- [ ] Lateral Movement and Privilege Escalation
	- [ ] Lateral Movement
	- [ ] Active Directory Compromise
	- [ ] Post-Exploitation

---
---

## Lateral Movement and Privilege Escalation

> After pillaging the host `DEV01`, we found the following set of credentials by dumping LSA secrets: `hporter:Gr8hambino!`.

### Lateral Movement

> Since we've got our hooks deep into `DEV01` we can use it as our staging area for launching further attacks.
> We'll use the [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) collector to enumerate all possible AD objects and then ingest the data into the BloodHound GUI for review.

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

### Active Directory Compromise

> To recap, we dug through the Active Directory environment and obtained the following credential pair: `mssqladm:DBAilfreight1!`.

> Digging into the BloodHound data we see that we have `GenericWrite` over the `ttimmons` user. Using this we can set a fake SPN on the `ttimmons account` and perform a targeted Kerberoasting attack. If this user is using a weak password then we can crack it and proceed onwards.

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

```
┌──(nabla㉿kali)-[~]
└─$ 
```

---

### Post-Exploitation

> Once we've compromised the domain, depending on the assessment type, our work is not over. There are many things we can do to add additional value to our clients.
- **Domain Password Analysis - Cracking NTDS**. After we have dumped the NTDS database we can perform offline password cracking with Hashcat. Once we've exhausted all possible rules and wordlists on our cracking rig we should use a tool such as [DPAT](https://github.com/clr2of8/DPAT) to perform a domain password analysis.
- **Active Directory Security Audit**. We can provide extra value to our clients by digging deeper into Active Directory and finding best practice recommendations and delivering them in the appendices of our report. The tool [PingCastle](https://www.pingcastle.com/) is excellent for auditing the overall security posture of the domain and we can pull many different items from the report it generates to give our client recommendations on additional ways they can harden their AD environment.
- **Hunting for Sensitive Data/Hosts**. Once we've gained access to the Domain Controller we can likely access most any resources in the domain. If we want to demonstrate impact for our clients a good spot to start is going back to the file shares to see what other types of data we can now view.

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

```
┌──(nabla㉿kali)-[~]
└─$ 
```

---
---
