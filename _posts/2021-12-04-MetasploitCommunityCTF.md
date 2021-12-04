---
layout: post
title: Metasploit Community CTF
date: 2021-12-04
type: post
tags:
- Writeup
- Hacking
- Metasploit
- CTF
permalink: /2021/12/MetasploitCommunityCTF
img: 2021/12/MetasploitCTF/Logo.png
---

This weekend, I participated in the [Metasploit Community CTF](https://metasploitctf.com/) with a team of members of the [Hackfest community](https://hackfest.ca/)

* [ava_kyoko](https://github.com/a42qc)
* [fil](https://lolkatz.github.io/will-hack-for-coffee/)
* [neoh](https://mikelizotte.ca/)

This was not a CTF with a Jeopardy still challenge board. We were given two VMs, one to use as a jump box, and one to attack. 

![Instructions Step 1](/assets/images/2021/12/MetasploitCTF/InstructionsStep1.png "Instructions Step 1")
![Instructions Step 2](/assets/images/2021/12/MetasploitCTF/InstructionsStep2.png "Instructions Step 2")

When I went to the list of challenges, they were all named after a deck of cards. 

![Challenges](/assets/images/2021/12/MetasploitCTF/Challenges.png "Challenges")

But clicking on one did not really help figuring out what I needed to do. 

![Challenge Description](/assets/images/2021/12/MetasploitCTF/ChallengeDescription.png "Challenge Description")

But at least I knew I needed to find images and calculate their MD5 checksum. 

> When you find a challenge flag, calculate and submit the MD5 checksum of the PNG image to receive points! Hashes are not case sensitive.

## Enumeration

So I connected to the jump box and started enumerating the opened port on the target machine. 

```bash
$ ssh kali@18.215.161.123 -i metasploit_ctf_kali_ssh_key.pem
Linux kali 5.10.0-kali9-cloud-amd64 #1 SMP Debian 5.10.46-4kali1 (2021-08-09) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Dec  4 16:47:55 2021 from 24.48.3.104
┏━(Message from Kali developers)
┃
┃ This is a cloud installation of Kali Linux. Learn more about
┃ the specificities of the various cloud images:
┃ ⇒ https://www.kali.org/docs/troubleshooting/common-cloud-setup/
┃
┃ We have kept /usr/bin/python pointing to Python 2 for backwards
┃ compatibility. Learn how to change this and avoid this message:
┃ ⇒ https://www.kali.org/docs/general-use/python3-transition/
┃
┗━(Run: “touch ~/.hushlogin” to hide this message)
┌──(kali㉿kali)-[~]
└─$ nmap 172.17.26.149 -A -oN nmap.txt                        
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-04 17:15 UTC

# Nmap 7.92 scan initiated Sat Dec  4 17:15:31 2021 as: nmap -A -oN nmap.txt 172.17.26.149
Nmap scan report for 172.17.26.149
Host is up (0.00100s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Werkzeug httpd 2.0.1 (Python 3.9.7)
|_http-title: Metasploit CTF
|_http-server-header: Werkzeug/2.0.1 Python/3.9.7
443/tcp   open  http    Apache httpd 2.4.51
|_http-title: Site doesn't have a title (text/html).
| http-git: 
|   172.17.26.149:443/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: More enthusiasm 
|_http-server-header: Apache/2.4.51 (Debian)
8080/tcp  open  http    WSGIServer 0.2 (Python 3.8.10)
|_http-server-header: WSGIServer/0.2 CPython/3.8.10
|_http-title: Cookies Galore
10010/tcp open  rxapi?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     X-Frame-Options: SAMEORIGIN
|     X-XSS-Protection: 1; mode=block
|     X-Content-Type-Options: nosniff
|     X-Download-Options: noopen
|     X-Permitted-Cross-Domain-Policies: none
|     Referrer-Policy: strict-origin-when-cross-origin
|     Link: </assets/application-b8c697e38f5ecf278f5ea80d758553eae08a5635194a002f5b5dc51db0ef1145.css>; rel=preload; as=style; nopush,</packs/js/application-e39138e5c24b0104f8e3.js>; rel=preload; as=script; nopush
|     Content-Type: text/html; charset=utf-8
|     ETag: W/"dcb9434a26f0c0cd3b35727278027ef0"
|     Cache-Control: max-age=0, private, must-revalidate
|     Set-Cookie: 321dece65c1d444b49c690630b2faca0d6e2f6e41cc5dacb19f2242ea6f745a44437e0f524427181e28f71d651f5982d9e36ba9542824f09cb103c7515d50a21ad2e4edd30573074c2d62296e6fb6ac5a4460060a646d108ede4a1793038eb061e8b27194ce54b5fbd3804f7ec76182fda465e6c51fc822eacc230b2f1721294=0n8IpiK%2BBmgDvdB4mCYBYvw%2Bgm3lkrJuMrKuvquMAlNdF9LjJ2H
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     X-Request-Id: bde53bb9-1e9f-4282-9f0a-e20a082fbf98
|     X-Runtime: 0.001649
|     Content-Length: 1722
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>The page you were looking for doesn't exist (404)</title>
|     <meta name="viewport" content="width=device-width,initial-scale=1">
|     <style>
|     .rails-default-error-page {
|     background-color: #EFEFEF;
|     color: #2E2F30;
|     text-align: center;
|     font-family: arial, sans-serif;
|     margin: 0;
|     .rails-default-error-page div.dialog {
|     width: 95%;
|     max-width: 33em;
|     margin: 4em auto 0;
|     .rails-default-error-page div.dialog > div {
|     border: 1px solid #CCC;
|     border-right-color: #999;
|     border-left-color: #999;
|     border-bottom-color: #BBB;
|     border-top: #B00100 solid 4px;
|     border-top-left-radius: 9px;
|     border-top-right-radius: 9px;
|_    background-color: white
11111/tcp open  http    Thin httpd
| http-title: Web App
|_Requested resource was http://172.17.26.149:11111/index
|_http-server-header: thin
15000/tcp open  hydap?
| fingerprint-strings: 
|   GenericLines: 
|     Welcome to the Student Database Management System!
|     Time is 2021-12-04 17:15:30 +0000.
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input: 
|     Error. Unrecognised choice: 0
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input: 
|     Error. Unrecognised choice: 0
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input:
|   GetRequest: 
|     Welcome to the Student Database Management System!
|     Time is 2021-12-04 17:15:41 +0000.
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input: 
|     Error. Unrecognised choice: 0
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input: 
|     Error. Unrecognised choice: 0
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input:
|   NULL: 
|     Welcome to the Student Database Management System!
|     Time is 2021-12-04 17:15:30 +0000.
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|_    Input:
20000/tcp open  http    SimpleHTTPServer 0.6 (Python 3.7.3)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: SimpleHTTP/0.6 Python/3.7.3
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10010-TCP:V=7.92%I=7%D=12/4%Time=61ABA239%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetReque
SF:st,AF3,"HTTP/1\.0\x20200\x20OK\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-X
SF:SS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosnif
SF:f\r\nX-Download-Options:\x20noopen\r\nX-Permitted-Cross-Domain-Policies
SF::\x20none\r\nReferrer-Policy:\x20strict-origin-when-cross-origin\r\nLin
SF:k:\x20</assets/application-b8c697e38f5ecf278f5ea80d758553eae08a5635194a
SF:002f5b5dc51db0ef1145\.css>;\x20rel=preload;\x20as=style;\x20nopush,</pa
SF:cks/js/application-e39138e5c24b0104f8e3\.js>;\x20rel=preload;\x20as=scr
SF:ipt;\x20nopush\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nETag:
SF:\x20W/\"dcb9434a26f0c0cd3b35727278027ef0\"\r\nCache-Control:\x20max-age
SF:=0,\x20private,\x20must-revalidate\r\nSet-Cookie:\x20321dece65c1d444b49
SF:c690630b2faca0d6e2f6e41cc5dacb19f2242ea6f745a44437e0f524427181e28f71d65
SF:1f5982d9e36ba9542824f09cb103c7515d50a21ad2e4edd30573074c2d62296e6fb6ac5
SF:a4460060a646d108ede4a1793038eb061e8b27194ce54b5fbd3804f7ec76182fda465e6
SF:c51fc822eacc230b2f1721294=0n8IpiK%2BBmgDvdB4mCYBYvw%2Bgm3lkrJuMrKuvquMA
SF:lNdF9LjJ2H")%r(HTTPOptions,75B,"HTTP/1\.0\x20404\x20Not\x20Found\r\nCon
SF:tent-Type:\x20text/html;\x20charset=UTF-8\r\nX-Request-Id:\x20bde53bb9-
SF:1e9f-4282-9f0a-e20a082fbf98\r\nX-Runtime:\x200\.001649\r\nContent-Lengt
SF:h:\x201722\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head>\n\x20\x20<title>Th
SF:e\x20page\x20you\x20were\x20looking\x20for\x20doesn't\x20exist\x20\(404
SF:\)</title>\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=devic
SF:e-width,initial-scale=1\">\n\x20\x20<style>\n\x20\x20\.rails-default-er
SF:ror-page\x20{\n\x20\x20\x20\x20background-color:\x20#EFEFEF;\n\x20\x20\
SF:x20\x20color:\x20#2E2F30;\n\x20\x20\x20\x20text-align:\x20center;\n\x20
SF:\x20\x20\x20font-family:\x20arial,\x20sans-serif;\n\x20\x20\x20\x20marg
SF:in:\x200;\n\x20\x20}\n\n\x20\x20\.rails-default-error-page\x20div\.dial
SF:og\x20{\n\x20\x20\x20\x20width:\x2095%;\n\x20\x20\x20\x20max-width:\x20
SF:33em;\n\x20\x20\x20\x20margin:\x204em\x20auto\x200;\n\x20\x20}\n\n\x20\
SF:x20\.rails-default-error-page\x20div\.dialog\x20>\x20div\x20{\n\x20\x20
SF:\x20\x20border:\x201px\x20solid\x20#CCC;\n\x20\x20\x20\x20border-right-
SF:color:\x20#999;\n\x20\x20\x20\x20border-left-color:\x20#999;\n\x20\x20\
SF:x20\x20border-bottom-color:\x20#BBB;\n\x20\x20\x20\x20border-top:\x20#B
SF:00100\x20solid\x204px;\n\x20\x20\x20\x20border-top-left-radius:\x209px;
SF:\n\x20\x20\x20\x20border-top-right-radius:\x209px;\n\x20\x20\x20\x20bac
SF:kground-color:\x20white");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port15000-TCP:V=7.92%I=7%D=12/4%Time=61ABA239%P=x86_64-pc-linux-gnu%r(N
SF:ULL,F6,"\nWelcome\x20to\x20the\x20Student\x20Database\x20Management\x20
SF:System!\nTime\x20is\x202021-12-04\x2017:15:30\x20\+0000\.\n\nPick\x20on
SF:e\x20of\x20the\x20following\x20options:\n1\.\x20Create\x20new\x20studen
SF:t\x20record\n2\.\x20Show\x20student\x20records\n3\.\x20Update\x20an\x20
SF:existing\x20record\n4\.\x20Delete\x20student\x20record\n5\.\x20Exit\n\n
SF:Input:\x20")%r(GenericLines,272,"\nWelcome\x20to\x20the\x20Student\x20D
SF:atabase\x20Management\x20System!\nTime\x20is\x202021-12-04\x2017:15:30\
SF:x20\+0000\.\n\nPick\x20one\x20of\x20the\x20following\x20options:\n1\.\x
SF:20Create\x20new\x20student\x20record\n2\.\x20Show\x20student\x20records
SF:\n3\.\x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x20student\x
SF:20record\n5\.\x20Exit\n\nInput:\x20\nError\.\x20Unrecognised\x20choice:
SF:\x200\n\nPick\x20one\x20of\x20the\x20following\x20options:\n1\.\x20Crea
SF:te\x20new\x20student\x20record\n2\.\x20Show\x20student\x20records\n3\.\
SF:x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x20student\x20reco
SF:rd\n5\.\x20Exit\n\nInput:\x20\nError\.\x20Unrecognised\x20choice:\x200\
SF:n\nPick\x20one\x20of\x20the\x20following\x20options:\n1\.\x20Create\x20
SF:new\x20student\x20record\n2\.\x20Show\x20student\x20records\n3\.\x20Upd
SF:ate\x20an\x20existing\x20record\n4\.\x20Delete\x20student\x20record\n5\
SF:.\x20Exit\n\nInput:\x20")%r(GetRequest,272,"\nWelcome\x20to\x20the\x20S
SF:tudent\x20Database\x20Management\x20System!\nTime\x20is\x202021-12-04\x
SF:2017:15:41\x20\+0000\.\n\nPick\x20one\x20of\x20the\x20following\x20opti
SF:ons:\n1\.\x20Create\x20new\x20student\x20record\n2\.\x20Show\x20student
SF:\x20records\n3\.\x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x
SF:20student\x20record\n5\.\x20Exit\n\nInput:\x20\nError\.\x20Unrecognised
SF:\x20choice:\x200\n\nPick\x20one\x20of\x20the\x20following\x20options:\n
SF:1\.\x20Create\x20new\x20student\x20record\n2\.\x20Show\x20student\x20re
SF:cords\n3\.\x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x20stud
SF:ent\x20record\n5\.\x20Exit\n\nInput:\x20\nError\.\x20Unrecognised\x20ch
SF:oice:\x200\n\nPick\x20one\x20of\x20the\x20following\x20options:\n1\.\x2
SF:0Create\x20new\x20student\x20record\n2\.\x20Show\x20student\x20records\
SF:n3\.\x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x20student\x2
SF:0record\n5\.\x20Exit\n\nInput:\x20");
Service Info: Host: 172.18.10.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec  4 17:18:14 2021 -- 1 IP address (1 host up) scanned in 163.26 seconds


```


## First flag - Port 80

I decided to start with port 80. It seemed like an easy target. And neoh had already did it. 

I looked at what curl would give me. 
```bash
┌──(kali㉿kali)-[~/eric]
└─$ curl http://172.17.26.149
```

```html
<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

  <title>Metasploit CTF</title>
  <link rel="stylesheet" href="css/styles.css?v=1.0">

  <style>
    body {
        margin: 0;
        font-family: sans-serif;
    }

    .h2 {
        font-size: 2em;
        color: #222;
        margin-bottom: 0.2em;
    }

    .container {
        text-align: center;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
        height: 100vh;
    }
  </style>
</head>

<body>
    <div class="container">
        <div>
            <h2>Welcome!</h2>
            <img src="static/065c6daa-a6e2-4634-b9c6-2eed5274ec47.png" />
            <p>Your remaining challenges are on other ports</p>
        </div>
    </div>
</body>
</html>
```

This is simple HTML that displayed an image. I tried downloading the image.

```bash
──(kali㉿kali)-[~/eric]
└─$ curl http://172.17.26.149/static/065c6daa-a6e2-4634-b9c6-2eed5274ec47.png --output 065c6daa-a6e2-4634-b9c6-2eed5274ec47.png                                                                                                       23 ⨯
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  129k  100  129k    0     0  24.7M      0 --:--:-- --:--:-- --:--:-- 25.3M

┌──(kali㉿kali)-[~/eric]
└─$ md5sum 065c6daa-a6e2-4634-b9c6-2eed5274ec47.png 
3bb0409396fdc4e168c9185929af8347  065c6daa-a6e2-4634-b9c6-2eed5274ec47.png
```

The first flag was 3bb0409396fdc4e168c9185929af8347. 

I knew on which card it would have needed to be submitted because neoh had already did it. 

But the real way to find out was to look at the image. To do that, I used scp to get the image on my machine and then opened the image.

```bash
$ scp -i metasploit_ctf_kali_ssh_key.pem kali@18.215.161.123:~/eric/065c6daa-a6e2-4634-b9c6-2eed5274ec47.png .
```

![First Card](/assets/images/2021/12/MetasploitCTF/065c6daa-a6e2-4634-b9c6-2eed5274ec47.png "First Card")

## SSH Tunnel

I did the first flag, but I realized that using curl to look at HTML files and scp to transfer the files was going to be painful. So I checked how I could use SSH tunnel to be able to query the target directly from my Kali VM. 

After some trial and error, I came up with this command:

```bash
$ ssh -L 8082:172.17.26.149:80 kali@18.215.161.123 -i metasploit_ctf_kali_ssh_key.pem
```

This command open a tunnel from my machine to the jump box (18.215.161.123). Then requests I make on port 8082 will go through the jump box and be sent to the target machine (172.17.26.149) on port 80. For the other challenges, I could just change the target port. 

neoh made [an  image that explains the command](https://mikelizotte.ca/2021/12/04/metasploit-community-ctf-writeup/).

![SSH Tunnel](/assets/images/2021/12/MetasploitCTF/sshTunnel.png "SSH Tunnel")

This way, I could just open by browser to http://localhost:8082/ and view the site on port 80.

![Port 80](/assets/images/2021/12/MetasploitCTF/Port80.png "Port 80")

## Port 443
Next I decided to go to the next port found by nmap: 443. I started by reopening the SSH tunnel on the new targeted port.

```bash
$ ssh -L 8082:172.17.26.149:443 kali@18.215.161.123 -i metasploit_ctf_kali_ssh_key.pem
```

I refreshed my browser and this time I had a page that was still under construction. 

![Port 443](/assets/images/2021/12/MetasploitCTF/Port443.png "Port 443")

I looked at the page source, the cookies and the headers in Burp, but I did not find anything there. Nothing in robots.txt either. 

So I fired up GoBuster, and it did find something of interest. 

```bash
$ gobuster dir -e -u http://localhost:8082 -t30 -w /usr/share/dirb/wordlists/common.txt  -xjs,txt,php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://localhost:8082
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,js,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/12/04 13:49:58 Starting gobuster in directory enumeration mode
===============================================================
http://localhost:8082/.hta                 (Status: 403) [Size: 276]
http://localhost:8082/.htaccess            (Status: 403) [Size: 276]
http://localhost:8082/.hta.js              (Status: 403) [Size: 276]
http://localhost:8082/.htaccess.js         (Status: 403) [Size: 276]
http://localhost:8082/.hta.txt             (Status: 403) [Size: 276]
http://localhost:8082/.htaccess.txt        (Status: 403) [Size: 276]
http://localhost:8082/.hta.php             (Status: 403) [Size: 276]
http://localhost:8082/.htaccess.php        (Status: 403) [Size: 276]
http://localhost:8082/.git/HEAD            (Status: 200) [Size: 23] 
http://localhost:8082/.htpasswd.txt        (Status: 403) [Size: 276]
http://localhost:8082/.htpasswd.php        (Status: 403) [Size: 276]
http://localhost:8082/.htpasswd            (Status: 403) [Size: 276]
http://localhost:8082/.htpasswd.js         (Status: 403) [Size: 276]
http://localhost:8082/index.html           (Status: 200) [Size: 26] 
http://localhost:8082/server-status        (Status: 403) [Size: 276]
                                                                    
===============================================================
2021/12/04 13:50:20 Finished
===============================================================
```

It looks like the site developers have deployed their git repository with the site. I had used a tool to extract that in the past. So I looked around and found [git-dumper](https://github.com/arthaud/git-dumper). 

```bash
$ git-dumper http://localhost:8082/.git/ temp                                                            
[-] Testing http://localhost:8082/.git/HEAD [200]                                                                    
[-] Testing http://localhost:8082/.git/ [403]                                                                        
[-] Fetching common files                                
[-] Fetching http://localhost:8082/.gitignore [404]                                                                  
[-] http://localhost:8082/.gitignore responded with status code 404
[-] Fetching http://localhost:8082/.git/COMMIT_EDITMSG [200]
[-] Fetching http://localhost:8082/.git/description [200]
[-] Fetching http://localhost:8082/.git/hooks/post-commit.sample [404]                         
[-] http://localhost:8082/.git/hooks/post-commit.sample responded with status code 404         
...
[-] Fetching http://localhost:8082/.git/objects/fa/efc0407d461914a05d2abf2cfae62230ea761a [200]
[-] Fetching http://localhost:8082/.git/objects/1e/4988fd28fdfb4116f7203451e6cf1b6c51ea43 [200]
[-] Running git checkout .

$ cd temp/

$ ls -la
total 16
drwxr-xr-x  3 ehogue ehogue 4096 Dec  4 13:57 .
drwxr-xr-x 44 ehogue ehogue 4096 Dec  4 13:57 ..
drwxr-xr-x  7 ehogue ehogue 4096 Dec  4 13:57 .git
-rw-r--r--  1 ehogue ehogue   27 Dec  4 13:57 index.html

$ git status
On branch master
nothing to commit, working tree clean

$ cat index.html 
Website under development
```

I had the git repository, but the master branch had only the index file. I then looked at the history.

```bash
$ git log
commit 687168d567086a87eccd0621eec3f90e331ee5a7 (HEAD -> master)
Author: developer <developer@127.0.0.1>
Date:   Tue Nov 16 16:55:27 2021 +0000

    More enthusiasm

commit b429a1087c6723fa1aff5a36e6c5055e775cb923
Author: developer <developer@127.0.0.1>
Date:   Tue Nov 16 16:55:27 2021 +0000

    Cleanup

commit 61fffcea82d8ed62623d34d956d69602e93d8747
Author: developer <developer@127.0.0.1>
Date:   Tue Nov 16 16:55:27 2021 +0000

    Initial commit
```

There is a Cleanup commit in there. That looks like someone might have removed some secrets from the repo. I checked out the previous commit to look at what was in there. 

```bash
$ git checkout 61fffcea82d8ed62623d34d956d69602e93d8747
Note: switching to '61fffcea82d8ed62623d34d956d69602e93d8747'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at 61fffce Initial commit

$ ls -la
total 20
drwxr-xr-x  3 ehogue ehogue 4096 Dec  4 14:05 .
drwxr-xr-x 44 ehogue ehogue 4096 Dec  4 13:57 ..
-rw-r--r--  1 ehogue ehogue   90 Dec  4 14:05 .env
drwxr-xr-x  7 ehogue ehogue 4096 Dec  4 14:05 .git
-rw-r--r--  1 ehogue ehogue   26 Dec  4 14:05 index.html

$ cat .env 
username=root
password=password123
flag_location=3e6f0e21-7faa-429f-8a1d-3f715a520da4.png
```

The flag location was in a .env file in the first commit of the repo. I opened that page in a browser. 

![Flag 2](/assets/images/2021/12/MetasploitCTF/Flag2.png "Flag 2")

I save the image locally, then used md5sum to get the flag for the 2 of spades.

```bash
$ md5sum ~/Downloads/3e6f0e21-7faa-429f-8a1d-3f715a520da4.png 
e908c9867ab88f1ee926b588b9b47be4  /home/ehogue/Downloads/3e6f0e21-7faa-429f-8a1d-3f715a520da4.png
```

## Port 8080

I next move on to port 8080. I opened the tunnel to the correct port and looked at the site in my browser. 

![Port 8082](/assets/images/2021/12/MetasploitCTF/Port8082.png "Port 8082")

I wonder if all those cookies are an hint? I looked at my cookies. At first I only had one called `visited-main-page` and set to `true`. 

I tried clicking on the Admin link. It gave me this message:
> Unauthenticated users cannot access this page.

So I clicked on the Sign Up link and created an account.

![Create Account](/assets/images/2021/12/MetasploitCTF/CreateAccount.png "Create Account")

I went back to the Admin page and got the same message as before. So I used the Sign In link to connect to the page. 

![Sign In](/assets/images/2021/12/MetasploitCTF/SignIn.png "Sign In")

When I went back to the Admin page I had a new message. 
> You don't have permissions to view this page.

And a few new cookies. 

![Cookies](/assets/images/2021/12/MetasploitCTF/Cookies.png "Cookies")

I changed the `admin` cookie from `false` to `true` and refreshed the page. This gave me the Nine of Diamonds images. 

![Nine of Diamonds](/assets/images/2021/12/MetasploitCTF/NineOfDiamonds.png "Nine of Diamonds")

## Port ?