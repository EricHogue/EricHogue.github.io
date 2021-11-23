---
layout: post
title: Hackfest 2021 Writeup - HellCorp
date: 2021-11-22
type: post
tags:
- Writeup
- Hacking
- Hackfest
- CTF
permalink: /2021/11/HackfestCTF/HellCorp
img: 2021/11/HackfestCTF/HellCorp/EncryptedTraffic.png
---

## 01 - Welcome (1 of 2)
I did not get a screenshot of this challenge. But it was something about catching someone trying to escape from hell. We had a network capture of the Wi-Fi traffic to do it.

I downloaded the file and opened it in Wireshark. But the traffic was encrypted, so I could not read it. 

![Encrypted Traffic](/assets/images/2021/11/HackfestCTF/HellCorp/EncryptedTraffic.png "Encrypted Traffic")

I searched a little bit how to decrypt it from a PCAP file. But I failed to find it, so I left that challenge aside. 

One of my teammates kept looking at it. And he found how to do it with Aircrack-ng. 

```bash
$ aircrack-ng -a1 hellcorp_1.cap
```

![Aircrack-ng](/assets/images/2021/11/HackfestCTF/HellCorp/Aircrack-ng-1.png "Aircrack-ng")

I took the key (68:33:21:21:43) and used it in Wireshark to decrypt the IEEE 802.11 traffic.

![Decryption Key](/assets/images/2021/11/HackfestCTF/HellCorp/FirstDecryptionKey.png "Decryption Key")

Now I could see the traffic on the network, and I could filter to view only the HTTP traffic.

![Http Traffic](/assets/images/2021/11/HackfestCTF/HellCorp/HttpTraffic.png "Http Traffic")

In this traffic, I could see a POST to a login page. I opened it and the flag was the password being sent.

![First Flag](/assets/images/2021/11/HackfestCTF/HellCorp/FirstFlag.png "First Flag")

Flag: HF-45BB35801D55AEA01DDDE4419BFCA649


## 02 - Escape (2 of 2)

In the second challenge, we also got a PCAP file. But this one had stronger encryption, and the traffic captured was in HTTPS.

![Description](/assets/images/2021/11/HackfestCTF/HellCorp/Description.png "Description")

```
Well that was weird... I swear I saw a link to a page named how_to_escape_from_hell.html in the HellCorp wiki. This must be why someone attacked HellCorp's wireless network...

The problem is: I heard that they hardened their infrastrucutre. WPA2 encrypted network, SSL certificates, etc...

I must try to access this web page and get out of here.

I noticed yesterday that they frequently change the password of HellCorp's public WiFi (sadly not connected to their intranet) and they write it on one of the meeting room's walls.

The passwords always have this in common :

The passwords are fairly simple
They always contain the word "hell"
They are always reversed (for example 12345 becomes 54321)
With a bit of luck, they might use the same password policy for their internal wireless network.

I need to hack this network and find a way to access the web page.

PS: I already took the rockyou.txt wordlist and extracted all passwords that contain "hell", I just need to find a way to reverse them...
```

This one was using a stronger encryption, but we had a word list to use to brute force it. 

```
michelle
hello
hellokitty
hello1
michelle1
shelly
mitchell
rochelle
hello123
rachelle
chelle
shelley
hellomoto
hellboy
gotohell
...
```

We only needed to reverse the words in the file. I wrote a small python script to do it. 

```python
file = open('rockyou_hellcorp.txt', 'r')
for line in file.readlines(): 
    line = line.strip()
    line = line[::-1]
    print(line)
```

Then I could use Aircrack-ng to crack the password. 

```bash
$ aircrack-ng -a2 -w rev.txt hellcorp_2.pcap
```

![Aircrack-ng](/assets/images/2021/11/HackfestCTF/HellCorp/Aircrack-ng-2.png "Aircrack-ng")

I used the found key (srekcahllehnitor) to decrypt the PCAP file.

![WAP Password](/assets/images/2021/11/HackfestCTF/HellCorp/WAPPassword.png "WAP Password")

But as mentioned, the web traffic was all encrypted, so I could not read it. But I found some FTP traffic. This was not encrypted. It contained the username and password used to connect to the server. But that was not very useful. 

![FTP Traffic](/assets/images/2021/11/HackfestCTF/HellCorp/FTPCreds.png "FTP Traffic")

FTP uses a different port for file transfer. So I looked around the FTP traffic, and I found a zip file being transferred. 

![File Transfer](/assets/images/2021/11/HackfestCTF/HellCorp/FileTransfer.png "File Transfer")

I saved the raw data to my machine and tried to uncompress it. 

```bash
unzip file.zip 

Archive:  file.zip
   creating: migrations/
[file.zip] migrations/env.py password: 
```

The file was password protected. I tried the password used to connect the the FTP server (autobackup), and it worked. I got a backup of the web site. 

```bash
$ unzip file.zip 
Archive:  file.zip
   creating: migrations/
[file.zip] migrations/env.py password: 
  inflating: migrations/env.py       
  inflating: migrations/alembic.ini  
 extracting: migrations/README       
  inflating: migrations/script.py.mako  
   creating: migrations/versions/
  inflating: migrations/versions/9d53acb7ea19_users_table.py  
  inflating: hellcorpwiki.py         
   creating: app/
  inflating: app/routes.py           
  inflating: app/forms.py            
   creating: app/templates/
  inflating: app/templates/how_to_escape_from_hell.html 
 ...
```

Then I just grepped for the flag. I found the flags for both challenges. 

```bash
$ grep -R 'HF-' .

./app/templates/how_to_escape_from_hell.html:        HF-B545032E743874E554A73B2721E18C24
./app/__init__.py:admin.set_password('HF-45BB35801D55AEA01DDDE4419BFCA649')
```

Flag:  HF-B545032E743874E554A73B2721E18C24
