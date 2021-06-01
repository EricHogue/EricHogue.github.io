---
layout: post
title: NorthSec 2021 Badge Writeup - Part 4 - Networking
date: 2021-05-31
type: post
tags:
- Writeup
- Hacking
- NorthSec
- BadgeLife
permalink: /2021/05/NorthSec2021BadgeNetworking/
img: 2021/05/NorthSecBadge/pcap.png
---

After having the [NorthSec 2021 badge](https://shop.nsec.io/collections/badge/products/northsec-2021-badge) for a while, I had found eight flags. I knew from extracting the firmware that for the 10th flag I would need to flip a bit in the firmware and push it to the badge so I kept that one for last. 

But I had absolutely no idea who to get flag 6 (Badge 9 in Discord). I was following the #badge channel in Discord. So I knew that while a lot of people were struggling with this one, others did it first. 

I looked around for a while, bit I couldn't find any clue or make any progress. I had dumped the firmware and extracted the elf program that runs on it. But I could not find any clues in the code. 

After a few days of banging my heads on this and dreaming about it, I got a clue from vicious. 

![Dreaming About Flag 9](/assets/images/2021/05/NorthSecBadge/Dreaming.jpg)

The first clue vicious gave me was to check the microcontroller features, check the capability that had the biggest attack surface and work on it. So I opened the [ESP32 specs](https://www.espressif.com/sites/default/files/documentation/esp32_datasheet_en.pdf) and started reading. 

The first thing that hit me was that the chip had a radio transmitter. That made me laugh. I imagined my neighbors trying to figure out why something was spelling 'F-L-A-G-...' on a random radio frequency. 

But I ruled this out quickly since vicious had said many time that we didn't need anything else that a laptop to get the flags. And [Padraignix](https://padraignix.github.io/) and told me I had already used the feature I needed.   I also ruled out the [JTAG](https://en.wikipedia.org/wiki/JTAG) for the same reasons. 

That left me with Wi-Fi. I knew the badge could act as a Wi-Fi access point, so I scanned for AP around me for anything that could be the badge. I found nothing. 

The next thing I tried was to scan the badge for opened ports. I scanned the entire port range in TCP and UDP. I also scanned for new IP appearing on my network, in case the badge opened a second connection. Again, nothing. 

Then I tough that maybe the port would only be opened if I was at a specific location on the map. So I started going to anywhere I could think of and repeat my scans from there. 

I tried:
* The Reverse Engineering house
* The Wi-Fi house
* In the boat
* The only house that we can walk in, near the Fisher_
* All the other houses
* Near the NorthSec horse
* Inside the castle
* After causing the glitch by going in the house in the castle

I also redid all of the same tests, with the glitch active to see if it changed anything. All the time running TCP, UDP and a IP scan. I wasted a lot of time on this. The UDP scan can take a while. 

## Flag 6 / Badge 9

After a few more days of looking around, vicious gave me another hint: 

```
If the badge tried to do curl https://nsec.io/flag.txt for example, do you think you would be able to detect this with your current setup?
```

This one made the solution pretty clear. I needed to listen to all the traffic on my network and check what call the badge was making. I had tried that only once, so this is not something I could do quickly. But I had a vague idea. I searched for how to do it, and found a [blog post](https://null-byte.wonderhowto.com/how-to/stealthfully-sniff-wi-fi-activity-without-connecting-target-router-0183444/) that explained it well. 

I setup my network interface in monitor mode, launched Wireshark, and connected the badge. 

And it worked. I quickly saw that the badge was trying to connect to the IP 198.51.100.42 on port 4444. 

![Wireshark](/assets/images/2021/05/NorthSecBadge/pcap.png "Wireshark")

That IP belongs to a range of IPs that are [reserved for documentation and examples](https://en.wikipedia.org/wiki/Reserved_IP_addresses). 

I needed to send all the traffic for this IP to my laptop so I could intercept what the badge would send once the connection was established. 

I didn't want to change my home Wi-Fi because my family is using it. Luckily I had an old router that I could use. I connected the router and configured it to use the correct subnet. Then I connected my laptop to it, assigning the laptop the static address 198.51.100.42. 

I launched a netcat listener on my machine, then joined the new Wi-Fi with the badge. A few second later I got a connection.

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 198.51.100.197 50358
Are u listening? FLAG-spOkeTh3Hors
```

Flag: FLAG-spOkeTh3Hors

![Badge 9](/assets/images/2021/05/NorthSecBadge/Badge9.png "Badge 9")

## Other Posts In The NorthSec 2021 Badge Series 
* [Part 1 - First Flags](/2021/05/NorthSec2021BadgeFirstFlags/)
* [Part 2 - Reverse Engineering Flags](/2021/05/NorthSec2021BadgeReverseEngineeringFlags/)
* [Part 3 - The Map](/2021/05/NorthSec2021BadgeTheMap/)
* [Part 5 - Last Flag](/2021/05/NorthSec2021BadgeLastFlag/)