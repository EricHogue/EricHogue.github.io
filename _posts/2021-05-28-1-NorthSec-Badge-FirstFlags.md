---
layout: post
title: NorthSec 2021 Badge Writeup - First Flags
date: 2021-05-28
type: post
tags:
- Writeup
- Hacking
- NorthSec
- BadgeLife
permalink: /2021/05/NorthSec2021BadgeFirstFlags/
img: 2021/05/NorthSecBadge/Badge.jpg
---

The 2021 edition of [NorthSec](https://nsec.io/) was held remotely. They produced a badge anyway. It was possible to buy it in [their online shop](https://shop.nsec.io/collections/badge/products/northsec-2021-badge) for $60. 

I bought one. It was absolutely beautiful. I cannot imagine the time they put on it to build it, and to write the software and challenges that were in the badge.

![The Badge](/assets/images/2021/05/NorthSecBadge/Badge.jpg "The Badge")

They made it clear that the badge would not give us any advantages in their [CTF](https://nsec.io/competition/) (Capture The Flag) competition. But it contains then flag that we could discover and submit to a bot on Discord. For fun and to get a few fun roles on their Discord server.

![Discord Roles](/assets/images/2021/05/NorthSecBadge/DiscordRoles.png "Discord Roles")

I need to thank [Padraignix](https://padraignix.github.io/) and Vicious. I would never have completed the badge without their help. 

## Flag 1 / Badge 1

When I started the badge by connecting it to a computer through it's USB port, I was first greeted by a warning message to make sure we are aware that it does not give points in the CTF.

![Warning](/assets/images/2021/05/NorthSecBadge/Warning.jpg "Warning")


I clicked the Enter button twice and it took me inside of a little RPG game.

![The RPG Game](/assets/images/2021/05/NorthSecBadge/TheGame.jpg "The RPG Game")

Right away, I saw the 10 flags on the bottom of the screen. It looks that this will be my objective 

The first flag is easy, the chest was visible when I first opened the game. I just walk to it and hit enter. 

![Flag 1](/assets/images/2021/05/NorthSecBadge/Flag1.jpg "Flag 1")

Flag 1: FLAG-W3lc0m2NSECxx

The chest also has a QR code that take you to [a page on the NorthSec site](https://nsec.io/badge2021/) with information about the badge and how to submit the flags.

I took that flag and submitted it to FLAGBOT. 

![Badge 1](/assets/images/2021/05/NorthSecBadge/Badge1.png "Badge 1")


## Flag 2 / Badge 4

I started walking around the map and talking to all the characters. Some of the dialog are pretty funny. If you have a badge, make you sure you talk to every one, and read everything they have to say. It's worth it. 

When I got to the top left corner of the map. I saw a chess that I couldn't reach. 


![Unreachable Chest](/assets/images/2021/05/NorthSecBadge/UnreachableChest.jpg "Unreachable Chest")

I looked around, trying to see a way in. But I didn't find any. Then I tried the [Konami Code](https://en.wikipedia.org/wiki/Konami_Code). I've been trying it all over the map with no success. But here, it did something. 

![Opened Door](/assets/images/2021/05/NorthSecBadge/OpenDoorAfterKonami.jpg "Opened Door")

There was now an hole opened in a building. I walked in it, and I could finally reached the chest and get the next flag.

![Flag 2](/assets/images/2021/05/NorthSecBadge/Flag2.jpg "Flag 2")

Flag 2: FLAG-UuDdLrLrBA0000

![Badge 4](/assets/images/2021/05/NorthSecBadge/Badge4.png "Badge 4")

One thing I noted here, the order of the flags in the badge don't match the order of the flag awarded on Discord. I guess they were trying to confuse more than I already was.

## Flag 5 / Badge 7

I got this flag by walking around and talking to everyone I saw. There is a Punk character that only asked me 'Are you really CYBER!? PROVE IT'.  

![Are You CYBER](/assets/images/2021/05/NorthSecBadge/AreYouCyber.jpg "Are You CYBER")

I missed it at first, because the text was not too long to fit the screen. But if I scrolled down on the Punk text, the flag was displayed. 

![Flag 5](/assets/images/2021/05/NorthSecBadge/Flag5.jpg "Flag 5")

Flag 5: FLAG-KLJV490uhkEJF28

![Badge 7](/assets/images/2021/05/NorthSecBadge/Badge7.png "Badge 7")

## Flag 4 / Badge 6

This one was weird. I was exploring the map, and eventually I saw that I had the 4th flag. But I never saw it. And I had no idea when it appeared. I kept walking around the map, and not seeing it anywhere. 

I left it aside for a while and worked on other flags. For the Reverse Engineering flags, I had to connect to the badge [CLI](https://en.wikipedia.org/wiki/Command-line_interface) to configure the Wi-Fi. I kept it opened after that, not paying too much attention to it. 

At one point, I realized that the screen had been erased. I first tough it was a fluke. But it turned out that every time I spoke to the duck, the screen go cleared. 

![Duck](/assets/images/2021/05/NorthSecBadge/Duck.jpg "Duck")

I tried to extract what was sent to the CLI before it got cleared, but I couldn't get it. 

I was using screen to connect to the badge using this command `sudo screen  /dev/ttyUSB0 115200`. But I could not get the output of talking to the duck. 

Padraignix told me he had more success using Minicom, so I tried it. Minicom has an option to copy the output to a file. I tried it. I saw a lot ot quick and quack sent to the CLI, but the data always seemed to be corrupted. 

Then I tried simply redirecting the output to a file, like with any Linux command and got a lot more success. 

I ran `sudo minicom -D /dev/ttyUSB0  > quack.txt` and talked to the duck. The output looked a lot better. It still contained some special characters, probably the commands to clear the terminal. 

I removed the garbage and was left with this string.

```
quackquackquickquack quickquickquack quickquack quackquickquackquick quackquickquack quickquick quackquack quickquack quackquickquick quickquickquack quackquickquackquick quackquickquack quack quackquackquack quackquackquick quick quack quackquickquickquick quickquackquick quick quickquack quackquickquick quickquickquack quickquickquick quick quack quickquickquickquick quickquick quickquickquick quickquickquackquick quickquackquickquick quickquack quackquackquick quackquickquickquick quackquick quickquickquickquack quackquackquickquick quackquickquack quickquack quickquackquack quackquack quickquickquick quackquickquackquack quickquickquick
```

I might be a little weird, or very old, but when I saw it, I immediately tough that this was Morse code. 

I took the string to CyberChef, and built a small [recipe](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Regex','string':'quack'%7D,'-',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'quick'%7D,'.',true,false,true,false)From_Morse_Code('Space','Line%20feed')&input=cXVhY2txdWFja3F1aWNrcXVhY2sgcXVpY2txdWlja3F1YWNrIHF1aWNrcXVhY2sgcXVhY2txdWlja3F1YWNrcXVpY2sgcXVhY2txdWlja3F1YWNrIHF1aWNrcXVpY2sgcXVhY2txdWFjayBxdWlja3F1YWNrIHF1YWNrcXVpY2txdWljayBxdWlja3F1aWNrcXVhY2sgcXVhY2txdWlja3F1YWNrcXVpY2sgcXVhY2txdWlja3F1YWNrIHF1YWNrIHF1YWNrcXVhY2txdWFjayBxdWFja3F1YWNrcXVpY2sgcXVpY2sgcXVhY2sgcXVhY2txdWlja3F1aWNrcXVpY2sgcXVpY2txdWFja3F1aWNrIHF1aWNrIHF1aWNrcXVhY2sgcXVhY2txdWlja3F1aWNrIHF1aWNrcXVpY2txdWFjayBxdWlja3F1aWNrcXVpY2sgcXVpY2sgcXVhY2sgcXVpY2txdWlja3F1aWNrcXVpY2sgcXVpY2txdWljayBxdWlja3F1aWNrcXVpY2sgcXVpY2txdWlja3F1YWNrcXVpY2sgcXVpY2txdWFja3F1aWNrcXVpY2sgcXVpY2txdWFjayBxdWFja3F1YWNrcXVpY2sgcXVhY2txdWlja3F1aWNrcXVpY2sgcXVhY2txdWljayBxdWlja3F1aWNrcXVpY2txdWFjayBxdWFja3F1YWNrcXVpY2txdWljayBxdWFja3F1aWNrcXVhY2sgcXVpY2txdWFjayBxdWlja3F1YWNrcXVhY2sgcXVhY2txdWFjayBxdWlja3F1aWNrcXVpY2sgcXVhY2txdWlja3F1YWNrcXVhY2sgcXVpY2txdWlja3F1aWNrCg
).

![CyberChef](/assets/images/2021/05/NorthSecBadge/CyberChef.png "CyberChef")

It returned this string: `QUACKIMADUCKTOGETBREADUSETHISFLAGBNVZKAWMSYS`

Flag: FLAGBNVZKAWMSYS

![Badge 6](/assets/images/2021/05/NorthSecBadge/Badge6.png "Badge 6")

## Flag 7 / Badge 8

This flag is not located on the map. I had seen hints that there is a CLI that could be used by connecting to the serial port. I had never played with something similar, so I had no idea how to connect to it. I was afraid I need to use the strange black port near the tail of the horse. 

![Shitty Add-On](/assets/images/2021/05/NorthSecBadge/ShittyAddOn.jpg "Shitty Add-On")

Turned out that's called a [Shitty Add-On port](https://hackaday.com/2019/03/20/introducing-the-shitty-add-on-v1-69bis-standard/) and it was not needed.

After doing to research, I only need to use screen to connect to it. 

```bash
sudo screen  /dev/ttyUSB0 115200
```


![CLI](/assets/images/2021/05/NorthSecBadge/CLI.png "CLI")

At the end of the Help, there are 3 question marks. It looks like there might be an additional command that is not documented. 

The last message when I reboot the badge says that you can hit TAB to get commands auto-completion. So I started going down the alphabet. I typed a letter that hit TAB to see if it will auto-complete to the hidden command. I had to go until 't' to find it. 

```bash
nsec-badge> the_sword_of_azeroth!
Your curiosity has led you to a legendary treasure - you are the SWORD MASTER now! FLAG-Cl1F0rFun&Pr0f1t
nsec-badge> 
```

Flag: FLAG-Cl1F0rFun&Pr0f1t

![Badge 8](/assets/images/2021/05/NorthSecBadge/Badge8.png "Badge 8")

## Other Posts

This post shows how I got the five easier flags of the NorthSec badge. I will write other posts for the rest of the flags.