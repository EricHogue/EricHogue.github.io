---
layout: post
title: iHack 2021 Writeup - The Onion Things #7
date: 2021-06-20
type: post
tags:
- Writeup
- Hacking
- iHack
- CTF
permalink: /2021/06/iHackWriteupTheOnionThings
img: 2021/06/CTFCollectionVol2/CTFCollectionVol2.png
---

As part of the [iHack 2021 CTF](https://ihack.computer/#ctf), Miu built an IOT track that was a nice continuation to her [workshop of the conference](https://www.youtube.com/watch?v=8Bg7CfZrZkU). 

```
The Onion Things (@Miu)
│   ├── 1 - Firmware Analysis Things 1/3 (75)
│   ├── 2 - Firmware Analysis Things 2/3 (75)
│   ├── 3 - Firmware Analysis Things 3/3 (75)
│   ├── 4 - Wallet Things 1/2 (100)
│   ├── 5 - Wallet Things 2/2 (100)
│   ├── 6 - LCD Thing (125)
│   ├── 7 - You shall experience my adventure ! (200)
|   └── 8 - Binary Kung Fu (250)
```

I got to this track at the very end of the competition. My teammates had already solved some of the flags. But I decided to give it a shot for the last hour. 

The first thing to do was to download the firmware that Miu provided and extract the file system. Luckily I knew from the talk that `binwalk` was probably the tool to use for that. 

```bash
$ file the-onion-thing.bin 
the-onion-thing.bin: u-boot legacy uImage, MIPS OpenWrt Linux-4.14.81, Linux/MIPS, OS Kernel Image (lzma), 1614170 bytes, Tue Jul 14 21:51:14 2020, Load Address: 0x80000000, Entry Point: 0x80000000, Header CRC: 0x34756B90, Data CRC: 0xCF6EDD01

$ binwalk -e the-onion-thing.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0x34756B90, created: 2020-07-14 21:51:14, image size: 1614170 bytes, Data Address: 0x80000000, Entry Point: 0x80000000, data CRC: 0xCF6EDD01, OS: Linux, CPU: MIPS, image type: OS Kernel Image, compression type: lzma, image name: "MIPS OpenWrt Linux-4.14.81"
64            0x40            LZMA compressed data, properties: 0x6D, dictionary size: 8388608 bytes, uncompressed size: 5111620 bytes

WARNING: Extractor.execute failed to run external extractor 'sasquatch -p 1 -le -d 'squashfs-root-0' '%e'': [Errno 2] No such file or directory: 'sasquatch', 'sasquatch -p 1 -le -d 'squashfs-root-0' '%e'' might not be installed correctly

WARNING: Extractor.execute failed to run external extractor 'sasquatch -p 1 -be -d 'squashfs-root-0' '%e'': [Errno 2] No such file or directory: 'sasquatch', 'sasquatch -p 1 -be -d 'squashfs-root-0' '%e'' might not be installed correctly
1614234       0x18A19A        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 8003064 bytes, 2144 inodes, blocksize: 262144 bytes, created: 2021-06-18 06:54:13

$ ls
the-onion-thing.bin  _the-onion-thing.bin.extracted

$ ls _the-onion-thing.bin.extracted 
18A19A.squashfs  40  40.7z  squashfs-root

$ ls _the-onion-thing.bin.extracted/squashfs-root 
bin  dev  etc  lib  mnt  overlay  proc  rom  root  sbin  sys  tmp  usr  var  welcome  www
```

It gave me some warnings, but the file system was extracted. I started looking around, and I found a program called flag in the `/bin` folder. 

```bash
file bin/flag 
bin/flag: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-mipsel-sf.so.1, with debug_info, not stripped
```

I remembered that one of the challenges was about running a program. 

```
You will need the firmware in attachment to the challenge : Firmware Analysis Things 1/3.

Given the architecture of the device, this binary can't be executed on your machine. Well.. That's actually not true ! There is a way : Emulation.

Let's use all the informations we gathered so far and find a way to do so.
```

The description says to use emulation to run the program. The workshop was about how to do this with Docker and [QEMU](https://www.qemu.org/). But I was too lazy to do that. Plus I probably did not have enough time to setup my machine for that. 

So I decided to try to reverse the executable. I loaded it in Ghidra and it identified MIPS correctly. I looked at the `main` function.

![Main Function](/assets/images/2021/06/iHack/Main.png "Main Function")

There are two things that look promising. The string `@N%Me}di|agfA{N}f` and the call to the function `encryptDecryptXOR`. 

Next, I looked at `encryptDecryptXOR`. 

![encryptDecryptXOR](/assets/images/2021/06/iHack/encryptDecryptXOR.png "encryptDecryptXOR")

This function takes the parameter it received, go through all characters from the string and XOR it with 8. 

To get the flag, I did the same thing with a [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=To_Hex('None',1)From_Hex('Auto')XOR(%7B'option':'Hex','string':'8'%7D,'Standard',false)&input=QE4lTWV9ZGl8YWdmQXtOfWY). 

It gave me the flag 'HF-EmulationIsFun'. I submitted it 10 minutes before the end of the CTF and it gave us 200 points. 