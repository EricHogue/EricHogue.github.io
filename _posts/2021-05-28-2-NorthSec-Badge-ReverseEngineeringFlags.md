---
layout: post
title: NorthSec 2021 Badge Writeup - Reverse Engineering Flags
date: 2021-05-28
type: post
tags:
- Writeup
- Hacking
- NorthSec
- BadgeLife
- ReverseEngineering
permalink: /2021/05/NorthSec2021BadgeReverseEngineeringFlags/
img: 2021/05/NorthSecBadge/REDownload.jpg
---

While exploring the maps to look for flags, I can across a house with a question mark on it. 

![Reverse Engineering House](/assets/images/2021/05/NorthSecBadge/REHouse.jpg "Reverse Engineering House")

When I pressed on the ENTER button, I received a message saying that I needed to connect to the wifi first. 

![Connect to the Wifi First](/assets/images/2021/05/NorthSecBadge/ConnectToWifi.jpg "Connect to the Wifi First")

I had already come across the house where I could turn wifi on and off. But it didn't work. I needed to configure it first. 

I connected to the badge [CLI](https://en.wikipedia.org/wiki/Command-line_interface) using screen.

```bash
sudo screen  /dev/ttyUSB0 115200
```

Once connected to the CLI, the help made it easy to find what I needed to do. 

```bash
nsec-badge> help
...

join  [--timeout=<t>] <ssid> [<pass>]
  Join WiFi AP as a station
  --timeout=<t>  Connection timeout, ms
        <ssid>  SSID of AP
        <pass>  PSK of AP

disconnect 
  Disconnect from WiFi AP

...

challenges  [<RE(101|102)>] <code>

...

```

I simply needed to use `join` with my SSID and password to connect. It also hinted that I would need to submit a code for the RE challenges. 

I then got back to the house with the question mark. This time when I entered it, it gave me instructions on how to download the binaries for the RE challenges.

![Download RE Challenges](/assets/images/2021/05/NorthSecBadge/REDownload.jpg "Download RE Challenges")

## Flag 8 / Badge 2
I followed the instructions to download the first binary, and the un-compress it. 

```bash
$ nc 192.168.185.113 1101 > rc101.zip

$ unzip rc101.zip 
Archive:  rc101.zip
  inflating: re101.elf               
  inflating: __MACOSX/._re101.elf    
  
$ file re101.elf 
re101.elf: ELF 32-bit LSB executable, Tensilica Xtensa, version 1 (SYSV), statically linked, with debug_info, not stripped
```

I tried to open the file in [Ghidra](https://ghidra-sre.org/), but it failed to detect the language of the program. I looked for [Xtensa](https://en.wikipedia.org/wiki/Tensilica) in the list, but it wasn't there. I search for how to read XTensa in Ghidra and quickly came across [a module that could read it](https://github.com/yath/ghidra-xtensa). I installed the module and tried to reload the binary. This time it worked. 

I found `app_main` function and started to read it. 

![RE 101 Main](/assets/images/2021/05/NorthSecBadge/RE101Main.png "RE 101 Main")

The beginning of the function has some code about a user input code. But starting at line 0x400d2381, there is a call to a `verify` function, then either jump to print an error message, or print the flag. I checked, and `PTR_s_flag_here_400d0394` did not contain the real flag. That would have been to easy.

I then looked at the `verify` function. 

![RE 101 Verify](/assets/images/2021/05/NorthSecBadge/RE101Verify.png "RE 101 Verify")

This one is longer, but there is a pattern that jumps to the eyes. The code move an hexadecimal value to a register and then copy that value to an offset on the stack. Looking at the hex values, they all look like possible [ASCII](https://en.wikipedia.org/wiki/ASCII) characters. The first value, 0x63 could be a 'c', and 0x34 a few lines later could represent a '4'.

I copied the code in a text editor, and replaced the register by the ASCII value they contain in the lines that move them to the stack. I needed to be careful, because the value of some registers change during the function. 

```Xtensa
        400e4248 36 41 01        entry      a1,0xa0
        400e424b c2 a0 63        movi       a12,c
        400e424e c2 61 15        s32i       c,0xa0,0x54=>Stack[0x54]
        400e4251 82 a0 62        movi       a8,b
        400e4254 82 61 10        s32i       b,0xa0,0x40=>Stack[0x40]
        400e4257 3c 4e           movi.n     a14,4
        400e4259 e9 a1           s32i.n     4,0xa0,0x28=>Stack[0x28]
        400e425b 3c 3b           movi.n     a11,3
        400e425d b2 61 12        s32i       3,0xa0,0x48=>Stack[0x48]
        400e4260 3c 83           movi.n     sig,8
        400e4262 32 61 18        s32i       8,0xa0,0x60=>Stack[0x60]
        400e4265 82 61 19        s32i       b,0xa0,0x64=>Stack[0x64]
        400e4268 3c 2a           movi.n     a10,2
        400e426a a9 51           s32i.n     2,0xa0,0x14=>Stack[0x14]
        400e426c 3c 18           movi.n     a8,1
        400e426e 89 01           s32i.n     1,0xa0=>Stack[0x0],0x0
        400e4270 a2 61 17        s32i       2,0xa0,0x5c=>Stack[0x5c]
        400e4273 82 61 16        s32i       1,0xa0,0x58=>Stack[0x58]
        400e4276 3c 7f           movi.n     a15,7
        400e4278 f2 61 1d        s32i       7,0xa0,0x74=>Stack[0x74]
        400e427b 3c 9d           movi.n     a13,9
        400e427d d9 31           s32i.n     9,0xa0,0xc=>Stack[0xc]
        400e427f 82 61 13        s32i       1,0xa0,0x4c=>Stack[0x4c]
        400e4282 92 a0 61        movi       a9,0x61
        400e4285 99 21           s32i.n     a,0xa0,0x8=>Stack[0x8]
        400e4287 92 a0 65        movi       a9,0x65
        400e428a 99 f1           s32i.n     e,0xa0,0x3c=>Stack[0x3c]
        400e428c 82 61 11        s32i       1,0xa0,0x44=>Stack[0x44]
        400e428f 89 11           s32i.n     1,0xa0,0x4=>Stack[0x4]
        400e4291 89 61           s32i.n     1,0xa0,0x18=>Stack[0x18]
        400e4293 3c 09           movi.n     a9,0x30
        400e4295 92 61 1f        s32i       0,0xa0,0x7c=>Stack[0x7c]
        400e4298 3c 69           movi.n     a9,0x36
        400e429a 99 e1           s32i.n     6,0xa0,0x38=>Stack[0x38]
        400e429c a9 41           s32i.n     2,0xa0,0x10=>Stack[0x10]
        400e429e 39 71           s32i.n     8,0xa0,0x1c=>Stack[0x1c]
        400e42a0 92 61 1b        s32i       6,0xa0,0x6c=>Stack[0x6c]
        400e42a3 f2 61 14        s32i       7,0xa0,0x50=>Stack[0x50]
        400e42a6 99 81           s32i.n     6,0xa0,0x20=>Stack[0x20]
        400e42a8 e9 c1           s32i.n     4,0xa0,0x30=>Stack[0x30]
        400e42aa 82 61 1c        s32i       1,0xa0,0x70=>Stack[0x70]
        400e42ad d9 d1           s32i.n     9,0xa0,0x34=>Stack[0x34]
        400e42af a2 61 1e        s32i       2,0xa0,0x78=>Stack[0x78]
        400e42b2 99 b1           s32i.n     6,0xa0,0x2c=>Stack[0x2c]
        400e42b4 c9 91           s32i.n     c,0xa0,0x24=>Stack[0x24]
        400e42b6 b2 61 1a        s32i       3,0xa0,0x68=>Stack[0x68]
        400e42b9 0c 08           movi.n     a8,0x0
        400e42bb 86 04 00        j          LAB_400e42d1
```

Then I took the lines that push to the stack and reorder them in order of the stack offset.

```Xtensa
400e426e 89 01           s32i.n     1,0xa0=>Stack[0x0],0x0
400e428f 89 11           s32i.n     1,0xa0,0x4=>Stack[0x4]
400e4285 99 21           s32i.n     a,0xa0,0x8=>Stack[0x8]
400e427d d9 31           s32i.n     9,0xa0,0xc=>Stack[0xc]
400e429c a9 41           s32i.n     2,0xa0,0x10=>Stack[0x10]
400e426a a9 51           s32i.n     2,0xa0,0x14=>Stack[0x14]
400e4291 89 61           s32i.n     1,0xa0,0x18=>Stack[0x18]
400e429e 39 71           s32i.n     8,0xa0,0x1c=>Stack[0x1c]
400e42a6 99 81           s32i.n     6,0xa0,0x20=>Stack[0x20]
400e42b4 c9 91           s32i.n     c,0xa0,0x24=>Stack[0x24]
400e4259 e9 a1           s32i.n     4,0xa0,0x28=>Stack[0x28]
400e42b2 99 b1           s32i.n     6,0xa0,0x2c=>Stack[0x2c]
400e42a8 e9 c1           s32i.n     4,0xa0,0x30=>Stack[0x30]
400e42ad d9 d1           s32i.n     9,0xa0,0x34=>Stack[0x34]
400e429a 99 e1           s32i.n     6,0xa0,0x38=>Stack[0x38]
400e428a 99 f1           s32i.n     e,0xa0,0x3c=>Stack[0x3c]
400e4254 82 61 10        s32i       b,0xa0,0x40=>Stack[0x40]
400e428c 82 61 11        s32i       1,0xa0,0x44=>Stack[0x44]
400e425d b2 61 12        s32i       3,0xa0,0x48=>Stack[0x48]
400e427f 82 61 13        s32i       1,0xa0,0x4c=>Stack[0x4c]
400e42a3 f2 61 14        s32i       7,0xa0,0x50=>Stack[0x50]
400e424e c2 61 15        s32i       c,0xa0,0x54=>Stack[0x54]
400e4273 82 61 16        s32i       1,0xa0,0x58=>Stack[0x58]
400e4270 a2 61 17        s32i       2,0xa0,0x5c=>Stack[0x5c]
400e4262 32 61 18        s32i       8,0xa0,0x60=>Stack[0x60]
400e4265 82 61 19        s32i       b,0xa0,0x64=>Stack[0x64]
400e42b6 b2 61 1a        s32i       3,0xa0,0x68=>Stack[0x68]
400e42a0 92 61 1b        s32i       6,0xa0,0x6c=>Stack[0x6c]
400e42aa 82 61 1c        s32i       1,0xa0,0x70=>Stack[0x70]
400e4278 f2 61 1d        s32i       7,0xa0,0x74=>Stack[0x74]
400e42af a2 61 1e        s32i       2,0xa0,0x78=>Stack[0x78]
400e4295 92 61 1f        s32i       0,0xa0,0x7c=>Stack[0x7c]
```

I pulled the characters out, it gave me the code `11a922186c46496eb1317c128b361720`. I submitted the code in the CLI to get the flag.

![CLI RE 101](/assets/images/2021/05/NorthSecBadge/CLIFlag8.png "CLI RE 101")

Flag: flag-REverSINg_xteNSA_is_NOt_that_HArd

![Badge 2](/assets/images/2021/05/NorthSecBadge/Badge2.png "Badge 2")

## Flag 9 / Badge 3

The second RE challenge start like the previous one. Download the binary and try to reverse it.

```xtensa
$ nc 192.168.185.113 1102 > rc102.zip

$ unzip rc102.zip
Archive:  rc102.zip
  inflating: re102.elf               
  inflating: __MACOSX/._re102.elf    
  
$ file re102.elf 
re102.elf: ELF 32-bit LSB executable, Tensilica Xtensa, version 1 (SYSV), statically linked, with debug_info, not stripped
```

I opened the elf file in Ghidra and went to the `app_main` function. I looks identical to the one for RE101. 

![RE 102 Main](/assets/images/2021/05/NorthSecBadge/RE102Main.png "RE 102 Main")

I looked at the `verify` function. This one looked more intimidating with all the jumps. 

![RE 102 Verify](/assets/images/2021/05/NorthSecBadge/RE102Verify.png "RE 102 Verify")

But when I looked at it, there is another simple pattern that stands out. It will move something from an offset of `ctx` to the register `a9`, move an hexadecimal value to `a8` and then compare both registers. If they are equals, it jumps to the next block, if not it make a jump, set `ctx`, and returns from the function.

I once again deduced that those hex values where the characters of the key at the offset used on `ctx`. 

So I pulled those out of the function and reorder them. 

```
0x00	0x66
0x1		0x32
0x2		0x31
0x3		0x39
0x4		0x65
0x5		0x36
0x6		0x63
0x7		0x64
0x8		0x62
0x9		0x31
0xa		0x66
0xb		0x61
0xc		0x34
0xd		0x61
0xe		0x34
0xf		0x38
0x10	0x62
0x11	0x31
0x12	0x36
0x13	0x30
0x14	0x64
0x15	0x30
0x16	0x30
0x17	0x64
0x18	0x36
0x19	0x31

0x1b	0x31
0x1c	0x38
0x1d	0x66
0x1e	0x39
0x1f	0x33
```

I saw that the offset 0x1a was missing. This got me confused and made me redo it again. But then I realized the character at this offset is not checked. I just need to provide one so the rest of the characters are at the correct offset. 

So I once again replace the hex values with the correct ASCII character, added a one at the missing offset and submitted in the CLI. 


Code: f219e6cdb1fa4a48b160d00d61118f93

![CLI RE 102](/assets/images/2021/05/NorthSecBadge/CLIFlag9.png "CLI RE 102")

Flag: flag-this_is_a_big_huge_enormous_condition

![Badge 3](/assets/images/2021/05/NorthSecBadge/Badge3.png "Badge 3")
