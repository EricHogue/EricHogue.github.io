---
layout: post
title: NorthSec 2021 Badge Writeup - Part 3 - The Map
date: 2021-05-28
type: post
tags:
- Writeup
- Hacking
- NorthSec
- BadgeLife
permalink: /2021/05/NorthSec2021BadgeTheMap/
img: 2021/05/NorthSecBadge/MapPost.png
---

After playing with the [NorthSec badge](https://shop.nsec.io/collections/badge/products/northsec-2021-badge) for a while, I had found seven flags out of ten. But things where getting harder.

Looking around the map. I saw an island on the far right, near where the Fisher_ is. I though it might contain a flag, but I had not idea how to get there. I could have poke at every pixels near the water to try and get to it. But I don't have that kind of patience. 

![The Island](/assets/images/2021/05/NorthSecBadge/Island.jpg "The Island")

At that point, I had already extracted the badge firmware. And talking with [Padraignix](https://padraignix.github.io/), I knew it was possible to extract the map out of it. So I decided that the easiest way to get there, was to extract the map out of the badge firmware and look for the way to the island in the map.

## Extracting the Firmware / Bonus Flag

Dumping the firmware out of the badge is not difficult. Espressif provides [a tool](https://github.com/espressif/esptool) to do it. You install it with pip, then you are ready to use it to extract the firmware out of the chip. Then you can use it to dump the firmware. For some reason, the extraction often fail. When it did, I just restarted the badge and tried again.

```bash
$ sudo esptool.py --chip esp32 --port /dev/ttyUSB0 -b 460800 read_flash 0x0 0x1000000 badge.bin             
[sudo] password for ehogue: 
esptool.py v3.0
Serial port /dev/ttyUSB0
Connecting.....
Chip is ESP32-D0WD-V3 (revision 3)
Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
Crystal is 40MHz
MAC: ac:67:b2:78:51:f0
Uploading stub...
Running stub...
Stub running...
Changing baud rate to 460800
Changed.
16777216 (100 %)
16777216 (100 %)
Read 16777216 bytes at 0x0 in 398.4 seconds (336.9 kbit/s)...
Hard resetting via RTS pin...
```

One of the first thing I did after dumping the firmware was to runs `strings` on it. 

```bash
strings badge.bin | grep -i flag
[0;33mW (%u) %s: ESP_INTR_FLAG_IRAM flag is set while CONFIG_UART_ISR_IN_IRAM is not enabled, flag updated
Have you dumped the firmware? Here is your flag [FLAG-JTAGPower0verwhelming]. Now flip the right bit in memory to activate the last (10th) flag icon in the status bar on screen.
flags and drink
Welcome! Your flag:
 FLAG-W3lc0m2NSECxx
Validate flags using the
!((vd->flags&VECDESC_FL_SHARED)&&(vd->flags&VECDESC_FL_NONSHARED))
pcb->flags & TF_RXCLOSED
tcp_enqueue_flags: need either TCP_SYN or TCP_FIN in flags (programmer violates API)
tcp_enqueue_flags: invalid pcb
tcp_enqueue_flags: check that first pbuf can hold optlen
tcp_enqueue_flags: invalid segment length
tcp_enqueue_flags: invalid queue length
tcp_enqueue_flags
intr flag not allowed
state wrong txa_flags=%x
set terminate flag
station: %02x:%02x:%02x:%02x:%02x:%02x leave, AID = %d, bss_flags is %d, bss:%p
discard flag
force sw tx %d state to idle, ebuf flag=%x
sched is null, if=%d tid=%d flags=%x
```

I could see the first flag in there, but also a bonus flag, and some indication about how to get the 10th flag.

![Bonus Flag](/assets/images/2021/05/NorthSecBadge/BadgeBonus.png "Bonus Flag")

## Dumping the Storage Partition

The format of the dump file was a mystery to me. I watched a the video [Extracting an ELF From an ESP32](https://www.youtube.com/watch?v=w4_3vwN_2dI) that has a nice description on the partition and how they are used. 

I installed the [ESP32 Image Parser](https://github.com/tenable/esp32_image_parser) with pip. 

I used it to read the partition table from the firmware dump.

```bash
$ python3 ../../tools/esp32_image_parser/esp32_image_parser.py show_partitions badge.bin

reading partition table...
entry 0:
  label      : nvs
  offset     : 0x9000
  length     : 24576
  type       : 1 [DATA]
  sub type   : 2 [WIFI]

entry 1:
  label      : phy_init
  offset     : 0xf000
  length     : 4096
  type       : 1 [DATA]
  sub type   : 1 [RF]

entry 2:
  label      : factory
  offset     : 0x10000
  length     : 1179648
  type       : 0 [APP]
  sub type   : 0 [FACTORY]

entry 3:
  label      : storage
  offset     : 0x130000
  length     : 5570560
  type       : 1 [DATA]
  sub type   : 130 [unknown]

MD5sum: 
d7e1de299e646439c0785bd243754384
Done
```

The partition that interested me at this point is the storage partition. I extracted it out, again use `esp32_image_parser.py`. 

```bash
python3 ../../tools/esp32_image_parser/esp32_image_parser.py dump_partition -partition storage badge.bin 
Dumping partition 'storage' to storage_out.bin
```

This gave me another binary file that I had no idea how to read. After some looking around, I learned that it was a [SPIFFS Filesystem](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/spiffs.html). 

There is a tool called [mkspiffs](https://github.com/igrr/mkspiffs) that allow us to read SPIFFS files. This was was harder to use because it requires compiling it, and running it with the correct switches. But once you find the correct values, it works well.

```bash
$ make dist CPPFLAGS="-DSPIFFS_OBJ_META_LEN=4"

$ /home/ehogue/Hacking/Conferences/NorthSec/2021/Badge/tools/mkspiffs/mkspiffs -u storage -d 5 -p 1024 storage_out.bin
Debug output enabled
Directory ./storage does not exists. Try to create it.
/qr.jpeg         > ./storage/qr.jpeg    size: 30270 Bytes
/nsec.jpeg       > ./storage/nsec.jpeg  size: 46429 Bytes
/re/re102.zip    > ./storage/re/re102.zip       size: 1136154 Bytes
/re/re101.zip    > ./storage/re/re101.zip       size: 1135073 Bytes
/library/.gitignore      > ./storage/library/.gitignore size: 16 Bytes
/library/maps    > ./storage/library/maps       size: 897679 Bytes
/library/jpeg    > ./storage/library/jpeg       size: 38730 Bytes
/welcome/sponsored-32.jpeg       > ./storage/welcome/sponsored-32.jpeg  size: 6202 Bytes
/welcome/nsec2021.jpeg   > ./storage/welcome/nsec2021.jpeg      size: 10909 Bytes
/welcome/sponsored-90.jpeg       > ./storage/welcome/sponsored-90.jpeg  size: 6751 Bytes
/welcome/sponsored-64.jpeg       > ./storage/welcome/sponsored-64.jpeg  size: 6581 Bytes
/welcome/sponsored-0.jpeg        > ./storage/welcome/sponsored-0.jpeg   size: 1107 Bytes
/welcome/sponsored-2.jpeg        > ./storage/welcome/sponsored-2.jpeg   size: 4257 Bytes
/welcome/blank.jpeg      > ./storage/welcome/blank.jpeg size: 1649 Bytes
/welcome/sponsored-100.jpeg      > ./storage/welcome/sponsored-100.jpeg size: 6810 Bytes
/welcome/nsec.jpeg       > ./storage/welcome/nsec.jpeg  size: 9662 Bytes
/welcome/sponsored-4.jpeg        > ./storage/welcome/sponsored-4.jpeg   size: 4811 Bytes
/welcome/start.jpeg      > ./storage/welcome/start.jpeg size: 15202 Bytes
/welcome/sponsored-80.jpeg       > ./storage/welcome/sponsored-80.jpeg  size: 6696 Bytes
/welcome/sponsored-8.jpeg        > ./storage/welcome/sponsored-8.jpeg   size: 5326 Bytes
/welcome/design.jpeg     > ./storage/welcome/design.jpeg        size: 5027 Bytes
/welcome/sponsored-1.jpeg        > ./storage/welcome/sponsored-1.jpeg   size: 3725 Bytes
/welcome/sponsored-16.jpeg       > ./storage/welcome/sponsored-16.jpeg  size: 5778 Bytes
/infoscreen/bootwarning.jpeg     > ./storage/infoscreen/bootwarning.jpeg        size: 80830 Bytes
/infoscreen/badgeinfo.jpeg       > ./storage/infoscreen/badgeinfo.jpeg  size: 149117 Bytes
/infoscreen/halloffame.jpeg      > ./storage/infoscreen/halloffame.jpeg size: 185000 Bytes
/rpg/.gitignore  > ./storage/rpg/.gitignore     size: 16 Bytes
/fonts/ILGH24XB.FNT      > ./storage/fonts/ILGH24XB.FNT size: 12305 Bytes
/fonts/ILGH16XB.FNT      > ./storage/fonts/ILGH16XB.FNT size: 4113 Bytes
/rpg/main.scene  > ./storage/rpg/main.scene     size: 54080 Bytes
/rpg/main.blocked        > ./storage/rpg/main.blocked   size: 5000 Bytes
```

## Reading the Map

Now I had a bunch of files. I could see the zip files for the two reverse engineering challenges. And a bunch of images that where used in the game. 

There were three files that looked interesting. 

```
storage/library/maps
storage/rpg/main.blocked
storage/rpg/main.scene
```

I was told to focus on the smaller one of those. So I started investigating `storage/rpg/main.blocked`. It contains binary data, and looking at it in vim did not make any sense. 

I started dumping it in hexadecimal and though I could see some pattern in there. But nothing that really helped me. So I kept trying to dump it in different ways. And with different number of columns. I also tried the `-e` option of `xxd` to switch to little-endian, but again it did not get anywhere. 

Then I started dumping the file as binary. I quickly saw some patterns in there. I wrote a small script to dump the file with every possible number of columns. But 25 columns gave me the best results. 

```bash
xxd -b -g0 -c25 storage/rpg/main.blocked | awk '{print $2}' > extracted.txt
```

![Map Version 1](/assets/images/2021/05/NorthSecBadge/MapV1.png "Map Version 1")

This looked close to the map, but not exactly there. We can see what looks like the castle, but it's a little off. With walls that are not there in the game. And the way in that do not connect. 

I had tried dumping the binary in little-endian, but it did not work with binary in `xxd`. So I wrote a small script to go through all the bytes and reverse them.

```python
import sys

if len(sys.argv) != 2:
    print('Usage {0} file'.format(sys.argv[0]));
    exit()

filename = sys.argv[1]

file = open(filename)

n = 8
for line in file.readlines():
    line = line.strip()
    chunks = [line[i:i+n] for i in range(0, len(line), n)]
    newLine = ''
    for chunk in chunks:
        newLine += chunk[::-1]
    print(newLine)
```

```bash
python3 ../endiannes.py extracted.txt > map.txt
```

![Map Version 2](/assets/images/2021/05/NorthSecBadge/MapV2.png "Map Version 2")

I finally had the map. The castle was showing correctly with the way in where I had found it. 

## Flag 3 / Badge 5

Getting the flag was now easy. On the previous screenshot, there is small path that goes all the way to a small island on the bottom right corner of the map. It's not the island I was trying to get to, there is no way to get to this one. But the path leads to another island that is not visible on the map. 

I followed the path up to see where it started. 

![Hidden Path](/assets/images/2021/05/NorthSecBadge/HiddenPath.png "Hidden Path")

Now I knew exactly where to go. From the boat where we start the game, I walked up until the end of the water, then to the right until I ended out of the map.

![Hidden Path Start](/assets/images/2021/05/NorthSecBadge/WalkingInTheHiddenPath.jpg "Hidden Path Start")

From there, I walked down until I reach a small island, clicked on ENTER and got the flag. 

![Flag 3](/assets/images/2021/05/NorthSecBadge/Flag3.jpg "Flag 3")

Flag: FLAG-MfoAkJu0TtD36

![Badge 5](/assets/images/2021/05/NorthSecBadge/Badge5.png "Badge 5")

## Other Posts In The NorthSec 2021 Badge Series 
* [Part 1 - First Flags](/2021/05/NorthSec2021BadgeFirstFlags/)
* [Part 2 - Reverse Engineering Flags](/2021/05/NorthSec2021BadgeReverseEngineeringFlags/)
* [Part 4 - Networking](/2021/05/NorthSec2021BadgeNetworking/)
* Part 5 - Flag 10 - Coming soon