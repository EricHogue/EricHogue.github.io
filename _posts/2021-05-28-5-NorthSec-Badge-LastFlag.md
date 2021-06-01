---
layout: post
title: NorthSec 2021 Badge Writeup - Part 5 - Last Flag
date: 2021-06-01
type: post
tags:
- Writeup
- Hacking
- NorthSec
- BadgeLife
permalink: /2021/05/NorthSec2021BadgeLastFlag/
img: 2021/05/NorthSecBadge/10Flags.jpg
---

Now that I had nine flags, I was missing only one. And I knew what I had to do from the hint in the firmware. 

```
Now flip the right bit in memory to activate the last (10th) flag icon in the status bar on screen.
```

But I had no idea which bit needed to be flipped. And how to push it back to the badge. I already knew how to dump the firmware from the badge and how to extract a partition from it. 

The partition that I needed to read in the [Non-volatile storage (NVS)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/nvs_flash.html). This partition is used to store key value pairs in the flash memory. 

The first thing I did was to clear the NVS partition. I needed to do it so I could start back for the start to take screenshots for the writeups. And it also allowed me do dump the firmware after every flag so I could compare the state at every steps.

I created an [empty NVS partition](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/nvs_partition_gen.html) CSV. 

```bash
$ cat nvs.txt 
key,type,encoding,value
namespace_name,namespace,,
key1,data,u8,1
```

Then I used the [NVS Partition Generator Utility](https://github.com/espressif/esp-idf/tree/master/components/nvs_flash/nvs_partition_generator) to generate the partition from the CSV.

```bash 
$ python3 nvs_partition_gen.py generate nvs.txt nvsPartition.bin 24576

Creating NVS binary with version: V2 - Multipage Blob Support Enabled
Created NVS binary: ===> nvsPartition.bin
```

Then I pushed the partition to the badge with [esptool.py](https://github.com/espressif/esptool).

```bash
$ sudo esptool.py --chip esp32 --port /dev/ttyUSB0 -b 460800 write_flash 0x9000 nvsPartition.bin 
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
Configuring flash size...
Compressed 24576 bytes to 184...
Wrote 24576 bytes (184 compressed) at 0x00009000 in 0.0 seconds (effective 27555.8 kbit/s)...
Hash of data verified.

Leaving...
Hard resetting via RTS pin...
```

This gave me a clean state to start analyzing what happens when I got a new flag.

![Clean State](/assets/images/2021/05/NorthSecBadge/CleanState.jpg "Clean State")

## Finding Bit To Change
I redid the 9 flags from the start, dumping the firmware at the beginning, and after every flag. 

Then for all the dumps, I extracted the NVS partition in json.

```bash
$ python3 ../tools/esp32_image_parser/esp32_image_parser.py dump_nvs -partition nvs badge.bin -nvs_output_type json > nvs.json

# Remove the first line from nvs.json

cat nvs.json | python -m json.tool > pretty.json
```

This gave me a big json file. I started comparing the version I had after each flag. I quickly tough I had found the value that needed to be changes. The value with the key `159875028` seemed to change with every flag I found. The way some values changes from a 3 to a 0 was weird, it did not seems to follow the order of the flags in the map, or in Discord. I still tough it might be the correct value.

```
222222222222222222222222222222220002200033333333333333333333333333333333333333333333333333333333333333333333333333333333333333
222222222222222222222222222222220002000022000022000000002000333333333333333333333333333333333333333333333333333333333333333333
222222222222222222222222222222220002000000000000000000000000000022223320333333333333333333333333333333333333333333333333333333
222222222222222222222222222222220002000000000000000000000000000000002000222233333333333333333333333333333333333333333333333333
222222222222222222222222222222220002000000000000000000000000000000000000000022000022332033333333333333333333333333333333333333
222222222222222222222222222222220002000000000000000000000000000000000000000000000000000022000022332033333333333333333333333333
222222222222222222222222222222220002000000000000000000000000000000000000000000000000000000000000000022000022000020003333333333
222222222222222222222222222222220002000000000000000000000000000000000000000000000000000000000000000000000000000000000000222233
222222222222222222222222222222220002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033
222222222222222222222222222222220002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033
```

But on the 9th flag, it didn't change. So that was not the value I needed to change. 

I went back to comparing the versions of the NVS. But that was not easy. The way [NVS handle updates](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/nvs_flash.html#pages-and-entries) is that it mark the values as 'Erased' and create a new entry to replace it. So comparing the different extraction did not really helped. 

I then decided to compare the entries with the same key in the dump after the last flag. I started analyzing a few of them, but eventually I came across one called 'save'. 

```json
{
	"entry_chunk_index": 0,
	"entry_data": "AAAAAAEAAAAAAAEBAQAZAAEAAAD/AP8AAQEBAQEBAQEBAAAA",
	"entry_data_size": 36,
	"entry_data_type": "BLOB_DATA",
	"entry_key": "save",
	"entry_ns_index": 2,
	"entry_span": 3,
	"entry_state": "Written",
	"entry_type": "BLOB_DATA"
},
```

If I take the data, [base64 decode it and convert it to hexadecimal](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',false)To_Hex('Space',0)&input=QUFBQUFBRUFBQUFBQUFFQkFRQVpBQUVBQUFEL0FQOEFBUUVCQVFFQkFRRUJBQUFB), I get this:

```
00 00 00 00 01 00 00 00 00 00 01 01 01 00 19 00 01 00 00 00 ff 00 ff 00 01 01 01 01 01 01 01 01 01 00 00 00
```

There is a series of nine '01' at the end of it. I took the previous value from the file and [applied the same transformations](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',false)To_Hex('Space',0)&input=QUFBQUFBRUFBQUFBQUFFQkFRQVpBQUVBQUFEL0FQOEFBUUVCQVFFQUFRRUJBQUFB).

```
00 00 00 00 01 00 00 00 00 00 01 01 01 00 19 00 01 00 00 00 ff 00 ff 00 01 01 01 01 01 00 01 01 01 00 00 00
```

When I compared the two values, I saw that one of the bit at the end changed from '00' to '01' when I got the last flag. It's the 6th bit, and the last flag I got is #6 on the badge. 

I looked at [another version](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',false)To_Hex('Space',0)&input=QUFBQUFBRUFBQUFBQUFBQkFRQVpBQUVBQUFEL0FQOEFBUUVBQVFFQUFRRUJBQUFB) and it also had a bit that went from '00' to '01'. 

## Setting The Last Flag
With that, I knew which bit needed to be set to get the tenth flag. 

I dumped the partition binary.

```bash
python3 ../tools/esp32_image_parser/esp32_image_parser.py dump_partition -partition nvs badge.bin 
Dumping partition 'nvs' to nvs_out.bin
```

Then I opened the `nvs_out.bin` file in hexeditor, found the correct byte and changed it. 

![Bit Flip](/assets/images/2021/05/NorthSecBadge/BitFlip.png)

I saved the file, then push it back to the badge.

```bash
sudo esptool.py --chip esp32 --port /dev/ttyUSB0 -b 460800 write_flash 0x9000 nvs_out.bin
esptool.py v3.0
Serial port /dev/ttyUSB0
Connecting....
Chip is ESP32-D0WD-V3 (revision 3)
Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
Crystal is 40MHz
MAC: ac:67:b2:78:51:f0
Uploading stub...
Running stub...
Stub running...
Changing baud rate to 460800
Changed.
Configuring flash size...
Compressed 24576 bytes to 2513...
Wrote 24576 bytes (2513 compressed) at 0x00009000 in 0.1 seconds (effective 3252.6 kbit/s)...
Hash of data verified.

Leaving...
Hard resetting via RTS pin...
```

With that, I had the 10th flag.

![10 Flags](/assets/images/2021/05/NorthSecBadge/10Flags.jpg "10 Flags")

## Thank You

I want to say thank you to everyone who was involved in making the badge. I had a lot of fun, and I learned a lot with it. I'm looking forward to see next year's badge. 

Also thanks to vicious and [Padraignix](https://padraignix.github.io/), I would not have done all 10 flags without you two.


## Other Posts In The NorthSec 2021 Badge Series 
* [Part 1 - First Flags](/2021/05/NorthSec2021BadgeFirstFlags/)
* [Part 2 - Reverse Engineering Flags](/2021/05/NorthSec2021BadgeReverseEngineeringFlags/)
* [Part 3 - The Map](/2021/05/NorthSec2021BadgeTheMap/)
* [Part 4 - Networking](/2021/05/NorthSec2021BadgeNetworking/)