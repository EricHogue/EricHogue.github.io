---
layout: post
title: NorthSec 2023 Writeup - Look Within Myself
date: 2023-05-22
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2023/05/NorthSec/LookWithinMyself
img: 2023/05/NorthSec/LookWithinMyself/Description.png
---

This was a simple steganography challenge. I had to extract a 7-zip archive from an image and crack its password.

```
Drawing of how I feel. Deep inside, I hold the key. I need to learn to be better with myself and who I am.
```

The challenge had only an image.

![Myself Avatar](/assets/images/2023/05/NorthSec/LookWithinMyself/myself-avatar.jpg "Myself Avatar")

I saved the image to disk and ran stegoveritas on it.

```bash
$ stegoveritas myself-avatar.jpg

$ ls -1 results
exif
keepers
myself-avatar.jpg_autocontrast.png
myself-avatar.jpg_Blue_0.png
myself-avatar.jpg_Blue_1.png

...

myself-avatar.jpg_Sharpen.png
myself-avatar.jpg_Smooth.png
myself-avatar.jpg_solarized.png
trailing_data.bin
```

I looked at the results and saw a file containing some extra data after the image.

```
$ file results/trailing_data.bin
results/trailing_data.bin: 7-zip archive data, version 0.4

$ 7zz x results/trailing_data.bin

7-Zip (z) 21.07 (x64) : Copyright (c) 1999-2021 Igor Pavlov : 2021-12-26
 64-bit locale=en_CA.UTF-8 Threads:16

Scanning the drive for archives:
1 file, 22875265 bytes (22 MiB)

Extracting archive: results/trailing_data.bin

Enter password (will not be echoed):
ERROR: results/trailing_data.bin
Cannot open encrypted archive. Wrong password?


Can't open as archive: 1
Files: 0
Size:       0
Compressed: 0
```

It was a 7-zip file, I tried to extract it, but it was password protected. I should have tried the simple passwords here, but instead I cracked it with John.

```bash
$ 7z2john trailing_data.bin > hash.txt
ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes

$ john hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 6 for all loaded hashes
Cost 3 (compression type) is 1 for all loaded hashes
Cost 4 (data length) is 458 for all loaded hashes
Will run 6 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:12 20.07% 1/3 (ETA: 23:08:49) 0g/s 46.49p/s 46.49c/s 46.49C/s Datatrailing_data.bin(..Trailingtrailing_data.bin*
0g 0:00:01:18 21.03% 1/3 (ETA: 23:09:01) 0g/s 46.62p/s 46.62c/s 46.62C/s Datatrailing=..Trailingdata?
0g 0:00:05:05 71.60% 1/3 (ETA: 23:09:56) 0g/s 47.04p/s 47.04c/s 47.04C/s +tdata+...bdata.
0g 0:00:05:33 75.99% 1/3 (ETA: 23:10:09) 0g/s 46.97p/s 46.97c/s 46.97C/s trailing_data.bin59..Btrailing_data.bin60
0g 0:00:06:35 85.28% 1/3 (ETA: 23:10:34) 0g/s 46.49p/s 46.49c/s 46.49C/s Tbin66666..Trailing_data.bintrailing888
0g 0:00:07:43 95.79% 1/3 (ETA: 23:10:54) 0g/s 45.68p/s 45.68c/s 45.68C/s trailingtrailing_data.bin194..trailing_data.bindata1946
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
password         (trailing_data.bin)
1g 0:00:08:13 DONE 2/3 (2023-05-19 23:11) 0.002025g/s 45.56p/s 45.56c/s 45.56C/s 123456..diamond
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

The password was simply 'password'. I used it to extract the files from the archive and got the flag.

```bash
$ 7zz x results/trailing_data.bin

7-Zip (z) 21.07 (x64) : Copyright (c) 1999-2021 Igor Pavlov : 2021-12-26
 64-bit locale=en_CA.UTF-8 Threads:16

Scanning the drive for archives:
1 file, 22875265 bytes (22 MiB)

Extracting archive: results/trailing_data.bin

Enter password (will not be echoed):
--
Path = results/trailing_data.bin
Type = 7z
Physical Size = 22875265
Headers Size = 561
Method = LZMA2:24 7zAES
Solid = +
Blocks = 1

Everything is Ok

Folders: 1
Files: 21
Size:       23050616
Compressed: 22875265


$ ls myself
cat10.png  cat12.jpg  cat14.png  cat16.jpg  cat18.jpg  cat1.jpg   cat2.png  cat4.png  cat6.png  cat8.png  myself.txt
cat11.png  cat13.png  cat15.jpg  cat17.jpg  cat19.jpg  cat20.jpg  cat3.png  cat5.png  cat7.png  cat9.png

$ cat myself/myself.txt
 I am 120875ABAB, Intermediate Operator for GOD. If you read this, it is because you want to know more about me. Things I like are pictures of animals, logic puzzles and computers. I dislike fizzy drinks, wearing my necktie and boring colors. I hope to become a senior GOD operator one day. As an employee of the Corporation, I believe in our power to succeed. It was nice talking to you, goodbye!

 FLAG-43e1f21fd2741b2266eaf9c6cf93b46f62b73d7d9df0fa1e98611e6f64200815
```

I did not look at the extracted images when I did the challenge. I just got the flag and moved on. I just did, they were a bunch of cat pictures.

![Cat and badges](/assets/images/2023/05/NorthSec/LookWithinMyself/cat12.jpg "Cat and badges")
![Cats hacking](/assets/images/2023/05/NorthSec/LookWithinMyself/cat14.png "Cats hacking")