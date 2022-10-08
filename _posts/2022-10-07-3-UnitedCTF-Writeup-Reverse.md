---
layout: post
title: UnitedCTF 2022 Writeup - Reverse
date: 2022-10-07
type: post
tags:
- Writeup
- Hacking
- UnitedCTF
- CTF
permalink: /2022/10/UnitedCTF/Reverse
img: 2022/10/UnitedCTF/Reverse/Reverse.png
---

## rodata

![rodata](/assets/images/2022/10/UnitedCTF/Reverse/rodata.png "rodata")

```
Find the input for which the program prints the success message.
```

Author: [hfz](https://github.com/hfz1337)

I downloaded the executable from the challenge and ran `strings` on it.

```bash
$ file rodata                                   
rodata: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7155669b4d056819c64fd2de4007b4d4fd83f81c, for GNU/Linux 3.2.0, stripped

$ strings rodata                                   
...
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
FLAG-str1ngsftw!
~~ Flag checker v1.0 ~~
Give me your input: 
Correct!
Wrong :(
;*3$"
GCC: (Debian 11.3.0-5) 11.3.0
```

The flag was printed.

Flag: FLAG-str1ngsftw!

## ltrace

![ltrace](/assets/images/2022/10/UnitedCTF/Reverse/ltrace.png "ltrace")

```
Find the input for which the program prints the success message.
```

Author: [hfz](https://github.com/hfz1337)

I took the challenge's file and ran it with `ltrace` to view the library calls it made.

```bash
$ ltrace ./ltrace 
write(1, "~~ Flag checker v1.1 ~~\n", 24~~ Flag checker v1.1 ~~
)                                                                                                        = 24
write(1, "Give me your input: ", 20Give me your input: )                                                                                                             = 20
read(0a
, "a\n", 32)                                                                                                                               = 2
strcspn("a\n", "\n")                                                                                                                             = 1
memfrob(0x7ffc01f545b0, 27, 1, 1)                                                                                                                = 0x7ffc01f545b0
strcmp("a", "FLAG-l1br4ryc4lltr4c1ngftw!")                                                                                                       = 27
write(1, "Wrong :(", 8Wrong :()                                                                                                                          = 8
+++ exited (status 0) +++
```

It used `stccmp`to compare the flag.

Flag: FLAG-l1br4ryc4lltr4c1ngftw!

## strace

![strace](/assets/images/2022/10/UnitedCTF/Reverse/strace.png "strace")

```
Here's the deal, the binary will send the flag to a black hole, but you need to catch it before it's too late!
```

Author: [hfz](https://github.com/hfz1337)

Another binary file. This time I used `strace` to check system calls.

```bash
$ strace ./strace                                     
execve("./strace", ["./strace"], 0x7ffdf455ef80 /* 63 vars */) = 0
brk(NULL)                               = 0x560fbaf6a000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f0cd712c000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=75998, ...}, AT_EMPTY_PATH) = 0
mmap(NULL, 75998, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f0cd7119000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300\223\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\200\0\300\4\0\0\0\1\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\244\311\214\f|x\0031\37\275\221\215\370\373\10\333"..., 68, 880) = 68
newfstatat(3, "", {st_mode=S_IFREG|0755, st_size=2049032, ...}, AT_EMPTY_PATH) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2101136, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f0cd6e00000
mmap(0x7f0cd6e28000, 1499136, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f0cd6e28000
mmap(0x7f0cd6f96000, 360448, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x196000) = 0x7f0cd6f96000
mmap(0x7f0cd6fee000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1ed000) = 0x7f0cd6fee000
mmap(0x7f0cd6ff4000, 53136, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f0cd6ff4000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f0cd7116000
arch_prctl(ARCH_SET_FS, 0x7f0cd7116740) = 0
set_tid_address(0x7f0cd7116a10)         = 2877
set_robust_list(0x7f0cd7116a20, 24)     = 0
mprotect(0x7f0cd6fee000, 16384, PROT_READ) = 0
mprotect(0x560fb90d8000, 4096, PROT_READ) = 0
mprotect(0x7f0cd715e000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f0cd7119000, 75998)           = 0
mprotect(0x560fb90d9000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0
write(1, "Hello! I'm about to write the fl"..., 54Hello! I'm about to write the flag... to /dev/null :)
) = 54
open("/dev/null", O_RDWR)               = 3
write(3, "FLAG-d1ds0m3on3s4yptr4ce??", 26) = 26
write(1, "Flag written to /dev/null, good "..., 37Flag written to /dev/null, good bye!
) = 37
exit_group(0)                           = ?
+++ exited with 0 +++
```

The program used `write` to send the flag to `/dev/null`. 

Flag: FLAG-d1ds0m3on3s4yptr4ce??