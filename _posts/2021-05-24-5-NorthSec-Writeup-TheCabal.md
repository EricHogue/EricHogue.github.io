---
layout: post
title: NorthSec 2021 Writeup - The Cabal
date: 2021-05-24
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2021/05/NorthSec2021WriteupTheCabal/
---

In this challenge from the [2021 NorthSec CTF](https://nsec.io/competition/), we are given a file to download and extract the flag from.

I downloaded the file, then tried to read it. It was just gibberish. 

I ran file on it, it contained [EBCDIC](https://en.wikipedia.org/wiki/EBCDIC) text. 

```bash
$ file challenge.cabal 
challenge.cabal: EBCDIC text
```

I vaguely remembered this as an old character encoding, but not much more. And I had no idea how to read it. I searched a little bit and converting it to ASCII was simple. 

```bash
dd conv=ascii if=challenge.cabal of=program.cobol
```

This gave a COBOL program that takes an input, apply some transformation to it and tells you if it's the valid flag or not.

```cobol
       IDENTIFICATION DIVISION.
       PROGRAM-ID. GET-FLAG.
       
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       78 KEY-LEN          VALUE   28.
       78 ANSWER-OF-LIFE   VALUE   42.
       01 CHAR-INDEX       PIC     99.
       01 USER-KEY         PIC     X(KEY-LEN).
       01 KEY-TABLE.
           05 KEY-VALUE    PIC     X(09)    OCCURS KEY-LEN TIMES.     
       01 IS-VALID         PIC     9(5)     COMP.
       01 ARG1             PIC     9(5)     COMP.
       01 ARG2             PIC     9(5)     COMP.
       01 RETRN            PIC     9(5)     COMP.
       01 RSD1             PIC     9(5)     COMP.
       01 RSD2             PIC     9(5)     COMP.
       01 QTN1             PIC     9(5)     COMP.
       01 QTN2             PIC     9(5)     COMP.
       01 BIT-VAL          PIC     9(5)     COMP.
           
       
       PROCEDURE DIVISION.
       000-MAIN.
           DISPLAY "PLEASE ENTER THE KEY ("KEY-LEN" chars)".
           ACCEPT USER-KEY.
           PERFORM 001-SET-FLAG-KEY.
           MOVE 1 TO IS-VALID
           MOVE 1 TO CHAR-INDEX.
           PERFORM UNTIL CHAR-INDEX > KEY-LEN
               COMPUTE ARG1 = FUNCTION ORD(USER-KEY(CHAR-INDEX:1)) - 1
               MOVE KEY-VALUE(CHAR-INDEX) TO ARG2
               PERFORM 002-MAGIC-OP
               IF RETRN IS NOT EQUAL TO ANSWER-OF-LIFE
                  MOVE 0 TO IS-VALID
                END-IF
               ADD 1 TO CHAR-INDEX
           END-PERFORM.
           IF IS-VALID IS EQUAL TO 1
              DISPLAY "VALID KEY ENTERED. WELCOME TO THE CABAL."
          ELSE
              DISPLAY "INVALID KEY ENTERED."
          END-IF.  
           STOP RUN.
       
       001-SET-FLAG-KEY.
           MOVE 108 TO KEY-VALUE(1).
           MOVE 102 TO KEY-VALUE(2).
           MOVE 107 TO KEY-VALUE(3).
           MOVE 109 TO KEY-VALUE(4).
           MOVE 7 TO KEY-VALUE(5).
           MOVE 105 TO KEY-VALUE(6).
           MOVE 101 TO KEY-VALUE(7).
           MOVE 104 TO KEY-VALUE(8).
           MOVE 101 TO KEY-VALUE(9).
           MOVE 102 TO KEY-VALUE(10).
           MOVE 27 TO KEY-VALUE(11).
           MOVE 121 TO KEY-VALUE(12).
           MOVE 126 TO KEY-VALUE(13).
           MOVE 98 TO KEY-VALUE(14).
           MOVE 111 TO KEY-VALUE(15).
           MOVE 105 TO KEY-VALUE(16).
           MOVE 107 TO KEY-VALUE(17).
           MOVE 104 TO KEY-VALUE(18).
           MOVE 107 TO KEY-VALUE(19).
           MOVE 102 TO KEY-VALUE(20).
           MOVE 108 TO KEY-VALUE(21).
           MOVE 106 TO KEY-VALUE(22).
           MOVE 124 TO KEY-VALUE(23).
           MOVE 101 TO KEY-VALUE(24).
           MOVE 120 TO KEY-VALUE(25).
           MOVE 99 TO KEY-VALUE(26).
           MOVE 126 TO KEY-VALUE(27).
           MOVE 25 TO KEY-VALUE(28).
           
       002-MAGIC-OP.
           MOVE 1 TO BIT-VAL.
           MOVE ZERO TO RETRN.
           IF ARG1 IS NOT EQUAL TO ZERO OR ARG2 IS NOT EQUAL TO ZERO
              PERFORM 003-MAGIC-OP-SUB
                UNTIL ARG1 IS EQUAL TO ZERO AND ARG2 IS EQUAL TO ZERO.
       
       003-MAGIC-OP-SUB.
           DIVIDE ARG1 BY 2 GIVING QTN1.
           COMPUTE RSD1 = ARG1 - QTN1 * 2.

           DIVIDE ARG2 BY 2 GIVING QTN2.
           COMPUTE RSD2 = ARG2 - QTN2 * 2.

           IF RSD1 IS NOT EQUAL TO RSD2 THEN
              ADD BIT-VAL TO RETRN
            END-IF.
           MULTIPLY BIT-VAL BY 2 GIVING BIT-VAL.

           MOVE QTN1 TO ARG1.
           MOVE QTN2 TO ARG2. 
```

The program build a key array. Then loop through each characters and apply some transformation to them. 
* Divide the character values from the key and the flag by 2
* Take the reminders 
* If the reminders are not equal, add BIT-VAL to the RETRN value
* Multiply BIT-VAL by 2
* Set the character values to the result of the divisions
* Once the character values reach 0, validate that the RETRN is set to 42

I understood the transformations done to the characters, but reversing it seemed very difficult. So I decided to port the algorithm to Python, and then brute force the characters one by one. 

Here's my Python version of the script.

```python
ASCII_MIN = 32
ASCII_MAX = 256

flagKey = [
    108,
    102,
    107,
    109,
    7,
    105,
    101,
    104,
    101,
    102,
    27,
    121,
    126,
    98,
    111,
    105,
    107,
    104,
    107,
    102,
    108,
    106,
    124,
    101,
    120,
    99,
    126,
    25
]

def main():
    flag = ''
    for target in flagKey:
        flag += chr(findCharFor(target))

    print(flag)

def findCharFor(target):

    for i in range(ASCII_MIN, ASCII_MAX + 1):
        arg1 = i
        arg2 = target
        isValid = magicOp(arg1, arg2)
        if isValid:
            return i
    
    return ord('?')

def magicOp(arg1, arg2):
    bitVal = 1
    toReturn = 0

    while arg1 != 0 and arg2 != 0:
        (arg1, arg2, bitVal, toReturn) = magicOpSub(arg1, arg2, bitVal, toReturn)

    return toReturn == 42

def magicOpSub(arg1, arg2, bitVal, toReturn):
    qtn1 = arg1 // 2
    rsd1 = arg1 - (qtn1 * 2)

    qtn2 = arg2 // 2
    rsd2 = arg2 - (qtn2 * 2)

    if rsd1 != rsd2:
        toReturn += bitVal

    bitVal = bitVal * 2
           
    arg1 = qtn1
    arg2 = qtn2

    return (arg1, arg2, bitVal, toReturn)


main()
```

The script loops through all the possible ASCII characters and check if they passed the 'magic' validation. 

I ran the script and I got this output.
```
FLAG?COBOL?STHECABALF@VORIT?
```

The question marks are characters that the script could not identified. I thought it was easy enough to see `FLAG-COBOLISTHECABALF@VORITE`, but that flag was rejected. Then I remember I was in a hacker competition, so it had to be l33t speak. I tried submitting `FLAG-COBOL1STHECABALF@VORIT3` and it got accepted.

Flag: FLAG-COBOL1STHECABALF@VORIT3
