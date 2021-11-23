---
layout: post
title: Hackfest 2021 Writeup - LoveCrypt - Offering
date: 2021-11-22
type: post
tags:
- Writeup
- Hacking
- Hackfest
- CTF
permalink: /2021/11/HackfestCTF/LoveCrypt
img: 2021/11/HackfestCTF/LoveCrypt/site.png
---

This one is the first challenge I solved at the [Hackfest 2021 CTF](https://hfctf.ca/). I first overlooked it because I am not very good at crypto. But when I took a better look at it, it was not very hard. 

![Challenge Description](/assets/images/2021/11/HackfestCTF/LoveCrypt/LovecryptOffering.png "Challenge Description")

> Bring your offering before the Old Ones, cultist!

The description of the challenge was short. It contained a link to a web site.

![Challenge Site](/assets/images/2021/11/HackfestCTF/LoveCrypt/site.png "Challenge Site")

The site had a few links, if I remember well they didn't bring me anywhere. 

At the bottom of the site, there was something that looked like a flag.

> If you're a true cultist, you're familiar with our insanely secure cipher and you'll know what to do with this : HF-{wpLDu8K0wq3HocSIx4bFi8agx53HvcKoxJLGi8eIxIXCpce0x7rFm8KsxKnCpcakx57Gr8ekxIXCtcKkwrrDow==}

This is clearly Base64 encoded, so I took tried to decode it, but got only garbage out. 
```bash
$ echo wpLDu8K0wq3HocSIx4bFi8agx53HvcKoxJLGi8eIxIXCpce0x7rFm8KsxKnCpcakx57Gr8ekxIXCtcKkwrrDow== | base64 -d 

û´­ǡĈǆŋƠǝǽ¨ĒƋǈą¥ǴǺś¬ĩ¥ƤǞƯǤąµ¤ºã% 
```

I needed to figure out how to decrypt it. In the page source code, I found a big comment that looked like some source code. But unreadable. 

```python
#!/hfe/ova/rai clguba3

# Cu’atyhv ztyj’ansu Pguhyuh E’ylru jtnu’anty sugnta.
# --  UNAQF BSS VS LBH'ER ABG N PHYGVFG --

vzcbeg netcnefr
vzcbeg onfr64

qrs znva():
        cnefre =  netcnefr.NethzragCnefre()
        cnefre.nqq_nethzrag("bssrevat", uryc="Cerfrag lbhe bssrevat gb gur Byq Barf, phygvfg!")
        netf = cnefre.cnefr_netf()
        bssrevat = netf.bssrevat

        cevag("\aVä! Fuho-Avtthengu!\a")
        cevag("---------------------------------")
        rapelcg(bssrevat)
        cevag("---------------------------------")
        cevag("\aPguhyuh sugnta! ^(;,;)^\a")

qrs rapelcg(cnlybnq):
        pvcure = ""
        frperg = "alneyngubgrc"
        xrl = "e'ylru" * 13
        xrl = xrl[:yra(cnlybnq)]
        sbeovqqra_punef = []
        sbe yrggre va frperg:
                vs yrggre abg va sbeovqqra_punef:
                        sbeovqqra_punef.nccraq(yrggre)
        sbe yrggre va cnlybnq:
                vs yrggre va sbeovqqra_punef:
                        pune_pbqr = beq(yrggre) - 13
                        yrggre = pue(pune_pbqr)
                pune_pbqr = beq(yrggre) << 2
                yrggre = pue(pune_pbqr)
                pvcure += yrggre
        pvcure = pvcure[::-1]
        kberq_pvcure = ''.wbva(pue(beq(k) ^ beq(l)) sbe k,l va mvc(pvcure,xrl))
        pvcure = (onfr64.o64rapbqr(kberq_pvcure.rapbqr('hgs-8'))).qrpbqr('hgs-8')
        cevag("Urer'f lbhe rapelcgrq bssrevat :\a")
        cevag(pvcure)

vs __anzr__ == "__znva__":
        znva()
```

The first line looked like the shebang of a script. And the overall structure looked like some Python code. But unreadable. 

I took the code to [CyberChef and used ROT13](https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)&input=IyEvaGZlL292YS9yYWkgY2xndWJhMwoKIyBDdeKAmWF0eWh2IHp0eWrigJlhbnN1IFBndWh5dWggReKAmXlscnUganRudeKAmWFudHkgc3VnbnRhLgojIC0tICBVTkFRRiBCU1MgVlMgTEJIJ0VSIEFCRyBOIFBIWUdWRkcgLS0KCnZ6Y2JlZyBuZXRjbmVmcgp2emNiZWcgb25mcjY0CgpxcnMgem52YSgpOgogICAgICAgIGNuZWZyZSA9ICBuZXRjbmVmci5OZXRoenJhZ0NuZWZyZSgpCiAgICAgICAgY25lZnJlLm5xcV9uZXRoenJhZygiYnNzcmV2YXQiLCB1cnljPSJDZXJmcmFnIGxiaGUgYnNzcmV2YXQgZ2IgZ3VyIEJ5cSBCYXJmLCBwaHlndmZnISIpCiAgICAgICAgbmV0ZiA9IGNuZWZyZS5jbmVmcl9uZXRmKCkKICAgICAgICBic3NyZXZhdCA9IG5ldGYuYnNzcmV2YXQKCiAgICAgICAgY2V2YWcoIlxhVsOkISBGdWhvLUF2dHRoZW5ndSFcYSIpCiAgICAgICAgY2V2YWcoIi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSIpCiAgICAgICAgcmFwZWxjZyhic3NyZXZhdCkKICAgICAgICBjZXZhZygiLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIikKICAgICAgICBjZXZhZygiXGFQZ3VoeXVoIHN1Z250YSEgXig7LDspXlxhIikKCnFycyByYXBlbGNnKGNubHlibnEpOgogICAgICAgIHB2Y3VyZSA9ICIiCiAgICAgICAgZnJwZXJnID0gImFsbmV5bmd1YmdyYyIKICAgICAgICB4cmwgPSAiZSd5bHJ1IiAqIDEzCiAgICAgICAgeHJsID0geHJsWzp5cmEoY25seWJucSldCiAgICAgICAgc2Jlb3ZxcXJhX3B1bmVmID0gW10KICAgICAgICBzYmUgeXJnZ3JlIHZhIGZycGVyZzoKICAgICAgICAgICAgICAgIHZzIHlyZ2dyZSBhYmcgdmEgc2Jlb3ZxcXJhX3B1bmVmOgogICAgICAgICAgICAgICAgICAgICAgICBzYmVvdnFxcmFfcHVuZWYubmNjcmFxKHlyZ2dyZSkKICAgICAgICBzYmUgeXJnZ3JlIHZhIGNubHlibnE6CiAgICAgICAgICAgICAgICB2cyB5cmdncmUgdmEgc2Jlb3ZxcXJhX3B1bmVmOgogICAgICAgICAgICAgICAgICAgICAgICBwdW5lX3BicXIgPSBiZXEoeXJnZ3JlKSAtIDEzCiAgICAgICAgICAgICAgICAgICAgICAgIHlyZ2dyZSA9IHB1ZShwdW5lX3BicXIpCiAgICAgICAgICAgICAgICBwdW5lX3BicXIgPSBiZXEoeXJnZ3JlKSA8PCAyCiAgICAgICAgICAgICAgICB5cmdncmUgPSBwdWUocHVuZV9wYnFyKQogICAgICAgICAgICAgICAgcHZjdXJlICs9IHlyZ2dyZQogICAgICAgIHB2Y3VyZSA9IHB2Y3VyZVs6Oi0xXQogICAgICAgIGtiZXJxX3B2Y3VyZSA9ICcnLndidmEocHVlKGJlcShrKSBeIGJlcShsKSkgc2JlIGssbCB2YSBtdmMocHZjdXJlLHhybCkpCiAgICAgICAgcHZjdXJlID0gKG9uZnI2NC5vNjRyYXBicXIoa2JlcnFfcHZjdXJlLnJhcGJxcignaGdzLTgnKSkpLnFycGJxcignaGdzLTgnKQogICAgICAgIGNldmFnKCJVcmVyJ2YgbGJoZSByYXBlbGNncnEgYnNzcmV2YXQgOlxhIikKICAgICAgICBjZXZhZyhwdmN1cmUpCgp2cyBfX2FuenJfXyA9PSAiX196bnZhX18iOgogICAgICAgIHpudmEoKQ) on it. 

That gave me back the following Python code.

```python
#!/usr/bin/env python3

# Ph’nglui mglw’nafh Cthulhu R’lyeh wgah’nagl fhtagn.
# --  HANDS OFF IF YOU'RE NOT A CULTIST --

import argparse
import base64

def main():
        parser =  argparse.ArgumentParser()
        parser.add_argument("offering", help="Present your offering to the Old Ones, cultist!")
        args = parser.parse_args()
        offering = args.offering

        print("\nIä! Shub-Niggurath!\n")
        print("---------------------------------")
        encrypt(offering)
        print("---------------------------------")
        print("\nCthulhu fhtagn! ^(;,;)^\n")

def encrypt(payload):
        cipher = ""
        secret = "nyarlathotep"
        key = "r'lyeh" * 13
        key = key[:len(payload)]
        forbidden_chars = []
        for letter in secret:
                if letter not in forbidden_chars:
                        forbidden_chars.append(letter)
        for letter in payload:
                if letter in forbidden_chars:
                        char_code = ord(letter) - 13
                        letter = chr(char_code)
                char_code = ord(letter) << 2
                letter = chr(char_code)
                cipher += letter
        cipher = cipher[::-1]
        xored_cipher = ''.join(chr(ord(x) ^ ord(y)) for x,y in zip(cipher,key))
        cipher = (base64.b64encode(xored_cipher.encode('utf-8'))).decode('utf-8')
        print("Here's your encrypted offering :\n")
        print(cipher)

if __name__ == "__main__":
        main()
```

This is the code used to encrypt the flag, with the key included. I just needed to reverse it to decrypt the flag on the page.


```python
#!/usr/bin/env python3

# Ph’nglui mglw’nafh Cthulhu R’lyeh wgah’nagl fhtagn.
# --  HANDS OFF IF YOU'RE NOT A CULTIST --

import argparse
import base64


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "offering", help="Present your offering to the Old Ones, cultist!")
    args = parser.parse_args()
    offering = args.offering

    print("\nIä! Shub-Niggurath!\n")
    print("---------------------------------")
    decrypt(offering)
    print("---------------------------------")
    print("\nCthulhu fhtagn! ^(;,;)^\n")


def decrypt(payload):
    cipher = (base64.b64decode(payload.encode('utf-8'))).decode('utf-8')

    key = "r'lyeh" * 13
    secret = "nyarlathotep"

    key = key[:len(cipher)]
    cipher = ''.join(chr(ord(y) ^ ord(x)) for x, y in zip(cipher, key))
    cipher = cipher[::-1]

    forbidden_chars = []

    for letter in secret:
        letter = ord(letter) - 13
        if letter not in forbidden_chars:
            forbidden_chars.append(letter)

    decoded = ""
    for letter in cipher:
        char_code = ord(letter) >> 2
        if char_code in forbidden_chars:
            char_code = char_code + 13

        letter = chr(char_code)
        decoded += letter

    print(decoded)


if __name__ == "__main__":
    main()
```

We the script written, I called it and got the flag back.

```bash
python3 decrypt.py wpLDu8K0wq3HocSIx4bFi8agx53HvcKoxJLGi8eIxIXCpce0x7rFm8KsxKnCpcakx57Gr8ekxIXCtcKkwrrDow==

Iä! Shub-Niggurath!

---------------------------------
1234looks0a0lot0like0fishmen5678
---------------------------------

Cthulhu fhtagn! ^(;,;)^
```

Flag:  FLAG-1234looks0a0lot0like0fishmen5678