---
layout: post
title: UnitedCTF 2022 Writeup - Cryptography
date: 2022-10-08
type: post
tags:
- Writeup
- Hacking
- UnitedCTF
- CTF
permalink: /2022/10/UnitedCTF/Cryptography
img: 2022/10/UnitedCTF/Cryptography/Cryptography.png
---

## Xorbsession 1

![Xorbsession 1](/assets/images/2022/10/UnitedCTF/Cryptography/Xorbsession1.png "Xorbsession 1")

```
Someone xored my flag :( and gave me the key: cafebabe

I will show you the base64 of the xored flag, here you go: jLL7+efO3NijndPfppLD5qWM2M2vy4/brg==
```

Author: [ntnco](https://github.com/ntnco)

I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'Hex','string':'cafebabe'%7D,'Standard',false)&input=akxMNytlZk8zTmlqbmRQZnBwTEQ1cVdNMk0ydnk0L2JyZz09) to base64 decode the flag. And then XOR it with the provided key. 

Flag: FLAG-0fficiallyXorbse55ed

## Xorbsession 2

![Xorbsession 2](/assets/images/2022/10/UnitedCTF/Cryptography/Xorbsession2.png "Xorbsession 2")

```
Flag has been xored with entire dictionary but i forgot in which order. Thankfully, xor is commutative.

Here is the base64 of the xored flag: XWxPUD5HSBhAR1gHVnh9b31mNUg=
```

Author: [ntnco](https://github.com/ntnco)

The flag was XORed with all the words in a dictionary file. I wrote a script to XOR it again and get the flag back.

```python
import base64

def xor_two_str(a,b):
    xored = []
    for i in range(len(a)):
        xored_value = chr(a[i%len(a)] ^ b[i%len(b)])
        xored.append(xored_value)
    return ''.join(xored)


encoded = "XWxPUD5HSBhAR1gHVnh9b31mNUg="
decoded = str(base64.b64decode(encoded), 'utf-8')

f = open("dictionary.csv","r")
lines = f.readlines()

for line in lines:
    key = line.strip()
    decoded = xor_two_str(decoded.encode(), key.encode())

print(decoded)
```

```bash
$ python xor2.py
FLAG-Pr0g_I5_Ur_Fr3n
```

Flag: FLAG-Pr0g_I5_Ur_Fr3n

## Xorbsession 3
![Xorbsession 3](/assets/images/2022/10/UnitedCTF/Cryptography/Xorbsession3.png "Xorbsession 3")

```
The flag has been xored then base64'd 10 times. I had 100 keys to choose from, so if you try them all at each step it will take you up to 1000 tries. You will never find the time to do that!!!

zyLDjqVFyZiZUfCtk3Lx7NchroudeuO3sH6pqo5BwK7TItyutTr3s75vsZmXb9DwyF7I7p9j+7KYJdbshFf+iYZnz7KrW625t03eqpJB2+/FZ8+PrizNsbB47KqLb8CaymfTraxj+6O/JNKWlnLLsctZqpqzc/fonyfS7oRGq6OGXK6ymmGsnb9SwqyEUdiYxXfDj5pl/7WZQa25zib2rMVmz6yzY83pmU2tiYpRwJrOTM+yn3PJgrVvqbmTVtPtkCPU6qtbqZq7Jqmqj2/ytspe06+fZuOPmECtrpt73JnKZN/rnnPNrL4n+JSEbcvwyiHTsqtF1pOef62Bkn/cgsxk+ZqmcNafsH7oopF7w/TPZ/m3nWbjv71S7K6KR/KdxGX9iJ46zbiyQNmZhGL+i8hh6a6zYPeiuXm1vohEo+yQINeanWDsn59C7OKTf/nsxXfDi5lh2by9U97rlHvb7sVf6q6zY++VmVPRloxG6qzOd6qvmnPJgZgn+Oubb/aIlyDU6qlg3rmwTfSsj0HIi9NZ+bmdLayWuVGpvoxdzO7LX6uqpWPNlLBAyo2TbK+py2bU7qVz/72ffMrjlkbMmpAjz6KfWtnitX7SrYwm1LzXd8OrmV/Vt7F71r6be9z0ynTf761hrLW7XaiDkk3ykMVZ/a6zc/idu0Leo4x8zIjMdO3pqHDv77Z70uqRfPntziCr7p9x/5W7UN6okSb29Mpn+YGxRd29sXii5g==
```

Author: [ntnco](https://github.com/ntnco)

The description explains that the flag was XOR and base64'd 10 times. But is selected a random key at each step for the XOR.

The code to `encrypt` it was provided, with all the keys to choose from.

```python
from base64 import b64encode
from random import choice


def xor(cur, b):
    res = cur.copy()
    for i in range(len(res)):
        res[i] ^= b[i % len(b)]
    return res


flag = bytearray(b'FLAG-REDACTEDHEXREDACTEDHEXREDACTEDHE')
keys = [0xa93f9c6f,
     0x3032fa89,
     0xc56714be,
     0x031734d4,
     ...
     0x2102a284
] 


if __name__ == '__main__':
     for _ in range(10):
         key = choice(keys)
         # print(hex(key)) # print keys
         flag = xor(flag, bytearray(key.to_bytes(4, 'big')))
         flag = bytearray(b64encode(flag))
     
     print(flag.decode('ascii')) # prints the puzzle input
```

I wrote a script to brute force the flag. It tried the oposite operations, until it got the flag back.

```python
from base64 import b64encode, b64decode
from random import choice


def xor(cur, b):
    res = cur.copy()
    for i in range(len(res)):
        res[i] ^= b[i % len(b)]
    return res



flag = bytearray(b'zyLDjqVFyZiZUfCtk3Lx7NchroudeuO3sH6pqo5BwK7TItyutTr3s75vsZmXb9DwyF7I7p9j+7KYJdbshFf+iYZnz7KrW625t03eqpJB2+/FZ8+PrizNsbB47KqLb8CaymfTraxj+6O/JNKWlnLLsctZqpqzc/fonyfS7oRGq6OGXK6ymmGsnb9SwqyEUdiYxXfDj5pl/7WZQa25zib2rMVmz6yzY83pmU2tiYpRwJrOTM+yn3PJgrVvqbmTVtPtkCPU6qtbqZq7Jqmqj2/ytspe06+fZuOPmECtrpt73JnKZN/rnnPNrL4n+JSEbcvwyiHTsqtF1pOef62Bkn/cgsxk+ZqmcNafsH7oopF7w/TPZ/m3nWbjv71S7K6KR/KdxGX9iJ46zbiyQNmZhGL+i8hh6a6zYPeiuXm1vohEo+yQINeanWDsn59C7OKTf/nsxXfDi5lh2by9U97rlHvb7sVf6q6zY++VmVPRloxG6qzOd6qvmnPJgZgn+Oubb/aIlyDU6qlg3rmwTfSsj0HIi9NZ+bmdLayWuVGpvoxdzO7LX6uqpWPNlLBAyo2TbK+py2bU7qVz/72ffMrjlkbMmpAjz6KfWtnitX7SrYwm1LzXd8OrmV/Vt7F71r6be9z0ynTf761hrLW7XaiDkk3ykMVZ/a6zc/idu0Leo4x8zIjMdO3pqHDv77Z70uqRfPntziCr7p9x/5W7UN6okSb29Mpn+YGxRd29sXii5g==')
keys = [0xa93f9c6f,
     0x3032fa89,
     0xc56714be,
     0x031734d4,
     ...
     0x2102a284
] 

def decryt(flag, depth):
    flagLength = len(flag)
    if (flagLength < 5):
        return

    try:
        flag = bytearray(b64decode(flag))
    except:
        return

    for key in keys: 
        attempt = xor(flag, bytearray(key.to_bytes(4, 'big')))
        if depth == 9 and len(attempt) > 3:
            try:
                possible = attempt.decode()
                if 'FLAG' in possible:
                    print(possible)
                    exit()
            except:
                pass
        if depth < 9:
            decryt(attempt, depth + 1)


if __name__ == '__main__':
    decryt(flag, 0)
```

I ran the script, and after a few minutes got the flag. 

```bash
$ python decryptxorbsession3.py
FLAG-26271dcfb25de5858c2216d47a563208
```

Flag: FLAG-26271dcfb25de5858c2216d47a563208

## Baby RSA

![Baby RSA](/assets/images/2022/10/UnitedCTF/Cryptography/BabyRSA.png "Baby RSA")

```
There's a reason prime numbers need to be large.
⚠️ Note: flag is not in standard format.
```

Author: [hfz](https://github.com/hfz1337)

The challenge provided a text file with all the values needed to decrypt the flag.

```
e = 0x10001
n = 0xac586f447e16c51821999902cf993f47
ciphertext = 0x9b7a8eb8ad559e3f52ff3ceeaf0025a4
```

I looked around and found [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) that allowed to break simple RSA. 

```
$ python RsaCtfTool.py -n 0xac586f447e16c51821999902cf993f47 -e 0x10001 --uncipher 0x9b7a8eb8ad559e3f52ff3ceeaf0025a4
private argument is not set, the private key will not be displayed, even if recovered.

[*] Testing key /tmp/tmpx_rnscks.
attack initialized...
[*] Performing factordb attack on /tmp/tmpx_rnscks.
[*] Attack success with factordb method !

Results for /tmp/tmpx_rnscks:

Unciphered data :
HEX : 0x74306f5f736d346c315f656666646338
INT (big endian) : 154441936670124153776196032734590952248
INT (little endian) : 74952841506873200485904127760714903668
utf-8 : t0o_sm4l1_effdc8
utf-16 : ぴ彯浳水弱晥摦㡣
STR : b't0o_sm4l1_effdc8'
HEX : 0x74306f5f736d346c315f656666646338
INT (big endian) : 154441936670124153776196032734590952248
INT (little endian) : 74952841506873200485904127760714903668
utf-8 : t0o_sm4l1_effdc8
utf-16 : ぴ彯浳水弱晥摦㡣
STR : b't0o_sm4l1_effdc8'
```

Flag: t0o_sm4l1_effdc8

## Recipe Decoder

![Recipe Decoder](/assets/images/2022/10/UnitedCTF/Cryptography/RecipeDecoder.png "Reciper Decoder")

```
Vous n'aurez jamais ma recette gna ahaha ! Essayez donc de la lire, mais je ne pense pas qu'un jour vous y arriverez gna ahaha !

44 27 61 62 6f 72 64 20 6d 65 74 74 72 65 20 6c 65 20 63 68 6f 63 6f 6c 61 74
77:111:110:116:101:114:32:108:101:115:32:98:108:97:110:99:115:32:97:118:101:99:32:97:109:111:117:114
41 6a 6f 75 74 65 72 20 6c 61 20 6e 65 69 67 65 20 61 75 20 63 68 6f 63 6f 6c 61 74 20 66 6f 6e 64 75
N%27oublie%20pas%20la%20pinc%C3%A9e%20de%20sel
RXQgdHUgb2J0aWVucyB1bmUgbW91c3NlIGF1IGNob2NvbGF0IA==
J'ai laissé ce flag pour quiconque réussirait à percer mon mystère, en guise de reconnaissance:

MzUlMjAzMiUyMDNhJTIwMzUlMjAzNCUyMDNhJTIwMzMlMjAzMiUyMDNhJTIwMzUlMjAzMiUyMDNhJTIwMzklMjAzOSUyMDNhJTIwMzMlMjAzMiUyMDNhJTIwMzUlMjAzMiUyMDNhJTIwMzQlMjAzOSUyMDNhJTIwMzMlMjAzMiUyMDNhJTIwMzUlMjAzMiUyMDNhJTIwMzUlMjAzNSUyMDNhJTIwMzMlMjAzMiUyMDNhJTIwMzUlMjAzMCUyMDNhJTIwMzElMjAzMCUyMDMwJTIwM2ElMjAzMyUyMDMyJTIwM2ElMjAzNSUyMDMzJTIwM2ElMjAzNSUyMDMxJTIwM2ElMjAzMyUyMDMyJTIwM2ElMjAzNSUyMDMzJTIwM2ElMjAzNCUyMDM4JTIwM2ElMjAzMyUyMDMyJTIwM2ElMjAzNSUyMDMyJTIwM2ElMjAzMSUyMDMwJTIwMzIlMjAzYSUyMDMzJTIwMzIlMjAzYSUyMDM1JTIwMzIlMjAzYSUyMDMxJTIwMzAlMjAzMSUyMDNhJTIwMzMlMjAzMiUyMDNhJTIwMzUlMjAzMiUyMDNhJTIwMzUlMjAzNSUyMDNhJTIwMzMlMjAzMiUyMDNhJTIwMzUlMjAzMCUyMDNhJTIwMzElMjAzMCUyMDMwJTIwM2ElMjAzMyUyMDMyJTIwM2ElMjAzNSUyMDMyJTIwM2ElMjAzNSUyMDMzJTIwM2ElMjAzMyUyMDMyJTIwM2ElMjAzNSUyMDMyJTIwM2ElMjAzMSUyMDMwJTIwMzElMjAzYSUyMDMzJTIwMzIlMjAzYSUyMDM1JTIwMzIlMjAzYSUyMDM1JTIwMzElMjAzYSUyMDMzJTIwMzIlMjAzYSUyMDM1JTIwMzIlMjAzYSUyMDMxJTIwMzAlMjAzMiUyMDNhJTIwMzMlMjAzMiUyMDNhJTIwMzUlMjAzMiUyMDNhJTIwMzUlMjAzMiUyMDNhJTIwMzMlMjAzMiUyMDNhJTIwMzUlMjAzMiUyMDNhJTIwMzUlMjAzMw==
```

Author: [Ioarana](https://github.com/ioarana)

I took each line of the recipe one by one and decoded it.

```
44 27 61 62 6f 72 64 20 6d 65 74 74 72 65 20 6c 65 20 63 68 6f 63 6f 6c 61 74
```
Is Hex for "D'abord mettre le chocolat".

```
77:111:110:116:101:114:32:108:101:115:32:98:108:97:110:99:115:32:97:118:101:99:32:97:109:111:117:114
```
Is the char codes for "Monter les blancs avec amour".

```
41 6a 6f 75 74 65 72 20 6c 61 20 6e 65 69 67 65 20 61 75 20 63 68 6f 63 6f 6c 61 74 20 66 6f 6e 64 75
```
Is Hex for "Ajouter la neige au chocolat fondu".

```
N%27oublie%20pas%20la%20pinc%C3%A9e%20de%20sel
```
Is url encoding of "N'oublie pas la pincée de sel".


```
RXQgdHUgb2J0aWVucyB1bmUgbW91c3NlIGF1IGNob2NvbGF0IA==
```
Is base64 of "Et tu obtiens une mousse au chocolat"

I applied the same transformations in reverse order to the 'encrypted' flag in [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)URL_Decode()From_Hex('Auto')From_Charcode('Colon',10)From_Hex('Auto')&input=TXpVbE1qQXpNaVV5TUROaEpUSXdNelVsTWpBek5DVXlNRE5oSlRJd016TWxNakF6TWlVeU1ETmhKVEl3TXpVbE1qQXpNaVV5TUROaEpUSXdNemtsTWpBek9TVXlNRE5oSlRJd016TWxNakF6TWlVeU1ETmhKVEl3TXpVbE1qQXpNaVV5TUROaEpUSXdNelFsTWpBek9TVXlNRE5oSlRJd016TWxNakF6TWlVeU1ETmhKVEl3TXpVbE1qQXpNaVV5TUROaEpUSXdNelVsTWpBek5TVXlNRE5oSlRJd016TWxNakF6TWlVeU1ETmhKVEl3TXpVbE1qQXpNQ1V5TUROaEpUSXdNekVsTWpBek1DVXlNRE13SlRJd00yRWxNakF6TXlVeU1ETXlKVEl3TTJFbE1qQXpOU1V5TURNekpUSXdNMkVsTWpBek5TVXlNRE14SlRJd00yRWxNakF6TXlVeU1ETXlKVEl3TTJFbE1qQXpOU1V5TURNekpUSXdNMkVsTWpBek5DVXlNRE00SlRJd00yRWxNakF6TXlVeU1ETXlKVEl3TTJFbE1qQXpOU1V5TURNeUpUSXdNMkVsTWpBek1TVXlNRE13SlRJd016SWxNakF6WVNVeU1ETXpKVEl3TXpJbE1qQXpZU1V5TURNMUpUSXdNeklsTWpBellTVXlNRE14SlRJd016QWxNakF6TVNVeU1ETmhKVEl3TXpNbE1qQXpNaVV5TUROaEpUSXdNelVsTWpBek1pVXlNRE5oSlRJd016VWxNakF6TlNVeU1ETmhKVEl3TXpNbE1qQXpNaVV5TUROaEpUSXdNelVsTWpBek1DVXlNRE5oSlRJd016RWxNakF6TUNVeU1ETXdKVEl3TTJFbE1qQXpNeVV5TURNeUpUSXdNMkVsTWpBek5TVXlNRE15SlRJd00yRWxNakF6TlNVeU1ETXpKVEl3TTJFbE1qQXpNeVV5TURNeUpUSXdNMkVsTWpBek5TVXlNRE15SlRJd00yRWxNakF6TVNVeU1ETXdKVEl3TXpFbE1qQXpZU1V5TURNekpUSXdNeklsTWpBellTVXlNRE0xSlRJd016SWxNakF6WVNVeU1ETTFKVEl3TXpFbE1qQXpZU1V5TURNekpUSXdNeklsTWpBellTVXlNRE0xSlRJd016SWxNakF6WVNVeU1ETXhKVEl3TXpBbE1qQXpNaVV5TUROaEpUSXdNek1sTWpBek1pVXlNRE5oSlRJd016VWxNakF6TWlVeU1ETmhKVEl3TXpVbE1qQXpNaVV5TUROaEpUSXdNek1sTWpBek1pVXlNRE5oSlRJd016VWxNakF6TWlVeU1ETmhKVEl3TXpVbE1qQXpNdz09).

Flag: FLAG-SPONG-ENCODE

## Corgis Code

![Corgis Code](/assets/images/2022/10/UnitedCTF/Cryptography/CorgisCode.png "Corgis Code")

```
Feu la reine Elizabeth a laissé derrière elle une armée de corgis tristes, qui semblent déboussolés depuis la disparition de leur maîtresse. Après leur examen avec un psychologue canin, le médecin a distingué des codes gravés au revers de la médaille de chaque chien. Sauras-tu percer le mystère des corgis de la reine?

Susan: 01011010 01000110 
Pickles: 01010101 01000001 
Tinker: 00101101 01000001 
Piper: 01001001 01011000 
Harris: 01001101 01010101 
Muick: 01010000 01011001 
Sandy: 01001110 01000010 
Mint: 01011001 01001011 
Disco: 00110001 01000110 
Fay: 01010101 01001101 
Phoenix: 01001110 01000011 
Brush: 01000111 01011001
```

Author: [Ioarana](https://github.com/ioarana)


The values after the dog names were all binary. I took them to [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Binary('Space',8)ROT13(true,true,false,6)&input=MDEwMTEwMTAgMDEwMDAxMTAgCjAxMDEwMTAxIDAxMDAwMDAxIAowMDEwMTEwMSAwMTAwMDAwMSAKMDEwMDEwMDEgMDEwMTEwMDAgCjAxMDAxMTAxIDAxMDEwMTAxIAowMTAxMDAwMCAwMTAxMTAwMSAKMDEwMDExMTAgMDEwMDAwMTAgCjAxMDExMDAxIDAxMDAxMDExIAowMDExMDAwMSAwMTAwMDExMCAKMDEwMTAxMDEgMDEwMDExMDEgCjAxMDAxMTEwIDAxMDAwMDExIAowMTAwMDExMSAwMTAxMTAwMQ) and got the flag.

Flag: FLAG-GODSAVETHEQ1LASTIME

## E
![E](/assets/images/2022/10/UnitedCTF/Cryptography/E.png "E")

```
Why does everyone use 0x10001 for the public exponent? I want to make my own choices.
```

Author: [hfz](https://github.com/hfz1337)

The challenge provided one file. 

```
N = 0x49ecbb13cc23b162b198731cc977c9cbe75a10a039f5f49db10bff80da81b7ea33627123e044521ce67939adf6804e6f1c693ce1aefe5977b31fd2b22eb3f8814cb7c1f05fbdaea5ac6c077958466cf77b1f2ae74cdbcad84ad392237217d64af3b008e13746df09fe632227d8cbfeac65e7b7d99f7e6327c43fb03cf0f28d81a612d7cd7acd6c3cec46ed2d2ad8dace48feed5ddfdfdad4061bc0ee513b4e304c923d4f4e62497fcc21b20c178cce17efa20448caa88728df3d4510d624b1918f60bc787e7fd863d4f6d43c9ffb0722d8fa25afb4dd8fdddfeaa06c7336e51d7fa5dd8c5fdd9911141ddef8fd5a47292ddd814c46b29185a4227d10fd259a157010d51eb146d9cd638e792fa4a745c0b570f812beabed5aa227dd7b558d599fefc2677da54582ac1bc6a1b5bc843a6b7a959ef5c3d9cbfddbea63f01c3e3e1d5535beca2c573892a5ad231b8847bc7f7b2774211e24e0461fb862c65834b04bc29ef51954b4c7ebd1b828a83d888073dccfe2addf6467d0be847a8f1609dcec9745d2fe19aaa58876e0fae21362dc73b5f560709fc8c3d642ba81a2d69afb96e974064602f4a3297034550dc313d7b68e9a0291ae687baca0916b6e6194a657bd9eaa18947883e41dff0c8447ecf44de09997406b024119459a9fc2cbf13e3a0a3dfffe395c062920825f23127069cece2153eb731102be4b320f5cab4e401d
E = 0x1
C = 352646212945048100016662024598128956103404695349368978684847519505954679111366360580499262174521087230819264434729435169122572890872633080743410655041631275256041885030165532475164003059213848494886459172451
```

I tried using RsaCtfTool on this one too, but it failed.

While I worked on 'Too Close', I saw this code in the encryption.

```python
ciphertext = pow(FLAG, e, n)
```

I realized that if the encryption was the same, having E = 1 meant that the encrypted value was simply `flag modulo N`. 

To decrypt it, I simply had to add N until I got the flag back.

```python
c = 352646212945048100016662024598128956103404695349368978684847519505954679111366360580499262174521087230819264434729435169122572890872633080743410655041631275256041885030165532475164003059213848494886459172451
n = 0x49ecbb13cc23b162b198731cc977c9cbe75a10a039f5f49db10bff80da81b7ea33627123e044521ce67939adf6804e6f1c693ce1aefe5977b31fd2b22eb3f8814cb7c1f05fbdaea5ac6c077958466cf77b1f2ae74cdbcad84ad392237217d64af3b008e13746df09fe632227d8cbfeac65e7b7d99f7e6327c43fb03cf0f28d81a612d7cd7acd6c3cec46ed2d2ad8dace48feed5ddfdfdad4061bc0ee513b4e304c923d4f4e62497fcc21b20c178cce17efa20448caa88728df3d4510d624b1918f60bc787e7fd863d4f6d43c9ffb0722d8fa25afb4dd8fdddfeaa06c7336e51d7fa5dd8c5fdd9911141ddef8fd5a47292ddd814c46b29185a4227d10fd259a157010d51eb146d9cd638e792fa4a745c0b570f812beabed5aa227dd7b558d599fefc2677da54582ac1bc6a1b5bc843a6b7a959ef5c3d9cbfddbea63f01c3e3e1d5535beca2c573892a5ad231b8847bc7f7b2774211e24e0461fb862c65834b04bc29ef51954b4c7ebd1b828a83d888073dccfe2addf6467d0be847a8f1609dcec9745d2fe19aaa58876e0fae21362dc73b5f560709fc8c3d642ba81a2d69afb96e974064602f4a3297034550dc313d7b68e9a0291ae687baca0916b6e6194a657bd9eaa18947883e41dff0c8447ecf44de09997406b024119459a9fc2cbf13e3a0a3dfffe395c062920825f23127069cece2153eb731102be4b320f5cab4e401d

from Crypto.Util.number import (
    long_to_bytes as l2b,
    bytes_to_long as b2l,
    getPrime,
    isPrime,
)


for i in range(500):
    flag = c + (i * n)
    flag = l2b(flag)

    if b'FLAG' in flag:
        print(flag)
        exit()
```

```bash
$ python reverseE.py
b'FLAG-https://github.com/saltstack/salt/commit/5dd304276ba5745ec21fc1e6686a0b28da29e6fc'
```

Flag: FLAG-https://github.com/saltstack/salt/commit/5dd304276ba5745ec21fc1e6686a0b28da29e6fc

The flag is a link to a [commit in SaltStack](https://github.com/saltstack/salt/commit/5dd304276ba5745ec21fc1e6686a0b28da29e6fc) where this bug was fixed.

## Too Close

![Too Close](/assets/images/2022/10/UnitedCTF/Cryptography/TooClose.png "Too Close")

```
Why is math so hard?
```

Author: [hfz](https://github.com/hfz1337)


The challenge provided a python script to perform the encryption.

```python
#!/usr/bin/python3
from Crypto.Util.number import (
    long_to_bytes as l2b,
    bytes_to_long as b2l,
    getPrime,
    isPrime,
)

FLAG = b2l(b"REDACTED")

p = getPrime(2048)
q = p + 1
while not isPrime(q):
    q += 1

e = 0x10001
n = p * q

ciphertext = pow(FLAG, e, n)

print(f"{e = :#x}")
print(f"{n = :#x}")
print(f"{ciphertext = :#x}")

# e = 0x10001
# n = 0x96b581aed615e5499976a5d6921fd8135f8bf7be296cdf311fb752484c3350a390fa354f1457bf32940cc0315628a57689bc1c12039c7e63f42a1e1bce2359eed540d9c3421bf69e268cc38e17db680b045017b9e65f15d46ca41cff2497f2833f63b159ac99ab9fb2706d440d36930b311dc76748d8b05c042babded675f3570a613db006c5b057a0a56eab473d432c9ade7741313938e8283b48e996a2c96d7463bd64d4a330b6ac37f15c97f1c83a1f78c2540de9c83221abd2d77c1fdd6c17b717bdfc2670f9c465137e777014501b3b4a57d3c65a8a6b304fe4bec8495b33d375751f3b27ba853686b6255adeb17cc02fb110e2a73ef8963a56aa8fbeb1c331a19134332147647f0409c4bcd11ba3d29b189040ccc770ae4b71a97f49f80438c0e915c77d9f8d2014ee27455257c8aca6bc254b9b71da5eb4c2971342cdfa83d1b8a03823abe1db3e0ed27819304476b4838a249ccac5003c4a8d3ea895cfe52d3c10ab11d9073fa819e816582bad29c9cb69466baf069b56ec500f799b6070cc9e8bc8c1d527b80d8a4f83b7aeaebc146ccfb09040413e4357e261e33c153267e2bd4f7f84871a47251bc7655b1473408b8d80bdebb6d9d7d7652974afaee79e5075ca2fbf40e7b5491f7e6ff7ec5887ecc90377e4e79824af8f449bece4670dfab175c564bb094e14996920bc1cf339b355b96ad935d9ca77c78f4297
# ciphertext = 0x93279830576c7290458b2b15f908d0ddab99d36da62c02744145f124223f748722b49df2914445fd10a0b58a64d7ec84445d7df9de5eea7ae1bb24fc87a51112dd35441688c253f4b44df0cea7e659dc5b73242a1d7aaa8ebf9eb5d22251d9c07afbd7a77f780d9ca702f5bbdbaad9958718aa5658931fc738b48aba963d3312acb0b4220476a05f2fc6f8345a5bc4fc3e8516d78dc52fe876d5e2593b194b21d9b6506b915fa51486cb04874e612fdcd893f9066cbe23c0436b1fc589e007bb5bcc1fa3c4dad53a037030ae2c2445e88290641021edb41c8c5fb6875379227f3117d96b830349a0bf297b6a89ba78ba3b8a7f9d141be21f9b38c720fc2164267ec8770c03940ff414ff7e76251df06ef2225cce4ca939381ebecf61c1ff022ed85ed79d78f921a42cec641c6721b9d81a9ab676a0fcbfe09e17079d8de28c6d0d8b9be94ba49234227c0fe2b82297affa9ef8fe9480b750a55a79fd181d4dd0807356255a7dbca571f626670e588e5705cdf2a479bd12b486d97b9d3fb0d5949653be00cef05c5b973f2ed161dc6e79b76f9a26a96ee6d45c210e407c317ccdbf9ee3e7c76d783082503cdceeb8f3414990d22a454c7bcfa3ee3435e031b525a8178dbcb1645d01ad227c4fa603b5d27734af2733a53db9402966fa306f4fb84fb9b7cb6638faaa0360fe21da900aa7fb3ae537f2fc417882f40924edcdd110
```

I was looking for a way to reverse it. But I decided to give RsaCtfTool a try again.

```bash
$ python RsaCtfTool.py -n 0x96b581aed615e5499976a5d6921fd8135f8bf7be296cdf311fb752484c3350a390fa354f1457bf32940cc0315628a57689bc1c12039c7e63f42a1e1bce2359eed540d9c3421bf69e268cc38e17db680b045017b9e65f15d46ca41cff2497f2833f63b159ac99ab9fb2706d440d36930b311dc76748d8b05c042babded675f3570a613db006c5b057a0a56eab473d432c9ade7741313938e8283b48e996a2c96d7463bd64d4a330b6ac37f15c97f1c83a1f78c2540de9c83221abd2d77c1fdd6c17b717bdfc2670f9c465137e777014501b3b4a57d3c65a8a6b304fe4bec8495b33d375751f3b27ba853686b6255adeb17cc02fb110e2a73ef8963a56aa8fbeb1c331a19134332147647f0409c4bcd11ba3d29b189040ccc770ae4b71a97f49f80438c0e915c77d9f8d2014ee27455257c8aca6bc254b9b71da5eb4c2971342cdfa83d1b8a03823abe1db3e0ed27819304476b4838a249ccac5003c4a8d3ea895cfe52d3c10ab11d9073fa819e816582bad29c9cb69466baf069b56ec500f799b6070cc9e8bc8c1d527b80d8a4f83b7aeaebc146ccfb09040413e4357e261e33c153267e2bd4f7f84871a47251bc7655b1473408b8d80bdebb6d9d7d7652974afaee79e5075ca2fbf40e7b5491f7e6ff7ec5887ecc90377e4e79824af8f449bece4670dfab175c564bb094e14996920bc1cf339b355b96ad935d9ca77c78f4297 -e 0x10001 --uncipher 0x93279830576c7290458b2b15f908d0ddab99d36da62c02744145f124223f748722b49df2914445fd10a0b58a64d7ec84445d7df9de5eea7ae1bb24fc87a51112dd35441688c253f4b44df0cea7e659dc5b73242a1d7aaa8ebf9eb5d22251d9c07afbd7a77f780d9ca702f5bbdbaad9958718aa5658931fc738b48aba963d3312acb0b4220476a05f2fc6f8345a5bc4fc3e8516d78dc52fe876d5e2593b194b21d9b6506b915fa51486cb04874e612fdcd893f9066cbe23c0436b1fc589e007bb5bcc1fa3c4dad53a037030ae2c2445e88290641021edb41c8c5fb6875379227f3117d96b830349a0bf297b6a89ba78ba3b8a7f9d141be21f9b38c720fc2164267ec8770c03940ff414ff7e76251df06ef2225cce4ca939381ebecf61c1ff022ed85ed79d78f921a42cec641c6721b9d81a9ab676a0fcbfe09e17079d8de28c6d0d8b9be94ba49234227c0fe2b82297affa9ef8fe9480b750a55a79fd181d4dd0807356255a7dbca571f626670e588e5705cdf2a479bd12b486d97b9d3fb0d5949653be00cef05c5b973f2ed161dc6e79b76f9a26a96ee6d45c210e407c317ccdbf9ee3e7c76d783082503cdceeb8f3414990d22a454c7bcfa3ee3435e031b525a8178dbcb1645d01ad227c4fa603b5d27734af2733a53db9402966fa306f4fb84fb9b7cb6638faaa0360fe21da900aa7fb3ae537f2fc417882f40924edcdd110
private argument is not set, the private key will not be displayed, even if recovered.

[*] Testing key /tmp/tmpf4dzxv3a.
attack initialized...
[*] Performing factordb attack on /tmp/tmpf4dzxv3a.
[*] Performing fibonacci_gcd attack on /tmp/tmpf4dzxv3a.
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 9999/9999 [00:00<00:00, 48307.79it/s]
[*] Performing pastctfprimes attack on /tmp/tmpf4dzxv3a.
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 113/113 [00:00<00:00, 293835.31it/s]
[*] Performing nonRSA attack on /tmp/tmpf4dzxv3a.
[*] Performing mersenne_primes attack on /tmp/tmpf4dzxv3a.
 35%|████████████████████████████████████████████████████████████████████▍                                                                                                                             | 18/51 [00:00<00:00, 199201.77it/s]
[*] Performing system_primes_gcd attack on /tmp/tmpf4dzxv3a.
100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 7007/7007 [00:00<00:00, 535717.98it/s]
[*] Performing smallq attack on /tmp/tmpf4dzxv3a.
[*] Performing comfact_cn attack on /tmp/tmpf4dzxv3a.
[*] Performing highandlowbitsequal attack on /tmp/tmpf4dzxv3a.
[*] Performing SQUFOF attack on /tmp/tmpf4dzxv3a.
[!] Timeout.
[*] Performing wolframalpha attack on /tmp/tmpf4dzxv3a.
[*] Performing partial_q attack on /tmp/tmpf4dzxv3a.
[!] partial_q attack is only for partial private keys not pubkeys...
[*] Performing cube_root attack on /tmp/tmpf4dzxv3a.
[*] Performing small_crt_exp attack on /tmp/tmpf4dzxv3a.
Can't load small_crt_exp because sage binary is not installed
[*] Performing qicheng attack on /tmp/tmpf4dzxv3a.
Can't load qicheng because sage binary is not installed
[*] Performing ecm2 attack on /tmp/tmpf4dzxv3a.
Can't load ecm2 because sage binary is not installed
[*] Performing primorial_pm1_gcd attack on /tmp/tmpf4dzxv3a.
100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 10000/10000 [00:01<00:00, 6033.28it/s]
[*] Performing pisano_period attack on /tmp/tmpf4dzxv3a.
[*] Performing fermat attack on /tmp/tmpf4dzxv3a.
[*] Attack success with fermat method !

Results for /tmp/tmpf4dzxv3a:

Unciphered data :
HEX : 0x464c41472d6334723366756c5f773174685f6d3474685f74723334745f31745f6c316b335f6d337468
INT (big endian) : 150155341245087526646791820159425578631835311286689526670525089946489557611251035682488488102687848
INT (little endian) : 223112197007436185681866838113943742286798425156391551418639827611371887958950804241515263847124038
utf-8 : FLAG-c4r3ful_w1th_m4th_tr34t_1t_l1k3_m3th
STR : b'FLAG-c4r3ful_w1th_m4th_tr34t_1t_l1k3_m3th'
HEX : 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000464c41472d6334723366756c5f773174685f6d3474685f74723334745f31745f6c316b335f6d337468
INT (big endian) : 150155341245087526646791820159425578631835311286689526670525089946489557611251035682488488102687848
INT (little endian) : 426134773159750547037616269289937154475875380954951838246453382692072997854520548362271385546114275846322462902115537404077467504701912680516938341946522826110229981450539493780866275333807517236686883981736912965760592715414722322885359087576367202459743862715349462673016675254136859016915843301369834044977480025942696793997926464293621997302685085982206665828592557651056135275177741815652747553719882180240345639665184344922586524455321781378724638889387686097123278789624093159226474873931859276495808736165115163195132234706217606680681875777462820129615751783277045248510978894794974377401673658737036937364421887262624512826976260945755056986885080580711706300640253484613260836264256369560351374159238305109512864226876093091337439725035251797331567501081676911559017255191959472619247055381425239499502062841971144194324365962537682843925812028538352738971040743160193169915085668668829014284290423080105788312543308932861574987508157823601877880050004963748779901468504514815636635569464204844145903223570423696324372817254650623096608419957789159808824909260104467575843174622486545748014778996523638567425820655060105870529655433719510656867650556688236491629565287336069511892449350992459067609690369998354755016982528
utf-8 : FLAG-c4r3ful_w1th_m4th_tr34t_1t_l1k3_m3th
utf-16 : 䘀䅌ⵇ㑣㍲畦彬ㅷ桴浟琴彨牴㐳彴琱江欱弳㍭桴
STR : b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00FLAG-c4r3ful_w1th_m4th_tr34t_1t_l1k3_m3th'
```

Flag: FLAG-c4r3ful_w1th_m4th_tr34t_1t_l1k3_m3th