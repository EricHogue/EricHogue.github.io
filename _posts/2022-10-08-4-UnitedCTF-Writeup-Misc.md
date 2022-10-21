---
layout: post
title: UnitedCTF 2022 Writeup - Misc
date: 2022-10-08
type: post
tags:
- Writeup
- Hacking
- UnitedCTF
- CTF
permalink: /2022/10/UnitedCTF/Misc
img: 2022/10/UnitedCTF/UnitedCTFLogo.png
---

![Challenges](/assets/images/2022/10/UnitedCTF/Misc/Misc.png "Challenges")

## Rules

![Rules](/assets/images/2022/10/UnitedCTF/Misc/Rules.png "Rules")

```
C'est important de lire les règles.

It's important to read the rules.
```

Author: [hfz](https://github.com/hfz1337)

This was the first challenge of the CTF. You could not access any other challenges until you had done this one.

I opened the rules page.

```markdown
Règles générales
1- Tout d'abord, amuse-toi bien !
2- Traite tout le monde avec respect, cela inclut les organisateurs ainsi que les autres participants.
3- Les attaques DoS/DDoS contre l'infrastructure et/ou les défis sont strictement interdites.
4- Le brute-force des formulaires de soumission des flags n'est pas permis (il n'y a rien à deviner).
5- Le brute-force contre les defis n'est pas permis (e.g., brute-force de login, URL path, etc.), sauf si explicitement permis dans la description du défi.
6- Tout problème rencontré avec l'infrastructure et/ou les défis doit être directement rapporté aux organisateurs.
7- UnitedCTF est une compétition individuelle, aucune collaboration entre individus n'est permise. Ne pas discuter les défis avec les autres participants avant la fin de la compétition.
8- Si tu résous un défi, soumets le flag immédiatement, nous ne tolérons pas l'accumulation des flags qui vise à manipuler la performance des autres participants.
9- L'utilisation d'outils d'exploitation automatique et de scanners de vulnérabilité de masse est strictement interdite.
10- Les tentatives d'ingénierie sociale contre les organisateurs entraîneront une sanction.
11- Ne pas publier les flags ou les solutions publiquement avant la fin du CTF.
12- Le flag que tu es en train de chercher se trouve sous cette balise, enlève tous les chiffres avant de le soumettre.
13- Garde tes solutions (captures d'écran, scripts, etc.) au cas où les organisateurs te demanderaient de les fournir.
Les organisateurs du UnitedCTF se réservent le droit de disqualifier toute personne susceptible de violer les règles du CTF.
```

Rule #12 said that the flag was under the tag and that I had to remove all the numbers before submitting it.

```html
<li>Le flag que tu es en train de chercher se trouve sous cette balise, enlève tous les chiffres avant de le soumettre.</li>
<!-- FLAG-67dbeb3ab99e4b8eea076970ac87c8b71488f7a044075d4b -->
```

Flag: FLAG-dbebabebeeaaccbfadb


## Back to School

![Back to School](/assets/images/2022/10/UnitedCTF/Misc/BackToSchool.png "Back to School")


```
Be quick, or be dead.

nc nc.ctf.unitedctf.ca 5000
```

Author: [hfz](https://github.com/hfz1337)

I connected to the server. It said I had to solve 100 equations in under 10 seconds.

```bash
$ nc nc.ctf.unitedctf.ca 5000
Can you solve 100 simple equations in less than 10 seconds?
Round   1: -386*x + 53 = 29003
Answer:
Invalid input, good bye!

$ nc nc.ctf.unitedctf.ca 5000
Can you solve 100 simple equations in less than 10 seconds?
Round   1: -919*x + 1209 = 1145364
Answer: Too slow!
```

I wrote a small script to do the math for me.

```python
from pwn import *
import re
from sympy import Eq, Symbol, solve
from sympy.parsing.sympy_parser import (
    parse_expr, standard_transformations
)


conn = remote('nc.ctf.unitedctf.ca', 5000)
line = conn.recvline()
print(line)

for i in range(100):
    line = conn.recvline().decode().strip()
    print(line)
    parts = re.search('.*:(.*)=(..*)', line)

    x = Symbol('x')
    res = solve(Eq(parse_expr(parts.group(1)), parse_expr(parts.group(2))))
    tosend = str(res[0])
    print(tosend)
    conn.sendline(tosend.encode('ascii'))

line = conn.recvline()
print(line.decode('utf-8'))
```

I ran the script to get the flag.

```bash
$ python backToSchool.py
[+] Opening connection to nc.ctf.unitedctf.ca on port 5000: Done
b'Can you solve 100 simple equations in less than 10 seconds?\n'
Round   1: 4*x + 273 = 3217
736
Answer: Round   2: -732*x + 539 = -721945
987
Answer: Round   3: 57*x - 239 = -57467
-1004
Answer: Round   4: 1064*x + 1250 = 19338
17

...

Answer: Round  99: 1317*x + 386 = 433679
329
Answer: Round 100: -1155*x + 900 = 686970
-594
Answer: FLAG-m0m_1_c4n_d0_m4ths_n0w_de1a425c

[*] Closed connection to nc.ctf.unitedctf.ca port 5000
```

Flag: FLAG-m0m_1_c4n_d0_m4ths_n0w_de1a425c

## Brainfuck

![Brainfuck](/assets/images/2022/10/UnitedCTF/Misc/Brainfuck.png "Brainfuck")


```
I found this piece at the Museum of Fine Esolangs, could you help me with that?

++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>.++++++.-----------.++++++.<+++++++++++++++.+++++++++++.-----.+.---..++++++++...--.---.>>++.<<++.+.----.-.++++.-.++.++.>>-----.<<----.+++.----.--.-.+++.--.>>+++.<<++++++.-.>>---.<<--.--.++.>>+++.-.<<-----.++..-.+++.>>--.<<---.>>++++.<<+++++++.------.>>-.++.
```

Author: [hfz](https://github.com/hfz1337)

The challenge name made it clear that this was Brainfuck code. I searched for an [online interpreter](https://www.dcode.fr/brainfuck-language) and ran the code there.

![Interpreter](/assets/images/2022/10/UnitedCTF/Misc/BrainfuckInterpreter.png "Interpreter")

Flag: FLAG-8341199974f67326579a5842142d87a535dc02214a1e82df

## CTRL+C CTRL+V

![Ctrl+C Ctrl+V](/assets/images/2022/10/UnitedCTF/Misc/CtrlCCtrlV.png "Ctrl+C Ctrl+V")

```
Did someone say FREE FLAG??! I LOVE FREE FLAGS! HURRY UP SUBMIT THIS FLAG BEFORE IT EXPIRES!!

FLAG-3​d​4​4​c​9​6​a​5​8​4​b​5​2​9​b​7​7​7​f​f​5​d​b​c​e​a​b​a​6​7​2​5​c​7​6​1​8​0​4​1​b​2​6​d​8​9​c​0​4​3​7​4​c​b​5​3​d​4​5​0​9​1​7​f​1​6​6​0​d​3​b​f​6​6​8​3​4​0​d​2​f​1​a​c​f​5​e​7​c​9​e​4​c​4​b​c​3​8​8​b​7​d​8​d​3​b​0​b​6​6​3​b​f​0​e​8​c​c​f​3​8​a​6​1​2​4​f​1​6​8​7​6​0​c​6​3​0​6​d​8​d​6​6​b​1​b​c​d​5​0​9​9​d​b​a​7​d​7​6​4​9​f​9​8​9​d​9​4​0​f​9​d​5​2​6​2​f​2​9​5​5​8​0​0​8​f​6​5​d​a​2​b​1​8​a​2​f​b​c​0​1​5​6​4​3​9​7​e​b​1​3​6​1​f​f​f​a​f​e​5​8​d​6​1​6​9​5​7​0​c​b​9​3​d​c​d​0​2​e​2​5​2​1​e​8​0​0​7​e​d​e​d​7​c​c
```

Author: [hfz](https://github.com/hfz1337)

I tried simply copy-pasting the flag, but it was rejected. The description talk about the flag expiring. This led me to think that I had to write a script to read the flag and submit it quickly.

But when I copied the flag in vim, I saw this:

```
FLAG-3<200b>d<200b>4<200b>4<200b>c<200b>9<200b>6<200b>a<200b>5<200b>8<200b>4<200b>b<200b>5<200b>2<200b>9<200b>b<200b>7<200b>7<200b>7<200b>f<200b>f<200b>5<200b>d<200b>b<200b>c<200b>e<200b>a<200b>b<200b>a<200b    >6<200b>7<200b>2<200b>5<200b>c<200b>7<200b>6<200b>1<200b>8<200b>0<200b>4<200b>1<200b>b<200b>2<200b>6<200b>d<200b>8<200b>9<200b>c<200b>0<200b>4<200b>3<200b>7<200b>4<200b>c<200b>b<200b>5<200b>3<200b>d<200b>4<2    00b>5<200b>0<200b>9<200b>1<200b>7<200b>f<200b>1<200b>6<200b>6<200b>0<200b>d<200b>3<200b>b<200b>f<200b>6<200b>6<200b>8<200b>3<200b>4<200b>0<200b>d<200b>2<200b>f<200b>1<200b>a<200b>c<200b>f<200b>5<200b>e<200b>    7<200b>c<200b>9<200b>e<200b>4<200b>c<200b>4<200b>b<200b>c<200b>3<200b>8<200b>8<200b>b<200b>7<200b>d<200b>8<200b>d<200b>3<200b>b<200b>0<200b>b<200b>6<200b>6<200b>3<200b>b<200b>f<200b>0<200b>e<200b>8<200b>c<20    0b>c<200b>f<200b>3<200b>8<200b>a<200b>6<200b>1<200b>2<200b>4<200b>f<200b>1<200b>6<200b>8<200b>7<200b>6<200b>0<200b>c<200b>6<200b>3<200b>0<200b>6<200b>d<200b>8<200b>d<200b>6<200b>6<200b>b<200b>1<200b>b<200b>c    <200b>d<200b>5<200b>0<200b>9<200b>9<200b>d<200b>b<200b>a<200b>7<200b>d<200b>7<200b>6<200b>4<200b>9<200b>f<200b>9<200b>8<200b>9<200b>d<200b>9<200b>4<200b>0<200b>f<200b>9<200b>d<200b>5<200b>2<200b>6<200b>2<200    b>f<200b>2<200b>9<200b>5<200b>5<200b>8<200b>0<200b>0<200b>8<200b>f<200b>6<200b>5<200b>d<200b>a<200b>2<200b>b<200b>1<200b>8<200b>a<200b>2<200b>f<200b>b<200b>c<200b>0<200b>1<200b>5<200b>6<200b>4<200b>3<200b>9<    200b>7<200b>e<200b>b<200b>1<200b>3<200b>6<200b>1<200b>f<200b>f<200b>f<200b>a<200b>f<200b>e<200b>5<200b>8<200b>d<200b>6<200b>1<200b>6<200b>9<200b>5<200b>7<200b>0<200b>c<200b>b<200b>9<200b>3<200b>d<200b>c<200b    >d<200b>0<200b>2<200b>e<200b>2<200b>5<200b>2<200b>1<200b>e<200b>8<200b>0<200b>0<200b>7<200b>e<200b>d<200b>e<200b>d<200b>7<200b>c<200b>c
```

The flag was full of non-printable characters. I made a quick search on how to remove them in vim and found a [Stack Overflow answer](https://stackoverflow.com/questions/3844311/how-do-i-replace-or-find-non-printable-characters-in-vim-regex) that showed how to do it. I used `:%s/[^[:print:]]//g` and then I could copy-paste the flag.


Flag: FLAG-3d44c96a584b529b777ff5dbceaba6725c7618041b26d89c04374cb53d450917f1660d3bf668340d2f1acf5e7c9e4c4bc388b7d8d3b0b663bf0e8c
cf38a6124f168760c6306d8d66b1bcd5099dba7d7649f989d940f9d5262f29558008f65da2b18a2fbc01564397eb1361fffafe58d6169570cb93dcd02e2
521e8007eded7cc

## RFC4648

![RFC4648](/assets/images/2022/10/UnitedCTF/Misc/RFC4648.png "RFC4648")

```
Welcome back to the base, Snake.

Download link
```

Author: [hfz](https://github.com/hfz1337)

The file to download contained a very long base64 string. I decoded it and got another base64 string. So I wrote a script to decode the string in a loop.

```python
import base64

f = open("rfc4648.txt","r")
line = f.readline()

for i in range(100):
    line = str(base64.b64decode(line), 'utf-8')
    if 'FLAG' in line:
        print(line)
        exit()
```

```bash
$ python rfc4648.py
FLAG-1l0v3b4s364encod1ng_efd3c54
```

Flag: FLAG-1l0v3b4s364encod1ng_efd3c54

## Early Access

![Early Access](/assets/images/2022/10/UnitedCTF/Misc/EarlyAccess.png "Early Access")

```
Legend has it that there used to be an early access ticket in UnitedCTF's landing page, but I don't believe this since it's not there... do you?
```

Author: [hfz](https://github.com/hfz1337)

The description made it sound like something was on the CTF website, but had been removed. I checked the [Wayback Machine](http://web.archive.org/web/20220000000000*/https://unitedctf.ca/) for previous versions of the site.

There were two versions on September 23.

![Wayback Machine](/assets/images/2022/10/UnitedCTF/Misc/WaybackMachine.png "Wayback Machine")

I checked the [first one](http://web.archive.org/web/20220923153405/https://unitedctf.ca/) and it had the flag.

![Flag](/assets/images/2022/10/UnitedCTF/Misc/EarlyAccessFlag.png "Flag")

Flag: FLAG-0nc3_it’s_publ1c_it’s_n0_m0r3_4_s3cr3t

## TXT

![TXT](/assets/images/2022/10/UnitedCTF/Misc/TXT.png "TXT")

```
This subdomain is sus.
```

Author: [hfz](https://github.com/hfz1337)

I checked the DNS for TXT records.

```bash
$ dig ctf.unitedctf.ca txt

; <<>> DiG 9.18.1-1ubuntu1.2-Ubuntu <<>> ctf.unitedctf.ca txt
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17247
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;ctf.unitedctf.ca.		IN	TXT

;; ANSWER SECTION:
ctf.unitedctf.ca.	300	IN	TXT	"google-site-verification=RkxBRy00ZWVmMWI1M2JhMDlkZmQ3ZmRiNzAzN2I0ODg4Mzk3NzAK"

;; Query time: 63 msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
;; WHEN: Mon Oct 03 08:59:01 EDT 2022
;; MSG SIZE  rcvd: 135
```

All I saw was a Google site verification token, so I ignored it. I looked for other things but did not find anything.

After a while, I got back to the token and realized this could be base64. I decoded it and got the flag.

```bash
$ echo -n RkxBRy00ZWVmMWI1M2JhMDlkZmQ3ZmRiNzAzN2I0ODg4Mzk3NzAK | base64 -d
FLAG-4eef1b53ba09dfd7fdb7037b488839770
```

Flag: FLAG-4eef1b53ba09dfd7fdb7037b488839770

## It's corn!

[It's corn!](/assets/images/2022/10/UnitedCTF/Misc/ItsCorn.png "It's corn!")

```
Connaissez-vous le corn kid ? Voici le lien pour le rencontrer: https://www.youtube.com/watch?v=1VbZE6YhjKk

Il adorerait se promener dans un labyrinthe de maïs, mais il est trop occupé à manger ce délicieux aliment. Aide-le en lui indiquant le plus court chemin à parcourir.

Envoie les coordonnées qu'il devra faire à chaque pas à partir du début S jusqu'à la fin E. Omet les coordonnées du début et de la fin, donc envoie seulement les coordonnées du chemin. Lorsque c'est terminé, envoie un point (le caractère).

x1 y1
x2 y2
x3 y3
x4 y4
x5 y5
.
I hope you guys have a cornstastic day !

nc nc.ctf.unitedctf.ca 5001
```

Author: [Granny](https://github.com/CloeD)

I tried connecting to the server. I got a maze that I needed to solve quickly.

```bash
$ nc nc.ctf.unitedctf.ca 5001
#####################
#   #               #
# # ### ####### #####
# #   #       # # # #
### ### ######### # #
#     #     # # # # #
# ### # ##### # # # #
# # #               #
### # ### ### ### ###
# # # # #   # #   # E
# # # # ########### #
S   #   # #   #     #
# ### ### # ### ### #
#                 # #
# # ### # # ##### ###
# #   # # # # # # # #
### ######### # ### #
# # #     #         #
# # # ##### ##### ###
#             #     #
#####################
Too slow!
```

I did not want to spend time writing an algorithm to solve a maze so I [found one](https://thecleverprogrammer.com/2021/01/26/maze-solver-with-python/) online. I modified it to read the maze from the server and send back the result.

```python
from pwn import *
from colorama import Fore


def find_symbol(maze, to_find):
    for line in range(len(maze)):
        for column in range(len(maze[line])):
            if maze[line][column] == to_find:
                return [line, column]



def get_starting_finishing_points(maze):
    start = find_symbol(maze, 'S')
    end = find_symbol(maze, 'E')
    return start, end

def maze_solver():
    for i in range(0, len(maze)):
        for j in range(0, len(maze[0])):
            if maze[i][j] == 'u':
                print(Fore.WHITE, f'{maze[i][j]}', end=" ")
            elif maze[i][j] == 'c':
                print(Fore.GREEN, f'{maze[i][j]}', end=" ")
            elif maze[i][j] == 'p':
                print(Fore.BLUE, f'{maze[i][j]}', end=" ")
            else:
                print(Fore.RED, f'{maze[i][j]}', end=" ")
        print('\n')


def is_free(maze, line, column):
    value = maze[line][column]
    return  value in [' ', 'S', 'E']

def escape(maze):
    current_cell = rat_path[len(rat_path) - 1]

    if current_cell == finish:
        return

    try:
        if is_free(maze, current_cell[0] + 1, current_cell[1]):
            maze[current_cell[0] + 1][current_cell[1]] = 'p'
            rat_path.append([current_cell[0] + 1, current_cell[1]])
            escape(maze)
    except:
        pass

    try:
        if is_free(maze, current_cell[0], current_cell[1] + 1):
            maze[current_cell[0]][current_cell[1] + 1] = 'p'
            rat_path.append([current_cell[0], current_cell[1] + 1])
            escape(maze)
    except:
        pass

    try:
        if is_free(maze, current_cell[0] - 1, current_cell[1]):
            maze[current_cell[0] - 1][current_cell[1]] = 'p'
            rat_path.append([current_cell[0] - 1, current_cell[1]])
            escape(maze)
    except:
        pass

    try:
        if is_free(maze, current_cell[0], current_cell[1] - 1):
            maze[current_cell[0]][current_cell[1] - 1] = 'p'
            rat_path.append([current_cell[0], current_cell[1] - 1])
            escape(maze)
    except:
        pass

    # If we get here, this means that we made a wrong decision, so we need to
    # backtrack
    current_cell = rat_path[len(rat_path) - 1]
    if current_cell != finish:
        cell_to_remove = rat_path[len(rat_path) - 1]
        rat_path.remove(cell_to_remove)
        maze[cell_to_remove[0]][cell_to_remove[1]] = ' '

def read_maze(conn):
    maze = []
    for i in range(21):
        line = conn.recvline().decode().strip()
        print(line)
        line = [*line]
        maze.append(line)
    return maze

if __name__ == '__main__':
    conn = remote('nc.ctf.unitedctf.ca', 5001)
    maze = read_maze(conn)

    start, finish = get_starting_finishing_points(maze)

    maze[start[0]][start[1]] = 'p'

    rat_path = [start]
    escape(maze)
    print(maze_solver())

    for point in rat_path[1:-1]:
        to_send = f"{point[0]} {point[1]}"
        conn.sendline(to_send.encode('ascii'))

    to_send = "."
    print(to_send)
    conn.sendline(to_send.encode('ascii'))

    line = conn.recvline().decode().strip()
    print(line)
```

Once the code was modified, I ran it and got the flag.

```bash
$ python itsCorn.py
[+] Opening connection to nc.ctf.unitedctf.ca on port 5001: Done
#E###################
#   #     #       # #
### ##### ### ##### #
#   # #     # # #   #
### # # # # # # ### #
#   # # # #     # # #
### # ####### # # # #
#   # #     # # #   #
# # # ### ### ### ###
# #         #       #
# ##### # ##### # ###
# #     # #   # #   #
####### ### ##### ###
#         # # # #   #
### ### ### # # # # #
#   #       #   # # #
# ######### ### ### #
# #               # #
# ####### ##### ### #
# #       #         #
#############S#######
 #  p  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #

 #  p  p  p  #                 #                       #     #

 #  #  #  p  #  #  #  #  #     #  #  #     #  #  #  #  #     #

 #        p  #     #                 #     #     #           #

 #  #  #  p  #     #     #     #     #     #     #  #  #     #

 #        p  #     #     #     #                 #     #     #

 #  #  #  p  #     #  #  #  #  #  #  #     #     #     #     #

 #        p  #     #                 #     #     #           #

 #     #  p  #     #  #  #     #  #  #     #  #  #     #  #  #

 #     #  p  p  p  p  p              #                       #

 #     #  #  #  #  #  p  #     #  #  #  #  #     #     #  #  #

 #     #              p  #     #           #     #           #

 #  #  #  #  #  #  #  p  #  #  #     #  #  #  #  #     #  #  #

 #                    p        #     #     #     #           #

 #  #  #     #  #  #  p  #  #  #     #     #     #     #     #

 #           #        p  p  p  p  p  #           #     #     #

 #     #  #  #  #  #  #  #  #  #  p  #  #  #     #  #  #     #

 #     #                          p  p  p  p  p        #     #

 #     #  #  #  #  #  #  #     #  #  #  #  #  p  #  #  #     #

 #     #                       #        p  p  p              #

 #  #  #  #  #  #  #  #  #  #  #  #  #  p  #  #  #  #  #  #  #

None
.
FLAG-SSBob3BlIHlvdSBndXlzIGhhdmUgYSBjb3JudGFzdGljIGRheSAh
[*] Closed connection to nc.ctf.unitedctf.ca port 5001
```

Flag: FLAG-SSBob3BlIHlvdSBndXlzIGhhdmUgYSBjb3JudGFzdGljIGRheSAh

## Tous les chemins mènent à Rome

![Tous les chemins mènent à Rome](/assets/images/2022/10/UnitedCTF/Misc/TousLesCheminsMenentARome.png "Tous les chemin mènent à Rome")

```
On dit souvent que tous les chemins mènent à Rome. Cependant, ce ne sont pas tous les chemins qui permettent d'arriver à destination rapidement.

Trouve le chemin le plus rapide vers Rome E en partant de Milan S, sans inclure leurs coordonnées. Lorsque c'est terminé, envoie un ..

x1 y1
x2 y2
x3 y3
x4 y4
x5 y5
.

nc nc.ctf.unitedctf.ca 5002
```

Author: [Granny](https://github.com/CloeD)


I connected to the server. This looked like the exact same challenge as the previous one, just bigger.

```bash
$ nc nc.ctf.unitedctf.ca 5002
#############################################################
# #     # # # #           # #   # #     #         # # #   # #
# ##### # # # # ##### # ### ### # # ##### # ### # # # # ### #
# # #       # # #   # # # #         #   # # # # # # # #   # #
# # ### # ### ### ##### # ##### # # # ##### # ##### # # ### #
#     # # #   #   # #     # #   # #   #   # # #   # #     # #
### # # # ### # ### ### ### # ####### ### # # ### # ### ### #
#   # # # # # #   # #     # #   #         #   #       #     #
### # ### # # # # # ### ### ####### # # ### ##### ####### ###
# # #   # # #   # #   # #   #       # #             #   # # #
# ##### # # # # ##### # ### ##### ##### ### ### ##### ### # #
E         #   # # #     #     # # #     # #   # #   #     # #
# ####### # ##### ### ##### ### ### ### # ######### # ##### #
#   # #         # # #   # #     # # #       #   # #     # # #
# ### ##### # ### # # ### ### ### # # # ### ### # ### ### # #
# # #       #         #     # #   # # # #     # #         # #
### # # ####### # ### ### ### # # ##### ####### ##### ### # #
# #   # #       # #     #   #   # # # #   #   # # #   #     #
# # ### ### ### ### # ### ### ##### # # ### ### # # ### # ###
#   #     #   # #   # # #     #         #   # # # # # # #   #
# # ##### ### ### ### # # ######### # # ### # # # ### ### ###
# # #       # # # #       # # # #   # #     #   # # # # #   #
# ### ######### ### ##### # # # ####### # # # ### # # # # ###
# #   #             #       # # # #   # # # # # #       #   #
# ### # ######### ####### ### # # ### ### ### # # ####### ###
# #   # #     #   #     #     #   # # #       #     #   #   #
####### # # # ####### # ##### ### # # # ##### ##### ### ### #
# #   # # # #         # #     #     # # #   # #       #   # #
# # ######### # ####### # ### ### ### ##### # ### # ### ### #
# #   # # #   #   # #   # # # # #     # # #   #   #         #
# # ### # ### ##### ### ### # # ### ### # ### # # # # # # # #
#   # # # # # # #     #                     # # # # # # # # #
# ### # # # ### # ### # # ### # ##### ### ### ### ###########
#           #     #     #   # # #   # #     #   #     #     S
# ### ##### ##### ### # ### ### ### ##### ### ### # ### #####
#   # #             # # # # #     #               #   # #   #
# # # ####### ##### # ### ### ##### ##### ####### ##### ### #
# # #   #     # #   # #         #     #   #             # # #
# ####### ##### ##### ##### # ##### ########### # # # ### # #
# # #       #         #   # # #     #           # # #       #
### # # ########### ##### # # ### # ### ### # ### ### ### # #
#     # #           # #     #   # # #   #   # #     #   # # #
####### ### # # ##### ##### ##### # ######### # ### # ### # #
# # # # #   # # # #           #   # # #       # # # #   # # #
# # # ### ### ### # ##### # ##### ### ### ##### # ##### #####
#   #   # #   #       #   # # # # #       #         #   #   #
# ### ############# ##### ### # # ##### # ### # # # # # ### #
# #       #   #   #   #     #     # #   # #   # # # # #     #
# ### ### # # # ### ### # ####### # ### ##### # # # ### # ###
#   #   # # # #   # # # # #     # #     #   # # # #   # #   #
### # ####### ### ### ######### ### # ### # ### ### # ### ###
# #   #     #                       # # # #       # # #     #
# # # ##### ##### # # ##### ####### ### ##### # ##### # ### #
#   #   # #   #   # #   #     #     #         # # #   # #   #
####### # # # ### ### ####### ######### ##### # # ##### # # #
# #         #     #   #         # #       #   #   # # # # # #
# ##### ####### # ######### ##### ### ####### # ### # # ### #
#       #       # #       # #         # #     #       # #   #
### # # ### ##### ### ### ### # ### # # ### ### # ##### # # #
#   # #   # #     #     #     #   # # #       # #   #   # # #
#############################################################
Too slow!
```

I copied the code from `It's corn!` and modified two lines to solve this challenge. The port number, and the number of lines to read.

```bash
$ diff itsCorn.py rome.py
85c85
<     for i in range(21):
---
>     for i in range(61):
93c93
<     conn = remote('nc.ctf.unitedctf.ca', 5001)
---
>     conn = remote('nc.ctf.unitedctf.ca', 5002)
```

I ran the modified script.

```bash
$ python rome.py
[+] Opening connection to nc.ctf.unitedctf.ca on port 5002: Done
###########################################################S#
#   # #   #   # # # # # #     # # # # # #   # #   #   #     #
# ### # ##### # # # # # # ##### # # # # ### # ### # ### ### #
#   # #     #       #   # #         # #   # #           # # #
# ### # ##### ### ##### # ##### ##### # ### # ### ####### ###
#         # # #     # #   #     # #             # #   #     #
####### ### ##### ### # ##### # # ### ####### ##### ### #####
# #           # # # #   #     #   #       # # # #       #   #
# ##### # # # # # # ### ### ### ##### ##### ### ### # ### ###
# # #   # # # #     #     #   # #       # # #     # # #   # #
# # ### ##### ### ### # ### ### ##### ### # ### ### ### ### #
# # #   #   # #     # #   # #       # #   #   # #           #
# # ####### # ### ##### ####### # ### ### # ### ### #########
#   # # #           #     # #   #     #   # #             # #
### # # ####### # ##### ### ####### ##### # ##### ######### #
# #             # # #           #           #           #   #
# # ######### ##### ##### # ### ##### # # ##### # ### # ### #
# # #     # # #   # # #   #   # #     # #       #   # # #   #
# ####### # # ### # # # ########### ##### ############### # #
#   #   #       # #   # #   # # #     #   #   #   #   #   # #
### ### # ### ### ### # # ### # ######### # # ### # ##### ###
#       # #     #   #         #   # #   #   # # #       #   #
### ####### ####### # ##### ##### # # ### ##### ### ##### ###
#     #   #   # #   #   # #     #   #   #   # #     # # #   #
### ##### # ### ### # ### ####### ### ### ### # ##### # # ###
# #   #         # #         #   #   # #   #     # # #       #
# # ######### ### # # # # ### ### # # ### ##### # # # #######
# #               # # # # #     # # # #   # #     #   #   # #
# ### ##### ### ####### ##### ##### # ### # # # ##### # ### #
#     #   # #     # #     # #   # #         # # # #       # #
####### # ##### ### ### ### # ### ####### ##### # ##### # # #
# # # # #       #   #               #     # # # # #   # # # #
# # # ######### ### ### ######### ####### # # # # # ### ### #
#     #     #   #   # #       # #     #   # # # # # # #     #
##### ##### ### # ### # ####### ### ### # # # # # # # # #####
# # #               #     # #     # #   #     # #       # # #
# # ### ### # # # ### ##### ### ##### # ### ### ### ##### # #
#   #   # # # # # # #   # # #       # # # #     #     # #   #
# ####### ##### ### # ### # # ########### # ####### ### # ###
#   # #         # #   # #     # # # #   #         #         #
# ### ####### # # # ### ##### # # # ### # # # # ### ##### # #
#     #   # # #       # #   #       # # # # # #     #     # #
### ##### # ### ### ### # ### # ##### # # ######### ####### #
#     #   # # #   #   # #   # #   #       #       #   # #   #
##### # ### # ####### # # ### ######### ### # # # ##### ### #
#     #   # # # #   #   #   # #             # # #   #   # # #
# # # # # # # # # # # ##### # # # ##### ### ########### # ###
# # #   # #     # # #   # #     # #   # #   #     #       # #
######### # # ### ### ### ##### ### # # ##### ####### # ### #
#   #       # #       # #           # #       # #     # #   #
### ####### ####### ### # # # ### # ##### ##### # ### ### ###
#           # # #   #   # # # #   #   # #     #   # # #     #
######### ### # ### ### ### ### # ##### ######### # ### ### #
# # #   # #   #       #     # # # #   #       #         # # #
# # ### # ### ##### ####### # # # # ### ####### ##### # # ###
#     #         # #   #       # # # #   #   # #     # #     #
### ####### # # # ### # ### # ##### ### # ### # ##### # #####
#     #   # # # # # # # #   # # #             # # # # # #   #
# # # ### ### ### # # ##### ### # ### # # ##### # # ##### # #
# # #                               # # #                 # #
###############################E#############################
 #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  p  #

 #           #     #           #           #     #     #     #     #     #                 #     #     #     #     #     #           #     #           #           #  p  p  p  p  p  #

 #     #  #  #     #     #  #  #  #  #     #     #     #     #     #     #     #  #  #  #  #     #     #     #     #     #  #  #     #     #  #  #     #     #  #  #  p  #  #  #     #

 #           #     #                 #                       #           #     #                             #     #           #     #  p  p  p  p  p  p  p  p  p  p  p  #     #     #

 #     #  #  #     #     #  #  #  #  #     #  #  #     #  #  #  #  #     #     #  #  #  #  #     #  #  #  #  #     #     #  #  #     #  p  #  #  #     #  #  #  #  #  #  #     #  #  #

 #                             #     #     #                 #     #           #                 #     #        p  p  p  p  p  p  p  p  p        #     #           #                 #

 #  #  #  #  #  #  #     #  #  #     #  #  #  #  #     #  #  #     #     #  #  #  #  #     #     #     #  #  #  p  #  #  #  #  #  #  #     #  #  #  #  #     #  #  #     #  #  #  #  #

 #     #                                   #     #     #     #           #                 #           #        p              #     #     #     #                       #           #

 #     #  #  #  #  #     #     #     #     #     #     #     #  #  #     #  #  #     #  #  #     #  #  #  #  #  p  #  #  #  #  #     #  #  #     #  #  #     #     #  #  #     #  #  #

 #     #     #           #     #     #     #                 #                 #           #     #              p        #     #     #                 #     #     #           #     #

 #     #     #  #  #     #  #  #  #  #     #  #  #     #  #  #     #     #  #  #     #  #  #     #  #  #  #  #  p  #  #  #     #     #  #  #     #  #  #     #  #  #     #  #  #     #

 #     #     #           #           #     #                 #     #           #     #                       #  p  #           #           #     #                                   #

 #     #     #  #  #  #  #  #  #     #     #  #  #     #  #  #  #  #     #  #  #  #  #  #  #     #     #  #  #  p  #  #  #     #     #  #  #     #  #  #     #  #  #  #  #  #  #  #  #

 #           #     #     #                                   #                 #     #           #        p  p  p  #           #     #                                         #     #

 #  #  #     #     #     #  #  #  #  #  #  #     #     #  #  #  #  #     #  #  #     #  #  #  #  #  #  #  p  #  #  #  #  #     #     #  #  #  #  #     #  #  #  #  #  #  #  #  #     #

 #     #                                         #     #     #                                   #        p  p  p  p  p  p  p        #                                   #           #

 #     #     #  #  #  #  #  #  #  #  #     #  #  #  #  #     #  #  #  #  #     #     #  #  #     #  #  #  #  #     #     #  p  #  #  #  #  #     #     #  #  #     #     #  #  #     #

 #     #     #                 #     #     #           #     #     #           #           #     #                 #     #  p                    #           #     #     #           #

 #     #  #  #  #  #  #  #     #     #     #  #  #     #     #     #     #  #  #  #  #  #  #  #  #  #  #     #  #  #  #  #  p  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #     #     #

 #           #           #                       #     #           #     #           #     #     #                 #        p  #           #           #           #           #     #

 #  #  #     #  #  #     #     #  #  #     #  #  #     #  #  #     #     #     #  #  #     #     #  #  #  #  #  #  #  #  #  p  #     #     #  #  #     #     #  #  #  #  #     #  #  #

 #                       #     #                 #           #                             #           #     #           #  p        #     #     #                       #           #

 #  #  #     #  #  #  #  #  #  #     #  #  #  #  #  #  #     #     #  #  #  #  #     #  #  #  #  #     #     #     #  #  #  p  #  #  #  #  #     #  #  #     #  #  #  #  #     #  #  #

 #                 #           #           #     #           #           #     #                 #           #           #  p        #     #                 #     #     #           #

 #  #  #     #  #  #  #  #     #     #  #  #     #  #  #     #     #  #  #     #  #  #  #  #  #  #     #  #  #     #  #  #  p  #  #  #     #     #  #  #  #  #     #     #     #  #  #

 #     #           #                             #     #                             #           #           #     #        p  #                 #     #     #                       #

 #     #     #  #  #  #  #  #  #  #  #     #  #  #     #     #     #     #     #  #  #     #  #  #     #     #     #  #  #  p  #  #  #  #  #     #     #     #     #  #  #  #  #  #  #

 #     #                                               #     #     #     #     #                 #     #     #     #        p  #     #                 #           #           #     #

 #     #  #  #     #  #  #  #  #     #  #  #     #  #  #  #  #  #  #     #  #  #  #  #     #  #  #  #  #     #     #  #  #  p  #     #     #     #  #  #  #  #     #     #  #  #     #

 #                 #           #     #                 #     #                 #     #           #     #                    p        #     #     #     #                       #     #

 #  #  #  #  #  #  #     #     #  #  #  #  #     #  #  #     #  #  #     #  #  #     #     #  #  #     #  #  #  #  #  #  #  p  #  #  #  #  #     #     #  #  #  #  #     #     #     #

 #     #     #     #     #                       #           #                                               #              p  #     #     #     #     #           #     #     #     #

 #     #     #     #  #  #  #  #  #  #  #  #     #  #  #     #  #  #     #  #  #  #  #  #  #  #  #     #  #  #  #  #  #  #  p  #     #     #     #     #     #  #  #     #  #  #     #

 #                 #                 #           #           #     #                       #     #                 #        p  #     #     #     #     #     #     #                 #

 #  #  #  #  #     #  #  #  #  #     #  #  #     #     #  #  #     #     #  #  #  #  #  #  #     #  #  #     #  #  #     #  p  #     #     #     #     #     #     #     #  #  #  #  #

 #     #     #                                               #                 #     #                 #     #           #  p  p  p        #     #                       #     #     #

 #     #     #  #  #     #  #  #     #     #     #     #  #  #     #  #  #  #  #     #  #  #     #  #  #  #  #     #     #  #  #  p  #  #  #     #  #  #     #  #  #  #  #     #     #

 #           #           #     #     #     #     #     #     #           #     #     #                       #     #     #     #  p              #                 #     #           #

 #     #  #  #  #  #  #  #     #  #  #  #  #     #  #  #     #     #  #  #     #     #     #  #  #  #  #  #  #  #  #  #  #     #  p  #  #  #  #  #  #  #     #  #  #     #     #  #  #

 #           #     #                             #     #           #     #                 #     #     #     #           #  p  p  p                    #                             #

 #     #  #  #     #  #  #  #  #  #  #     #     #     #     #  #  #     #  #  #  #  #     #     #     #     #  #  #     #  p  #     #     #     #  #  #     #  #  #  #  #     #     #

 #                 #           #     #     #                       #     #           #                       #     #     #  p  #     #     #                 #                 #     #

 #  #  #     #  #  #  #  #     #     #  #  #     #  #  #     #  #  #     #     #  #  #     #     #  #  #  #  #     #     #  p  #  #  #  #  #  #  #  #  #     #  #  #  #  #  #  #     #

 #                 #           #     #     #           #           #     #           #     #           #              p  p  p  #                       #           #     #           #

 #  #  #  #  #     #     #  #  #     #     #  #  #  #  #  #  #     #     #     #  #  #     #  #  #  #  #  #  #  #  #  p  #  #  #     #     #     #     #  #  #  #  #     #  #  #     #

 #                 #           #     #     #     #           #           #           #     #  p  p  p  p  p  p  p  p  p              #     #     #           #           #     #     #

 #     #     #     #     #     #     #     #     #     #     #     #  #  #  #  #     #     #  p  #     #  #  #  #  #     #  #  #     #  #  #  #  #  #  #  #  #  #  #     #     #  #  #

 #     #     #           #     #                 #     #     #           #     #              p  #     #           #     #           #                 #                       #     #

 #  #  #  #  #  #  #  #  #     #     #     #  #  #     #  #  #     #  #  #     #  #  #  #  #  p  #  #  #     #     #     #  #  #  #  #     #  #  #  #  #  #  #     #     #  #  #     #

 #           #                       #     #                       #     #        p  p  p  p  p              #     #                       #     #                 #     #           #

 #  #  #     #  #  #  #  #  #  #     #  #  #  #  #  #  #     #  #  #     #     #  p  #     #  #  #     #     #  #  #  #  #     #  #  #  #  #     #     #  #  #     #  #  #     #  #  #

 #                                   #     #     #           #           #     #  p  #     #           #           #     #                 #           #     #     #                 #

 #  #  #  #  #  #  #  #  #     #  #  #     #     #  #  #     #  #  #     #  #  #  p  #  #  #     #     #  #  #  #  #     #  #  #  #  #  #  #  #  #     #     #  #  #     #  #  #     #

 #     #     #           #     #           #                       #              p  #     #     #     #           #                       #                             #     #     #

 #     #     #  #  #     #     #  #  #     #  #  #  #  #     #  #  #  #  #  #  #  p  #     #     #     #     #  #  #     #  #  #  #  #  #  #     #  #  #  #  #     #     #     #  #  #

 #                 #                             #     #           #              p        #     #     #     #           #           #     #                 #     #                 #

 #  #  #     #  #  #  #  #  #  #     #     #     #     #  #  #     #     #  #  #  p  #     #  #  #  #  #     #  #  #     #     #  #  #     #     #  #  #  #  #     #     #  #  #  #  #

 #                 #           #     #     #     #     #     #     #     #        p  #     #     #                                         #     #     #     #     #     #           #

 #     #     #     #  #  #     #  #  #     #  #  #     #     #     #  #  #  #  #  p  #  #  #     #     #  #  #     #     #     #  #  #  #  #     #     #     #  #  #  #  #     #     #

 #     #     #                                                                    p  p  p  p  p              #     #     #                                                     #     #

 #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  p  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #  #

None
.
FLAG-RXN0LWNlIHF1ZSB0b24gY2hlbWluIG3DqG5lIMOgIFJvbWUgPw==
[*] Closed connection to nc.ctf.unitedctf.ca port 5002
```

Flag: FLAG-RXN0LWNlIHF1ZSB0b24gY2hlbWluIG3DqG5lIMOgIFJvbWUgPw==

The flag is base64 for `Est-ce que ton chemin mène à Rome ?`
