---
layout: post
title: Hackfest 2021 Writeup - secure'nt - The Aftermath
date: 2021-11-23
type: post
tags:
- Writeup
- Hacking
- Hackfest
- CTF
permalink: /2021/11/HackfestCTF/securent
img: 2021/11/HackfestCTF/SecureNt/NotWhitelisted.png
---

The secure'nt track was composed of multiple challenges on web and AWS vulnerabilities. It was a follow up on the [secure'nt track from iHack 2021](/2021/06/iHackWriteupSecureNt). 

All the challenges had the same description, but a different title.

![Challenge Description](/assets/images/2021/11/HackfestCTF/SecureNt/ChallengeDescription.png "Challenge Description")

```
05 - Knock knock, who's there ? Nope, not you
150
secure'nt | Secure your new technologies

secure'nt is a resilient company, and that is why we are proud to announce that, even after the terrible hack of June 19th, we are back in business and ready to help you scale your cloud infrastructure. We have fixed the bug and implemented monitoring measures, but we are still in the process of cleaning up the Website defacement. Come pay us a visit at https://securent.daxnbrain.hfctf.ca/ !

Flag format: HF-[a-zA-Z\d]{32}

New to AWS? Head on over to the beginner CTF and do the AWS beginner track to get you started!
```

I found two flags from this track. 

## 05 - Knock knock, who's there? Nope, not you

When I got to this challenge, we already had some credentials to log to the site. I was looking through the site. On the main page, a Kanban board, there was an encrypted flag. The site had a Decryptor page, with a button to get the secret key to decrypt. But I could not use it has my IP was not whitelisted. 

![IP Not Whitelisted](/assets/images/2021/11/HackfestCTF/SecureNt/NotWhitelisted.png "IP Not Whitelisted")

I tried to bypass the IP filter. Mostly by adding headers like `X-Forwarded-For` to the request. But it did not work. 

So I left the page aside for some time. The Kanban board had mentions of a watermarking API. I was using Burp Repeater to try to find that API when it hit me that there might be a whitelisting API also. 

I try to get from `/api/whitelist` and instead of a 404, I got 405 - Method Not Allowed. 

![Method Not Allowed](/assets/images/2021/11/HackfestCTF/SecureNt/MethodeNotAllowed.png "Method Not Allowed")

I knew I was onto something. I tried to send a POST to the same endpoint and got a different error. 

![No Body](/assets/images/2021/11/HackfestCTF/SecureNt/NoBody.png "No Body")

I added an empty JSON body, and the new error showed me what I needed to provide to the endpoint.

![No IP Address](/assets/images/2021/11/HackfestCTF/SecureNt/NoIpAddress.png "No IP Address")

All I had left to do to whitelist my IP was to add it to the body of my POST request. 

![IP Whitelisted](/assets/images/2021/11/HackfestCTF/SecureNt/IPWhitelisted.png "IP Whitelisted")

This gave me the flag. And opened the GetSecret endpoint for me. 

Flag: HF-DHmbRpASDdYhsnwYpjtf609X4tUSSUIN

## 06 - Something is hiding behind this crypto magic

Now that my IP was whitelisted, I thought that I could use the Decryptor page to decrypt the flag from the Kanban board. But it was not that straightforward. 

I could use the GetSecret button.

![Get Secret](/assets/images/2021/11/HackfestCTF/SecureNt/GetSecret.png "Get Secret")

But when I tried to decrypt the flag, I got a new error. 

![Not Implemented](/assets/images/2021/11/HackfestCTF/SecureNt/NotImplemented.png "Not Implememented")

I looked at the page source and saw the decypt function. 

```js
async function decrypt(){
    try {
        let decryption_div = document.getElementById("decryptor");
        enc = document.getElementById("data").value;
        secret = document.getElementById("secret_input").value;
        if (enc === "" || secret === "") {
            throw "Empty fields"
        }
        else{
            throw "Not implemented yet"
            //decryption_div.innerHTML += `<div id="decrypted"><p>Decrypted content : ${decrypted_content}</p></div>`;
        }
    }
    catch(err) {
        document.getElementById("error").innerHTML = err;
    }
}
```

There was no code to decrypt the flag. But I remember that while looking around the other files I saw a function called `decryption`. I used Burp proxy to intercept the response to that page and modify the code inside the else to call the function and uncommented the code that displayed the result. 

```js
let decrypted_content = await decryption(enc, secret);
decryption_div.innerHTML += `<div id="decrypted"><p>Decrypted content : ${decrypted_content}</p></div>`;
```

I tried decrypting the flag again. Full of hope. But I got yet another error. 

![Crypto JS Is Not Defined](/assets/images/2021/11/HackfestCTF/SecureNt/CryptoJSIsNotDefined.png "Crypto JS Is Not Defined")


That was easy to fix, I needed to intercept the response again and import the CryptoJS library. And remember to call the `decryption` function and display the result. 

```js
// In the header
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/crypto-js.js"></script>

// In the decrypt() function
let decrypted_content = await decryption(enc, secret);
decryption_div.innerHTML += `<div id="decrypted"><p>Decrypted content : ${decrypted_content}</p></div>`;
```

I tried to decrypt again. And this time I got flag 6. 

![Decrypted](/assets/images/2021/11/HackfestCTF/SecureNt/Decrypted.png "Decrypted")

Flag:  HF-ZhzyD0QMbvlUxh4hNNtJG1xx1clWVH4L