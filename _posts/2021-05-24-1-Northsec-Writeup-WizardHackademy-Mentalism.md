---
layout: post
title: Northsec 2021 Writeup - Wizard Hackademy - Mentalism
date: 2021-05-24
type: post
tags:
- Writeup
- Hacking
- Northsec
- CTF
permalink: /2021/05/Northsec2021WriteupMentalism/
---

The Wizard Hackademy challenges where challenges aimed at beginners. The Mentalism track had three flags. I did the first and the third flags. 

On each level, we are presented with a conversation between an apprentice and a trainer. We need to find the name of the trainer. 

![Mentalism Site](/assets/images/2021/05/Northsec/WizardHackademy/Mentalism/site.png "Mentalism Site")

## Mentalism 101

Looking at the page source, I did not see anything of interest. The requests made to the server and their responses also looked normal.

But the URL was interesting: `http://chal2.wizard-hackademy.ctf/?page=hackademy.php`.  This looks like it could be vulnerable to a [Local File Inclusion attack](https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Local_file_inclusion) (LFI).

Once I saw that, I immediately tried to include `/etc/passwd` as a proof of concept. I loaded `http://chal2.wizard-hackademy.ctf/?page=/etc/passwd` in my browser and the content of the file was displayed in my browser. The browser show it all on one line, so I looked a the page source to make it easier to read.

![/etc/passwd](/assets/images/2021/05/Northsec/WizardHackademy/Mentalism/flag1.png "/etc/passwd")

The first flag was in the information about the trainer user on the last line of the file.

Flag 1: FLAG-c4cefba425ad40b0befbde893a7bea93

## Mentalism 103

The next thing I tried was to include the hackademy.php file. But this one cannot be read the same way as the passwd file. Because the backend code is probably using `require` or `include`. Any PHP file will be parsed and executed and we would only get the result of the code executed instead of the file content. This is exactly how the page is rendered from the start. 

Luckily for us, the [PHP include function](https://www.php.net/manual/en/function.include.php) supports multiple [wrappers](https://www.php.net/manual/en/wrappers.php) that allow us to change what the function reads and how it reads it. 

The [php://](https://www.php.net/manual/en/wrappers.php.php) wrapper let us include a stream and apply some transformation on it. We can use this to load the content of a PHP file, and apply the [base64 filter](https://www.php.net/manual/en/filters.convert.php) on it. This way the PHP code is transformed into a base64 string and is not interpreted by `include()`. 

I used this method to read the code of `hackademy.php`. I loaded `http://chal2.wizard-hackademy.ctf/?page=php://filter/convert.base64-encode/resource=hackademy.php` in my browser, but the file contained only the conversation between the apprentice and the trainer. 

I then tried to load the `index.php` file. Loading `http://chal2.wizard-hackademy.ctf/?page=php://filter/convert.base64-encode/resource=index.php` gave me the content of the file as base64. 

![index.php](/assets/images/2021/05/Northsec/WizardHackademy/Mentalism/flag2.png "index.php")

I took that base64 string copied it in [CyberChef](https://gchq.github.io/CyberChef/) using the 'From Base64' recipe and it gave me the PHP code. 

```php
<?php
    #FLAG-f5fa636eb7234d4a74c2c3d5d84a9506 (2/2)
    if(!isset($_GET["page"])){
        header("Location: ?page=hackademy.php");
        die();
    }

    $page = $_GET["page"];
    if(strpos($_GET["page"], "index.php") !== false && !preg_match("/.*=([.\/]*)?index.php$/", $_GET["page"])){
        header("Location: ?page=hackademy.php");
        die();
    }
?>
<!DOCTYPE html>
<html>
    <head>
        <title>Wizard Hackademy</title>
        <script type="text/javascript" src="https://code.jquery.com/jquery-3.5.1.js"></script>
        <script type="text/javascript" src="js/bootstrap.bundle.min.js"></script>
        <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
    </head>
    <body>
        <div class="container">
            <?php include($page); ?>
        </div>
    </body>
</html>
```

The flag was in a comment at the beginning of the file.

Flag 2: FLAG-f5fa636eb7234d4a74c2c3d5d84a9506
