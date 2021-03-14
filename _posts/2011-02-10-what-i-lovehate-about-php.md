---
layout: post
title: What I Love/Hate About PHP
date: 2011-02-10 21:01:31.000000000 -05:00
tags:
- PHP
permalink: "/2011/02/php/what-i-lovehate-about-php/"
---
I have been programming in PHP for 5 years now. I did not choose this language, I had to learn it to work on the code of the company my bosses bought. Since I started, I heard many rants about how bad PHP is. Some where valid, but a lot of them are just blaming the language for bad code written by bad programmers.

I am by no mean an expert in programming languages or PHP, but here is my take on the language I use every day.

## What I Love

The first thing that comes to my mind about PHP is it's ease of use. When I started PHP, I had experience in C++, Delphi, VB and C#. The low barrier of entry allowed me to be productive in it quickly. I lacked a lot of knowledge, especially in web development, but I was able to maintain the existing code right away. I no time I could add new functionalities to the existing code.

The [PHP documentation](http://www.php.net/manual/en/ "PHP Manual") is an amazing resource. It's available online, but it can also be downloaded in html of chm format. The manual contains everything there is to know about the language fundamentals. It has descriptions of every functions, their parameters and return values. It also contains examples on almost every pages to help understand what the page is about. The manual is maintain by the community, and most of the pages have notes from users that clarifies the subject even more.

Over the last five years I have become a web developer and PHP is targeted at web development. It can be embedded in html to produce dynamic pages quickly. I know this can lead to spaghetti code, but if used correctly if a powerful tool. PHP has many features that makes the life of web programmers easy. Things like writing and reading cookies, sessions handling and file uploading are easy to do.

PHP also has an interactive shell. I learned about this about a month ago. For a long time I hoped that PHP had one. I used the interactive Ruby prompt, I saw it it other languages and every time I was thinking it was a neat thing. But I never though of looking for one in PHP. Then last month I saw it in the manual and now I feel stupid for never searching for it. It's a great reminder that I know so little and that because of that I am not always using the best solutions for the problems I have. You cannot use a solution you don't know about. I don't use the interactive shell much, but it's a great tool to make a quick test before implementing something.

The community around PHP is fantastic. It is very friendly and forthcoming. There are many use groups around the world. Here in Montréal we have [PHP Québec](http://www.phpquebec.org/ "PHP Québec") that organize monthly meetups. Once a year, they hold a family barbecue in a park an they occasional do nights in a bar where we can speak with other developers around a beer. And last year with other Montréal user groups they started the new [Confoo conference](http://confoo.ca/en "Confoo").

This is just the Montréal PHP community. If you look on the web, the worldwide community is nice and helping. In [Coder at Work](http://codersatwork.com/ "Coders at Work"), [Joshua Bloch](http://twitter.com/#!/joshbloch "Joshua Bloch") says that when you choose a language, you choose a community. He compares it to choosing a bar, you want good beer, but you also want it to have nice people that hang around. I did not pick the PHP bar, but I am glad I ended up with that bunch.

## What I Hate

PHP has a few fiction point. The first thing that comes to my mind is again the low barrier of entry. This is both a blessing and a curse. Because it's easy to code in PHP, many peoples who don't know anything about programming are making PHP web sites. Because of this, there is a tremendous amount of bad PHP code out there. Most of the web pages they build have security vulnerabilities. As a result, many people consider PHP a bad language, and think that all PHP programmers are bad. This is far from the true, there are very good PHP developers out there. And there are bad programmers in every languages. PHP just tends to attract the beginners.

One thing that can be confusing in PHP is that the order of some parameters changes between functions. The needle/haystack example is known to all PHP developers. The strpos function takes the haystack parameter first and the needle second. The array\_search takes them in the opposite order. The array\_map and array\_filter have the same kind of inconsistencies with the callback parameter.

Another annoying things to me is that the constructor of a derived class does not call the constructor of the base class. This can lead to some problems because if you forgot to call it explicitly, the properties of the base class might not be initialized. The base constructor should probably be implicitly called on every instantiation. But we would also need a way to pass parameters to the base class constructor. Maybe something like in C++ would do it.

## Conclusion

PHP is not a perfect language, there is no such thing. However, I think it is a very good multi purpose language. I was able to be productive with it in a few days when we inherited from a bad code base. Since then I have learn much about it and I still have a lot to learn. The language keeps improving, with version 5 we got decent object oriented programming. With 5.3, closures and namespaces And with 5.4 we will get traits.

PHP as a lot of detractors, it also has some fan boys, don't believe any of them. Ask for more details, what they think is so bad or good about it. And go ahead and try it for yourself and make your own opinion.

