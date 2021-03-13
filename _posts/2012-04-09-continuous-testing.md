---
layout: post
title: Continuous Testing in PHP
date: 2012-04-09 07:30:01.000000000 -04:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Best Practices
tags:
- Best Practices
- PHP
- PHPUnit
- Testing
meta:
  _edit_last: '1'
  _aioseop_keywords: Continuous Testing, PHP, PHPUnit, watchr, autotest
  _aioseop_description: Description of continuous testing and how it can be done on
    a PHP project.
  _aioseop_title: Continuous Testing in PHP
  dsq_thread_id: '4212225831'
author:
  login: EricHogue
  email: eric@erichogue.ca
  display_name: Eric Hogue
  first_name: Eric
  last_name: Hogue
permalink: "/2012/04/best-practices/continuous-testing/"
---
Continuous testing is a way to automate the execution of your tests while you work. This makes the feedback loop very short. As soon as you save a file, the tests are run and you know right away if anything fails.

## Autotest

I discovered continuous testing over a year ago when I watched a video where [Corey Haines](http://coreyhaines.com/ "Corey Haines") performed a kata in front of a crowd. He was doing it in Ruby and using [Autotest](http://www.zenspider.com/ZSS/Products/ZenTest/ "Autotest") to run his test suite. I tough it was awesome that he immediately saw the result of his changes without having to do anything.

Back then I had used [PHPsrc](http://erichogue.ca/2011/05/php/php-tool-integration-phpsrc/ "PHP Tool Integration (PHPsrc)"). It's a great tool, but I didn't like that I had to take my hand off the keyboard and click on a button to run my tests. So I was mainly running them from the command line.

## AutoPHPUnit

When I saw Autotest, I was immediately sold and I looked for something similar in PHP. Sadly I didn't found anything like it. So after a while I wrote something for myself. I called it [AutoPHPUnit](https://github.com/EricHogue/AutoPHPUnit "AutoPHPUnit"). It uses libnotify to watch the file system. Every time a file is changed, it runs PHPUnit. You can also specify a configuration file for PHPUnit.

It worked well for me, I really loved using it. But it was not very flexible.

## Watchr

Then I read the book [Continuous Testing: with Ruby, Rails, and JavaScript](http://www.amazon.com/gp/product/1934356700/ref=as_li_ss_tl?ie=UTF8&tag=erhosbl-20&linkCode=as2&camp=1789&creative=390957&creativeASIN=1934356700) (affiliate link) that I won at the [Code Retreat in Quebec city](http://erichogue.ca/2011/05/training/code-retreat-quebec/ "Code Retreat Quebec").

In the book, the authors use [watchr](https://github.com/mynyml/watchr "watchr") to monitor the file system and perform any actions when a file changes. Watchr can be used to monitor any kind of file, so it's more flexible than my solution. And you tell it what to do with a Ruby block so it can react to changes any way you want.

To install it, you need to have Ruby already installed on your machine. Then you use RubyGems to install it. Simply run "gem install watchr" and you will have watchr on your machine. If you are not using RVM to manage your versions of Ruby, you might need to use sudo to install watchr.

You can then create a simple Ruby script. Calling the function watch() with a regexp for the files you want to watch and the block you want to execute when a file changes. Then, you run watchr passing it the script file as a parameter.

Here's a simple script to run PHPUnit:

`
watch ('.*\.php$') {|phpFile| system("phpunit -c phpunit.xml")}
`

I watch every file that ends with '.php'. When watchr detects a change, it simply runs PHPUnit for me.

[caption id="attachment\_876" align="alignnone" width="300" caption="watchr running"][![watchr running]({{ site.baseurl }}/assets/images/2012/04/watchr_result-300x75.jpg "watchr running")](http://erichogue.ca/wp-content/uploads/2012/04/watchr_result.jpeg)[/caption]

## Notifications

Using watchr like this is great if you have enough screen space to show a terminal beside your code. But if you can't have a terminal on the screen at the same time as your editor, you can use notify-send on Ubuntu to get a pop up in the notification section.

```
watch ('.*\.php$') {|phpFile| run_php_unit(phpFile)} 

def run_php_unit(modified_file)
    system('clear')
    if (system("phpunit -c phpunit.xml")) 
        system("notify-send 'All test passed'")
    else
        system("notify-send 'Test failed'")
    end
end
```

You can add any logic you want. In the Continuous Testing book they go further. You can have it display notifications only when the tests fails and when they pass again for the first time. They also count the numbers of successful runs and display notifications every 5 consecutive successful run.

[caption id="attachment\_884" align="alignnone" width="300" caption="watchr notification"][![watchr notification]({{ site.baseurl }}/assets/images/2012/04/notification-300x110.jpg "watchr notification")](http://erichogue.ca/wp-content/uploads/2012/04/notification.jpeg)[/caption]

## Beyond PHP

The main advantage of watchr is that it is not limited to only testing Ruby or PHP. Since you are using a block of Ruby code, you can do almost anything. At work, we are starting a little Node.js project, and I plan on using it to run the Vows tests.

Here's a few other things you can do with it

- Compile CoffeeScript
- Run PHP Code Sniffer
- Run lint tests
- Minify your JavaScript and CSS

Basically, anything you can automate can be ran every time a file of a certain type is changed. I've seen only one drawback to watchr, it does not see new files. So when you add files, you need to restart it if you want them to be monitored.

### Update 2012-09-04

I posted a follow up about [Continuous Testing](http://erichogue.ca/2012/09/php/continuous-testing-in-php-with-guard/ "Continuous Testing in PHP with Guard"). I now use Guard to run my tests automatically.

