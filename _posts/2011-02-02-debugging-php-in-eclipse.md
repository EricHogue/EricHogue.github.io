---
layout: post
title: Debugging PHP In Eclipse
date: 2011-02-02 20:39:54.000000000 -05:00
categories:
- PHP
- Debugging
- Eclipse
- PHP
- Xdebug
tags: []
permalink: "/2011/02/php/debugging-php-in-eclipse/"
---
Debugging a PHP application can be painful. When I have a bug in my code I tend to use echo and error\_log to pinpoint the source of the problem. Then I can usually look at the code and figure out what my mistake is.

But sometime the ability to step through the code is very useful. Looking at the actual values of variable and the actual path taken can point at some wrong assumptions I have about my code.

There is a very good [tutorial](http://www.eclipse.org/pdt/articles/debugger/os-php-eclipse-pdt-debug-pdf.pdf "Tutorial on setting up Eclipse for debugging") that explains how to setup Eclipse for debugging PHP. It's 35 pages long and very easy to follow. This post is just a summary of how I do it on an Ubuntu box. This way next time I need to set it up I won't need to go through all the document.

## Setup XDebug

Make sure that Xdebug is installed on your machine. Execute the following command and verify that you have at least one row with "xdebug" in it.  
```bash
php -m | grep xdebug -i
```

If XDebug is not installed on your system, you can can install it with this command:  

```bash
sudo apt-get install php5-xdebug
```

You have to allow remote debugging if you want to debug web pages. Edit /etc/php5/conf.d/xdebug.ini and add those lines:  

```bash
xdebug.remote_enable=On
xdebug.remote_host="localhost"
xdebug.remote_port=9000
xdebug.remote_handler="dbgp"
```

## Configure Eclipse

Open Eclipse preferences and navigate to "PHP/Debug". Select XDebug in the PHP Debugger drop down. Go to "PHP/PHP Executables" and make sure that you have an executable configured and that the debugger type is set to XDebug. You might want to have two executables. One to debug web pages and one for cli scripts. Set each one to load the appropriate php.ini.

Since I work on many web applications, I have many vhosts on my machine. So I need to set up multiple servers in Eclipse. Go to "PHP/PHP Servers" and click on New to create a new server. Enter a name for the server and the URL to use and click on finish.

## Debugging

When debugging, Eclipse overwrite the include\_path from your php.ini. At first I though this was really bad, but after I gave it some though it kind of make sense. This way you don't have to setup your machine like the server where your code will run. This is useful if your projects will run on different severs that can have different configurations.

You need to set up the include\_path for each project. Go to the project properties and click on "PHP Include Path". From there you will be able to add path from the project, others Eclipse projects or paths on your machine.

Then you can go to "Run/Debug Configurations" and create a new configuration. For a PHP script, pick the correct executable, choose the file to debug and you're set.

For web pages, choose the XDebug debugger, the server to use and the file to launch. Eclipse will generate a URL for you, but you can change it.

That's it, now you can add breakpoints and step through your code. You can inspect and change the value of your variables. Debugging like this can be a very powerful tools. But you still need to know your code base if you want to know where to look for because stepping through thousands of line of code can be very long and tedious.

## Sources

- [Debugging PHP using Eclipse and PDT](http://www.eclipse.org/pdt/articles/debugger/os-php-eclipse-pdt-debug-pdf.pdf "Tutorial on setting up Eclipse for debugging")
- [Debugging PHP in Eclipse using XDebug from Techmania](http://techmania.wordpress.com/2008/07/02/debugging-php-in-eclipse-using-xdebug/ "Debugging PHP in Eclipse using XDebug from Techmania")

## Update 2011-11-07

One problem you can encounter while debugging in Eclipse is that it does not take into account the files in '/etc/php5/conf.d'. This is because Eclipse use the -n option when calling PHP. This tell PHP not to use the php.ini. You can avoid this by creating a shell script that removes the option. I found this great [answer on Stack Overflow](http://stackoverflow.com/questions/6238873/eclipse-and-xdebug-does-not-parse-additional-ini-files-in-etc-php5-conf-d "Eclipse and Xdebug does not parse additional ini files in /etc/php5/conf.d").

