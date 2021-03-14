---
layout: post
title: PHP Tool Integration (PHPsrc)
date: 2011-05-09 11:22:33.000000000 -04:00
tags:
- Best Practices
- PHP
- Testing
permalink: "/2011/05/php/php-tool-integration-phpsrc/"
---
In a [previous post](http://erichogue.ca/2011/05/php/continuous-integration-in-php/ "Continuous Integration In PHP"), I talked about [Continuous Integration](http://en.wikipedia.org/wiki/Continuous_integration "Continuous Integration"). If your Continuous Integration server runs on every commits, it will help you keep your code quality high. It will also make integration a non issue.

However, when I make a mistake, produce sub-optimal code or if I write code that does not respect our coding standards I want to know before I commit. I would rather fix my errors before they break the build. I can run all the tools that the server runs. But running them on my machine and analyzing the results every time I save will be painful. Fortunately, there is an easy solution.

### PHPsrc

[PHPsrc](http://www.phpsrc.org/ "PHPsrc") is a plugin that allow you to run PHP\_CodeSniffer, PHPUnit, PHP Depend and PHP Copy/Paste Detector directly in Eclipse. The site also says that more tools should come. As you work, you will see any transgression you make. That will save you from breaking the build, but it also makes it easier to fix the problem. After all, you just wrote the faulty lines of code.

You install it like any other Eclipse plugin. Go to the Help menu and click on "Install new software..." In the Install dialog, click on "Add...", choose a name for the repository and enter "http://www.phpsrc.org/eclipse/pti/" in the location. After you click on OK, Eclipse will detect "PHP Tool integration. Select it and click on Next twice. Accept the condition and click on Finish. After the installation is completed, you will have to restart Eclipse.

After the installation, in the preferences you will have a new "PHP Tools" menu. Make sure that every tools have an PHP executable and a PEAR library selected. For PHP CodeSniffer, you will also need to pick a standard. 

![PHPsrc Configuration]({{ site.baseurl }}/assets/images/2011/05/PHPsrcConfig-298x300.png "PHPsrc Configuration")

Your Eclipse should now have new buttons in the toolbar and a new "PHP Tools" sub menu in the PHP Explorer.  
![PHPsrc Toolbar]({{ site.baseurl }}/assets/images/2011/05/PHPsrcToolbar.png "PHPsrc Toolbar")

![PHPsrc Menu]({{ site.baseurl }}/assets/images/2011/05/PHPsrcMenu-300x289.png "PHPsrc Menu")

PHPsrc will now check your code every time you save. Errors and warnings will be added to the Problems tab and the Type will be the tool that found the problem. The lines that causes problems will also be underlined like a syntax error. The copy paste detector will send the results to the console.

Here's what Eclipse looks like with PHPsrc:  
![PHPsrc Results]({{ site.baseurl }}/assets/images/2011/05/PHPsrcResults-300x182.png "PHPsrc Results")

If you develop PHP code in eclipse, you should definitely give PHPsrc a try. If you use a continuous integration server, being warned about potential issues before you commit to your source control repository can save you from becoming the one who broke the build.

