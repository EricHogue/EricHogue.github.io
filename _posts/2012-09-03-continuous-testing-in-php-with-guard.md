---
layout: post
title: Continuous Testing in PHP with Guard
date: 2012-09-03 21:43:17.000000000 -04:00
tags:
- PHP
- Best Practices
- TDD
- Testing
permalink: "/2012/09/php/continuous-testing-in-php-with-guard/"
img: 2012/09/Guard-300x161.jpeg
---
A few months ago, I wrote about [continuous testing](http://erichogue.ca/2012/04/best-practices/continuous-testing/ "Continuous Testing"). When I wrote that post, I was using [watchr](https://github.com/mynyml/watchr "watchr") to run my tests. A few weeks ago, I started using [Guard](https://github.com/guard/guard "Guard") instead of watchr and I wouldn't go back.

## Reasons to Change

One of the problems I had with watchr, is that it did not see new files. Every time I added a test file, I had to switch window and restart watchr. Then I would add the class to test and have to do the same thing. It's not a big deal, but I'm lazy. And the main reason to use a tool like this is to have the test runs automatically.

Another concerns, is that watchr is not maintained anymore. The latest commit on GitHub was done over a year ago. And the last time there where any real activity is 2 years ago. There is a couple pull requests waiting, but some of them have been there for a year.

And lastly, Guard comes built in with some functionality that required code in watchr, and others are part of additional Guards.

## Guard

Like watchr, Guard watch your file system and trigger some actions when files are modified. It's also build in Ruby. There are many plugins that will simplify frequent tasks. One of those is [guard-phpunit](https://github.com/Maher4Ever/guard-phpunit "guard=phpunit") that runs [PHPUnit](https://github.com/sebastianbergmann/phpunit/ "PHPUnit") when PHP files are changed. Guard runs only the needed tests when you change a file. It will run all the tests only when you ask for it, or after a failing test finally succeed. It also has a very good notification system.

To install Guard, you need to have ruby already installed. On Ubuntu, you can install it like this

```
sudo apt-get install ruby1.9
```

Once you have Ruby installed, you just need to run

```
gem install guard guard-phpunit
```

to install Guard with the PHPUnit plugin. If you don't use RVM to manage your Ruby versions, you will need to run gem install with sudo.

That's all there is to it. You are now ready to use Guard.

## The Guardfile

The Guardfile is where you tell Guard which files to watch, and what it should do when a file is modified. You can generate one with all the plugins installed by running

```
guard init
```

If you want to have a file only for one plugin, or add the code for another plugin, just run

```
guard init phpunit
```

You can also generate the Guardfile manually, it's a simple Ruby file. My Guard file for PHPUnit looks like this:

```
guard 'phpunit', :cli =\> '--colors', :tests\_path =\> 'tests', :keep\_failed =\> true, :all\_after\_pass =\> true do 
	watch(%r{^tests/.+Test\.php$}) 
	watch(%r{^src/(.+)\.php$}) { |m| "tests/#{m[1]}Test.php" } 
end
```

The first line, tells guard to use the PHPUnit plugin. This plugin will execute PHPUnit and check if the tests pass or not. We give it a few options. First we tell guard to pass the colors argument to PHPUnit. keep\_failed is to make sure that when a test case fails, guard will run it on every save until it passes. all\_after\_pass, tells Guard to run all the tests once a failing tests succeed. This way you are sure you didn't break anything in the process of getting the test to pass.

This file has two calls to watch, the first one makes Guard watch the tests folder and run PHPUnit on any file modified in it.

The second one watches the src folder. When a file is modified in this folder, it makes Guard run the associated file in the tests folder. For this to work, I just have to keep the structure of my src and tests folders identical.

## Running Guard

Running Guard is done by simply issuing the 'guard' command in your project folder. It will look for the Guard file in the current directory. If there are none, it will look in your home directory for a file called '.Guardfile'.

In addition to the '.Guardfile', you can use a file called '.guard.rb', also in your home directory. .Guardfile will be use if you don't have a Guardfile in the current directory. .guard.rb is appended to your Guardfile. This is useful for configurations that you don't want to share between developers on the same project. Notifications preferences are a good example of what can go in .guard.rb.

One interesting parameter to Guard is -c or --clear. If you run it with this parameter, Guard will clear the terminal before running the tests.

![Running Guard]({{ site.baseurl }}/assets/images/2012/09/Guard-300x161.jpeg "Running Guard")

## Notifications

Guard has a comprehensive notification system. It uses Libnotify on Linux, Growl on Mac and Notifu on Windows. To use it on Linux, make sure you have libnotify-bin and the libnotify gem installed.

```
sudo apt-get install libnotify-bin gem install libnotify
```

You can then add this line to your Guardfile

```
notification :libnotify
```

![Notifications]({{ site.baseurl }}/assets/images/2012/09/Notifications-300x91.jpeg "Notifications")

If you want to turn them off, change the notification value to :off.

```
notification :off
```

## Other Plugins

There are a lot of [plugins for Guard](https://github.com/guard/guard/wiki/List-of-available-Guards "Guard plugins"). Here's a small list of the ones I found interesting:

- [guard-coffeescript](https://github.com/guard/guard-coffeescript "guard-coffeescript") - Compile your CoffeeScript
- [guard-jasmine](https://github.com/guard/guard-jasmine "guard-jasmine") - Run Jasmine tests
- [guard-less](https://github.com/guard/guard-less "guard-less") - Compile less into css
- [guard-sass](https://github.com/guard/guard-sass "guard-sass") - Complie sass into css
- [guard-puppet](https://github.com/guard/guard-puppet "guard-puppet") - Run Puppet
- [guard-remote-sync](https://github.com/pmcjury/guard-remote-sync "guard-remote-sync") - rsync your files when you change them
- [guard-shell](https://github.com/guard/guard-shell "guard-shell") - Run any shell command
- [guard-livereload](https://github.com/guard/guard-livereload "guard-livereload") - Reload your browser when you change your views

## Inline Guard

When there are no plugin to perform a task you need, you can use guard-shell. Another alternative is to create an inline guard. Just add a class that extends Guard to your Guardfile. In the class you need to at a minimum override the method run\_on\_change. Here's what I did for running [Behat](http://behat.org/ "Behat").

```
module ::Guard 
	class Behat < Guard 
		def start 
			run_all 
		end 
		
		def run_all 
			puts 'Run all Behat tests' 
			puts `behat`
		end 
		
		def run_on_change(paths) 
			paths.each do |file| 
				puts `behat #{file}` 
			end 
		end 
	end 
end 

guard 'behat' do 
	watch %r{^tests/integrationTests/.+\.feature$} 
end
```

This runs Behat every time a .feature file is changed.

I'm working on a plugin for Behat. There is not much yet, it just runs Behat on file changes. It won't parse the results or display notifications yet. I still have a lot of work, but it can be useful as it is now. It's on [my GitHub](https://github.com/EricHogue/guard-behat "guard-behat").

## Give It a Try

Continuous testing has been a great addition to my toolbox. It took me some time to find the correct tools for me, but now, Guard is making my life easier. If you do [Test Driven Development (TDD)](http://erichogue.ca/2011/06/php/test-driven-development-in-php/ "Test Driven Development"), you should try it.

If you have some better tools, or improvements I can make to the way I use Guard, please let me know in a comment.

## Update 2013-11-15

The Guard::PHPUnit plugin has some issues. The main one is that it's calling a PHPUnit function that does not exist anymore. The name had a typo in it and it got fixed. There is a pull request to Guard::PHPUnit to fix it, but it's not maintained anymore.

Someone as forked the repository and create [Guard::PHPUnit2](https://github.com/ramon/guard-phpunit2 "Guard::PHPUnit2"). The fork fix the issue. And it will also provide a way to pass the path to PHPUnit. This will allow using it with [Composer](http://getcomposer.org/ "Composer").

Make sure you use Guard::PHPUnit2 to avoid a lot of problems.

