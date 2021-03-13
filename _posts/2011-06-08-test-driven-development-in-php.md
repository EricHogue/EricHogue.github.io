---
layout: post
title: Test Driven Development in PHP
date: 2011-06-08 07:16:20.000000000 -04:00
categories:
- Best Practices
- PHP
- PHPUnit
- TDD
tags: []
permalink: "/2011/06/php/test-driven-development-in-php/"
---
[Test driven development](http://en.wikipedia.org/wiki/Test-driven_development "test driven development") (TDD) is at the core of the [Agile Methodology](http://en.wikipedia.org/wiki/Agile_software_development "Agile software development") and [Extreme Programming](http://en.wikipedia.org/wiki/Extreme_Programming "Extreme Programming"). This practice has been known for a while and a lot have been written on it. However, I still meet developers that don't know what it is. I understand that many employers won't let their employees write tests, but we should at least know about the best practices of our industry.

In this post I will describe TDD as I understand it. I will also talk about the tools that are available in PHP.

## What Is TDD

In TDD, developers write a failing test before writing any production code. The expected behavior of the code to write is defined this way. It is then easy to know when we have reached this goal. This produce a very small feedback loop. It also push the developer to write code that is very loosely coupled to the rest of the system. This code is easier to change, and it can be reused outside without having to bring half of the current system.

One of the greatest advantage TDD comes with maintenance. You can modify your existing code without the fear of breaking anything else. Because the code is loosely coupled, the risk of side effects is practically non existent. If the behavior of the application change in any way, your tests should warn you. You should also always write a failing test before fixing a bug. This way if the bug gets reintroduce, you will know right away.

## How To Practice TDD

Practicing TDD can be resumed with the following mantra: red/green/refactor. Red is a failing test. You write a test for the simpler thing you can achieve. Then you write the code to make that test pass and go to green. You should write as little code as possible to get the test passing. Commit any crime you need, the only important thing is to get back to green. Then in the refactor phase, you fix the code you wrote. Remove any duplication, make sure the code is readable, use descriptive names... Just make sure your tests are still passing while you refactor. And then, you go back and write another failing test.

[Robert C. Martin](http://www.objectmentor.com/omTeam/martin_r.html "Robert C. Martin") (Uncle Bob) wrote [The Three Rules Of TDD](http://butunclebob.com/ArticleS.UncleBob.TheThreeRulesOfTdd "The Three Rules Of TDD"). It is a great read, but here are the rules:

> 1. You are not allowed to write any production code unless it is to make a failing unit test pass.  
> 2. You are not allowed to write any more of a unit test than is sufficient to fail; and compilation failures are failures.  
> 3. You are not allowed to write any more production code than is sufficient to pass the one failing unit test.

You can see the very short feedback loop in those rules. There is also a strong emphasis on writing as little code as possible. Just write what you need and nothing more. This goes with the [YAGNI (You ain't gonna need it)](http://en.wikipedia.org/wiki/You_ain't_gonna_need_it "You ain't gonna need it") approach.

## TDD in PHP

PHP has two main tools for unit testing. [Simple Test](http://www.simpletest.org/ "Simple Test") and [PHPUnit](http://www.phpunit.de/manual/current/en/index.html "PHPUnit"). I always used PHPUnit for unit testing in PHP. I love the tool, it [integrate with Eclipse](http://erichogue.ca/2011/05/09/php-tool-integration-phpsrc/ "PHP Tool Integration (PHPsrc)") and it can generate code coverage reports. Apparently Simple Test is pretty good also, but I have never tried it. You can pick any unit testing framework you like, just start writing test.

To write unit tests with PHPUnit, you simply create a file with a name ending by 'Test.php'. If you want to test a class named [KarateChop](http://codekata.pragprog.com/2007/01/kata_two_karate.html "Kata Two -- Karate Chop"), you create the file 'KarateChopTest.php'. In this file you create a class KarateChopTest that extends 'PHPUnit\_Framework\_TestCase'.

You then create your testing methods inside this class. The testing methods must be public and their names must start with test. I just found out that you can use the @test annotation in the docblock instead of prefixing your method name with test. All your test will be run in isolation. An instance of the test class will be created for each test method. Just be careful with global data. Global variable and static properties can make you code very hard to test.

If your methods needs some code to prepare the test, you can create a setup() method. It will be call before every test. You can also add a teardown() method to do any clean up after the test.

Your test methods should be small. They should test for only one behavior, and every test should end with an assertion that verify that the system under test (SUT) behaved has expected. Don't forget to write the test before the actual code. This way you can see the test fail first, and when it will pass, you will know that the system act as intended.

To verify the results of your test, PHPUnit has a [wide range of assertions](http://www.phpunit.de/manual/current/en/writing-tests-for-phpunit.html#writing-tests-for-phpunit.assertions "PHPUnit Assertions"). They go from the simple assertTrue to more elaborates ones like assertEqualXMLStructure and assertGreaterThanOrEqual. I counted 36 assertions types in the documentation. It even have an assertThat method to write tests in the [Behavior Driven Development](http://en.wikipedia.org/wiki/Behavior_Driven_Development "Behavior Driven Development") style.

All your tests could simply use assertTrue to verify a condition, but the intent of your code is more obvious with the verbose assertions. Those 2 lines are the same:  
```php
$this->assertStringStartsWith($prefix, $string);
$this->assertTrue(0 === strpos($string, $prefix));
```
But the first one says what it is I'm testing.

To run your tests, all you need to do is run phpunit, passing it the file with the tests as a parameter. If you pass it a folder, PHPUnit will run the test in every files with a name ending by 'Test.php' in that folder and any sub folders.

### Bootstrapping

Sometimes, you will need to have some code run before all the test cases. You might need to alter the require path, add an autoloader or set some environment variables. PHPUnit allow us to pass it a bootstrap file. This file will be run before your tests to prepare your testing environment.  
```bash
phpunit --bootstrap Tests/testBootstrap.php .
```

## Testing Databases

One of the common issue when doing TDD, or writing unit tests in general is how should we test code that interact with the database. The short answer to that, is don't. Your database should be tested during your integration tests, not in unit tests. You should try to keep your data access layer isolated from the rest of the code. That will help you testing, but also make changing the way you store your data easier.

However, we work in the real world and we sometimes have to test code that access a database. To make it easier, you should not create the connection, but require it in the object constructor or as a parameter to the method that use it. If you can't do this, consider creating a setter that allow your testing code to inject a different connection.

Make sure you use PDO connections and try to stick to standard SQL. This way in your tests, you can create a [SQLite](http://www.sqlite.org/ "SQLite") database and pass it to your tests. Make sure that you create your database in memory, not in a file. This way each test will have his own database and they will stay isolated. Creating a database like this can become very cumbersome if you use a lot of tables, or need to populate them with a lot of fake data.

If you need to connect to a real database to run your tests, you can pass your code a different configuration so at least it does not connect to your production server. You can also add an entry to your hosts file so when you try to connect to production, you end up in the test database. This can be dangerous though, someone might end up running your tests without the entry in the hosts file and alter your production database.

Connecting to a real database cause problems with the isolation of the tests. Changes made by a test can alter the result of another test. Testing against a database can also be very slow. So you should do this only if you have no other choices.

## [PHPsrc](http://www.phpsrc.org/ "PHPsrc")

I already wrote about PHPsrc in [a previous post](http://erichogue.ca/2011/05/php/php-tool-integration-phpsrc/ "PHP Tool Integration (PHPsrc)"). This tool will allow you to run your tests from inside Eclipse.

![PHPsrc PHPUnit Configuration]({{ site.baseurl }}/assets/images/2011/06/PHPsrcPHPUnitConfig-270x300.png "PHPsrc PHPUnit Configuration")

The PHPUnit integration will allow you to easily run the tests. It can also jump between the tests and the class being tested. You can give it a bootstrap file in the configuration. Either in the global settings, or by project. It will underline failing tests as errors, and it can also show code that is not covered by your tests.

## Where To Start

Beginning TDD is not an easy task. At first it will slow you down. You might appear to lose some productivity, but you should catch up pretty fast. Especially when you will maintain your code. You should then be able to make changes while being confident that you didn't break anything.

If you want to be good at anything, you need to practice. There are many resources available to practice TDD. You can perform some [Code Kata](http://codekata.pragprog.com/ "Code Kata"), attempt a [Code Retreat](http://coderetreat.com/ "Code Retreat"), find a [Coding Dojo](http://www.codingdojo.org/ "Coding Dojo") or try [CyberDojo](http://www.cyber-dojo.com/ "CyberDojo"). All these are excellent, just go and practice.

If you need any more information about TDD, I would recommend reading [Test Driven Development: By Example](http://www.amazon.com/gp/product/0321146530/ref=as_li_ss_tl?ie=UTF8&tag=erhosbl-20&linkCode=as2&camp=1789&creative=390957&creativeASIN=0321146530) (affiliate link) by [Kent Beck](http://www.threeriversinstitute.org/blog/ "Kent Beck"). It starts with an in-depth explanation of TDD and finishes by implementing an xUnit framework in TDD.

