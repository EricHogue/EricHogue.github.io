---
layout: post
title: Mocking PDO in PHPUnit
date: 2013-02-12 21:30:10.000000000 -05:00
tags:
- Best Practices
- Testing
permalink: "/2013/02/best-practices/mocking-pdo-in-phpunit/"
---
The subject of mocking a PDO object in PHPUnit has come around a few times lately. It cannot be done like normal classes because a PDO object cannot be serialized.

```php
$pdo = $this->getMockBuilder('PDO')->disableOriginalConstructor()->getMock();
```

This will work on another class, but with PDO you will get this error:

```php
PDOException: You cannot serialize or unserialize PDO instances
```

## The solution

My solution for this problem is to create a class that derive from PDO. This class has only an empty constructor. Then you can mock this class, making sure that you don't disable the original constructor. This way the mocked object can be passed to the code to test even if this code does type hinting.

```php
class PDOMock extends \PDO { 
	public function __construct() {} 
} 

class PDOTest extends \PHPUnit_Framework_TestCase { 
	public function setup() { 
		$pdo = $this->getMockBuilder('PDOMock') ->getMock(); 
	} 
}
```
