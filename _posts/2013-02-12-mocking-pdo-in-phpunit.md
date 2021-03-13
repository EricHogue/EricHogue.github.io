---
layout: post
title: Mocking PDO in PHPUnit
date: 2013-02-12 21:30:10.000000000 -05:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Best Practices
tags:
- Mock
- PDO
- PHPUnit
meta:
  _edit_last: '1'
  _aioseop_title: Mocking PDO in PHPUnit
  _aioseop_description: Simple solution to error that occur when trying to mock a
    PDO object with PHPUnit. Workaround to the "You cannot serialize or unserialize
    PDO instances" error.
  _aioseop_keywords: PHPUnit, PDO, Mock, Serialize, Unserialized
  _wpas_done_all: '1'
  dsq_thread_id: '4212194955'
author:
  login: EricHogue
  email: eric@erichogue.ca
  display_name: Eric Hogue
  first_name: Eric
  last_name: Hogue
permalink: "/2013/02/best-practices/mocking-pdo-in-phpunit/"
---
The subject of mocking a PDO object in PHPUnit has come around a few times lately. It cannot be done like normal classes because a PDO object cannot be serialized.

```
$pdo = $this-\>getMockBuilder('PDO') -\>disableOriginalConstructor() -\>getMock();
```

This will work on another class, but with PDO you will get this error:

```
PDOException: You cannot serialize or unserialize PDO instances
```

## The solution

My solution for this problem is to create a class that derive from PDO. This class has only an empty constructor. Then you can mock this class, making sure that you don't disable the original constructor. This way the mocked object can be passed to the code to test even if this code does type hinting.

```
class PDOMock extends \PDO { public function \_\_construct() {} } class PDOTest extends \PHPUnit\_Framework\_TestCase { public function setup() { $pdo = $this-\>getMockBuilder('PDOMock') -\>getMock(); } }
```
