---
layout: post
title: Late Static Binding
date: 2011-04-14 20:41:17.000000000 -04:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- PHP
tags:
- PHP
- static
meta:
  _edit_last: '1'
  _aioseop_description: 'A brief explanation of late static binding, one of the new
    PHP 5.3 features. '
  _aioseop_title: Late Static Binding
  _aioseop_keywords: late static binding, PHP 5.3, static, inheritance
  dsq_thread_id: '4212225731'
author:
  login: EricHogue
  email: eric@erichogue.ca
  display_name: Eric Hogue
  first_name: Eric
  last_name: Hogue
permalink: "/2011/04/php/late-static-binding/"
---
[Late static binding](http://www.php.net/manual/en/language.oop5.late-static-bindings.php "Late static binding") is one of the new features of PHP 5.3. It came out almost 2 years ago, but it to me that many programmers around me have no idea about it. Myself, I have learned about it around 6 months ago.

The PHP documentation defines late static binding as a way to "reference the called class in a context of static inheritance." This definition didn't really help me the first time I read it. Fortunately, there are more explanations in the documentation, and there are good examples. If you haven't, you should read it.

## How Does It Work

To use late static binding, you need a class that inherits from another one and some static methods that are overridden. Take the following code:

```
class ParentClass { public static function normalCall() { self::calledMethod(); } public static function lateStaticCall() { static::calledMethod(); } public static function calledMethod() { echo "Called in Parent\n"; } } class ChildClass extends ParentClass { public static function calledMethod() { echo "Called in Child\n"; } }
```

The method normallCall() represent the traditional way of using static functions. The self keyword will call the function in the current class. So no matter if I call it with ParentClass::normalCall() or ChildClass::normalCall(), the calledMethod() of the ParentClass will be called and "Called in Parent" will be printed.

However, the lateStaticCall() method uses the new "static" keyword. With this keyword, the call will be forwarded to the class on witch the original method was called. So ParentClass::lateStaticCall() will end up calling ParentClass::calledMethod() and print "Called in Parent". But ChildClass::lateStaticCall() will call calledMethod() in the ChildClass and print "Called in Child".

## When Should I Use It

I am really not sure. Personally, I try to avoid static methods. They are often better ways to do it. However, if you have a class hierarchy with static methods and you need to override how they act for some child classes, it can be a solution.

If you used in production code, or know a good reason to use it, I would really appreciate if you leave a comment with it.

