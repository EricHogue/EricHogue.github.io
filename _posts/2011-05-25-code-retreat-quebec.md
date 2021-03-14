---
layout: post
title: Code Retreat Quebec
date: 2011-05-25 21:19:39.000000000 -04:00
tags:
- Best Practices
- Training
permalink: "/2011/05/training/code-retreat-quebec/"
---
Last Saturday I had the privilege of attempting [a code retreat in Quebec City](http://coderetreatquebec.wordpress.com/ "Code Retreat Quebec"). I have been hoping for this for a while, so I registered as soon as I found out about it. When I learned that [Corey Haines](http://coreyhaines.com/ "Corey Haines") and [J. B. Rainsberger](http://www.jbrains.ca/ "J. B. Rainsberger") where going to be there I was really thrilled.

## The Setup

The event took place at the [Germain-Dominion Hotel](http://www.germaindominion.com/en/home "Hotel le Germain-Dominion"). It is located in the old port district of Quebec City, close to the [fortifications](http://www.pc.gc.ca/lhn-nhs/qc/fortifications/index.aspx "Fortifications of Québec National Historic Site of Canada").

The retreat started at 8 AM with a breakfast and finished at 5 PM after 6 sessions of coding. With had 2 coffee breaks and a nice diner. The room was nice, with plenty of plugs for the laptop and a good WiFi connection. The organizers did a great job setting this up. Everything was ready for a full day of learning.

## How The Day Went

After the breakfast, the actual retreat started by an introduction from Corey. He describes the goals of the retreat, how it got started and the problem we where going to work on. If you are interested in his introduction, you can look at the [introduction he gave in Cleveland in January](http://programmingtour.blogspot.com/2011/01/on-goals-of-coderetreat.html "On the goals of Coderetreat").  
<iframe src="http://player.vimeo.com/video/18955165?title=0&amp;byline=0&amp;portrait=0" width="400" height="225" frameborder="0"></iframe>

[Cleveland Code Retreat Introduction](http://vimeo.com/18955165) from [Corey Haines](http://vimeo.com/coreyhaines) on [Vimeo](http://vimeo.com).

After that, Corey explained that we where going to focus on the [The Four Elements of Simple Design](http://www.jbrains.ca/permalink/the-four-elements-of-simple-design "The Four Elements of Simple Design"). They are in order of importance:

- Passes its tests
- Minimizes duplication
- Maximizes clarity
- Has fewer elements

Then we started the first session. Each sessions lasted 45 minutes. During this time we had to do [Pair programming](http://en.wikipedia.org/wiki/Pair_programming "Pair programming") to work on the problem. Every time we tried to produce the best code we could. And at the end of the session we had to delete the code. Then Corey did a brief recap of the session and gave some tips to help us move forward. Then we had to find another partner for the next session.

At the end of the day, we took pictures, then we formed a circle and everyone had to answer 3 questions. What we learned, what surprised us the most and what we will change at work.

## My Impressions

The first thing I notice is that there where people programming in many different languages. We where a few PHP developers, but not all of us had a testing environment ready. I was happy to show some people how to do TDD in PHP with [PHPUnit](https://github.com/sebastianbergmann/phpunit/ "PHPUnit").

During the day, I paired with six different developers. We covered Java, C#, PHP and Python. I got to work with good developers. The pairing is probably the greatest thing about the retreat. During each session we got to exchange ideas with someone else. Every one brought a different way to attack the problem. This is a great chance to try to code differently. Especially in a setup where we can take the time to do it correctly, with no pressure to deliver. Pairing is also a great way to transfer knowledge. While working in pair, you can learn things such as language features, better design, IDE features and keyboard shortcuts. All this just by looking at the other developer.

Practicing [Test-driven development](http://en.wikipedia.org/wiki/Test-driven_development "Test-driven development") during an entire day reminded me of how much I love it. Even in an event like this one, not every one I paired with was doing TDD. Some started by writing some code before adding a test to verify it. But when I was doing TDD, it really felt like the correct thing to do. I know I still need a lot of practice, but when I did TDD, programming was just more fun.

## What I Got Out Of It

I think the greatest lesson I got from the code retreat is a new perspective on programming. Now I will try to look at my projects for another angle. Corey and J. B. made me realize that even if we are all against the waterfall approach, we still tend to over-think our design before we start coding. On the first 3 sessions, I started with a Cell class. It seemed like it was a good starting point because it will be needed for the game. But it was a dead end.

Corey told us that when we are ready to start coding something, we should ask why? Why are we coding this? Then take the answer and ask why again. After a few time we will reach a point where we cannot ask it anymore, this is where we should start.

With the Cell class example, I was starting there because I needed to know if a cell was alive or not. I needed to know this because I needed to check if a cell needed to be killed or not. I needed this because... In the end, what I needed is a board to play the game of life. Starting with the board seemed counter intuitive to me, but when I tried it everything fell into place.

I also got to see some Python. This is a language I barely know. Pairing with a Python developer was really fun. I think I could really like this language. I especially liked the list comprehension. This is something I really wish we had in PHP.

## What Now?

The code retreat was fun, I got to experiment with practices that are not accepted where I work. It is now up to me to try and change that. I already used TDD on some project. But I really need to get back to doing it as much as I can. If it does not slow me down, and I end up producing better code, nobody can complain about it. It would also be great if I could get the other members of the team to try it. I gave a little presentation about it at work over a year ago. Sadly as far as I know, no one else tried it.

Pair programming is harder to sell. I still think it's an amazing way to transfer knowledge. It can help bring up to speed a new developer. Pairing a junior developer with someone with more experience can help both of them. The junior will get an access to the knowledge and techniques of an experienced developers. And the experienced one should consolidate is knowledge by explaining it. And he may also learn something from the other developer.

I also have to thanks the organizers, the sponsors and the facilitator. They made this amazing event possible. For only 30$, I got to spend a day coding with better developers than me. I hope it made me a better programmer, and I am looking forward to the next event.

## Update

[Karl Metivier](http://karlmetivier.wordpress.com/ "Karl Metivier") has posted [the videos of the introduction](http://karlmetivier.wordpress.com/2011/08/31/introduction-un-code-retreat-par-corey-haines/ "Introduction à un Code Retreat par Corey Haines") that [Corey Haines](http://coreyhaines.com/ "Corey Haines") did at the Quebec code retreat.

