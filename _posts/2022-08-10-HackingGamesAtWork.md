---
layout: post
title: Hacking Games At Work
date: 2022-08-10
type: post
tags:
- Hacking
permalink: /2022/08/HackingGamesAtWork
img: 2022/08/HackingGamesAtWork/HackingGamesAtWork.jpg
---

A few years ago I started doing some hacking with my colleagues during lunchtime. I had been learning to hack by myself for some time and I thought it might interest some of my colleagues. It was an immediate success. I did that for over 2 years at my previous company. First in the office, sitting in a board room. Then as the pandemic started, we did it remotely. We were also able to include teams for different cities. And add a second event in a different time zone for people on the west coast. 

## Format

When I started doing the hacking games, we would get into a meeting room on Thursdays from 12:30 to 13:00. I would share my screen, open up a challenge and try to solve it with my colleagues. 

I picked challenges I already solved. I wanted to make sure we got progress every week, and that it was fun for everyone. This way, we avoided spending hours spread over multiple weeks going into rabbit holes. 

I am always at the keyboard, typing and doing the exploits. But I try to let my colleagues tell me what I should do. At first, when most of them had never done anything like this, it was mostly me explaining what I was doing. But as they learned more, they started to guide me. Eventually, I just did what they told me, nudging them in the correct direction when needed.

## What Do We Hack

When we started doing the hacking games at work, we started with [OverTheWire](https://overthewire.org/wargames/). First with [Bandit](https://overthewire.org/wargames/bandit/), and then [Natas](https://overthewire.org/wargames/natas/). OverTheWire is great for learning gradually. It starts with very simple challenges, then it slowly introduces techniques and tools in more advanced levels. The first few levels are very easy for a bunch of developers. We should all know how to connect to an ssh server. But we quickly started learning new stuff. OverTheWire is also very good at teaching us to read the man pages of the tools.

We next moved to [RingZer0](https://ringzer0ctf.com/). RingZer0 offers challenges separated into categories. Very similar to what you would see in a [Capture The Flag (CTF)](https://en.wikipedia.org/wiki/Capture_the_flag_(cybersecurity)). Many of the challenges on the site are from past CTF competitions. The challenges here are more difficult, and there is no hand holding.

Finally, we moved to challenges on [TryHackMe](https://tryhackme.com/) and [HackTheBox](https://www.hackthebox.com/). On those sites, we need to find a way to hack a server and gain access, then get root on the machine. Those challenges can feel like we are hacking real applications.

## Current Job

When I changed to company, I brought this idea with me. After a few weeks here, I proposed the idea to my team and we started doing the same hacking games during lunch once a week. I started with only my team, then opened it to a bigger audience. I was also asked to record the sessions and made them available on the tool we use internally to share videos of presentations. I don't think anyone watches them after, but they are available if someone is interested.

A few weeks ago my team lead went to his managers and asked if we could do it during business hours. I could also expand it to 45 minutes which really helps us accomplish something every week. More people are now showing up every week, and I have more participation. With new people showing up, it forces me to make sure I always explain what I'm doing, and why I'm doing it. It helps make sure everyone understands it. And putting it in words also makes sure I understand it, and shows me if I have any holes in my comprehension.

I also had a comment about how many of these challenges are built around PHP applications. This worked well when I worked in a company that used PHP. But now that it's not on our stack, people wanted to see other things. So I went back to the list of boxes I picked and trim it down, trying to find machines that use other technologies. Now instead of keeping all the machines I do, I keep those that I think have something to teach us. Machines that will allow me to show the team techniques and vulnerabilities we haven't seen yet.

## Why Am I Doing This?

When I started learning to hack, I did it because I thought that it would make me a better developer. I had been interested in writing secure code for years. I learned about things I should or shouldn't do to keep my applications secure. I knew about the different kinds of attacks, but I would not have been able to perform any of them.

I wanted to learn the offensive side to make sure I understood why I had to do what I was doing. And maybe find where it was not enough. I was also the annoying guy at work, looking for vulnerabilities in code and asking for fixes. I thought that if I could show exploits for the vulnerabilities I was asking my colleagues to fix, it might help them understand and pay closer attention in the future. I started the hacking games as a way to expand our collective knowledge and make our applications safer.

When I started learning how to hack, it was primarily to become a better developer. But I quickly found out that I really liked it. And when I introduced the hacking games at work, I enjoyed sharing that new passion I had. I loved when the team participated and suggested things we should try to pwn a machine. Seeing their reactions when we got a foothold, or when we got root was also great. So the thing I started as a way to spread knowledge quickly became something I look forward to every week.


Image Credit: [Andi Weiland](https://www.flickr.com/photos/ohrenflimmern/8118630906/)