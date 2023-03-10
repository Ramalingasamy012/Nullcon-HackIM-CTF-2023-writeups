# Nullcon HackIM CTF

Category : **Cloud**

## Challenge : Rain checks

Description : So many options to make sure everything stays as it is. Let's use them all.

Attachments :  **exposed-user-credentials.txt, policy-exposed-user.json**

### Solution:

The exposed-user-credentials.txt has aws Access Key ID, AWS Secret Access Key .Using this , we can able to configure aws-cli using the command 

```bash
aws configure
```

the policy-exposed-user.json contains

```bash
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "lambda:GetLayerVersion",
                "lambda:GetFunction",
                "lambda:GetLayerVersionPolicy"
            ],
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "lambda:UpdateFunctionCode",
                "lambda:InvokeFunction"
            ],
            "Resource": "arn:aws:lambda:eu-central-1:743296330440:function:lambda-confirm-secret",
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
    ]
}
```

Using this file , we can able to find the region (eu-central-1) and it using lambda function.

aws has the method get-function returns information about the function or function version, with a link to download the deployment package that's valid for 10 minutes.

```bash
aws lambda get-function --function-name lambda-confirm-secret
```

Using this , we can able to download the lamba-confirm-secret python file and it also gives two more function names in the output.

```bash
lambda-aws-config-confirm-state-of-lambda
lambda-aws-config-confirm-state-of-secrets
```

Again, we have to download the python code of the above two functions using the get-function method.

In the lambda-aws-config-confirm-state-of-secrets , it has method called **correct_secret()**

```bash
def correct_secret():
    secret_name = "flag1"
    region_name = "eu-central-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    response = client.put_secret_value(
    SecretId=secret_name,
    SecretString=base64.b64decode('RU5Pe04wX0VkMXRfU3QxbGxfVnVsbn0='))
```

This code have some base64 enocoded value , decode it and get the flag !!.

```bash
echo "RU5Pe04wX0VkMXRfU3QxbGxfVnVsbn0=" | base64 -d
```

Flag : `ENO{N0_Ed1t_St1ll_Vuln}`
