# Gotta Catch'em All - Linux - Easy

**IP may change over the document**

## Enumeration

### Nmap: `nmap -sV -oN nmap-initial 10.10.182.82`

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Gobuster: `gobuster dir -u http://10.10.182.82 -w ../wordlist_common.txt| tee gobuster-scan`

```bash
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 11217]
/server-status        (Status: 403) [Size: 277]  
```

### Manual enumeration

Got the following text in source code at `http://10.10.182.82`: `<!--(Check console for extra surprise!)-->`

Checking the console just gives an array of pokemon list.... After a lot of poking around I had to see the walkthrough for this part... It was right in front of me: `<pokemon>:<hack_the_pokemon>`. It was just above the commented line but I mistook it for some tag.....


Use these creds to ssh to the box.

---
## Find the Grass-Type Pokemon

After logging into the box we see a bunch of dir.. using `ls -a *` reveals a dir in Videos and a zip file in Desktop.

Let's check the zip file first. On unzipping the file and catting the file we see: `50 6f 4b 65 4d 6f 4e 7b 42 75 6c 62 61 73 61 75 72 7d`

Maybe Hex to ascii? Can be done using [online decoder](https://www.rapidtables.com/convert/number/hex-to-ascii.html) or python code.

```python
hex_str = "506f4b654d6f4e7b42756c6261736175727d"
print(bytes.fromhex(hex_str).decode())
```

We got our first flag.

---
## Find the Water-Type Pokemon

Let's follow the other trail we have (dir inside Videos). After opening the file at last we have 

```C++
# include <iostream>

int main() {
        std::cout << "ash : pikapika"
        return 0;
}
```

Checking the /home dir we have a dir named ash but its owned by root....

There is also a file named `roots-pokemon.txt`. Using `su ash` to switch to user ash and then cat out the file we get: `Pikachu!`

Hmmm.. dead end? Rabbit hole? *Spoiler Alert: It wasn't :)*

Checking the hint gave it away: `Maybe the website has an answer?`. Let's check the /etc/passwd file for web server's home dir

```bash
$grep www /etc/passwd
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

We have the next flag at `/var/www/html`. But it seems not right.. Maybe Ceaser cipher? Using [online tool](https://www.dcode.fr/caesar-cipher) for decoding we have our flag at +12.

---
## Find the Fire-Type Pokemon

Uptill now we had *grass-type.txt* and *water-type.txt* as our flag files... This one could be named *fire-type.txt* (Total Guesswork).

Using `find` for checking if such a file exists on the sytem 

```bash
$find / -name fire-type.txt -type f 2>/dev/null
/etc/why_am_i_here?/fire-type.txt
```

Yupp... it's there. Let's check it out

We have some string ending with *==* ... Maybe base64? Let's try decoding.

```bash
echo <string_here> | base64 -d
```

Yupp we have our flag....

---
## Who is Root's Favorite Pokemon?

Hmm... We had something like `roots-pokemon.txt` file found earlier. That's the answer for this one.
