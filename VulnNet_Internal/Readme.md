# VulnNet : Internal - Easy linux

## IP: 10.10.153.68

## Scanning

### Nmap

**Command**

`nmap -A 10.10.153.68 | tee nmap-scan`

**Output**

```
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5e:27:8f:48:ae:2f:f8:89:bb:89:13:e3:9a:fd:63:40 (RSA)
|   256 f4:fe:0b:e2:5c:88:b5:63:13:85:50:dd:d5:86:ab:bd (ECDSA)
|_  256 82:ea:48:85:f0:2a:23:7e:0e:a9:d9:14:0a:60:2f:ad (ED25519)
111/tcp  open     rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34563/tcp6  mountd
|   100005  1,2,3      36177/udp6  mountd
|   100005  1,2,3      45406/udp   mountd
|   100005  1,2,3      51829/tcp   mountd
|   100021  1,3,4      38760/udp   nlockmgr
|   100021  1,3,4      40599/tcp   nlockmgr
|   100021  1,3,4      45753/tcp6  nlockmgr
|   100021  1,3,4      47061/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open     netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp  open     rsync       (protocol version 31)
2049/tcp open     nfs_acl     3 (RPC #100227)
9090/tcp filtered zeus-admin
Service Info: Host: VULNNET-INTERNAL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -39m58s, deviation: 1h09m15s, median: 0s
|_nbstat: NetBIOS name: VULNNET-INTERNA, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: vulnnet-internal
|   NetBIOS computer name: VULNNET-INTERNAL\x00
|   Domain name: \x00
|   FQDN: vulnnet-internal
|_  System time: 2021-05-21T14:35:03+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-21T12:35:03
|_  start_date: N/A

```

## Enumeration

We have some smb/nfs stuff to check now. Let's see

### SMB

**Commmand**

`smbclient //10.10.153.68/shares` 

**No password required**

Get file **temp/services.txt**. It contains first flag.

### NFS

Checking NFS export file

`showmount -e 10.10.153.68`

**Output**

`/opt/conf *`

Mounting NFS to a dir (just make one)

`sudo mount -t nfs 10.10.153.68:/opt/conf nfs_export_list`

checking each directory for some sort of info..... **redis/redis.conf** has something like **requirepass "B65Hx562F@ggAZ@F"**. Could be useful.

### Redis

`Redis is an in-memory data structure store, used as a distributed, in-memory key–value database, cache and message broker, with optional durability.`
-Source Wikipedia

**Default port - 6379**

Trying to connect to redis on port 6379 using: `nc 10.10.153.68 6379`

Command list for redis that can be used:

```
info --> It may return output with information of the Redis instance
AUTH --> used for authenticating with redis
KEYS --> find all keys matching the given pattern
```

**Command used :** `info`

**Output:** `-NOAUTH Authentication required.`

**Command used :** `auth B65Hx562F@ggAZ@F`

**Output:**`+OK`

Looks like we are in. Lets see what we can get. A list of supported commands can be found by typing **command** which will return redis commands or use https://redis.io/commands for checking the commands and their usage.

Lets check for keys now: `keys *`

**Output**

```
*5
$3
tmp
$3
int
$8
authlist
$10
marketlist
$13
internal flag
```

The following command results in showing the internal flag: `get "internal flag"`

