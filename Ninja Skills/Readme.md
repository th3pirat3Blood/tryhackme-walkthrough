# Ninja Skills - Easy TryHackMe

**SSH CREDS:**
```
username: new-user
password: new-user
```

**Files to answer**

```
8V2L
bny0
c4ZX
D8B3
FHl1
oiMO
PFbD
rmfX
SRSq
uqyw
v2Vb
X1Uy
```

## Finding file locations on machine

In order to this we first create a file **file-list** with every name on a new line. After that we execute the following command:

`for f in $(cat file-list);do find / -name $f 1>>locations 2>/dev/null; done`

Check the current directory for a file name called **locations**. It will have the absolute paths for those files.

**locations**
```
/etc/8V2L
/mnt/c4ZX
/mnt/D8B3
/var/FHl1
/opt/oiMO
/opt/PFbD
/media/rmfX
/etc/ssh/SRSq
/var/log/uqyw
/home/v2Vb
/X1Uy
```

## File info

Using the below code we can figure the file info on all those files at once.

`for f in  $(cat locations); do ls -l $f; done`

**Output**
```
-rwxrwxr-x 1 new-user new-user 13545 Oct 23  2019 /etc/8V2L
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /mnt/c4ZX
-rw-rw-r-- 1 new-user best-group 13545 Oct 23  2019 /mnt/D8B3
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /var/FHl1
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /opt/oiMO
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /opt/PFbD
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /media/rmfX
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /etc/ssh/SRSq
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /var/log/uqyw
-rw-rw-r-- 1 new-user best-group 13545 Oct 23  2019 /home/v2Vb
-rw-rw-r-- 1 newer-user new-user 13545 Oct 23  2019 /X1Uy
```

## Finding file with IP address

Now assuming IPv4 is used here, the following command can be used to get the filename:

`for f in  $(cat locations); do grep -lE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" $f; done`

**Output**

`/opt/oiMO`

## Which file has the SHA1 hash of 9d54da7584015647ba052173b84d45e8007eba94

All the hashes can be calculated using following command:

`for f in  $(cat locations); do sha1sum $f; done`

**Output**
```
0323e62f06b29ddbbe18f30a89cc123ae479a346  /etc/8V2L
9d54da7584015647ba052173b84d45e8007eba94  /mnt/c4ZX
2c8de970ff0701c8fd6c55db8a5315e5615a9575  /mnt/D8B3
d5a35473a856ea30bfec5bf67b8b6e1fe96475b3  /var/FHl1
5b34294b3caa59c1006854fa0901352bf6476a8c  /opt/oiMO
256933c34f1b42522298282ce5df3642be9a2dc9  /opt/PFbD
4ef4c2df08bc60139c29e222f537b6bea7e4d6fa  /media/rmfX
acbbbce6c56feb7e351f866b806427403b7b103d  /etc/ssh/SRSq
57226b5f4f1d5ca128f606581d7ca9bd6c45ca13  /var/log/uqyw
7324353e3cd047b8150e0c95edf12e28be7c55d3  /home/v2Vb
59840c46fb64a4faeabb37da0744a46967d87e57  /X1Uy
```

## Which file contains 230 lines?

**There is no such file with 230 line numbers... moreover only 11 files out of given 12 are present on the system hence the last file should be that**

Again a simple command:

`for f in  $(cat locations); do wc -l $f; done`

**Output**
```
209 /etc/8V2L
209 /mnt/c4ZX
209 /mnt/D8B3
209 /var/FHl1
209 /opt/oiMO
209 /opt/PFbD
209 /media/rmfX
209 /etc/ssh/SRSq
209 /var/log/uqyw
209 /home/v2Vb
209 /X1Uy
```

## Which file's owner has an ID of 502?

The following command will help with that:
``` cat /etc/passwd | grep 502```

**Output**
`newer-user:x:502:503::/home/newer-user:/bin/bash`

Just check the [File info section](#file-info) for the file with username **newer-user**

