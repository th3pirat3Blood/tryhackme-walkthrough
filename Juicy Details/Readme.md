# Juicy Details


## Task-2

### What tools did the attacker use? (Order by the occurrence in the log)

This can be done manually by reading the file

```bash
::ffff:192.168.10.5 - - [11/Apr/2021:09:08:34 +0000] "POST / HTTP/1.1" 200 1924 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:27 +0000] "GET /rest/user/login HTTP/1.0" 500 - "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:29:14 +0000] "GET /rest/products/search?q=1 HTTP/1.1" 200 - "-" "sqlmap/1.5.2#stable (http://sqlmap.org)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:32:51 +0000] "GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200 3742 "-" "curl/7.74.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /a54372a1404141fe8842ae5c029a00e3 HTTP/1.1" 200 1924 "-" "feroxbuster/2.2.1"
```

Using following command will give all the user-agents in the file

```bash
sed "s/^.*\"\(.*\)\"/\1/g" access.log| uniq
```

```bash
-
Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Mozilla/5.0 (Hydra)
Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
sqlmap/1.5.2#stable (http://sqlmap.org)
Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
curl/7.74.0
feroxbuster/2.2.1
Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
```

`nmap,hydra,sqlmap,curl,feroxbuster`

### What endpoint was vulnerable to a brute-force attack?

Check the url attack performed by hydra

`/rest/user/login`

### What endpoint was vulnerable to SQL injection?

Just check the sqlmap attack payload

`/rest/products/search?`

### What parameter was used for the SQL injection?

`q`

### What endpoint did the attacker try to use to retrieve files? (Include the /)

It is the GET request made by feroxbuster

`/ftp`


## Task-3

### What section of the website did the attacker use to scrape user email addresses?

Using the below *grep* command we can get list of all the pages on server as scraped by the attacker

```bash
$grep -oE "\"GET\s.*\"\s[0-9]+" access.log| grep -vE "[3|4|5][0-9]+"| sort| uniq 

"GET /admin HTTP/1.1" 200
"GET /administartion HTTP/1.1" 200
"GET /api/Addresss/3 HTTP/1.1" 200
"GET /api/Addresss HTTP/1.1" 200
"GET /api/Challenges/?name=Score%20Board HTTP/1.1" 200
"GET /api/Feedbacks/ HTTP/1.1" 200
"GET /api/Quantitys/ HTTP/1.1" 200
"GET /api/SecurityQuestions/ HTTP/1.1" 200
"GET /assets/public/images/uploads/%F0%9F%98%BC- HTTP/1.1" 200
"GET /backup HTTP/1.1" 200
"GET /favicon.ico HTTP/1.1" 200
"GET /ftp HTTP/1.1" 200
"GET /.git/HEAD HTTP/1.1" 200
"GET /login HTTP/1.1" 200
"GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0" 200
"GET /promotion HTTP/1.1" 200
"GET /rest/admin/application-configuration HTTP/1.1" 200
"GET /rest/admin/application-version HTTP/1.1" 200
"GET /rest/basket/1 HTTP/1.1" 200
"GET /rest/basket/6 HTTP/1.1" 200
"GET /rest/captcha/ HTTP/1.1" 200
"GET /rest/continue-code HTTP/1.1" 200
"GET /rest/image-captcha/ HTTP/1.1" 200
"GET /rest/languages HTTP/1.1" 200
"GET /rest/memories/ HTTP/1.1" 200
"GET /rest/products/13/reviews HTTP/1.1" 200
"GET /rest/products/14/reviews HTTP/1.1" 200
"GET /rest/products/15/reviews HTTP/1.1" 200
"GET /rest/products/16/reviews HTTP/1.1" 200
"GET /rest/products/17/reviews HTTP/1.1" 200
"GET /rest/products/18/reviews HTTP/1.1" 200
"GET /rest/products/19/reviews HTTP/1.1" 200
"GET /rest/products/1/reviews HTTP/1.1" 200
"GET /rest/products/20/reviews HTTP/1.1" 200
"GET /rest/products/21/reviews HTTP/1.1" 200
"GET /rest/products/22/reviews HTTP/1.1" 200
"GET /rest/products/23/reviews HTTP/1.1" 200
"GET /rest/products/24/reviews HTTP/1.1" 200
"GET /rest/products/25/reviews HTTP/1.1" 200
"GET /rest/products/26/reviews HTTP/1.1" 200
"GET /rest/products/29/reviews HTTP/1.1" 200
"GET /rest/products/2/reviews HTTP/1.1" 200
"GET /rest/products/3/reviews HTTP/1.1" 200
"GET /rest/products/4/reviews HTTP/1.1" 200
"GET /rest/products/5/reviews HTTP/1.1" 200
"GET /rest/products/6/reviews HTTP/1.1" 200
"GET /rest/products/7/reviews HTTP/1.1" 200
"GET /rest/products/8/reviews HTTP/1.1" 200
"GET /rest/products/9/reviews HTTP/1.1" 200
"GET /rest/products/search?q=1%20AND%20%28SELECT%208087%20FROM%20%28SELECT%28SLEEP%285%29%29%29UJRs%29--%20jYOJ HTTP/1.1" 200
"GET /rest/products/search?q=1%20AND%20%28SELECT%208087%20FROM%20%28SELECT%28SLEEP%285%29%29%29UJRs%29 HTTP/1.1" 200
"GET /rest/products/search?q=1%20AND%209700%3D9700--%20jEIr HTTP/1.1" 200
"GET /rest/products/search?q=1%20AND%209700%3D9700 HTTP/1.1" 200
"GET /rest/products/search?q=1%20ORDER%20BY%201--%20GdNP HTTP/1.1" 200
"GET /rest/products/search?q=1%20ORDER%20BY%201--%20TAan HTTP/1.1" 200
"GET /rest/products/search?q=1%27%20AND%209700%3D9700%20AND%20%27IyBx%27%3D%27IyBx HTTP/1.1" 200
"GET /rest/products/search?q=1%27%29%20AND%209700%3D9700%20AND%20%28%27IYGA%27%3D%27IYGA HTTP/1.1" 200
"GET /rest/products/search?q=1%29%20ORDER%20BY%201--%20DtMP HTTP/1.1" 200
"GET /rest/products/search?q=1%29%3BSELECT%20DBMS_PIPE.RECEIVE_MESSAGE%28CHR%28110%29%7C%7CCHR%2869%29%7C%7CCHR%28113%29%7C%7CCHR%2872%29%2C5%29%20FROM%20DUAL-- HTTP/1.1" 200
"GET /rest/products/search?q=1%29%3BSELECT%20PG_SLEEP%285%29-- HTTP/1.1" 200
"GET /rest/products/search?q=1%3BSELECT%20DBMS_PIPE.RECEIVE_MESSAGE%28CHR%28110%29%7C%7CCHR%2869%29%7C%7CCHR%28113%29%7C%7CCHR%2872%29%2C5%29%20FROM%20DUAL-- HTTP/1.1" 200
"GET /rest/products/search?q=1%3BSELECT%20PG_SLEEP%285%29-- HTTP/1.1" 200
"GET /rest/products/search?q=1.9xqhL HTTP/1.1" 200
"GET /rest/products/search?q=1 HTTP/1.1" 200
"GET /rest/products/search?q=1&QKqc=7074%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1" 200
"GET /rest/products/search?q=%27))%20UNION%20SELECT%20%271%27,%20%272%27,%20%273%27,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200
"GET /rest/products/search?q=6813 HTTP/1.1" 200
"GET /rest/products/search?q= HTTP/1.1" 200
"GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200
"GET /rest/saveLoginIp HTTP/1.1" 200
"GET /rest/user/whoami HTTP/1.1" 200
```

The sqli was executed on `/rest/products/reviews` page. Looking at the hint gave a little help at exact answer string: `product reviews`

### Was their brute-force attack successful? If so, what is the timestamp of the successful login? (Yay/Nay, 11/Apr/2021:09:xx:xx +0000)

This can be done by searching the status code 200 in the access.log file

`grep -iE "200.*hydra" access.log`

```bash
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "POST /rest/user/login HTTP/1.0" 200 831 "-" "Mozilla/5.0 (Hydra)"
```

`Yay,11/Apr/2021:09:16:31 +0000`

### What user information was the attacker able to retrieve from the endpoint vulnerable to SQL injection?

Looking at the GET request its clear.

```bash
"GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200
```

`email, password`

### What files did they try to download from the vulnerable endpoint? (endpoint from the previous task, question #5)

```bash
$grep ftp access.log 

::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /ftp HTTP/1.1" 200 4852 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:40 +0000] "GET /ftp/www-data.bak HTTP/1.1" 403 300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:43 +0000] "GET /ftp/coupons_2013.md.bak HTTP/1.1" 403 78965 "-" ""Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

Can also be checked by viewing `vsftpd.log` file

```bash
$tail -n2 vsftpd.log

Sun Apr 11 09:35:45 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/www-data.bak", 2602 bytes, 544.81Kbyte/sec
Sun Apr 11 09:36:08 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/coupons_2013.md.bak", 131 bytes, 3.01Kbyte/sec
```

`coupons_2013.md.bak,www-data.bak`

### What service and account name were used to retrieve files from the previous question? (service, username)

Just check the `vsftpd.log` file for username

`ftp,anonymous`

### What service and username were used to gain shell access to the server? (service, username)

Just check the auth.log file for username used. 

```bash 
$grep Accepted auth.log 

Apr 11 09:41:19 thunt sshd[8260]: Accepted password for www-data from 192.168.10.5 port 40112 ssh2
Apr 11 09:41:32 thunt sshd[8494]: Accepted password for www-data from 192.168.10.5 port 40114 ssh2
```

`ssh,www-data`
