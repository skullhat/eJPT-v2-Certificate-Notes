--- 
### Metasploit Fundamentals

1. How to search for modules.
`search etrnalblue`
2. How to select modules.
`use 5`
3. How to configure module options & variables.
`show options`
4. How to search for payloads.
`search payload reverce_tcp`

5. Managing sessions.
`sessions 2`
6. Additional searching functionality.
`search cve:2017 type:exploit platform:windows`

 > You can hit the `save` command to save the configuration. This means that next time you fire up Metasploit, you will land up with the same parameters and workspace you left behind

## MSF Workspaces
+ Workspaces allow you to keep track of all your hosts, scans and activities
and are extremely useful when conducting penetration tests as they allow
you to sort and organize your data based on the target or organization.

+ MSFconsole provides you with the ability to create, manage and switch
between multiple workspaces depending on your requirements.

+ We will be using workspaces to organize our assessments as we progress
through the course.

``` bash
msf6 > workspace -a Test # Add workspace(s)
msf6 > hosts 
msf6 > workspace default 
msf6 > workspace -D # Delete all workspaces
msf6 > workspace -d Test # Delete workspace(s)
msf6 > workspace -h # Show this help information
msf6 > workspace -r <old> <new> # Rename workspace workspace
```

> **Metasploit tip:**
> 	 To save all commands executed since start up to a file, use the `makerc` command

## Enumeration Phase Using Metasploit

### Extract nmap results to MSF

1. Output the results of Nmap into an XML file, then import it in the MSF:
``` bash
nmap -Pn -sV -O 10.2.5.14 -oX windowd_server_2016

msf5 > db_import /root/windows_server_2012

msf5 > hosts 
# to check for the stored hosts
msf5 > services
# to check for the stored services
msf5 > vulns
# to check for the stored vulnrabilities
```

2. Run the Nmap from the MSF itself:
``` bash
msf5 > db_nmap -Pn -sV -O 10.4.22.73
```


### Port Scanning with auxiliary modules:
``` bash
msf5 auxiliary(scanner/portscan/tcp) > run
maf5 > curl 192.186.2.1
maf5 > use exploit/unix/webapp/xoda file_upload
meterpreter >  run autoroute -s 192.156.74.2
msf5 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.156.74.2
msf5 auxiliary(scanner/portscan/tcp) > run
``` 

### SCANNER FTP AUXILIARY MODULES

```bash
msf > use auxiliary/scanner/ftp/anonymous
# scan a range of IP addresses searching for FTP servers that allow anonymous access and determines where read or write permissions are allowed.

msf > use auxiliary/scanner/ftp/ftp_login
# scan a range of IP addresses attempting to log in to FTP servers

msf > use auxiliary/scanner/ftp/ftp_version
# scans a range of IP addresses and determines the version of any FTP servers that are running.
```

### Scanner HTTP Auxiliary Modules

```bash
msf > use auxiliary/scanner/http/apache_userdir_enum
# Apache with the UserDir directive enabled generates different error codes when a username exists and there is no public_html directory and when the username does not exist, which could allow remote attackers to determine valid usernames on the server.

msf > use auxiliary/scanner/http/brute_dirs
# identifies the existence of interesting directories by brute forcing the name in a given directory path.

msf > use auxiliary/scanner/http/dir_scanner
#identifies the existence of interesting directories in a given directory path.

msf > use auxiliary/scanner/http/
#identifies directory listing vulnerabilities in a given directory path.

msf > use auxiliary/scanner/http/http_put
#can abuse misconfigured web servers to upload and delete web content via PUT and DELETE HTTP requests. Set ACTION to either PUT or DELETE. PUT is the default. If filename isn't specified, the module will generate a random string for you as a .txt file. If DELETE is used, a filename is required.

msf > use auxiliary/scanner/http/http_header
#shows HTTP Headers returned by the scanned systems.

msf > use auxiliary/scanner/http/files_dir
#takes a wordlist as input and queries a host or range of hosts for the presence of interesting files on the target.

msf > use auxiliary/scanner/http/http_login
#is a brute-force login scanner that attempts to authenticate to a system using HTTP authentication.

msf > use auxiliary/scanner/http/robots_txt
# scans a server or range of servers for the presence and contents of a robots.txt file. 

msf > use auxiliary/scanner/http/http_version
#scan a range of hosts and determine the web server version that is running on them.

msf > use auxiliary/scanner/http/webdav_scanner
#scans a server or range of servers and attempts to determine if WebDav is enabled. This allows us to better fine-tune our attacks.
```

### SCANNER SMB AUXILIARY MODULES

``` bash
msf > use auxiliary/scanner/smb/smb2
# scans the remote hosts and determines if they support the SMB2 protocol.

msf > use auxiliary/scanner/smb/smb_enumshares
# enumerates any SMB shares that are available on a remote system.

msf > use auxiliary/scanner/smb/smb_enumusers
# connect to each system via the SMB RPC service and enumerate the users on the system.

msf > use auxiliary/scanner/smb/smb_login
# attempt to login via SMB across a provided range of IP addresses. If you have a database plugin loaded, successful logins will be stored in it for future reference and usage.

msf > use auxiliary/scanner/smb/smb_version
# connects to each workstation in a given range of hosts and determines the version of the SMB service that is running.
```

### SCANNER MYSQL AUXILIARY MODULES

MySQL utilizes TCP port 3306 by default, however, like any service it can be
hosted on any open TCP port.

``` bash
msf > use auxiliary/scanner/mysql/mysql_login
# is a brute-force login tool for MySQL servers.

msf > use auxiliary/scanner/mysql/mysql_version
# to determine the version of MySQL that is running.

msf6 > use auxiliary/admin/mysql/mysql_enum
# simple enumeration of MySQL Database Server provided proper credentials to connect remotely.

msf6 > use auxiliary/admin/mysql/mysql_sql
#  performs SQL queries on a remote server when provided with a valid set of credentials.

msf6 > use auxiliary/scanner/mysql/mysql_file_enum
#Enumerate files and directories using the MySQL load_file feature, for more information see the URL in the references.

msf6 > use auxiliary/scanner/mysql/mysql_hashdump
# extracts the usernames and encrypted password hashes from a MySQL server and stores them for later cracking.
msf6 > use auxiliary/scanner/mysql/mysql_schemadump
# extracts the schema information from a MySQL DB server.
msf6 > use auxiliary/scanner/mysql/mysql_writable_dirs
Enumerate writeable directories using the MySQL SELECT INTO DUMPFILE feature, for more information see the URL in the references. 
```

**_Note: In the module `mysql_writable_dirs` For every writable directory found, a file with the specified FILE_NAME containing the text test will be written to the directory._**

### SCANNER SSH AUXILIARY MODULES
```bash
msf > use auxiliary/scanner/ssh/ssh_version
# This module is a scanner module, and is capable of testing against multiple hosts.

msf > use auxiliary/scanner/ssh/ssh_login
# versatile in that it can not only test a set of credentials across a range of IP addresses, but it can also perform brute force login attempts. We will pass a file to the module containing usernames and passwords separated by a space as shown below.

msf > use auxiliary/scanner/ssh/ssh_login_pubkey
# Using public key authentication for SSH is highly regarded as being far more secure than using usernames and passwords to authenticate. The caveat to this is that if the private key portion of the key pair is not kept secure, the security of the configuration is thrown right out the window. If, during an engagement, you get access to a private SSH key, you can use the ssh_login_pubkey module to attempt to login across a range of devices.
```

### SCANNER SMTP AUXILIARY MODULES

``` bash
msf > use auxiliary/scanner/smtp/smtp_enum
# connect to a given mail server and use a wordlist to enumerate users that are present on the remote system.

msf > use auxiliary/scanner/smtp/smtp_version
# scan a range of IP addresses and determine the version of any mail servers it encounters.
```

### **i****SMTP**

**iSMTP** is the Kali Linux tool which is used for testing SMTP user enumeration (RCPT TO and VRFY), internal spoofing, and relay.

``` bash
ismtp -h 192.168.1.107:25 -e /root/Desktop/email.txt
# -h <host> The target IP and port (IP:port)

# -e <file> Enable SMTP user enumeration testing and imports email list.
```

From the given image you can see blue color text refer to a valid email account and the red color text refers to an invalid account.