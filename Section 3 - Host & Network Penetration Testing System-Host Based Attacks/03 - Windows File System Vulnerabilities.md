--- 

## Alternate Data Streams (ADS)
- Alternate Data Streams (ADS) is an NTFS (New Technology File System) file attribute and
was designed to provide compatibility with the MacOS HFS (Hierarchical File System).

 - Any file created on an NTFS formatted drive will have two different forks/streams:
 
	1.  **Data stream** - Default stream that contains the data of the file.
	2.  **Resource stream** - Typically contains the metadata of the file.

- Attackers **can use ADS to hide malicious code or executables in legitimate files in order to evade detection.**

- This can be done by storing the malicious code or executables in the file attribute resource stream (metadata) of a legitimate file.
 
 - This technique is usually **used** to evade basic signature based AVs and static scanning tools.

``` powershell
C:\\Temp > type payload.exe > windowslog.txt:winpeas.exe

C:\\ > cd C:\\Windows\Systems32\

C:\\Windows\Systems32\ > mklink excupdate.exe C:\\Tempwindowslog.txt:winpeas.exe
# Creates a directory or file symbolic or hard link.

C:\\Windows\Systems32\ > excupdate
...
```

## [Windows Privilege Escalation Awesome Scripts](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

**WinPEAS is a script that search for possible paths to escalate privileges on Windows hosts. The checks are explained on [book.hacktricks.xyz](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)**

Check also the **Local Windows Privilege Escalation checklist** from **[book.hacktricks.xyz](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation)**

The goal of this project is to search for possible **Privilege Escalation Paths** in Windows environments.

It should take only a **few seconds** to execute almost all the checks and **some seconds/minutes during the lasts checks searching for known filenames** that could contain passwords (the time depened on the number of files in your home folder). By default only **some** filenames that could contain credentials are searched, you can use the **searchall** parameter to search all the list (this could will add some minutes).

