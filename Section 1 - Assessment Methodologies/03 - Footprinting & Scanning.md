--- 

# Mapping a Network

## Purpose
+ Scope
+ Discovery

![[Pasted image 20230402204920.png]]

## Process

### Physical Access
+ Physical Security
+ OSINT
+ Social Engineering

### Sniffing
**A sniffing attack occurs when an attacker uses a packet sniffer to intercept and read sensitive data passing through a network**
+ Passive Reconnaissance
+ Watch network traffic

### ARP
- Stands for: Address Resolution Protocol
+ Resolve IP to MAC
> Who has 10.10.1.5? Tell 10.10.1.7
   10.10.1.5 is at 00:0c:29:af:ea:d2 
   ARP Table

### ICMP

+ Stands for: Internet Control Message Protocol
+ Traceroute
+ Ping
![[Pasted image 20230402205324.png]]

## Tools

## [arp-scan](https://github.com/royhills/arp-scan)
_arp-scan_ is a network scanning tool that uses the ARP protocol to discover and fingerprint IPv4 hosts on the local network.

``` bash
sudo arp-scan -I eth0 -g 10.142.111.0/24
```


## [fping](https://github.com/schweikert/fping)
fping is a program to send ICMP echo probes to network hosts, similar to ping, but much better performing when pinging multiple hosts.

``` bash
fping -I eth0 -g 10.142.111.0/24 -a 2>/dev/null
```


## nmap
``` bash
nmap -sn 10.142.111.0/24
nmap -iL ips
nmap 178.25.36.1 -137 -UVC --script=discovery
```


## Zenmap
Zenmap is the official Nmap Security Scanner GUI. It is a multi-platform (Linux, Windows, Mac OS X, BSD, etc.) free and open source application which aims to make Nmap easy for beginners to use while providing advanced features for experienced Nmap users. Frequently used scans can be saved as profiles to make them easy to run repeatedly. A command creator allows interactive creation of Nmap command lines. Scan results can be saved and viewed later. Saved scan results can be compared with one another to see how they differ. The results of recent scans are stored in a searchable database.

![[Pasted image 20230402204512.png]]


## Steps for Footprinting using nmap:

1. Check for hosts `sn`.
2. Check for open ports in the hosts you've found.
3. If you can't find any of this in TCP, try using UDP port scanning `-sU`.
4. Check for `-sV` versions of services and the `-O` operating systems that are running, if you can't find a thing use `--script=discovery` for more search and use aggressive ,mode `-A`. 

