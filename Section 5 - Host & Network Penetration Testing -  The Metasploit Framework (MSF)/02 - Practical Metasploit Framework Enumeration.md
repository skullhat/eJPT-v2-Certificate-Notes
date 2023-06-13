--- 
+ The Metasploit Framework (MSF) is an open-source, robust penetration testing and exploitation framework that is used by penetration testers and security researchers worldwide.
+ It provides penetration testers with a robust infrastructure required to automate every stage of the penetration testing life cycle.
+ It is also used to develop and test exploits and has one of the world’s largest database of public, tested exploits.
+ The Metasploit Framework is designed to be modular, allowing for new functionality to be implemented with ease.
+  The Metasploit Framework (MSF) source code is available on GitHub.
+ Developers are constantly adding new exploits to the framework.

#### History of The Metasploit 
Framework
+ Developed by HD Moore in 2003
+ Originally developed in Perl
+ Rewritten in Ruby in 2007
+ Acquired by Rapid7 in 2009
+ Metasploit 5.0 released in 2019
+ Metasploit 6.0 released in 2020

#### Metasploit Editions
+ Metasploit Pro (Commercial)
+ Metasploit Express (Commercial)
+ Metasploit Framework (Community)

#### Essential Terminology
+ **Interface** – Methods of interacting with the Metasploit Framework.
+ **Module** – Pieces of code that perform a particular task, an example of a module is an exploit.
+ **Vulnerability** – Weakness or flaw in a computer system or network that can be exploited.
+ **Exploit** – Piece of code/module that is used to take advantage a vulnerability within a system, service or application.
+ **Payload** – Piece of code delivered to the target system by an exploit with the objective of executing arbitrary commands or providing remote access to an attacker.
+ **Listener** – A utility that listens for an incoming connection from a target.

## Metasploit Framework Interfaces

### Metasploit Framework Console
+ The Metasploit Framework Console (MSFconsole) is an easy-to-use all in
one interface that provides you with access to all the functionality of the Metasploit Framework.

### Metasploit Framework CLI
The Metasploit Framework Command Line Interface (MSFcli) is a command
line utility that is used to facilitate the creation of automation scripts that
utilize Metasploit modules.

+ It can be used to redirect output from other tools in to msfcli and vice versa.

**Note**: MSFcli was discontinued in 2015, however, the same functionality can
be leveraged through the MSFconsole.

### Metasploit Community Edition
+ Metasploit Community Edition is a web based GUI front-end for the
Metasploit Framework that simplifies network discovery and vulnerability
identification.

### Armitage
+ Armitage is a free Java based GUI front-end for the Metasploit Framework
that simplifies network discovery, exploitation and post exploitation

## MSF Architecture
A **module** in the context of MSF,is a piece of code that can be utilized by the MSF.
-  The MSF **libraries** facilitate theexecution of modules withouthaving to write the code necessary in order to execute them.

![[Pasted image 20230503082825.png]]

### MSF Modules
+ **Exploit** - A module that is used to take advantage of vulnerability and is typically paired with a payload.

+ **Payload** - Code that is delivered by MSF and remotely executed on the target after successful exploitation. An example of a payload is a reverse shell that initiates a connection from the target system back to the attacker.

+ **Encoder** - Used to encode payloads in order to avoid AV detection. For example, shikata_ga_nai is used to encode Windows payloads.

+ **NOPS** - Used to ensure that payloads sizes are consistent and ensure the stability of a payload when executed.

+ **Auxiliary** - A module that is used to perform additional functionality like
port scanning and enumeration.


### MSF Payload Types
When working with exploits, MSF provides you with two types of payloads
that can be paired with an exploit:
1. **Non-Staged Payload** - Payload that is sent to the target system as is along
with the exploit.
1. S**taged Payload** - A staged payload is sent to the target in two parts,
whereby:
- The first part (stager) contains a payload that is used to establish a reverse connection back to the attacker, download the second part of the payload (stage) and execute it.


### Stagers & Stages
1. **Stagers** - Stagers are typically used to establish a stable communication channel between the attacker and target, after which a stage payload is downloaded and executed on the target system.

2. **Stage** - Payload components that are downloaded by the stager.

## Meterpreter Payload
The Meterpreter (Meta-Interpreter) payload is an advanced multi-functional
payload that is executed in memory on the target system making it difficult to
detect.

It communicates over a stager socket and provides an attacker with an
interactive command interpreter on the target system that facilitates the
execution of system commands, file system navigation, keylogging and much
more.

## MSF File System Structure
The MSF file system is organized in a simple and easy to understand format
and is organized into various directories.
![[Pasted image 20230503082934.png]]

### MSF Module Locations
+ MSF stores modules under the following directory on Linux systems: /usr/share/metasploit-framework/modules
+ User specified modules are stored under the following directory on Linux
systems:
~/.ms4/modules

## Penetration Testing With MSF
- The MSF can be used to perform and automate various tasks that fall under
the penetration testing life cycle.
+ In order to understand how we can leverage the MSF for penetration
testing, we need to explore the various phases of a penetration test and
their respective techniques and objectives.
+ We can adopt the PTES (Penetration Testing Execution Standard) as a
roadmap to understanding the various phases that make up a penetration
test and how Metasploit can be integrated in to each phase.

The Penetration Testing Execution Standard (PTES) is a penetration testing
methodology that was developed by a team of information security
practitioners with the aim of addressing the need for a comprehensive and up-
to-date standard for penetration testing.

![[Pasted image 20230503113516.png]]

> **This diagram outlines the various phases involved in a typical penetration test.**


![[Pasted image 20230503113649.png]]


### The Metasploit Framework Database
+ The Metasploit Framework Database (**msfdb**) is an integral part of the
Metasploit Framework and is used to keep track of all your assessments,
host data scans etc.
+ The Metasploit Framework uses **PostgreSQL** as the primary database
server, as a result, we will also need to ensure that the PostgreSQL
database service is running and configured correctly.
+ The Metasploit Framework Database also facilitates the importation and
storage of scan results from various third party tools like Nmap and
Nessus.

## Installation Steps
+ Update our repositories and upgrade our Metasploit Framework to the
latest version.
+ Start and enable the PostgreSQL database service.
+ Initialize the Metasploit Framework Database (msfdb).
+ Launch MSFconsole!