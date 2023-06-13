--- 

## `host` commdand

 host is a simple utility for performing DNS  lookups.  It  is  normally used to convert names to IP addresses and vice versa. When no arguments or options are given, host prints a short summary of  its  command-line arguments and options.
       
``` bash
host google.com                                                 
# Google.com has address 142.251.39.110
# Google.com has IPv6 address 2a00:1450:400e:811::200e
# google.com mail is handled by 10 smtp.google.com.
```

> On Web Information Gathering if there are 2 IPs here is a WAF or Proxy Server there.

## `robots.txt` File

A robots.txt file **tells search engine crawlers which URLs the crawler can access on your site**. This is used mainly to avoid overloading your site with requests; it is not a mechanism for keeping a web page out of Google. To keep a web page out of Google, block indexing with noindex or password-protect the page.

![[Pasted image 20230330095548.png]]

## `XML sitemaps` 

An XML sitemap is **a file that lists a website's essential pages, making sure Google can find and crawl them all**. It also helps search engines understand your website structure. You want Google to crawl every important page of your website.

![[Pasted image 20230330095528.png]]


## `whatweb` command:
WhatWeb identifies websites. It's goal is to answer the question, "What
is  that  Website?". WhatWeb recognises web technologies including con‐
tent management systems (CMS), blogging platforms,  statistic/analytics
packages,  JavaScript  libraries,  web  servers,  and embedded devices.
WhatWeb has over 1800 plugins, each to recognise  something  different.
WhatWeb also identifies version numbers, email addresses, account ID's,
web framework modules, SQL errors, and more.

``` bash
whatweb sustech.edu
# OUTPUT 
http://sustech.edu [302 Found] Country[SUDAN][SD], HTTPServer[nginx/1.22.1], IP[41.67.53.4], RedirectLocation[http://www.sustech.edu/], Strict-Transport-Security[max-age=31536000; includeSubDomains], UncommonHeaders[permissions-policy,x-content-type-options,content-security-policy,referrer-policy,expect-ct], X-Cache[Backend], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block, 1; mode=block], nginx[1.22.1]
http://www.sustech.edu/ [301 Moved Permanently] Country[SUDAN][SD], HTTPServer[nginx/1.22.1], IP[41.67.53.4], RedirectLocation[https://www.sustech.edu/], Strict-Transport-Security[max-age=31536000; includeSubDomains], UncommonHeaders[x-redirect-by,permissions-policy,x-content-type-options,content-security-policy,referrer-policy,expect-ct], X-Cache[Backend], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block, 1; mode=block], nginx[1.22.1]
https://www.sustech.edu/ [200 OK] Bootstrap[4.1.3], Country[SUDAN][SD], DublinCore, Email[contact@sustech.edu], Frame, HTML5, HTTPServer[nginx/1.22.1], IP[41.67.53.4], JQuery[3.6.1], MetaGenerator[Site Kit by Google 1.96.0], Open-Graph-Protocol[article,website], Script[application/ld+json,deferjs], Strict-Transport-Security[max-age=31536000; includeSubDomains, max-age=31536000], Title[Sudan University of Science and Technology - SUST], UncommonHeaders[link,permissions-policy,x-content-type-options,content-security-policy,referrer-policy,expect-ct], WordPress, X-Cache[Backend], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block, 1; mode=block], nginx[1.22.1]
``` 


## [webhttrack](https://www.httrack.com/) tool: 
offline browser to copy websites to a local directory.

``` bash
webhttrack
```

## `whois` command
client for the whois directory service

``` bash
whois elzero.org   
# OUTPUT
Domain Name: elzero.org
Registry Domain ID: 002629ae82554ce98dc4805cee2cae52-LROR
Registrar WHOIS Server: http://whois.godaddy.com
Registrar URL: http://www.whois.godaddy.com
Updated Date: 2022-10-15T22:41:26Z
Creation Date: 2016-05-12T15:23:47Z
Registry Expiry Date: 2024-05-12T15:23:47Z
Registrar: GoDaddy.com, LLC
Registrar IANA ID: 146
Registrar Abuse Contact Email: abuse@godaddy.com
Registrar Abuse Contact Phone: +1.4806242505
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Registry Registrant ID: REDACTED FOR PRIVACY
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: Domains By Proxy, LLC
Registrant Street: REDACTED FOR PRIVACY
Registrant City: REDACTED FOR PRIVACY
Registrant State/Province: Arizona
Registrant Postal Code: REDACTED FOR PRIVACY
Registrant Country: US
Registrant Phone: REDACTED FOR PRIVACY
Registrant Phone Ext: REDACTED FOR PRIVACY
Registrant Fax: REDACTED FOR PRIVACY
Registrant Fax Ext: REDACTED FOR PRIVACY
Registrant Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Registry Admin ID: REDACTED FOR PRIVACY
Admin Name: REDACTED FOR PRIVACY
Admin Organization: REDACTED FOR PRIVACY
Admin Street: REDACTED FOR PRIVACY
Admin City: REDACTED FOR PRIVACY
Admin State/Province: REDACTED FOR PRIVACY
Admin Postal Code: REDACTED FOR PRIVACY
Admin Country: REDACTED FOR PRIVACY
Admin Phone: REDACTED FOR PRIVACY
Admin Phone Ext: REDACTED FOR PRIVACY
Admin Fax: REDACTED FOR PRIVACY
Admin Fax Ext: REDACTED FOR PRIVACY
Admin Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Registry Tech ID: REDACTED FOR PRIVACY
Tech Name: REDACTED FOR PRIVACY
Tech Organization: REDACTED FOR PRIVACY
Tech Street: REDACTED FOR PRIVACY
Tech City: REDACTED FOR PRIVACY
Tech State/Province: REDACTED FOR PRIVACY
Tech Postal Code: REDACTED FOR PRIVACY
Tech Country: REDACTED FOR PRIVACY
Tech Phone: REDACTED FOR PRIVACY
Tech Phone Ext: REDACTED FOR PRIVACY
Tech Fax: REDACTED FOR PRIVACY
Tech Fax Ext: REDACTED FOR PRIVACY
Tech Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Name Server: kyle.ns.cloudflare.com
Name Server: lovisa.ns.cloudflare.com
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2023-03-30T08:19:50Z <<<


```


## [ZoneTransfer.me](https://digi.ninja/projects/zonetransferme.php)

When teaching, and when talking to clients, I sometimes have to explain the security problems related to DNS zone transfer. The problem usually comes when trying to demonstrate how it works and what information can be leaked, trying to remember which domains have zone transfer enabled and then hoping that they still have it turned on can make it hard. So, to ease both of these problems I've registered zonetransfer.me, a domain which is easy to remember and which will always have zone transfer enabled.


## [Netcraft - Internet Data Mining](https://www.netcraft.com/internet-data-mining/)


Using our unique methodologies we've been collecting _internet data_ since 1995, allowing for long term trends to be observed and _analysis_ to be generated.

![[Pasted image 20230330103131.png]]


## [DNSRecon](https://github.com/darkoperator/dnsrecon)

DNSRecon is a Python port of a Ruby script that I wrote to learn the language and about DNS in early 2007. This time I wanted to learn about Python and extend the functionality of the original tool and in the process re-learn how DNS works and how could it be used in the process of a security assessment and network troubleshooting.

``` bash
dnsrecon -d hackersploit.org
# OUTPUT
[*] std: Performing General Enumeration against: hackersploit.org...
[*] DNSSEC is configured for hackersploit.org
[*] DNSKEYs:
[*] 	NSEC KSk ECDSAP256SHA256 99db2cc14cabdc33d6d77da63a2f15f7 1112584f234e8d1dc428e39e8a4a97e1 aa271a555dc90701e17e2a4c4b6f120b 7c32d44f4ac02bd894cf2d4be7778a19
[*] 	NSEC ZSK ECDSAP256SHA256 a09311112cf9138818cd2feae970ebbd 4d6a30f6088c25b325a39abbc5cd1197 aa098283e5aaf421177c2aa5d714992a 9957d1bcc18f98cd71f1f1806b65e148
[*] 	 SOA dee.ns.cloudflare.com 108.162.192.93
[*] 	 SOA dee.ns.cloudflare.com 173.245.58.93
[*] 	 SOA dee.ns.cloudflare.com 172.64.32.93
[*] 	 SOA dee.ns.cloudflare.com 2803:f800:50::6ca2:c05d
[*] 	 SOA dee.ns.cloudflare.com 2606:4700:50::adf5:3a5d
[*] 	 SOA dee.ns.cloudflare.com 2a06:98c1:50::ac40:205d
[*] 	 NS dee.ns.cloudflare.com 172.64.32.93
[*] 	 Bind Version for 172.64.32.93 "2023.3.4"
[*] 	 NS dee.ns.cloudflare.com 173.245.58.93
[*] 	 Bind Version for 173.245.58.93 "2023.3.4"
[*] 	 NS dee.ns.cloudflare.com 108.162.192.93
[*] 	 Bind Version for 108.162.192.93 "2023.3.4"
[*] 	 NS dee.ns.cloudflare.com 2a06:98c1:50::ac40:205d
[*] 	 NS dee.ns.cloudflare.com 2606:4700:50::adf5:3a5d
[*] 	 NS dee.ns.cloudflare.com 2803:f800:50::6ca2:c05d
[*] 	 NS jim.ns.cloudflare.com 172.64.33.125
[*] 	 Bind Version for 172.64.33.125 "2023.3.4"
[*] 	 NS jim.ns.cloudflare.com 173.245.59.125
[*] 	 Bind Version for 173.245.59.125 "2023.3.4"
[*] 	 NS jim.ns.cloudflare.com 108.162.193.125
[*] 	 Bind Version for 108.162.193.125 "2023.3.4"
[*] 	 NS jim.ns.cloudflare.com 2803:f800:50::6ca2:c17d
[*] 	 NS jim.ns.cloudflare.com 2606:4700:58::adf5:3b7d
[*] 	 NS jim.ns.cloudflare.com 2a06:98c1:50::ac40:217d
[*] 	 MX _dc-mx.2c2a3526b376.hackersploit.org 198.54.120.212
[*] 	 A hackersploit.org 188.114.97.7
[*] 	 A hackersploit.org 188.114.96.7
[*] 	 TXT hackersploit.org google-site-verification=TW0pQsFZ0xx3w4b7kysBV0UrcMq7fJFB-5Rz9h6GwkU
[*] 	 TXT hackersploit.org v=spf1 a:my.hackersploit.org ~all
[*] Enumerating SRV Records
[+] 0 Records Found
```


## [DNSdumpster](https://dnsdumpster.com/)

is a FREE domain research tool that can discover hosts related to a domain. Finding visible hosts from the attackers perspective is an important part of the security assessment process.

![[Pasted image 20230330104430.png]]


## [WAFW00F](https://github.com/EnableSecurity/wafw00f)
 is a Python tool to help you fingerprint and identify Web Application Firewall (WAF) products. It is an active reconnaissance tool as it actually connects to the web server, but it starts out with a normal HTTP response and escalates as necessary.

![[Pasted image 20230330110147.png]]


``` bash
wafw00f google.com
```

## Google Hacking Database ([GHDB](https://www.exploit-db.com/google-hacking-database))
The  is an index of search queries (we call them dorks) used to find publicly available information, intended for pentesters and security researchers.

## [theHarvester](https://github.com/laramies/theHarvester) to gather emails

is a simple to use, yet powerful tool designed to be used during the reconnaissance stage of a red  team assessment or penetration test. It performs open source intelligence (OSINT) gathering to help determine  
a domain's external threat landscape. The tool gathers names, emails, IPs, subdomains, and URLs by using multiple public resources.

```
*******************************************************************
*  _   _                                            _             *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 4.2.0                                              *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
* cmartorella@edge-security.com                                   *
*                                                                 *
*******************************************************************
```


## [Have i been pwned ?](https://haveibeenpwned.com/) 

- _Have I Been Pwned_ allows you to search across multiple data breaches to see if your email address or phone number has been compromised.
- Used to check for [[07 - Password Spraying Attack]]

![[Pasted image 20230331094133.png]]



