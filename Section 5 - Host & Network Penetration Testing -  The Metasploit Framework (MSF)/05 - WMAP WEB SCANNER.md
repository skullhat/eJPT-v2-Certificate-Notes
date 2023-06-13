--- 

+ WMAP is a powerful, feature-rich web application vulnerability scanner that can be used to automate web server enumeration and scan web applications for vulnerabilities.

+ WMAP is available as an MSF plugin and can be loaded directly into MSF.

+ WMAP is fully integrated with MSF, which consequently allows us to perform web app vulnerability scanning from within the MSF
``` bash

msf > load wmap
#  load the wmap plugin

msf > wmap_sites -h
msf > wmap_sites -a http://172.16.194.172

msf > wmap_targets -h
msf > wmap_targets -t http://172.16.194.172/mutillidae/index.php

msf > wmap_run -h
msf > wmap_run -t
# We first use the **-t** switch to list the modules that will be used to scan the remote system.
msf > wmap_run -e
# All that remains now is to actually run the WMAP scan against our target URL.

msf > wmap_vulns -l
msf > vulns

```
Take a few minutes to analyze the results produced by WMAP to identify misconfigurations and vulnerabilities on the web server that can be exploited.