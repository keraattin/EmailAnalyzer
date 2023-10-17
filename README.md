![Python](https://img.shields.io/badge/python-3.10-blue.svg) 
![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)
# EmailAnalyzer
With EmailAnalyzer you can able to analyze your suspicious emails. You can extract headers, links and hashes from the .eml file

## Usage
```
usage: email-analyzer.py [-h] -f FILENAME [-H] [-d] [-l] [-a] [-i] [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -f FILENAME, --filename FILENAME
                        Name of the EML file
  -H, --headers         To get the Headers of the Email
  -d, --digests         To get the Digests of the Email
  -l, --links           To get the Links from the Email
  -a, --attachments     To get the Attachments from the Email
  -i, --investigate     Activate if you want an investigation
  -o OUTPUT, --output OUTPUT
                        Name of the Output file (Only HTML or JSON format supported)
```

## Run All
This command will get you Headers, Links, Attachments, and Digests with Investigations:
```
python3 email-analyzer.py -f <eml file> 
```

## Extract Outputs
If you want to extract the outputs to a file you can use this commands:
```
python3 email-analyzer.py -f <eml file> -o report.html
```
Check the ![Wiki Page](https://github.com/keraattin/EmailAnalyzer/wiki/Generate-an-HTML-Report) for details
![image](https://github.com/keraattin/EmailAnalyzer/assets/6709252/b449246e-881c-4d2d-822b-71c4d4a21ca1)
or 
```
python3 email-analyzer.py -f <eml file> -o report.json
```
Check the ![Wiki Page](https://github.com/keraattin/EmailAnalyzer/wiki/Generate-a-JSON-Report) for details

> Only supported **JSON** and **HTML** formats currently.

## To get ONLY Headers
```
python3 email-analyzer.py -f <eml file> --headers
```
or
```
python3 email-analyzer.py -f <eml file> -H
```

```
██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝

_________________________________________________________
[received]
from TEST.TEST.PROD.OUTLOOK.COM (2603:10a6:20b:4f2::13)
 by TEST.TEST.PROD.OUTLOOK.COM with HTTPS; Fri, 25 Nov 2022
 12:36:39 +0000
_________________________________________________________
_________________________________________________________
[content-type]
multipart/alternative; boundary=335b23d5689bd75ab002f9c46a6e8023c265d60dd923308dcc7eb7a2cf25
_________________________________________________________
_________________________________________________________
[date]
Fri, 25 Nov 2022 12:36:36 +0000 (UTC)
_________________________________________________________
_________________________________________________________
[subject]
How to use EmailAnalyzer
_________________________________________________________
_________________________________________________________
[reply-to]
info123@gmail.com
_________________________________________________________
_________________________________________________________
[from]
"Admin"<info@officialmail.com>
_________________________________________________________
_________________________________________________________
[to]
me
_________________________________________________________
_________________________________________________________
[x-sender-ip]
127.0.0.1
_________________________________________________________
```

## To Investigate Headers
```
python3 mail-analyzer.py -f <eml file> --headers --investigate
```
or
```
python3 mail-analyzer.py -f <eml file> -Hi
```

```
 █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗██╗███████╗
██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝
███████║██╔██╗ ██║███████║██║   ╚████╔╝ ███████╗██║███████╗
██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ╚════██║██║╚════██║
██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████║██║███████║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝

_________________________________________________________
[X-Sender-IP]
Virustotal:
https://www.virustotal.com/gui/search/127.0.0.1

Abuseipdb:
https://www.abuseipdb.com/check/127.0.0.1
_________________________________________________________

_________________________________________________________
[Spoof Check]
Reply-To:
info123@gmail.com

From:
info@officialmail.com

Conclusion:
Reply Address and From Address is NOT Same. This mail may be SPOOFED.
_________________________________________________________
```

## To get Hash of eml file & content
```
python3 email-analyzer.py -f <eml file> --digests
```
or
```
python3 email-analyzer.py -f <eml file> -d
```

```
██████╗ ██╗ ██████╗ ███████╗███████╗████████╗███████╗
██╔══██╗██║██╔════╝ ██╔════╝██╔════╝╚══██╔══╝██╔════╝
██║  ██║██║██║  ███╗█████╗  ███████╗   ██║   ███████╗
██║  ██║██║██║   ██║██╔══╝  ╚════██║   ██║   ╚════██║
██████╔╝██║╚██████╔╝███████╗███████║   ██║   ███████║
╚═════╝ ╚═╝ ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚══════╝

_________________________________________________________
[File MD5]
81dc9bdb52d04dc20036dbd8313ed055
_________________________________________________________
_________________________________________________________
[File SHA1]
7110eda4d09e062aa5e4a390b0a572ac0d2c0220
_________________________________________________________
_________________________________________________________
[File SHA256]
03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
_________________________________________________________
_________________________________________________________
[Content MD5]
827ccb0eea8a706c4c34a16891f84e7b
_________________________________________________________
_________________________________________________________
[Content SHA1]
8cb2237d0679ca88db6464eac60da96345513964
_________________________________________________________
_________________________________________________________
[Content SHA256]
5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5
_________________________________________________________
```

## To Investigate Digests
```
python3 email-analyzer.py -f <eml file> --digests --investigate
```
or
```
python3 email-analyzer.py -f <eml file> -di
```

```
 █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗██╗███████╗
██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝
███████║██╔██╗ ██║███████║██║   ╚████╔╝ ███████╗██║███████╗
██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ╚════██║██║╚════██║
██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████║██║███████║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝

_________________________________________________________
[File MD5]
Virustotal:
https://www.virustotal.com/gui/search/81dc9bdb52d04dc20036dbd8313ed055
_________________________________________________________

_________________________________________________________
[File SHA1]
Virustotal:
https://www.virustotal.com/gui/search/7110eda4d09e062aa5e4a390b0a572ac0d2c0220
_________________________________________________________

_________________________________________________________
[File SHA256]
Virustotal:
https://www.virustotal.com/gui/search/03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
_________________________________________________________

_________________________________________________________
[Content MD5]
Virustotal:
https://www.virustotal.com/gui/search/827ccb0eea8a706c4c34a16891f84e7b
_________________________________________________________

_________________________________________________________
[Content SHA1]
Virustotal:
https://www.virustotal.com/gui/search/8cb2237d0679ca88db6464eac60da96345513964
_________________________________________________________

_________________________________________________________
[Content SHA256]
Virustotal:
https://www.virustotal.com/gui/search/5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5
_________________________________________________________

```

## To get Links from eml file

```
python3 email-analyzer.py -f <eml file> --links
```
or
```
python3 email-analyzer.py -f <eml file> -l
```

```
██╗     ██╗███╗   ██╗██╗  ██╗███████╗
██║     ██║████╗  ██║██║ ██╔╝██╔════╝
██║     ██║██╔██╗ ██║█████╔╝ ███████╗
██║     ██║██║╚██╗██║██╔═██╗ ╚════██║
███████╗██║██║ ╚████║██║  ██╗███████║
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝


[1]->https://example.com
[2]->https://testlinks.com/campaing/123124
```

## To Investigate Links
```
python3 email-analyzer.py -f <eml file> --links --investigate
```
or
```
python3 email-analyzer.py -f <eml file> --li
```

```
 █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗██╗███████╗
██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝
███████║██╔██╗ ██║███████║██║   ╚████╔╝ ███████╗██║███████╗
██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ╚════██║██║╚════██║
██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████║██║███████║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝

_________________________________________________________
[1]
VirusTotal:
https://www.virustotal.com/gui/search/example.com

UrlScan:
https://urlscan.io/search/#example.com
_________________________________________________________

_________________________________________________________
[2]
VirusTotal:
https://www.virustotal.com/gui/search/testlinks.com/campaing/123124

UrlScan:
https://urlscan.io/search/#testlinks.com/campaing/123124
_________________________________________________________
```

## To get Attachments from eml file
```
python3 email-analyzer.py -f <eml file> --attachments
```
or
```
python3 email-analyzer.py -f <eml file> -a
```

```
 █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗███████╗
██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║  ██║██╔════╝
███████║   ██║      ██║   ███████║██║     ███████║███████╗
██╔══██║   ██║      ██║   ██╔══██║██║     ██╔══██║╚════██║
██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██║███████║
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝

[1]->example.pdf
_________________________________________________________
[2]->malicious.pdf
_________________________________________________________
```

## To Investigate Attachments
```
python3 email-analyzer.py -f <eml file> --attachments --investigate
```
or
```
python3 email-analyzer.py -f <eml file> -ai
```

```
 █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗██╗███████╗
██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝
███████║██╔██╗ ██║███████║██║   ╚████╔╝ ███████╗██║███████╗
██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ╚════██║██║╚════██║
██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████║██║███████║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝

_________________________________________________________
- example.pdf

Virustotal:
[Name Search]->https://www.virustotal.com/gui/search/example.pdf
[MD5]->https://www.virustotal.com/gui/search/81dc9bdb52d04dc20036dbd8313ed055
[SHA1]->https://www.virustotal.com/gui/search/7110eda4d09e062aa5e4a390b0a572ac0d2c0220
[SHA256]->https://www.virustotal.com/gui/search/03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
_________________________________________________________
_________________________________________________________
- malicious.pdf

Virustotal:
[Name Search]->https://www.virustotal.com/gui/search/malicious.pdf
[MD5]->https://www.virustotal.com/gui/search/827ccb0eea8a706c4c34a16891f84e7b
[SHA1]->https://www.virustotal.com/gui/search/8cb2237d0679ca88db6464eac60da96345513964
[SHA256]->https://www.virustotal.com/gui/search/5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5
_________________________________________________________
```
