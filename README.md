# EmailAnalyzer
With EmailAnalyzer you can able to analyze your suspicious emails. You can extract headers, links and hashes from the .eml file

## Usage
```
usage: email-analyzer.py [-h] -f FILENAME [-H] [-d] [-l] [-a]

options:
  -h, --help            show this help message and exit
  -f FILENAME, --filename FILENAME
                        Name of file
  -H, --headers         Headers of the eml file
  -d, --digests         Digests of the eml file
  -l, --links           Links from the eml file
  -a, --attachments     Attachments from the eml file
```

## To get Headers
```
python3 email-analyzer.py -f <eml file> --headers
```

```
 _   _                _
| | | | ___  __ _  __| | ___ _ __ ___
| |_| |/ _ \/ _` |/ _` |/ _ \ '__/ __|
|  _  |  __/ (_| | (_| |  __/ |  \__ \
|_| |_|\___|\__,_|\__,_|\___|_|  |___/

_________________________________________________________
Received:
from TEST.TEST.PROD.OUTLOOK.COM (2603:10a6:20b:4f2::13)
 by TEST.TEST.PROD.OUTLOOK.COM with HTTPS; Fri, 25 Nov 2022
 12:36:39 +0000
_________________________________________________________
_________________________________________________________
Content-Type:
multipart/alternative; boundary=335b23d5689bd75ab002f9c46a6e8023c265d60dd923308dcc7eb7a2cf25
_________________________________________________________
_________________________________________________________
Date:
Fri, 25 Nov 2022 12:36:36 +0000 (UTC)
_________________________________________________________
_________________________________________________________
Subject:
How to use EmailAnalyzer
_________________________________________________________
_________________________________________________________
Reply-To:
mymail@example.com
_________________________________________________________
_________________________________________________________
X-Sender-IP:
127.0.0.1
_________________________________________________________

 ___                     _   _             _   _
|_ _|_ ____   _____  ___| |_(_) __ _  __ _| |_(_) ___  _ __
 | || '_ \ \ / / _ \/ __| __| |/ _` |/ _` | __| |/ _ \| '_ \
 | || | | \ V /  __/\__ \ |_| | (_| | (_| | |_| | (_) | | | |
|___|_| |_|\_/ \___||___/\__|_|\__, |\__,_|\__|_|\___/|_| |_|
                               |___/

_________________________________________________________
[X-Sender-IP]
[Virustotal]
https://www.virustotal.com/gui/search/127.0.0.1
[Abuseipdb]
https://www.abuseipdb.com/check/127.0.0.1
_________________________________________________________
```
