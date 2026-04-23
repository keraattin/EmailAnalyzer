![Python](https://img.shields.io/badge/python-3.10-blue.svg) 
![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)
# EmailAnalyzer
With EmailAnalyzer you can able to analyze your suspicious emails. You can extract headers, links and hashes from the .eml file

## Usage
```
usage: email-analyzer.py [-h] [--version] -f FILENAME [-H] [-d] [-l] [-a] [-A] [-D] [-i] [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  --version             Show program version and exit
  -f, --filename FILENAME
                        Name of the EML file
  -H, --headers         To get the Headers of the Email
  -d, --digests         To get the Digests of the Email
  -l, --links           To get the Links from the Email
  -a, --attachments     To get the Attachments from the Email
  -A, --authentication  To get the Authentication Results of the Email (SPF, DKIM, DMARC)
  -D, --defang          Defang URLs in Links output (hxxps://, [.] notation)
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

<img width="1349" height="657" alt="image" src="https://github.com/user-attachments/assets/c95aa923-e7cf-423d-8041-3c69a54fe2e8" />

or 
```
python3 email-analyzer.py -f <eml file> -o report.json
```

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

> RFC 2047 encoded headers (e.g. `=?UTF-8?B?...?=`) are automatically decoded and displayed as readable text.

## To Investigate Headers
```
python3 email-analyzer.py -f <eml file> --headers --investigate
```
or
```
python3 email-analyzer.py -f <eml file> -Hi
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

> Investigation also extracts public IP addresses from `Received` headers and generates VirusTotal and AbuseIPDB lookup links for each one.

### Investigation Checks

The `-i` / `--investigate` flag enables all of the following checks when used with `-H`:

| Check | What it detects |
|---|---|
| **X-Sender-IP** | Generates VirusTotal and AbuseIPDB lookup links for the sending IP |
| **X-Originating-IP** | Same lookup links for the `X-Originating-IP` header when present |
| **Received IPs** | Extracts all public IPs from `Received` headers and generates lookup links |
| **Spoof Check** | Flags when `Reply-To` and `From` addresses differ |
| **Display Name Check** | Flags when the `From` display name contains a domain that doesn't match the sending domain (e.g. display name `"paypal.com"` sent from `attacker@gmail.com`) |
| **Reply-To Domain Check** | Flags when the `Reply-To` domain differs from the `From` domain — replies would be redirected to a different domain |
| **Suspicious Headers** | Flags missing `Message-ID`, missing `MIME-Version`, dates far in the future or past (>2 days / >30 days), and known bulk-sender `X-Mailer` values (PHPMailer, The Bat, libwww-perl) |

## To get Authentication Results
```
python3 email-analyzer.py -f <eml file> --authentication
```
or
```
python3 email-analyzer.py -f <eml file> -A
```

Parses `Authentication-Results` and `Received-SPF` headers to extract SPF, DKIM, and DMARC verdicts.

```
 █████╗ ██╗   ██╗████████╗██╗  ██╗███████╗███╗   ██╗████████╗██╗ ██████╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
███████║██║   ██║   ██║   ███████║█████╗  ██╔██╗ ██║   ██║   ██║██║     ███████║   ██║   ██║██║   ██║██╔██╗ ██║
██╔══██║██║   ██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║   ██║   ██║██║     ██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
██║  ██║╚██████╔╝   ██║   ██║  ██║███████╗██║ ╚████║   ██║   ██║╚██████╗██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

_________________________________________________________
[SPF]
pass
_________________________________________________________
_________________________________________________________
[DKIM]
pass
_________________________________________________________
_________________________________________________________
[DMARC]
pass
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

> Links are extracted from both HTML (`href` attributes) and plain-text parts of the email. Bare URLs in plain-text bodies (e.g. `https://example.com`) are also captured and deduplicated.

## To get Defanged Links
Add `-D` / `--defang` to convert URLs to defanged format (`hxxps://`, `[.]` for domain dots). Safe to share in reports without creating clickable links.
```
python3 email-analyzer.py -f <eml file> --links --defang
```
or
```
python3 email-analyzer.py -f <eml file> -lD
```

```
[1]->hxxps://example[.]com
[2]->hxxps://testlinks[.]com/campaing/123124
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

[1] example.pdf (application/pdf)
_________________________________________________________
[2] malicious.pdf (application/octet-stream)
_________________________________________________________
```

> The MIME type is shown alongside the filename, allowing you to detect files whose extension does not match their actual content type (e.g. a `.pdf` with MIME type `application/octet-stream`).

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
_________________________________________________________
- Duplicate Warning

[03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4]
  example.pdf
  malicious.pdf
_________________________________________________________
```

> When two or more attachments share the same SHA256 hash, a **Duplicate Warning** is added to the investigation output listing the shared hash and the filenames involved.

## HTML Report
Generate a self-contained HTML report with Bootstrap 5 styling:
```
python3 email-analyzer.py -f <eml file> -o report.html
```

The HTML report includes:
- **Threat Summary** — email overview (From, To, Subject, Date, link/attachment counts), threat level badge (LOW / MEDIUM / HIGH), and Bootstrap alert cards for each triggered investigation check
- **Sticky navbar** — always visible while scrolling, with jump links to each section
- **Copy-to-clipboard buttons** — next to every hash value and URL for quick threat-intel lookups
- **Clickable investigation links** — all VirusTotal, AbuseIPDB, and URLscan entries are rendered as anchor tags
- **Merged tables** — Links, Attachments, and Digests each show data and scan links in a single unified table

## To Check Version
```
python3 email-analyzer.py --version
```

## Testing

The test suite uses [pytest](https://pytest.org). Install it before running tests:
```
pip install pytest
```

Run all tests from the project root:
```
python3 -m pytest tests/ -v
```

Run a specific test file:
```
python3 -m pytest tests/test_headers.py -v
python3 -m pytest tests/test_links.py -v
python3 -m pytest tests/test_digests.py -v
python3 -m pytest tests/test_attachments.py -v
python3 -m pytest tests/test_auth_results.py -v
python3 -m pytest tests/test_defang.py -v
python3 -m pytest tests/test_duplicate_attachments.py -v
python3 -m pytest tests/test_cli.py -v
```

### Test Structure
```
tests/
├── fixtures/                        # Sample .eml files used by tests
│   ├── basic.eml
│   ├── spoofed.eml
│   ├── not_spoofed.eml
│   ├── display_name_only.eml
│   ├── quoted_printable.eml
│   ├── no_links.eml
│   ├── binary_attachment.eml
│   ├── multi_attachment.eml
│   ├── image_attachment.eml
│   ├── no_attachment.eml
│   ├── no_filename_attachment.eml
│   ├── multipart_alternative.eml
│   ├── duplicate_attachments.eml
│   ├── rfc2047_encoded.eml
│   ├── rfc2047_qp_encoded.eml
│   ├── rfc2047_mixed.eml
│   ├── received_public_ips.eml
│   ├── received_mixed_ips.eml
│   ├── auth_pass_all.eml
│   ├── auth_fail_spf_dkim.eml
│   ├── auth_softfail_spf.eml
│   ├── auth_received_spf_only.eml
│   ├── auth_no_headers.eml
│   ├── phishing_displayname.eml
│   ├── legitimate_displayname.eml
│   ├── suspicious_no_message_id.eml
│   ├── suspicious_future_date.eml
│   ├── suspicious_old_date.eml
│   ├── suspicious_xmailer.eml
│   ├── clean_headers.eml
│   ├── originating_ip.eml
│   ├── replyto_diff_domain.eml
│   └── replyto_same_domain.eml
├── conftest.py                      # Shared fixtures and module loader
├── test_headers.py                  # Tests for get_headers()
├── test_links.py                    # Tests for get_links()
├── test_digests.py                  # Tests for get_digests()
├── test_attachments.py              # Tests for get_attachments()
├── test_attachment_mime.py          # Tests for MIME type in attachment output
├── test_duplicate_attachments.py    # Tests for duplicate attachment detection
├── test_rfc2047.py                  # Tests for RFC 2047 encoded header decoding
├── test_received_ips.py             # Tests for Received header IP extraction
├── test_auth_results.py             # Tests for SPF/DKIM/DMARC parsing
├── test_defang.py                   # Tests for defanged URL output
├── test_plaintext_links.py          # Tests for plain-text URL extraction
├── test_display_name.py             # Tests for display name spoofing detection
├── test_suspicious_headers.py       # Tests for suspicious header pattern detection
├── test_originating_ip.py           # Tests for X-Originating-IP investigation
├── test_replyto_domain.py           # Tests for Reply-To domain check
├── test_html_generator.py           # Tests for HTML report generation and XSS escaping
├── test_cli.py                      # Tests for CLI argument validation
└── test_encoding.py                 # Tests for non-UTF-8 email encoding handling
```
