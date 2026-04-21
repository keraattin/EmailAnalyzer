#!/usr/bin/env python3

# Libraries
##############################################################################
from email.parser import HeaderParser
from email import message_from_binary_file,message_from_string,policy
from email.header import decode_header,make_header
from email.utils import parseaddr, parsedate_to_datetime
from argparse import ArgumentParser
import sys
import hashlib
import re
import os
import json
import ipaddress
from datetime import datetime, timezone
from banners import (
    get_introduction_banner,get_headers_banner,get_links_banner,
    get_digests_banner,get_attachment_banner,get_investigation_banner,
    get_auth_banner
)
from html_generator import generate_table_from_json
##############################################################################

# Global Values
##############################################################################
# Version
VERSION = "2.0"

# Supported File Types
SUPPORTED_FILE_TYPES = ["eml"]

# Supported Output File Types
SUPPORTED_OUTPUT_TYPES = ["json","html"]

# REGEX
LINK_REGEX           = r'href=["\']([^"\'>\s]+)["\']'
PLAINTEXT_URL_REGEX  = r'https?://\S+'
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
IP_REGEX   = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
AUTH_REGEX = r'\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b'
SPF_REGEX  = r'\b(pass|fail|softfail|neutral|none|temperror|permerror)\b'

# Date Format
DATE_FORMAT = "%B %d, %Y - %H:%M:%S"

# Terminal Column Size
TER_COL_SIZE = 60
##############################################################################

# Functions
##############################################################################
def _is_public_ip(ip_str):
    '''Return True if the IP is a valid, globally routable address'''
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_multicast
    except ValueError:
        return False

def get_headers(mail_data : str, investigation):
    '''Get Headers from mail data'''
    # Get Headers from mail data
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    # Create JSON data
    data = {"Headers": {"Data": {}, "Investigation": {}}}
    # Put Header data to JSON
    for k,v in headers.items():
        decoded = str(make_header(decode_header(v)))
        data["Headers"]["Data"][k.lower()] = decoded.replace('\t', '').replace('\n', '')
    
    # To get all 'Received' headers
    if data["Headers"]["Data"].get('received'):
        received_all = ' '.join(headers.get_all('Received'))
        data["Headers"]["Data"]["received"] = str(make_header(decode_header(received_all))).replace('\t', '').replace('\n', '')

    # If investigation requested
    if investigation:
        # X-Sender-Ip Investigation
        if data["Headers"]["Data"].get("x-sender-ip"):
            data["Headers"]["Investigation"]["X-Sender-Ip"] = {
                "Virustotal":f'https://www.virustotal.com/gui/search/{data["Headers"]["Data"]["x-sender-ip"]}',
                "Abuseipdb":f'https://www.abuseipdb.com/check/{data["Headers"]["Data"]["x-sender-ip"]}'
            }

        # X-Originating-IP Investigation
        if data["Headers"]["Data"].get("x-originating-ip"):
            data["Headers"]["Investigation"]["X-Originating-Ip"] = {
                "Virustotal": f'https://www.virustotal.com/gui/search/{data["Headers"]["Data"]["x-originating-ip"]}',
                "Abuseipdb": f'https://www.abuseipdb.com/check/{data["Headers"]["Data"]["x-originating-ip"]}'
            }

        # Received Header IP Investigation
        if data["Headers"]["Data"].get("received"):
            received_ips = dict.fromkeys(
                ip for ip in re.findall(IP_REGEX, data["Headers"]["Data"]["received"])
                if _is_public_ip(ip)
            )
            if received_ips:
                data["Headers"]["Investigation"]["Received IPs"] = {
                    ip: {
                        "Virustotal": f"https://www.virustotal.com/gui/search/{ip}",
                        "Abuseipdb":  f"https://www.abuseipdb.com/check/{ip}"
                    }
                    for ip in received_ips
                }

        # Reply To - From Investigation (Spoof Check)
        if data["Headers"]["Data"].get("reply-to") and data["Headers"]["Data"].get("from"):
            # Get Reply-To Address
            replyto_matches = re.findall(MAIL_REGEX, data["Headers"]["Data"]["reply-to"])
            mailfrom_matches = re.findall(MAIL_REGEX, data["Headers"]["Data"]["from"])

            if not replyto_matches or not mailfrom_matches:
                data["Headers"]["Investigation"]["Spoof Check"] = {
                    "Reply-To": data["Headers"]["Data"]["reply-to"],
                    "From": data["Headers"]["Data"]["from"],
                    "Conclusion": "Could not parse email address from Reply-To or From header."
                }
            else:
                replyto  = replyto_matches[0]
                mailfrom = mailfrom_matches[0]

                # Check if From & Reply-To is same
                if replyto == mailfrom:
                    conclusion = "Reply Address and From Address is SAME."
                else:
                    conclusion = "Reply Address and From Address is NOT Same. This mail may be SPOOFED."

                # Write data to JSON
                data["Headers"]["Investigation"]["Spoof Check"] = {
                    "Reply-To" : replyto,
                    "From": mailfrom,
                    "Conclusion": conclusion
                }

        # Display Name Check
        if data["Headers"]["Data"].get("from"):
            disp_name, addr = parseaddr(data["Headers"]["Data"]["from"])
            sending_domain = addr.split("@")[-1].lower() if "@" in addr else ""

            if disp_name:
                # Find domain-like tokens (e.g. "paypal.com") inside the display name
                display_domains = re.findall(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b', disp_name)

                if display_domains and all(d.lower() != sending_domain for d in display_domains):
                    conclusion = (
                        f"Display name contains '{', '.join(display_domains)}' "
                        f"which does not match sending domain '{sending_domain}'. "
                        f"Possible impersonation."
                    )
                elif display_domains:
                    conclusion = "Display name is consistent with the sending domain."
                else:
                    conclusion = "No domain detected in display name."

                data["Headers"]["Investigation"]["Display Name Check"] = {
                    "Display Name": disp_name,
                    "Address": addr,
                    "Sending Domain": sending_domain,
                    "Conclusion": conclusion
                }

        # Reply-To Domain Check
        if data["Headers"]["Data"].get("reply-to") and data["Headers"]["Data"].get("from"):
            replyto_matches = re.findall(MAIL_REGEX, data["Headers"]["Data"]["reply-to"])
            mailfrom_matches = re.findall(MAIL_REGEX, data["Headers"]["Data"]["from"])
            if replyto_matches and mailfrom_matches:
                replyto_addr  = replyto_matches[0]
                mailfrom_addr = mailfrom_matches[0]
                replyto_domain  = replyto_addr.split("@")[-1].lower()  if "@" in replyto_addr  else ""
                mailfrom_domain = mailfrom_addr.split("@")[-1].lower() if "@" in mailfrom_addr else ""
                if replyto_domain and mailfrom_domain and replyto_domain != mailfrom_domain:
                    conclusion = (
                        f"Reply-To domain '{replyto_domain}' differs from From domain "
                        f"'{mailfrom_domain}'. Replies will be directed to a different domain."
                    )
                else:
                    conclusion = f"Reply-To domain matches From domain ('{replyto_domain}')."
                data["Headers"]["Investigation"]["Reply-To Domain Check"] = {
                    "Reply-To Address": replyto_addr,
                    "Reply-To Domain": replyto_domain,
                    "From Address": mailfrom_addr,
                    "From Domain": mailfrom_domain,
                    "Conclusion": conclusion
                }

        # Suspicious Headers Check
        suspicious = {}

        if not data["Headers"]["Data"].get("message-id"):
            suspicious["Missing Message-ID"] = (
                "Legitimate mail transfer agents always generate a Message-ID. "
                "Its absence suggests a script-generated or spoofed email."
            )

        if not data["Headers"]["Data"].get("mime-version"):
            suspicious["Missing MIME-Version"] = (
                "MIME-Version header is absent. Expected in all modern emails."
            )

        if data["Headers"]["Data"].get("date"):
            try:
                msg_date = parsedate_to_datetime(data["Headers"]["Data"]["date"])
                now = datetime.now(timezone.utc)
                days_diff = (msg_date - now).total_seconds() / 86400
                if days_diff > 2:
                    suspicious["Future Date"] = (
                        f"Email date is {int(days_diff)} days in the future "
                        f"({data['Headers']['Data']['date']}). Possible timestamp manipulation."
                    )
                elif days_diff < -30:
                    suspicious["Old Date"] = (
                        f"Email date is {int(abs(days_diff))} days in the past "
                        f"({data['Headers']['Data']['date']}). Possible replayed or manipulated message."
                    )
            except Exception:
                suspicious["Unparseable Date"] = (
                    f"Could not parse Date header: {data['Headers']['Data']['date']}"
                )

        SUSPICIOUS_MAILERS = ["phpmailer", "the bat", "libwww-perl"]
        xmailer = data["Headers"]["Data"].get("x-mailer", "").lower()
        if any(tool in xmailer for tool in SUSPICIOUS_MAILERS):
            suspicious["Suspicious X-Mailer"] = (
                f"X-Mailer value '{data['Headers']['Data']['x-mailer']}' is associated "
                f"with bulk or script-based mail sending."
            )

        if suspicious:
            data["Headers"]["Investigation"]["Suspicious Headers"] = suspicious

    return data

def get_auth_results(mail_data : str):
    '''Parse SPF, DKIM, DMARC authentication results from email headers'''
    headers = HeaderParser().parsestr(mail_data, headersonly=True)

    # Create JSON data
    data = {"Authentication": {"Data": {}}}

    # Parse Authentication-Results header(s)
    auth_headers = headers.get_all('Authentication-Results') or []
    combined = ' '.join(auth_headers).lower()
    for protocol, result in re.findall(AUTH_REGEX, combined):
        data["Authentication"]["Data"][protocol.upper()] = result

    # Fall back to Received-SPF for SPF if not found in Authentication-Results
    if "SPF" not in data["Authentication"]["Data"]:
        received_spf = headers.get('Received-SPF') or ''
        spf_match = re.search(SPF_REGEX, received_spf.lower())
        if spf_match:
            data["Authentication"]["Data"]["SPF"] = spf_match.group(1)

    return data

def get_digests(mail_data : str, file_bytes : bytes, investigation):
    '''Get Hash value of mail'''
    file_md5    = hashlib.md5(file_bytes).hexdigest()
    file_sha1   = hashlib.sha1(file_bytes).hexdigest()
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()

    content_md5     = hashlib.md5(mail_data.encode("utf-8")).hexdigest()
    content_sha1    = hashlib.sha1(mail_data.encode("utf-8")).hexdigest()
    content_sha256  = hashlib.sha256(mail_data.encode("utf-8")).hexdigest()

    # Create JSON data
    data = {"Digests": {"Data": {}, "Investigation": {}}}

    # Write Data to JSON
    data["Digests"]["Data"]["File MD5"]         = file_md5
    data["Digests"]["Data"]["File SHA1"]        = file_sha1
    data["Digests"]["Data"]["File SHA256"]      = file_sha256
    data["Digests"]["Data"]["Content MD5"]      = content_md5
    data["Digests"]["Data"]["Content SHA1"]     = content_sha1
    data["Digests"]["Data"]["Content SHA256"]   = content_sha256

    # If investigation requested
    if investigation:
        data["Digests"]["Investigation"]["File MD5"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{file_md5}"
        }
        data["Digests"]["Investigation"]["File SHA1"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{file_sha1}"
        }
        data["Digests"]["Investigation"]["File SHA256"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{file_sha256}"
        }
        data["Digests"]["Investigation"]["Content MD5"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{content_md5}"
        }
        data["Digests"]["Investigation"]["Content SHA1"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{content_sha1}"
        }
        data["Digests"]["Investigation"]["Content SHA256"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{content_sha256}"
        }
    return data

def _defang_url(url):
    '''Defang a URL for safe sharing in reports'''
    url = url.replace("https://", "hxxps://")
    url = url.replace("http://",  "hxxp://")
    # Defang dots in the domain only (between :// and the next /)
    if "://" in url:
        scheme, rest = url.split("://", 1)
        domain, _, path = rest.partition("/")
        domain = domain.replace(".", "[.]")
        url = f"{scheme}://{domain}/{path}" if path else f"{scheme}://{domain}"
    else:
        # No scheme — defang all dots
        url = url.replace(".", "[.]")
    return url

def get_links(mail_data : str, investigation, defang=False):
    '''Get Links from mail data'''

    # Parse the email and extract links from each part by content type
    msg = message_from_string(mail_data, policy=policy.compat32)
    html_links   = []
    plain_links  = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = payload.decode("utf-8", errors="replace")

        if part.get_content_type() == "text/html":
            html_links.extend(re.findall(LINK_REGEX, text))
        elif part.get_content_type() == "text/plain":
            # Strip trailing punctuation that is unlikely to be part of a URL
            plain_links.extend(
                url.rstrip(".,;:!?)]>\"'")
                for url in re.findall(PLAINTEXT_URL_REGEX, text)
            )

    # HTML href links take priority; plain-text URLs fill in anything new
    links = list(dict.fromkeys(html_links + plain_links))
    # Remove Empty Values
    links = list(filter(None, links))

    # Create JSON data
    data = {"Links": {"Data": {}, "Investigation": {}}}

    for index,link in enumerate(links,start=1):
        data["Links"]["Data"][str(index)] = _defang_url(link) if defang else link
    
    # If investigation requested
    if investigation:
        for index,link in enumerate(links,start=1):
            # Remove http/s from link
            if "://" in link:
                link = link.split("://")[-1]
            
            data["Links"]["Investigation"][str(index)] = {
                "Virustotal":f"https://www.virustotal.com/gui/search/{link}",
                "Urlscan":f"https://urlscan.io/search/#{link}"
            }
    return data

def get_attachments(filename : str, investigation):
    ''' Get Attachments from eml file'''
    with open(filename, "rb") as f:
        msg = message_from_binary_file(f, policy=policy.default)
    
    # Create JSON data
    data = {"Attachments": {"Data": {}, "Investigation": {}}}

    # Get Attachments from Mail
    attachments = []
    collected = 0
    for attachment in msg.iter_attachments():
        payload = attachment.get_payload(decode=True)
        if payload is None:
            continue
        collected += 1
        attached_file = {}
        attached_file["filename"]  = attachment.get_filename() or f"unnamed_attachment_{collected}"
        attached_file["mime_type"] = attachment.get_content_type()
        attached_file["MD5"]    = hashlib.md5(payload).hexdigest()
        attached_file["SHA1"]   = hashlib.sha1(payload).hexdigest()
        attached_file["SHA256"] = hashlib.sha256(payload).hexdigest()
        attachments.append(attached_file)

    for index,attachment in enumerate(attachments,start=1):
        data["Attachments"]["Data"][str(index)] = {
            "filename":  attachment["filename"],
            "mime_type": attachment["mime_type"]
        }

    # If investigation requested
    if investigation:
        for index,attachment in enumerate(attachments,start=1):
            data["Attachments"]["Investigation"][attachment["filename"]] = {
                "Virustotal":{
                    "Name Search":f'https://www.virustotal.com/gui/search/{attachment["filename"]}',
                    "MD5":f'https://www.virustotal.com/gui/search/{attachment["MD5"]}',
                    "SHA1":f'https://www.virustotal.com/gui/search/{attachment["SHA1"]}',
                    "SHA256":f'https://www.virustotal.com/gui/search/{attachment["SHA256"]}'
                }
            }

        # Detect duplicate attachments by SHA256
        sha256_map = {}
        for attachment in attachments:
            sha256_map.setdefault(attachment["SHA256"], []).append(attachment["filename"])
        duplicates = {sha: names for sha, names in sha256_map.items() if len(names) > 1}
        if duplicates:
            data["Attachments"]["Investigation"]["Duplicate Warning"] = duplicates

    return data
##############################################################################

# Pretty Print Function
##############################################################################
def print_data(data):
    global TER_COL_SIZE
    try:
        TER_COL_SIZE = os.get_terminal_size().columns
    except OSError:
        pass  # keep default when not in a terminal

    # Inroduction Banner
    get_introduction_banner()

    # Print Headers
    if data["Analysis"].get("Headers"):
        # Print Banner
        get_headers_banner()

        # Print Headers
        for key,val in data["Analysis"]["Headers"]["Data"].items():
            print("_"*TER_COL_SIZE)
            print(f"[{key}]")
            print(val)
            print("_"*TER_COL_SIZE)
        
        # Print Investigation
        if data["Analysis"]["Headers"].get("Investigation"):
            get_investigation_banner() # Print Banner
            for key,val in data["Analysis"]["Headers"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print(f"[{key}]")
                for k,v in val.items():
                    print(f"{k}:\n{v}\n")
                print("_"*TER_COL_SIZE)
    
    # Print Authentication
    if data["Analysis"].get("Authentication"):
        # Print Banner
        get_auth_banner()

        for key,val in data["Analysis"]["Authentication"]["Data"].items():
            print("_"*TER_COL_SIZE)
            print(f"[{key}]")
            print(val)
            print("_"*TER_COL_SIZE)

    # Print Digests
    if data["Analysis"].get("Digests"):
        # Print Banner
        get_digests_banner()

        for key,val in data["Analysis"]["Digests"]["Data"].items():
            print("_"*TER_COL_SIZE)
            print(f"[{key}]")
            print(val)
            print("_"*TER_COL_SIZE)
        
        # Print Investigation
        if data["Analysis"]["Digests"].get("Investigation"):
            get_investigation_banner() # Print Banner
            for key,val in data["Analysis"]["Digests"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print(f"[{key}]")
                for k,v in val.items():
                    print(f"{k}:\n{v}\n")
                print("_"*TER_COL_SIZE)

    # Print Links
    if data["Analysis"].get("Links"):
        # Print Banner
        get_links_banner()

        # Print Links
        for key,val in data["Analysis"]["Links"]["Data"].items():
            print(f"[{key}]->{val}")
        
        # Print Investigation
        if data["Analysis"]["Links"].get("Investigation"):
            get_investigation_banner() # Print Banner
            # Print Links with Investigation tools
            for key,val in data["Analysis"]["Links"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print(f"[{key}]")
                for k,v in val.items():
                    print(f"{k}:\n{v}\n")
                print("_"*TER_COL_SIZE)
    
    # Print Attachments
    if data["Analysis"].get("Attachments"):
        # Print Banner
        get_attachment_banner()

        # Print Attachments
        for key,val in data["Analysis"]["Attachments"]["Data"].items():
            print(f"[{key}] {val['filename']} ({val['mime_type']})")
            print("_"*TER_COL_SIZE)
        
        # Print Investigation
        if data["Analysis"]["Attachments"].get("Investigation"):
            get_investigation_banner() # Print Banner
            for key,val in data["Analysis"]["Attachments"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print(f"- {key}\n")
                if key == "Duplicate Warning":
                    for sha,names in val.items():
                        print(f"[{sha}]")
                        for name in names:
                            print(f"  {name}")
                else:
                    for k,v in val.items():
                        print(f"{k}:")
                        for a,b in v.items():
                            print(f"[{a}]->{b}")
                print("_"*TER_COL_SIZE)
##############################################################################

# Write to File Function
##############################################################################
def write_to_file(filename, data):
    # Get File Format
    file_format = filename.split('.')[-1]
    file_format = file_format.lower()
    
    if file_format == "json":
        with open(filename, 'w', encoding="utf-8") as file:
            json.dump(data, file, indent=4)
    elif file_format == "html":
        with open(filename, 'w', encoding="utf-8") as file:
            html_data = generate_table_from_json(data)
            file.write(html_data)
##############################################################################

# Main
##############################################################################
if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )
    parser.add_argument(
        "-f",
        "--filename",
        type=str,
        help="Name of the EML file",
        required=True
    )
    parser.add_argument(
        "-H",
        "--headers",
        help="To get the Headers of the Email",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-d",
        "--digests",
        help="To get the Digests of the Email",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-l",
        "--links",
        help="To get the Links from the Email",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-a",
        "--attachments",
        help="To get the Attachments from the Email",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-A",
        "--authentication",
        help="To get the Authentication Results of the Email (SPF, DKIM, DMARC)",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-D",
        "--defang",
        help="Defang URLs in Links output (hxxps://, [.] notation)",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-i",
        "--investigate",
        help="Activate if you want an investigation",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Name of the Output file (Only HTML or JSON format supported)",
        required=False
    )
    args = parser.parse_args()

    # Validate output format before doing any work
    if args.output:
        output_format = args.output.split('.')[-1].lower()
        if output_format not in SUPPORTED_OUTPUT_TYPES:
            print(f"{output_format} file format not supported for output. Supported formats: {', '.join(SUPPORTED_OUTPUT_TYPES)}")
            sys.exit(-1)

    # Filename
    if args.filename:
        # Get Filename
        filename = str(args.filename)
        # Get File Format
        file_format = filename.split('.')[-1]
        if file_format not in SUPPORTED_FILE_TYPES:
            print(f"{file_format} file format not supported")
            sys.exit(-1) #Exit with error code

    if not os.path.isfile(filename):
        print(f"File not found: {filename}")
        sys.exit(-1)

    with open(filename,"rb") as file:
        file_bytes = file.read()
    data = file_bytes.decode("utf-8", errors="replace").rstrip()

    # Create JSON data
    app_data = {"Information": {}, "Analysis": {}}
    app_data["Information"]["Project"] = {
        "Name":"EmailAnalyzer",
        "Url":"https://github.com/keraattin/EmailAnalyzer",
        "Version": VERSION,
    }
    app_data["Information"]["Scan"] = {
        "Filename": filename,
        "Generated": str(datetime.now().strftime(DATE_FORMAT))
    }
    
    # List of Arguments
    arg_list = [args.headers, args.digests, args.links, args.attachments, args.authentication]

    # Check if any argument given
    if any(arg_list):
        # Headers
        if args.headers:
            # Get Headers
            headers = get_headers(data, args.investigate)
            app_data["Analysis"].update(headers)

        # Authentication
        if args.authentication:
            authentication = get_auth_results(data)
            app_data["Analysis"].update(authentication)

        # Digests
        if args.digests:
            # Get Digests
            digests = get_digests(data, file_bytes, args.investigate)
            app_data["Analysis"].update(digests)

        # Links
        if args.links:
            # Get & Print Links
            links = get_links(data, args.investigate, defang=args.defang)
            app_data["Analysis"].update(links)

        # Attachments
        if args.attachments:
            # Get Attachments
            attachments = get_attachments(filename, args.investigate)
            app_data["Analysis"].update(attachments)
        
        # If write to file requested
        if args.output:
            output_filename = str(args.output) # Filename
            write_to_file(output_filename, app_data)
            get_introduction_banner()
            print(f"Your data has been written to the {output_filename}")
        else:
            # Print data to Terminal
            print_data(app_data)
            
    else:
        # If no argument given then run all processes
        investigate = True
        # Get Headers
        headers = get_headers(data, investigate)
        app_data["Analysis"].update(headers)

        # Get Authentication Results
        authentication = get_auth_results(data)
        app_data["Analysis"].update(authentication)

        # Get Digests
        digests = get_digests(data, file_bytes, investigate)
        app_data["Analysis"].update(digests)

        # Get & Print Links
        links = get_links(data, investigate, defang=False)
        app_data["Analysis"].update(links)

        # Get Attachments
        attachments = get_attachments(filename, investigate)
        app_data["Analysis"].update(attachments)

        # If write to file requested
        if args.output:
            output_filename = str(args.output) # Filename
            write_to_file(output_filename, app_data)
            get_introduction_banner()
            print(f"Your data has been written to the {output_filename}")
        else:
            # Print data to Terminal
            print_data(app_data)
##############################################################################