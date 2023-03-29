#!/usr/bin/env python3

# Libraries
##############################################################################
from email.parser import HeaderParser
from email import message_from_file,policy
from argparse import ArgumentParser
import sys
import hashlib
import re
import quopri
import os
import json
from datetime import datetime
from pprint import pprint
from banners import *
##############################################################################

# Global Values
##############################################################################
# Supported File Types
SUPPORTED_FILE_TYPES = ["eml"]

# REGEX
LINK_REGEX = r'href=\"((?:\S)*)\"'
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

# Terminal Column Size
TER_COL_SIZE = 60
##############################################################################

# Functions
##############################################################################
def get_headers(mail_data : str, investigation):
    '''Get Headers from mail data'''
    # Get Headers from mail data
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    # Create JSON data
    data = json.loads('{"Headers":{"Data":{},"Investigation":{}}}')
    # Put Header data to JSON
    for k,v in headers.items():
        data["Headers"]["Data"][k.lower()] = v.replace('\t', '').replace('\n', '')
    
    # If investigation requested
    if investigation:
        # X-Sender-Ip Investigation
        if data["Headers"]["Data"].get("x-sender-ip"):
            data["Headers"]["Investigation"]["X-Sender-Ip"] = {
                "Virustotal":"https://www.virustotal.com/gui/search/{}".format(
                    data["Headers"]["Data"]["x-sender-ip"]
                ),
                "Abuseipdb":"https://www.abuseipdb.com/check/{}".format(
                    data["Headers"]["Data"]["x-sender-ip"]
                )
            }
        
        # Reply To - From Investigation (Spoof Check)
        if data["Headers"]["Data"].get("reply-to") and data["Headers"]["Data"].get("from"):
            # Get Reply-To Address
            replyto = re.findall(
                    MAIL_REGEX,data["Headers"]["Data"]["reply-to"]
            )[0]
            
            # Get From Address
            mailfrom = re.findall(
                    MAIL_REGEX,data["Headers"]["Data"]["from"]
            )[0]
            
            # Check if From & Reply-To is same
            if replyto == mailfrom:
                conclusion = "Reply Address and From Address is SAME."
            else:
                conclusion = "Reply Address and From Address is NOT Same. This mail may be SPOOFED."
            
            # Write data to JSON
            data["Headers"]["Investigation"]["Spoof Check"] = {
                "Reply-To" : replyto,
                "From": mailfrom,
                "Conclusion":conclusion
            }

    return data


def get_digests(mail_data : str, filename : str, investigation):
    '''Get Hash value of mail'''
    with open(filename, 'rb') as f:
        file        = f.read()
        file_md5    = hashlib.md5(file).hexdigest()
        file_sha1   = hashlib.sha1(file).hexdigest()
        file_sha256 = hashlib.sha256(file).hexdigest()

    content_md5     = hashlib.md5(mail_data.encode("utf-8")).hexdigest()
    content_sha1    = hashlib.sha1(mail_data.encode("utf-8")).hexdigest()
    content_sha256  = hashlib.sha256(mail_data.encode("utf-8")).hexdigest()

    # Create JSON data
    data = json.loads('{"Digests":{"Data":{},"Investigation":{}}}')

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
            "Virustotal":"https://www.virustotal.com/gui/search/{}".format(file_md5)
        }
        data["Digests"]["Investigation"]["File SHA1"] = {
            "Virustotal":"https://www.virustotal.com/gui/search/{}".format(file_sha1)
        }
        data["Digests"]["Investigation"]["File SHA256"] = {
            "Virustotal":"https://www.virustotal.com/gui/search/{}".format(file_sha256)
        }
        data["Digests"]["Investigation"]["Content MD5"] = {
            "Virustotal":"https://www.virustotal.com/gui/search/{}".format(content_md5)
        }
        data["Digests"]["Investigation"]["Content SHA1"] = {
            "Virustotal":"https://www.virustotal.com/gui/search/{}".format(content_sha1)
        }
        data["Digests"]["Investigation"]["Content SHA256"] = {
            "Virustotal":"https://www.virustotal.com/gui/search/{}".format(content_sha256)
        }
    return data

def get_links(mail_data : str, investigation):
    '''Get Links from mail data'''
    get_links_banner() # Print Banner

    # If content of eml file is Encoded -> Decode
    if "Content-Transfer-Encoding" in mail_data:
        mail_data = str(quopri.decodestring(mail_data)) # Decode

    # Find the Links    
    links = re.findall(LINK_REGEX, mail_data)

    # Remove Duplicates
    links = list(dict.fromkeys(links))
    # Remove Empty Values
    links = list(filter(None, links))

    # Create JSON data
    data = json.loads('{"Links":{"Data":{},"Investigation":{}}}')

    for index,link in enumerate(links,start=1):
        data["Links"]["Data"][str(index)] = link
    
    # If investigation requested
    if investigation:
        for index,link in enumerate(links,start=1):
            # Remove http/s from link
            if "://" in link:
                link = link.split("://")[-1]
            
            data["Links"]["Investigation"][str(index)] = {
                "Virustotal":"https://www.virustotal.com/gui/search/{}".format(link),
                "Urlscan":"https://urlscan.io/search/#{}".format(link)
            }
    return data

def get_attachments(filename : str, investigation):
    ''' Get Attachments from eml file'''
    with open(filename, "r") as f:
        msg = message_from_file(f, policy=policy.default)
    
    # Create JSON data
    data = json.loads('{"Attachments":{"Data":{},"Investigation":{}}}')

    # Get Attachments from Mail
    attachments = []
    for attachment in msg.iter_attachments():
        attached_file = {}
        attached_file["filename"] = attachment.get_filename()
        attached_file["MD5"] = hashlib.md5(attachment.get_payload(decode=True)).hexdigest()
        attached_file["SHA1"] = hashlib.sha1(attachment.get_payload(decode=True)).hexdigest()
        attached_file["SHA256"]=hashlib.sha256(attachment.get_payload(decode=True)).hexdigest()
        attachments.append(attached_file)

    for index,attachment in enumerate(attachments,start=1):
        data["Attachments"]["Data"][str(index)] = attachment["filename"]

    # If investigation requested
    if investigation:
        for index,attachment in enumerate(attachments,start=1):
            data["Attachments"]["Investigation"][attachment["filename"]] ={
                "Virustotal":{
                    "Name Search":"https://www.virustotal.com/gui/search/{}".format(attachment["filename"]),
                    "MD5":"https://www.virustotal.com/gui/search/{}".format(attachment["MD5"]),
                    "SHA1":"https://www.virustotal.com/gui/search/{}".format(attachment["SHA1"]),
                    "SHA256":"https://www.virustotal.com/gui/search/{}".format(attachment["SHA256"])
                }
            }

    return data
##############################################################################
        
# Main
##############################################################################
description = str(get_introduction_banner())+"_"*TER_COL_SIZE
if __name__ == '__main__':
    parser = ArgumentParser(
        description=description
    )
    parser.add_argument(
        "-f",
        "--filename",
        type=str,
        help="Name of EML file",
        required=True
    )
    parser.add_argument(
        "-H",
        "--headers",
        help="Headers of the eml file",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-d",
        "--digests",
        help="Digests of the eml file",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-l",
        "--links",
        help="Links from the eml file",
        required=False,
        action="store_true"
    )
    parser.add_argument(
        "-a",
        "--attachments",
        help="Attachments from the eml file",
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
        help="Name of the Output file",
        required=False
    )
    args = parser.parse_args()

    # If we are in a terminal
    if sys.stdout.isatty():
        # Get Terminal Column Size
        terminal_size = os.get_terminal_size()
        # Set Terminal Column Size
        TER_COL_SIZE = terminal_size.columns

    # Filename
    if args.filename:
        # Get Filename
        filename = str(args.filename)
        # Get File Format
        file_format = filename.split('.')[-1]
        if not file_format in SUPPORTED_FILE_TYPES:
            print("{} file format not supported".format(file_format))
            sys.exit(-1) #Exit with error code
    
    with open(filename,"r",encoding="utf-8") as file:
        data = file.read().rstrip()

    # If printing to file requested
    if args.output:
        # Create JSON data
        app_data = json.loads('{"Information": {}, "Analysis":{}}')
        app_data["Information"] = {
            "Project":"EmailAnalyzer",
            "Url":"https://github.com/keraattin/EmailAnalyzer",
            "Version": "1.0",
            "Generated": str(datetime.now())
        }
        # Write to the file
        with open(args.output, 'w', encoding="utf-8") as file:
            json.dump(app_data, file, indent=4)

    # Headers
    if args.headers:
        # Get Headers
        headers = get_headers(data, args.investigate)
        # Print Headers
        get_headers_banner() # Print Banner
        
        for key,val in headers["Headers"]["Data"].items():
            print("_"*TER_COL_SIZE)
            print("[{}]".format(key))
            print(val)
            print("_"*TER_COL_SIZE)
        # If Investigation requested
        if args.investigate:
            get_investigation_banner() # Print Banner
            for key,val in headers["Headers"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print("[{}]".format(key))
                for k,v in val.items():
                    print("{}:\n{}\n".format(k,v))
                print("_"*TER_COL_SIZE)
        
        # If printing to file requested
        if args.output:
            with open(args.output, 'r+', encoding="utf-8") as file:
                json_data = json.load(file)
                json_data["Analysis"].update(headers)
                file.seek(0)
                json.dump(json_data, file, indent=4)

    # Digests
    if args.digests:
        # Get & Print Digests
        digests = get_digests(data, filename, args.investigate)
        # Print digests
        get_digests_banner() # Print Banner
        for key,val in digests["Digests"]["Data"].items():
            print("_"*TER_COL_SIZE)
            print("[{}]".format(key))
            print(val)
            print("_"*TER_COL_SIZE)
        
        # If Investigation requested
        if args.investigate:
            get_investigation_banner() # Print Banner
            for key,val in digests["Digests"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print("[{}]".format(key))
                for k,v in val.items():
                    print("{}:\n{}\n".format(k,v))
                print("_"*TER_COL_SIZE)
    
        # If printing to file requested
        if args.output:
            with open(args.output, 'r+', encoding="utf-8") as file:
                json_data = json.load(file)
                json_data["Analysis"].update(digests)
                file.seek(0)
                json.dump(json_data, file, indent=4)

    # Links
    if args.links:
        # Get & Print Links
        links = get_links(data, args.investigate)
        # Print Links
        for key,val in links["Links"]["Data"].items():
            print("[{}]->{}".format(key,val))
        
        # If Investigation requested
        if args.investigate:
            get_investigation_banner() # Print Banner
            # Print Links with Investigation tools
            for key,val in links["Links"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print("[{}]".format(key))
                for k,v in val.items():
                    print("{}:\n{}\n".format(k,v))
                print("_"*TER_COL_SIZE)
        
        # If printing to file requested
        if args.output:
            with open(args.output, 'r+', encoding="utf-8") as file:
                json_data = json.load(file)
                json_data["Analysis"].update(links)
                file.seek(0)
                json.dump(json_data, file, indent=4)
    
    # Attachments
    if args.attachments:
        # Get Attachments 
        attachments = get_attachments(filename, args.investigate)

        # Print Attachments
        get_attachment_banner() # Print Banner
        print("_"*TER_COL_SIZE)
        for key,val in attachments["Attachments"]["Data"].items():
            print("[{}]->{}".format(key,val))
        print("_"*TER_COL_SIZE)
        
        # If Investigation requested
        if args.investigate:
            get_investigation_banner() # Print Banner
            for key,val in attachments["Attachments"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print("- {}\n".format(key))
                for k,v in val.items():
                    print("{}:".format(k))
                    for a,b in v.items():
                        print("[{}]->{}".format(a,b))
                print("_"*TER_COL_SIZE)
        
        # If printing to file requested
        if args.output:
            with open(args.output, 'r+', encoding="utf-8") as file:
                json_data = json.load(file)
                json_data["Analysis"].update(attachments)
                file.seek(0)
                json.dump(json_data, file, indent=4)
##############################################################################
