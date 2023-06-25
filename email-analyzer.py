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
from banners import (
    get_introduction_banner,get_headers_banner,get_links_banner,
    get_digests_banner,get_attachment_banner,get_investigation_banner
)
from html_generator import generate_table_from_json
##############################################################################

# Global Values
##############################################################################
# Supported File Types
SUPPORTED_FILE_TYPES = ["eml"]

# Supported Output File Types
SUPPORTED_OUTPUT_TYPES = ["json","html"]

# REGEX
LINK_REGEX = r'href=\"((?:\S)*)\"'
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

# Date Format
DATE_FORMAT = "%B %d, %Y - %H:%M:%S"

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
    
    # To get all 'Received' headers
    if data["Headers"]["Data"].get('received'):
        data["Headers"]["Data"]["received"] = ' '.join(headers.get_all('Received')).replace('\t', '').replace('\n', '')

    # If investigation requested
    if investigation:
        # X-Sender-Ip Investigation
        if data["Headers"]["Data"].get("x-sender-ip"):
            data["Headers"]["Investigation"]["X-Sender-Ip"] = {
                "Virustotal":f'https://www.virustotal.com/gui/search/{data["Headers"]["Data"]["x-sender-ip"]}',
                "Abuseipdb":f'https://www.abuseipdb.com/check/{data["Headers"]["Data"]["x-sender-ip"]}'
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
        eml_file    = f.read()
        file_md5    = hashlib.md5(eml_file).hexdigest()
        file_sha1   = hashlib.sha1(eml_file).hexdigest()
        file_sha256 = hashlib.sha256(eml_file).hexdigest()

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

def get_links(mail_data : str, investigation):
    '''Get Links from mail data'''

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
                "Virustotal":f"https://www.virustotal.com/gui/search/{link}",
                "Urlscan":f"https://urlscan.io/search/#{link}"
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
        attached_file["SHA256"] = hashlib.sha256(attachment.get_payload(decode=True)).hexdigest()
        attachments.append(attached_file)

    for index,attachment in enumerate(attachments,start=1):
        data["Attachments"]["Data"][str(index)] = attachment["filename"]

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

    return data
##############################################################################

# Pretty Print Function
##############################################################################
def print_data(data):
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
            print(f"[{key}]->{val}")
            print("_"*TER_COL_SIZE)
        
        # Print Investigation
        if data["Analysis"]["Attachments"].get("Investigation"):
            get_investigation_banner() # Print Banner
            for key,val in data["Analysis"]["Attachments"]["Investigation"].items():
                print("_"*TER_COL_SIZE)
                print(f"- {key}\n")
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
    # if Output File Format is NOT Supported
    # file_format is NOT in SUPPORTED_FILE_TYPES
    else:
        print(f"{filename} file format not supported for output")
        sys.exit(-1) #Exit with error code
##############################################################################

# Main
##############################################################################
description = ""
if __name__ == '__main__':
    parser = ArgumentParser(
        description=description
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
        if file_format not in SUPPORTED_FILE_TYPES:
            print(f"{file_format} file format not supported")
            sys.exit(-1) #Exit with error code
    
    with open(filename,"r",encoding="utf-8") as file:
        data = file.read().rstrip()

    # Create JSON data
    app_data = json.loads('{"Information": {}, "Analysis":{}}')
    app_data["Information"]["Project"] = {
        "Name":"EmailAnalyzer",
        "Url":"https://github.com/keraattin/EmailAnalyzer",
        "Version": "2.0",
    }
    app_data["Information"]["Scan"] = {
        "Filename": filename,
        "Generated": str(datetime.now().strftime(DATE_FORMAT))
    }
    
    # List of Arguments
    arg_list = [args.headers, args.digests, args.links, args.attachments]

    # Check if any argument given
    if any(arg_list):
        # Headers
        if args.headers:
            # Get Headers
            headers = get_headers(data, args.investigate)
            app_data["Analysis"].update(headers)

        # Digests
        if args.digests:
            # Get Digests
            digests = get_digests(data, filename, args.investigate)
            app_data["Analysis"].update(digests)

        # Links
        if args.links:
            # Get & Print Links
            links = get_links(data, args.investigate)
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

        # Get Digests
        digests = get_digests(data, filename, investigate)
        app_data["Analysis"].update(digests)

        # Get & Print Links
        links = get_links(data, investigate)
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
