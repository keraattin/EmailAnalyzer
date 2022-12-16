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
from banners import *
##############################################################################

# Global Values
##############################################################################
# Supported File Types
SUPPORTED_FILE_TYPES = ["eml"]

# REGEX
LINK_REGEX = r'href=\"((?:\S)*)\"'

# Terminal Column Size
TER_COL_SIZE = 60
##############################################################################

# Functions
##############################################################################
def get_headers(mail_data : str):
    '''Get Headers from mail data'''
    # Get Headers from mail data
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    return headers


def get_digests(mail_data : str, filename : str):
    '''Get & Print Hash value of mail'''
    with open(filename, 'rb') as f:
        file        = f.read()
        file_md5    = hashlib.md5(file).hexdigest()
        file_sha1   = hashlib.sha1(file).hexdigest()
        file_sha256 = hashlib.sha256(file).hexdigest()

    digests = {
        "File MD5":file_md5,
        "File SHA1":file_sha1,
        "File SHA256":file_sha256,
        "Content MD5":hashlib.md5(mail_data.encode("utf-8")).hexdigest(),
        "Content SHA1":hashlib.sha1(mail_data.encode("utf-8")).hexdigest(),
        "Content SHA256":hashlib.sha256(mail_data.encode("utf-8")).hexdigest()
    }
    return digests

def get_links(mail_data : str):
    '''Get & Print Links from mail data'''
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

    return links

def get_attachments(filename : str):
    ''' Get & Print Attachments from eml file'''
    with open(filename, "r") as f:
        msg = message_from_file(f, policy=policy.default)
    
    attachments = []
    for attachment in msg.iter_attachments():
        attached_file = {}
        attached_file["filename"] = attachment.get_filename()
        attached_file["md5"] = hashlib.md5(attachment.get_payload(decode=True)).hexdigest()
        attached_file["sha1"] = hashlib.sha1(attachment.get_payload(decode=True)).hexdigest()
        attached_file["sha256"]=hashlib.sha256(attachment.get_payload(decode=True)).hexdigest()
        attachments.append(attached_file)
    
    return attachments
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
        help="Name of file", 
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

    # Headers
    if args.headers:
        # Get Headers
        headers = get_headers(data)
        # Print Headers
        get_headers_banner() # Print Banner
        for key,val in headers.items():
            print("_"*TER_COL_SIZE)
            print(key+":")
            print(val)
            print("_"*TER_COL_SIZE)
        
        get_investigation_banner() # Print Banner
        for key,val in headers.items():
            if key == "X-Sender-IP":
                print("_"*TER_COL_SIZE)
                print("["+key+"]")
                print("[Virustotal]")
                print("https://www.virustotal.com/gui/search/"+val)
                print("[Abuseipdb]")
                print("https://www.abuseipdb.com/check/"+val)
                print("_"*TER_COL_SIZE)
    
    # Digests
    if args.digests:
        # Get & Print Digests
        digests = get_digests(data,filename)
        # Print digests
        get_digests_banner() # Print Banner
        for key,val in digests.items():
            print("_"*TER_COL_SIZE)
            print(key+":")
            print(val)
            print("_"*TER_COL_SIZE)
        
        get_investigation_banner() # Print Banner
        for key,val in digests.items():
            print("_"*TER_COL_SIZE)
            print("["+key+"]")
            print("[Virustotal]")
            print("https://www.virustotal.com/gui/search/"+val)
            print("_"*TER_COL_SIZE)
    
    # Links
    if args.links:
        # Get & Print Links
        links = get_links(data)
        # Print Links
        for index,link in enumerate(links,start=1):
            print("["+str(index)+"]->"+link)
        
        get_investigation_banner() # Print Banner
        # Print Links with Investigation tools
        for index,link in enumerate(links,start=1):
            if "://" in link:
                link = link.split("://")[-1]
            print("_"*TER_COL_SIZE)
            print("["+str(index)+"]")
            print("[VirusTotal]:")
            print("https://www.virustotal.com/gui/search/"+link)
            print("[UrlScan]:")
            print("https://urlscan.io/search/#"+link)
            print("_"*TER_COL_SIZE)
    
    # Attachments
    if args.attachments:
        # Get Attachments 
        attachments = get_attachments(filename)

        # Print Attachments
        get_attachment_banner() # Print Banner
        print("_"*TER_COL_SIZE)
        for index,attachment in enumerate(attachments,start=1):
            print("["+str(index)+"]->"+attachment["filename"])
        print("_"*TER_COL_SIZE)
        
        get_investigation_banner() # Print Banner
        for index,attachment in enumerate(attachments,start=1):
            print("_"*TER_COL_SIZE)
            print("["+str(index)+"]->"+attachment["filename"])
            print("[Virustotal]")
            print("[md5]->https://www.virustotal.com/gui/search/"+attachment["md5"])
            print("[sha1]->https://www.virustotal.com/gui/search/"+attachment["sha1"])
            print("[sha256]->https://www.virustotal.com/gui/search/"+attachment["sha256"])
            print("_"*TER_COL_SIZE)
##############################################################################
