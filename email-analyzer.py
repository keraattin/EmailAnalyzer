#!/usr/bin/env python3

# Libraries
##############################################################################
from email.parser import HeaderParser
import pyfiglet
from argparse import ArgumentParser
import sys
import hashlib
import re
import quopri
import os
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
    '''Get & Print Headers from mail data'''
    print(pyfiglet.figlet_format("Headers")) # Print Banner
    # Get Headers from mail data
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    # Print Headers
    for key,val in headers.items():
        print("_"*TER_COL_SIZE)
        print(key+":")
        print(val)
        print("_"*TER_COL_SIZE)

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

    print(pyfiglet.figlet_format("Digests")) # Print Banner
    # Print digests
    for key,val in digests.items():
        print("_"*TER_COL_SIZE)
        print(key+":")
        print(val)
        print("_"*TER_COL_SIZE)

def get_links(mail_data : str):
    '''Get & Print Links from mail data'''
    print(pyfiglet.figlet_format("Links")) # Print Banner

    # If content of eml file is Encoded -> Decode
    if "Content-Transfer-Encoding" in mail_data:
        mail_data = str(quopri.decodestring(mail_data)) # Decode

    # Find the Links    
    links = re.findall(LINK_REGEX, mail_data)

    # Remove Duplicates
    links = list(dict.fromkeys(links))
    # Remove Empty Values
    links = list(filter(None, links))

    # Print Links
    for index,link in enumerate(links,start=1):
        print("["+str(index)+"]->"+link)
    
    print(pyfiglet.figlet_format("Investigation")) # Print Banner
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
##############################################################################
        
# Main
##############################################################################
if __name__ == '__main__':
    parser = ArgumentParser()
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
    args = parser.parse_args()

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
        # Get & Print Headers
        get_headers(data)
    
    # Digests
    if args.digests:
        # Get & Print Digests
        get_digests(data,filename)
    
    # Links
    if args.links:
        # Get & Print Links
        get_links(data)
##############################################################################
