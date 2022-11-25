#!/usr/bin/env python3

from email.parser import HeaderParser
import pyfiglet
from argparse import ArgumentParser
import sys

SUPPORTED_FILE_TYPES = ["eml"]


# Main
if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument(
        "-f",
        "--filename", 
        type=str, 
        help="Name of file", 
        required=True
    )
    args = parser.parse_args()
    
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
        data = file.read().rstrip(
