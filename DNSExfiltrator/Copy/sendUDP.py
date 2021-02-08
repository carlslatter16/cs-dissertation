#!/usr/bin/env python3

import binascii
import socket
import sys
from collections import OrderedDict

#----------------------------------------------------------------------------------------------
# Portion used & modified from: https://gist.github.com/mrpapercut/92422ecf06b5ab8e64e502da5e33b9f7
# GNU License - https://gist.github.com/mrpapercut/b73e8748c4cf22a541f442622f5672ff
#Typical socketted DNS functions verify if subdomain exists - Not good for this! This uses UDP which will try regardless.


url = sys.argv[1]

def send_udp_message(message, address, port):
    """send_udp_message sends a message to UDP server

    message should be a hexadecimal encoded string
    """
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")

def build_message(type="A", address=""):
    ID = 43690  # 16-bit identifier (0-65535) # 43690 equals 'aaaa'

    QR = 0      # Query: 0, Response: 1     1bit
    OPCODE = 0  # Standard query            4bit
    AA = 0      # ?                         1bit
    TC = 0      # Message is truncated?     1bit
    RD = 1      # Recursion?                1bit
    RA = 0      # ?                         1bit
    Z = 0       # ?                         3bit
    RCODE = 0   # ?                         4bit

    query_params = str(QR)
    query_params += str(OPCODE).zfill(4)
    query_params += str(AA) + str(TC) + str(RD) + str(RA)
    query_params += str(Z).zfill(3)
    query_params += str(RCODE).zfill(4)
    query_params = "{:04x}".format(int(query_params, 2))

    QDCOUNT = 1 # Number of questions           4bit
    ANCOUNT = 0 # Number of answers             4bit
    NSCOUNT = 0 # Number of authority records   4bit
    ARCOUNT = 0 # Number of additional records  4bit

    message = ""
    message += "{:04x}".format(ID)
    message += query_params
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    # QNAME is url split up by '.', preceded by int indicating length of part
    addr_parts = address.split(".")
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        message += addr_len
        message += addr_part.decode()

    message += "00" # Terminating bit for QNAME

    # Type of request
    QTYPE = get_type(type)
    message += QTYPE

    # Class for lookup. 1 is Internet
    QCLASS = 1
    message += "{:04x}".format(QCLASS)

    return message



def get_type(type):
    types = [
        "ERROR", # type 0 does not exist
        "A",
        "NS",
        "MD",
        "MF",
        "CNAME",
        "SOA",
        "MB",
        "MG",
        "MR",
        "NULL",
        "WKS",
        "PTS",
        "HINFO",
        "MINFO",
        "MX",
        "TXT"
    ]

    return "{:04x}".format(types.index(type)) if isinstance(type, str) else types[type]
