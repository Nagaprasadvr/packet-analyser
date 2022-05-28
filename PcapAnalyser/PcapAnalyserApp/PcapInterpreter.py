# this is the python script to interpret pcap files
import binascii
import sys
from struct import *
import os
import argparse
from scapy.all import *
import random

file1 = "./pcaps/SSHv2.cap"
cap = rdpcap(file1)
p1 = cap[0]


def GetHexData(frame):
    hexpac = binascii.hexlify(bytes(frame))
    hexstr = str(hexpac).strip("b")
    hexstr = hexstr.strip("'")

    print(hexstr)
    return hexstr

def printMac(mac:str):
    for i in range(0,len(mac),2):
        print(mac[i],end="")
        print(mac[i+1],end="")
        print(":",end="")
    print()

hex = GetHexData(p1)


printMac(hex[0:12])
printMac(hex[12:24])


