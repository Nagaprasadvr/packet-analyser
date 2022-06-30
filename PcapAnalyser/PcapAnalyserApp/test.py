import binascii
import sys
import plotly.express as px
import pandas as pd
from struct import *
import os
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
import argparse
from scapy.all import *
import random
file1 = "./pcaps/SSHv2.cap"

cap = rdpcap(file1)
appdata = []
for i in range(len(cap)):
    tmp = " "
    frame = cap[i]
    pkt = frame.payload
    segment = pkt.payload
    ap = segment.payload
    apd = bytes(ap)

    if len(apd) > 60:
        apd = str(apd[2:])
        count = 0
        for j in apd:
            if j.isalnum() and j!="x" and j!="0":
                tmp = tmp+j
            else:

                tmp = tmp+"-"

            tmp.strip("'")
            tmp.strip("b")
            tmp.lstrip("-")
            tmp.rstrip("-")
        appdata.append(tmp)

