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
# appdata = []
# for i in range(len(cap)):
#     tmp = " "
#     frame = cap[i]
#     pkt = frame.payload
#     segment = pkt.payload
#     ap = segment.payload
#     apd = bytes(ap)

#     if len(apd) > 60:
#         apd = str(apd[2:])
#         count = 0
#         for j in apd:
#             if j.isalnum() and j!="x" and j!="0":
#                 tmp = tmp+j
#             else:

#                 tmp = tmp+"-"

#             tmp.strip("'")
#             tmp.strip("b")
#             tmp.lstrip("-")
#             tmp.rstrip("-")
#         appdata.append(tmp)

# print(p.conversations(type="jpg", target="> test.jpg"))
# p[0].pdfdump(layer_shift=1)
# p[0].psdump("/tmp/isakmp_pkt.eps",layer_shift=1)
# mytrace,err = traceroute (["www.google.com"])
# mytrace.graph(target=">trace.svg")
# mytrace.trace3D()
# a[0].pdfdump(layer_shift=1)
# a[0].psdump("./isakmp_pkt.jpeg",layer_shift=1)
a=cap[0]
a.show()
hexdump(cap)

