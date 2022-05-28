# this is the python script to interpret pcap files
import sys
import os
import argparse
from scapy.all import *
import random

file1 = "./pcaps/rawcap-localhost-tor.pcap"
