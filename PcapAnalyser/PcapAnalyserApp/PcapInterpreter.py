# this is the python script to interpret pcap files
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

print(len(cap[0]))


def buildDframe():
    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    udp_fields = [field.name for field in UDP().fields_desc]

    dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload', 'payload_raw', 'payload_hex']+['packetno']

    # Create blank DataFrame
    df = pd.DataFrame(columns=dataframe_fields)
    i = 0
    for packet in cap[IP]:
        # Field array for each row of DataFrame
        field_values = []
        # Add all IP fields to dataframe
        for field in ip_fields:
            if field == 'options':
                # Retrieving number of options defined in IP Header
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])

        field_values.append(packet.time)

        layer_type = type(packet[IP].payload)
        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
            except:
                field_values.append(None)

        # Append payload
        field_values.append(len(packet[layer_type].payload))
        field_values.append(packet[layer_type].payload.original)
        field_values.append(binascii.hexlify(packet[layer_type].payload.original))
        field_values.append(i)
        i+=1
        # Add row to DF
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append], axis=0)
 
    # Reset Index
    df = df.reset_index()
    # Drop old index column
    df = df.drop(columns="index")
    print(df.iloc[1])

    print(df.shape)

    print(df[['src', 'dst', 'sport', 'dport']])
    print(df[['len','packetno']])
    print(df[['time','packetno']])

    print(df[6:7]['len'])
    return df

d = buildDframe()

frame = cap[6]
pkt = frame.payload
segment = pkt.payload
ap = segment.payload
ap = bytes(ap)
#h1 = GetHexData(ap)
#print(IP().fields_desc)
#print(pkt.fields['src'])
def getSSHdata(apd):
    string = ""

    tmp = ""
    for j in range(len(apd)-1):
        if apd[j:j+1].isalnum() :
            tmp = str(apd[j:j+1])
            tmp = tmp.strip("'")
            tmp = tmp.strip("b")
            tmp = tmp.strip("'")
            string = string+tmp
        else:
            string = string+"-"

    string.strip(" ")
    return string




print(ap)
print("\n\n---------SSH DATA ------------\n\n")
print(getSSHdata(apd=ap))
j = 0
def plotSizevsNum(n):
    fig = px.line(d[['len','packetno']],x='packetno',y='len',title="Packet size vs Packet number")
    fig.write_html(f"./templates/PcapAnalyserApp/plot{n}.html")
    global j
    j+=1



            
                
plotSizevsNum(j)
print(d['time'][1])


def plotTimevsNum(n):
    
   

    fig = px.line(d[['time','packetno']],range_y=[d['time'].min(),d['time'].max()])
    fig.write_html(f"./templates/PcapAnalyserApp/plot{n}.html")
    global j
    j+=1
plotTimevsNum(j)    