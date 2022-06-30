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




def buildDframe(cap):
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


def getSSHdata(cap):
    appdata = []
    for f in cap:
        frame = f
        pkt = frame.payload
        segment = pkt.payload
        ap = segment.payload
        apd = bytes(ap)
        if len(apd)>=100 and len(apd)<=500:

            apd = str(apd[2:])
            count = 0
            tmp = ""
            for j in apd:

                if j.isalnum() and j != "x" and j != "0":
                    tmp = tmp + j
                else:
                    tmp = tmp + "-"

                tmp.strip("'")
                tmp.strip("b")
                tmp.lstrip("-")
                tmp.rstrip("-")
            appdata.append(tmp)

    return appdata



def plotSizevsNum(d):
    fig = px.line(d[['len','packetno']],x='packetno',y='len',title="Packet size vs Packet number")
    n = ""
    for _ in range(5):
        n = n+str(math.ceil((random.random())))

    fig.write_html(f"./templates/PcapAnalyserApp/plot{n}.html")


def plotTimevsNum(d):
    fig = px.line(d[['time','packetno']],range_y=[d['time'].min(),d['time'].max()])
    n = ""
    for _ in range(5):
        n = n + str(math.ceil((random.random())))
    fig.write_html(f"./templates/PcapAnalyserApp/plot{n}.html")
