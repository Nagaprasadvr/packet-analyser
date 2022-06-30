from django.http import HttpResponse
from django.shortcuts import render
from django.shortcuts import render, redirect
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.contrib import messages
from httplib2 import Response
from PcapAnalyser.settings import STATIC_URL
from .models import Document
from .forms import DocumentForm
from django.contrib import messages
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
from django.templatetags.static import static

# Create your view here.
absolute_path="/home/rohith/Desktop/ciscoproject/PcapAnalyser/PcapAnalyserApp/templates/PcapAnalyserApp"

def index(request):
    return render(request, "PcapAnalyserApp/base.html")

def packet_details(request):
    return render(request, "PcapAnalyserApp/packet-details.html")    

def packet_structure(request):
    return render(request, "PcapAnalyserApp/ps.html")

def packetno_size(request):
    return render(request,"PcapAnalyserApp/plot1.html")


def packetno_time(request):
    return render(request,"PcapAnalyserApp/plot2.html")    

def GetHexData(frame,f):
    hexpac = binascii.hexlify(bytes(frame))
    hexstr = str(hexpac).strip("b")
    hexstr = hexstr.strip("'")
    print(hexstr,file=f)
    return (hexstr)

def buildDframe(cap,f):
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
    print(df.iloc[1],file=f)

    print(df.shape)

    print(df[['src', 'dst', 'sport', 'dport']],file=f)
    print(df[['len','packetno']],file=f)
    print(df[['time','packetno']],file=f)

    print(df[6:7]['len'],file=f)
    return df

def plotSizevsNum(d):
    fig = px.line(d[['len','packetno']],x='packetno',y='len',title="Packet size vs Packet number")
    fig.write_html(absolute_path+"/plot1.html")


def plotTimevsNum(d):
    fig = px.line(d[['time','packetno']],range_y=[d['time'].min(),d['time'].max()])
    fig.write_html(absolute_path+"/plot2.html")

def analyze(request,id):
    ref=Document.objects.get(id=id)
    file1 = '/home/rohith/Desktop/ciscoproject/PcapAnalyser/media/'+str(ref.document)
    # file1 = "./pcaps/SSHv2.cap"
    # /home/rohith/Desktop/ciscoproject/PcapAnalyser/media/documents/SSHv2.cap
    print(file1)
    cap = rdpcap(file1)
    p1 = cap[0]
    p1.pdfdump("/home/rohith/Desktop/ciscoproject/PcapAnalyser/PcapAnalyserApp/static/ps.pdf",layer_shift=1)
    # mytrace,err = traceroute(["www.google.com"])
    # mytrace.graph(target=">trace.svg")
    with open('filename.txt', 'w') as f:
        print("hello",file=f)
        GetHexData(p1,f)
        d=buildDframe(cap,f)
    plotSizevsNum(d)
    plotTimevsNum(d)
    f = open('filename.txt', 'r')
    file_content = f.read()
    f.close()
    return redirect('packet-details')


def model_form_upload(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            a=form.save()
            print(a.document)
            messages.success(request, 'Pcap file uploaded successfully!')
            return redirect('analyze',id=a.id)
            # return Response({}, status=statu)
    else:
        form = DocumentForm()
    return render(request, 'PcapAnalyserApp/model_form_upload.html', {
        'form': form
    })