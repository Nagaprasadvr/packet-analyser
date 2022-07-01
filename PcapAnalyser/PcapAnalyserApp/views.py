from django.http import HttpResponse
from django.shortcuts import render
from django.shortcuts import render, redirect
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.contrib import messages
from httplib2 import Response
from .models import Document
from .forms import DocumentForm
from django.contrib import messages
import binascii
from .PcapInterpreter import getSSHdata
import sys
import plotly.express as px
import pandas as pd
from struct import *
import os
from traceroute import traceroute
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
import argparse
from scapy.all import *
import random
from . import PcapInterpreter as pint
# Create your view here.


def index(request):
    return render(request, "PcapAnalyserApp/base.html")

def packet_details(request):
    return render(request, "PcapAnalyserApp/packet-details.html")    

def packetno_size(request):
    return render(request, "PcapAnalyserApp/plot0.html")


def packetno_time(request):
    return render(request, "PcapAnalyserApp/plot1.html")    
      

# def size_vs_no(request):
#     dirt = os.path.abspath(__file__)
#     file1 = os.path.join(dirt,"/media/documents/"+)
#     #file1 = "/home/rishu/Projects/cisco_project_packet_analysis/PcapAnalyser/media/documents/SSHv2.cap"
#     caps = rdpcap(file1)
#     # for cap in caps:
#     print(len(caps))

    #return render(request, "PcapAnalyserApp/base.html")

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
    for i in range(10):
        print("\n", file=f)
        print(f"--------------------Packet - {i}--------------------------", file=f)
        print(df.iloc[i],file=f)
        print("--------------------------------------------------------", file=f)
        print("\n", file=f)

    #print(df.shape)

    print(df[['src', 'dst', 'sport', 'dport']].head(10),file=f)
    print("-------------------------------------------",file=f)
    print("\n",file=f)
    print(df[['len','packetno']].head(10),file=f)
    print("-------------------------------------------", file=f)
    print("\n", file=f)
    print(df[['time','packetno']].head(10),file=f)
    print("-------------------------------------------", file=f)
    print("\n", file=f)

    #print(df[6:7]['len'],file=f)
    return df

def analyze(request,id):
    ref=Document.objects.get(id=id)

    file1 = "media/"+str(ref.document)
   # file1 = '/home/rohith/Desktop/ciscoproject/PcapAnalyser/media/'+str(ref.document)
    # file1 = "./pcaps/SSHv2.cap"
    # /home/rohith/Desktop/ciscoproject/PcapAnalyser/media/documents/SSHv2.cap
    print(file1)
    cap = rdpcap(file1)
    l = getSSHdata(cap)

    p1 = cap[0]
    #p1.pdfdump("./first.pdf",layer_shift=1)
    #mytrace,err = traceroute(["www.google.com"])
    #mytrace.graph(target=">trace.svg")
    with open('filename.txt', 'w') as f:
        print("-----------------------------------Packets-Summary--------------------------------------------")
        GetHexData(p1,f)
        buildDframe(cap,f)
        print(l, file=f)
    f = open('filename.txt', 'r')
    file_content = f.read()
    f.close()
    return HttpResponse(file_content, content_type="text/plain")

def test(request,id):
    ref=Document.objects.get(id=id)

    file1 = "media/"+str(ref.document)
    # file1 = '/home/rohith/Desktop/ciscoproject/PcapAnalyser/media/'+str(ref.document)
    # file1 = "./pcaps/SSHv2.cap"
    # /home/rohith/Desktop/ciscoproject/PcapAnalyser/media/documents/SSHv2.cap
    print(file1)
    cap = rdpcap(file1)
    l = pint.getSSHdata(cap)

    p1 = cap[0]
    #p1.pdfdump("./first.pdf",layer_shift=1)
    #mytrace,err = traceroute(["www.google.com"])
    #mytrace.graph(target=">trace.svg")
    f = None
    hexdata = []
    for i in cap:
         hexdata.append(pint.GetHexData(i))

   
    df = pint.buildDframe(cap)
    appdata = pint.getSSHdata(cap)
    pkt = []
    packets = {}
    #print(df[['src', 'dst', 'sport', 'dport']])
    #print(df[['len','packetno']])
    #print(df[['time','packetno']])
    for i in df.itertuples():
        pkt.append(i)
    
    names = df.columns.values.tolist()
    names.insert(0,'Packet no ')
    #print(type(pkt[0][5]))
    for i in range(len(pkt)):
        pkt[i] = zip(names,pkt[i])

    l = df[['packetno','time','src','dst','sport','dport','len',]].values.tolist()
    obj = df[['packetno','len']].values.tolist()
    print(obj)
    length = []
    for i in obj:
        if i[1] >500:
            length.append(i)

    print(length)

    #print(l)

    i = 0
    
    data = {"appdata":appdata,"packets":pkt,"pktfields":names,"frames":l,"len":length}
    return render(request,"PcapAnalyserApp/test.html",data)
    


def analyse_from_source(request):
    file1 = "media/documents/SSHv2.cap"
   # file1 = '/home/rohith/Desktop/ciscoproject/PcapAnalyser/media/'+str(ref.document)
    # file1 = "./pcaps/SSHv2.cap"
    # /home/rohith/Desktop/ciscoproject/PcapAnalyser/media/documents/SSHv2.cap
    print(file1)
    cap = rdpcap(file1)
    l = getSSHdata(cap)

    f = None
    hexdata = []
    for i in cap:
         hexdata.append(pint.GetHexData(i))

   
    df = pint.buildDframe(cap)
    appdata = pint.getSSHdata(cap)
    pkt = []
    packets = {}
    #print(df[['src', 'dst', 'sport', 'dport']])
    #print(df[['len','packetno']])
    #print(df[['time','packetno']])
    for i in df.itertuples():
        pkt.append(i)
    
    names = df.columns.values.tolist()
    names.insert(0,'Packet no ')
    #print(type(pkt[0][5]))
    for i in range(len(pkt)):
        pkt[i] = zip(names,pkt[i])
    #print(pkt[0])
    obj = df[['packetno', 'len']].values.tolist()
    print(obj)
    length = []
    for i in obj:
        if i[1] > 500:
            length.append(i)


    l = df[['packetno','time','src','dst','sport','dport','len',]].values.tolist()
    #print(l)
    #print(names)
    i = 0
    
    data = {"appdata":appdata,"packets":pkt,"pktfields":names,"frames":l,"len":length}
    return render(request,"PcapAnalyserApp/test.html",data)



def model_form_upload(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            a=form.save()
            #filename = request.FILES
            #print(filename)
            #print(a.document)
            messages.success(request, 'Pcap file uploaded successfully!')
            return redirect('test',a.id)
            # return Response({}, status=statu)
    else:
        form = DocumentForm()
        return render(request, 'PcapAnalyserApp/model_form_upload.html', {'form': form})