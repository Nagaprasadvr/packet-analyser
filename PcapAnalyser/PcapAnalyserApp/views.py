from django.http import HttpResponse
from django.shortcuts import render
from django.shortcuts import render, redirect
from .PcapInterpreter import pieChart
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
from django.templatetags.static import static

# Create your view here.
#absolute_path="/home/rohith/Desktop/ciscoproject/PcapAnalyser/PcapAnalyserApp/templates/PcapAnalyserApp"

def index(request):
    return render(request, "PcapAnalyserApp/base.html")


def packet_details(request):
    return render(request, "PcapAnalyserApp/packet-details.html")    


def packet_structure(request):
    return render(request, "PcapAnalyserApp/ps.html")


def packetno_size(request):
    return render(request,"PcapAnalyserApp/plot1.html")



    #return render(request, "PcapAnalyserApp/base.html")
def packetno_time(request):
    return render(request,"PcapAnalyserApp/plot2.html")


def plotSizevsNum(d):
    fig = px.line(d[['len','packetno']],x='packetno',y='len',title="Packet size vs Packet number")
    fig.write_html("PcapAnalyserApp/templates/PcapAnalyserApp"+"/plot1.html")


def plotTimevsNum(d):
    fig = px.line(d[['time','packetno']],range_y=[d['time'].min(),d['time'].max()])
    fig.write_html("PcapAnalyserApp/templates/PcapAnalyserApp"+"/plot2.html")



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
    dir = os.path.dirname(os.path.abspath(__file__))

    file = os.path.join(dir, 'static')
    p1.pdfdump(file+"/ps.pdf", layer_shift=1)
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
    plotSizevsNum(df)
    plotTimevsNum(df)
    for i in df.itertuples():
        pkt.append(i)

    names = df.columns.values.tolist()
    names.insert(0,'Packet no ')
    #print(type(pkt[0][5]))
    for i in range(len(pkt)):
        pkt[i] = zip(names,pkt[i])

    l = df[['packetno','time','src','dst','sport','dport','len',]].values.tolist()
    obj = df[['packetno','len']].values.tolist()
    #print(obj)
    length = []
    avg = 0.0
    sum = 0
    for i in obj:
        sum = sum + i[1]
    avg = sum/len(df)

    for i in obj:
        if i[1] > avg:
            length.append(i)

    #print(length)

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
    obj = df[['packetno', 'len','payload_raw']].values.tolist()
    print(obj)
    length = []
    avg = 0.0
    sum = 0
    for i in obj:
        sum = sum + i[1]
    avg = sum / len(df)

    for i in obj:
        if i[1] > avg:
            length.append(i)


    l = df[['packetno','time','src','dst','sport','dport','len',]].values.tolist()
    #print(l)
    #print(names)
    i = 0
    plen = [j[1] for j in length ]
    pno = [k[0] for k in length ]
    pieChart(pno,plen)
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