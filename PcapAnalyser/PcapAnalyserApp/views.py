from django.shortcuts import render
from django.shortcuts import render, redirect
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.contrib import messages
from .models import Document
from .forms import DocumentForm
# Create your view here.


def index(request):
    return render(request, "PcapAnalyserApp/base.html")


def model_form_upload(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()

            return redirect('index')
    else:
        form = DocumentForm()
    return render(request, 'PcapAnalyserApp/model_form_upload.html', {
        'form': form
    })

def size_vs_no(request):
    file1 = "/home/rishu/Projects/cisco_project_packet_analysis/PcapAnalyser/media/documents/SSHv2.cap"
    caps = rdpcap(file1)
    # for cap in caps:
    print(len(caps))

    return render(request, "PcapAnalyserApp/base.html")

