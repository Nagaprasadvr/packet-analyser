from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="index"),
    path('upload-file', views.model_form_upload, name="upload-file"),
    path('size-vs-no', views.size_vs_no, name="size_vs_no_analysis")

]