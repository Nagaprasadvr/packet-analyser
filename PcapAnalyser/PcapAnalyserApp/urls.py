from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="index"),
<<<<<<< HEAD
    path('upload-file', views.model_form_upload, name="upload-file"),
    path('size-vs-no', views.size_vs_no, name="size_vs_no_analysis")
=======
    path('upload-file/', views.model_form_upload, name="upload-file")
>>>>>>> 4f97381031804d8220e06c94eb05fb105792a799

]