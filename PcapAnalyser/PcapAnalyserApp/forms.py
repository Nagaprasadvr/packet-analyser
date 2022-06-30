from pydoc import TextDoc
from django import forms
from matplotlib import widgets

from .models import Document

class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ('description', 'document')
        widgets = {
            "description":forms.TextInput(attrs={'class':'form-control'}),
            "document":forms.FileInput(attrs={'class':'form-control'})
        }