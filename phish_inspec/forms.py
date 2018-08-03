# -*- coding: utf-8 -*-
from .models import URLModel
from django import forms
from django.core.validators import URLValidator

class URLModelForm(forms.ModelForm):

    url = forms.URLField(label='URL',
                         widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder':"e.g: http://www.example.com"}),
                         #validators=[URLValidator],
                         #required=True,
                         )

    class Meta:
        model = URLModel
        fields = ('url', )
        exclude = ('created_date',)

class ContactForm(forms.Form):
    from_email = forms.EmailField(required=True)
    subject = forms.CharField(required=True)
    message = forms.CharField(widget=forms.Textarea, required=True)
