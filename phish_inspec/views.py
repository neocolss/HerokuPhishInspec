# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.shortcuts import render, redirect, HttpResponseRedirect
from .forms import URLModelForm
from django.core.urlresolvers import reverse
from django.utils import timezone
from .forms import ContactForm

# Create your views here.
def home(request):
    return render(request, 'phis_inspec/home.html')

def index(request):
    return render(request, 'phis_inspec/index.html')

def about_phishing(request):
    return render(request, 'phis_inspec/about_phishing.html')


def documentatiom(request):
    return render(request, 'phis_inspec/documentation.html')


def about(request):
    return render(request, 'phis_inspec/about.html')



def batch(request):

    if request.method == 'POST':
        form = URLModelForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            try:

                import requests
                r = requests.get(url)
                r.close()
            except Exception:
                form = URLModelForm()
                return render(request, 'phis_inspec/batch.html', {'form': form, 'error':'Bad URL or doesn\'t exist.'})

            urlModel = form.save(commit=False)
            urlModel.created_date = timezone.now()
            urlModel.save()

            from Core.main_process import Core
            main_process = Core(urlModel.url)

            results = main_process.main_batch()
            results_to_display = {}
            results_to_display['is_blacklisted'] = results['is_blacklisted']

            results_to_display['final_result'] = results['final_result']


            return render(request, 'phis_inspec/batch.html', {'form': form, 'url': urlModel, 'results':results_to_display})

    else:
        form = URLModelForm()
        return render(request, 'phis_inspec/batch.html', {'form': form})


def contact(request):
    return render(request, 'phis_inspec/contact.html')

def emailView(request):
    if request.method == 'GET':
        form = ContactForm()
    else:
        form = ContactForm(request.POST)
        if form.is_valid():
            subject = form.cleaned_data['subject']
            from_email = form.cleaned_data['from_email']
            message = form.cleaned_data['message']
            try:
                send_mail(subject, message, from_email, ['mourtaji.y@gmail.com'])
            except BadHeaderError:
                return HttpResponse('Invalid header found.')
            return HttpResponseRedirect(reverse('success'))
    return render(request, "email.html", {'form': form})

def successView(request):
    return render(request, "success.html")

def handler404(request):
    return render(request, 'errors/404.html', status=404)

def handler500(request):
    return render(request, 'errors/500.html', status=500)