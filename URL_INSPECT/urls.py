"""URL_INSPECT URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
	https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
	1. Add an import:  from my_app import views
	2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
	1. Add an import:  from other_app.views import Home
	2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
	1. Import the include() function: from django.conf.urls import url, include
	2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from phish_inspec import views

urlpatterns = [
	url(r'^admin/', admin.site.urls),
	url(r'^index/', views.index, name='index'),
	url(r'^$', views.home, name='home'),
	url(r'^phishing/', views.about_phishing, name='about_phishing'),
	url(r'^documentation/', views.documentatiom, name='documentation'),
	url(r'^about/', views.about, name='about'),
	url(r'^contact/', views.contact, name='contact'),
	url('email/', views.emailView, name='email'),
	url('success/', views.successView, name='success'),
	url(r'^phish_inspec/',include('phish_inspec.urls')),
]
handler404 = views.handler404
handler500 = views.handler500