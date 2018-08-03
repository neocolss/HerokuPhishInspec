# -*- coding: utf-8 -*-
from django.conf.urls import url
from phish_inspec import views


# SET THE NAMESPACE!
app_name = 'phish_inspec'

# Be careful setting the name to just /login use userlogin instead!
urlpatterns=[
	
	url(r'^batch/$', views.batch, name='batch'),
	url('email/', views.emailView, name='email'),
	url('success/', views.successView, name='success'),

]
