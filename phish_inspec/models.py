# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.utils import timezone

# Create your models here.
class URLModel(models.Model):
    url = models.URLField(max_length=500, blank=False, null=False)
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url


class DataModel(models.Model):
    theURL = models.ForeignKey('phish_inspec.URLModel')

    having_IP_Address = models.IntegerField()
    URL_Length = models.IntegerField()
    Shortining_Service = models.IntegerField()
    having_At_Symbol = models.IntegerField()
    double_slash_redirecting = models.IntegerField()
    Prefix_Suffix = models.IntegerField()
    having_Sub_Domain = models.IntegerField()
    SSLfinal_State = models.IntegerField()
    Domain_registeration_length= models.IntegerField()
    Favicon= models.IntegerField()
    port= models.IntegerField()
    HTTPS_token= models.IntegerField()
    Request_URL= models.IntegerField()
    URL_of_Anchor= models.IntegerField()
    Links_in_tags= models.IntegerField()
    SFH= models.IntegerField()
    Submitting_to_email= models.IntegerField()
    Abnormal_URL= models.IntegerField()
    Redirect= models.IntegerField()
    on_mouseover= models.IntegerField()
    RightClick= models.IntegerField()
    popUpWidnow= models.IntegerField()
    Iframe= models.IntegerField()
    age_of_domain= models.IntegerField()
    DNSRecord= models.IntegerField()
    web_traffic= models.IntegerField()
    Page_Rank= models.IntegerField()
    Google_Index= models.IntegerField()
    Links_pointing_to_page= models.IntegerField()
    Statistical_report= models.IntegerField()
    Result= models.IntegerField()

    created_date = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return 'is_ip: %d'%self.having_IP_Address
