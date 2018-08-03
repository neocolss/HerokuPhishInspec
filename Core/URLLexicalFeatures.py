#!/usr/bin/env python
# -*- coding: utf-8 -*-
from furl import furl
import tldextract
import socket

class URLLexical:
	
	def __init__(self, URL):
		self.url = URL
	
	def having_IP_Address(self):
		try:
			socket.inet_aton(furl(self.url).netloc)
			return 1
		except:
			return -1
	
	
	def url_length(self):
		length = len(self.url)
		if length<54:
			return -1
		elif 54 <= length < 75:
			return 0
		elif length >= 75:
			return 1
	
	def does_it_use_shorteningService(self):
		#At this time we can't check the parent of the url
		#will be added in online mode check
		short_services_list=['t.co', 'goo.gl', 'bit.ly', 'amzn.to', 'tinyurl.com', 'ow.ly', 'youtu.be', 'bit.ly', 'Tiny.cc', 'lc.chat',
							 'is.gd', 'soo.gd', 's2r.co', 'clicky.me', 'budurl.com', 'bc.vc', 'rebrand.ly']
		for element in  short_services_list:
			if element == furl(self.url).netloc:
				return 1
		return -1
	
	def having_At_Symbol(self):
		if '@' in self.url:
			return 1
		else:
			return -1
	
	
	def double_slash_redirecting(self):
		
		if str(self.url).count('//')>1:
			return 1
		else:
			return -1
	
	
	def non_standard_port_use(self):
		standard_ports=[21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3389]
		if furl(self.url).port in standard_ports:
			return -1
		else:
			return 1
		
	def prefix_suffix(self):
		if '-' in furl(self.url).host:
			return 1
		else:
			return -1
	
	
	
	def having_sub_domain(self):
		if furl(self.url).host.startswith('www.'):
			u = furl(self.url).host.split('www.')
			#print u
			ext = tldextract.extract(u[1])
			newUrl = ext.subdomain+'.'+ext.domain
			url = newUrl
		else:
			url = furl(self.url).host 
		
		nbrOfDots = url.count('.')
		if nbrOfDots==1:
			return -1
		elif nbrOfDots==2:
			return 0
		elif nbrOfDots>2:
			return 1
	
	def is_https_in_domain(self):
		if 'https' in furl(self.url).host:
			return 1
		else:
			return -1
	
	def does_domain_contains_stop_words(self):
		sec_sen_words=['confirm', 'account', 'banking', 'secure', 'ebayisapi', 'webscr', 'login', 'signin']
		cnt=0
		for ele in sec_sen_words:
			if(ele in furl(self.url).host):
				cnt+=1;
	
		return 1 if cnt>=1 else -1
