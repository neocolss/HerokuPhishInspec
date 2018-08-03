# -*- coding: utf-8 -*-
from __future__ import division
from pyfav import get_favicon_url
import re
from URLIdentity import URLIdentity
from furl import furl
from random import randint
import validators
import os, sys
from bs4 import BeautifulSoup
import requests
import urllib2

class URLContent:
	
	
	def __init__(self, url):
		self.theURL = url
		soup = BeautifulSoup(requests.get(url).content, "html.parser")
		self.content = soup


	#Get the URL
	def get_url(self):
		"""
		Get the url
		"""
		return self.theURL

	def get_source_code(self):
		"""
		Get the source code
		"""
		return self.content
	
	def get_favico_url(self):
		"""
		Get the favico URL
		"""
		try:
			favicon_url = get_favicon_url(self.get_url())
			return str(favicon_url)
		except Exception:
			return 'null'
	
	def Favicon(self):
		url = self.get_url()
		link_favicon = self.get_favico_url()
		
		if link_favicon == 'null':
			return 1
		#print link_favicon
		#name_servers = URLIdentity(url).get_whois()['name_servers']

		try:
			identity = URLIdentity(self.get_url())
			name_servers = identity.get_whois()['nameservers']
		except KeyError:
			whois_data = identity.parse_whois_data()
			name_servers = whois_data['name_servers'] if 'name_servers' in whois_data else 'null'

		all = []
		for element in name_servers:
			if element != 'null':
				all.append(str(element).encode('utf-8').lower())


		if not all :
			return 1
		else:
			if (furl(link_favicon).netloc == furl(url).netloc) or (furl(link_favicon).netloc in name_servers):
				return -1
			else:
				return 1

		
	def get_images_urls(self):
		urls = []
		for img in self.get_source_code().findAll('img'):
			src = img.get('src')
			#print (src)
			urls.append(src)
		return urls
	
	def get_anchor_links(self):
		url = self.get_url()
		anchor_list=['#', '#content', '#skip', 'javascript:void(0)']
		href_links=[]
		for a in self.get_source_code().find_all('a', href=True):
			href_links.append(a['href'])
		#print 'href links:{}'.format(href_links)
		counter =0
		for element in href_links:
			if validators.url(element) == True:
				if furl(element).netloc != furl(url).netloc:
					counter +=1
			else:
				if (element in anchor_list) and (not (str(element).startswith('/'))):
					counter += 1
			
		try:
							
			pourcentage = (counter/len(href_links))*100
			if pourcentage <31:
				return -1
			elif (pourcentage >=31) and (pourcentage <= 67):
				return 0
			else:
				return 1
		except ZeroDivisionError:
			return -1
	
	def get_meta_link_script_links(self):
		url = self.get_url()
		#target=['link', 'meta', 'script']
		returns=[]
		soup = self.get_source_code()
		try:
			Meta_url = soup.find("meta",  property="og:url")
			if Meta_url != None:
				returns.append(Meta_url.get("content"))
			for a in soup.find_all('script', src=re.compile(".*")):
				returns.append(a.get('src'))
			for u in soup.find_all('link'):
				returns.append(u.get('href'))
		except None as e:
			pass
		
		counter =0
		for element in returns:
			if validators.url(element) == True:
				if furl(element).netloc != furl(url).netloc:
					counter +=1
			
		try:
			pourcentage = (counter/len(returns))*100
			#print pourcentage
			if pourcentage < 17:
				return -1
			elif (pourcentage >= 17) and (pourcentage < 81):
				return 0
			else:
				return 1
		except ZeroDivisionError:
			return -1
	
	def get_form_links(self):
		links=[]
		soup = self.get_source_code()
		for f in soup.find_all('form'):
			#print 'f: {}'.format(f)
			action = f.get("action")
			if action is None:
				action = ''
			links.append(action)
		return links
	
	def SFH(self):
		links = self.get_form_links()
		#print 'form action links:{}'.format(links)
		url = self.get_url()
		negative_action_forms=['about: blank', '']
		
		if not links:
			return -1
		else:
			for element in links:
				if (element is not None) and (validators.url(element) == True):
					if (furl(element).netloc == furl(url).netloc) or (furl(element).netloc in furl(url).netloc):
						return -1
					else:
						return 0
				else:
					return 1

			if [ele for ele in links if ele in negative_action_forms]:
				return 1
			

	
	def Submitting_to_email(self):
		links = self.get_form_links()
		
		if not links:
			return -1
		
		negative_form_mail = ['mail()', 'mailto:']
		for ele in negative_form_mail:
			for element in links:
				if element in ele:
					return 1
				else:
					return -1
			
		
	def Request_URL(self):
		#in this section, we get only images, should see for videos and audio tags
		url = self.get_url()
		images_links = self.get_images_urls()
		images_links_domains = []
		if images_links:
			for image_link in images_links:
				images_links_domains.append(furl(image_link).netloc)
		
		counter =0
		for domain in images_links_domains:
			if domain != furl(url).netloc:
				counter +=1
		
		
		try:
			pourcentage = (counter/len(images_links_domains))*100
			#print pourcentage
			if  pourcentage < 22:
				return -1
			elif (pourcentage >= 22) and (pourcentage <61):
				return 0
			else:
				return 1
		except ZeroDivisionError:
			return -1
			
	def Links_pointing_to_page(self):
		return 1
	
	def Iframe(self):
		iframes_counter=[]
		soup = self.get_source_code()
		for f in soup.find_all('iframe'):
			iframes_counter.append(f)
		
		if len(iframes_counter) >= 1:
			return 1
		else :
			return -1
	
	def download_content_as_string(self, url):

		import urllib2
		import ssl
		data = ''
		if furl(url).scheme == 'https':
			try:
				ctx = ssl.create_default_context()
				ctx.check_hostname = False
				ctx.verify_mode = ssl.CERT_NONE
				f = urllib2.urlopen(url, context=ctx)
				data = str(f.read())

			except Exception:
				pass
		else:
			try:
				f = urllib2.urlopen(url)
				data = str(f.read())
			except Exception:
				pass

		return data


	def get_Content_Features_directAccess(self):
		url = self.get_url()

		#add <meta http-equiv="refresh" content="2; url=https://www.google.sn/">
		redirect_list = ['window.location', 'window.location.replace', 'window.location.href', 'link.click', 'window.location.assign',
						 'window.history.back','window.history.go', '$(location).attr', '$(location).prop']
		redirect_counter = 0

		changeBarStatus_list = ['onMouseover', 'onMouseOut', 'window.status', 'window.statusbar.visible','window.defaultStatus']

		disableRightClick_list = ['e.which == 2', 'e.which==2', 'e.which== 2', 'e.which==3', 'e.which == 3','e.which== 3', 'event.button==2']

		Content_Features = {}
		Content_Features['disableRightClick'] = -1
		Content_Features['changeBarStatus'] = -1
		Content_Features['redirect'] = -1

		soup = self.get_source_code()
		for a in soup.find_all('script'):
			#print '*** Script FOund  :{}   ***'.format(a)
			js_src = ''
			content = ''
			if a.get('src') is None:
				content = a

			else:
				js_src = a.get('src')
				#print 'js_src: %s'%(js_src)
				import re
				if (re.search("^/", js_src) is not None) and (re.search("^//", js_src) is None):
					if re.search("^/", js_src).group(0) == '/':
				#if js_src.startswith('/'):
						js_src = furl(url).scheme+'://'+furl(url).netloc+js_src
						#print 'js_src 1 : %s'%(js_src)
				if re.search("^//", js_src) is not None:
					if re.search("^//", js_src).group(0) == '//':
						js_src = furl(url).scheme + ':' + js_src
						#print 'js_src 2 : %s' % (js_src)
				if  js_src.startswith('../') or js_src.startswith('./'):
					pass

				#dowload the content as String
				content = self.download_content_as_string(js_src)

			#print 'js_src: %s'%(content)

			for element in disableRightClick_list:
				if element in content:
					Content_Features['disableRightClick'] = 1
					#print 'disableRightClick found'
					break

			for element in changeBarStatus_list:
				if element in content:
					Content_Features['changeBarStatus'] = 1
					#print 'changeBarStatus found'
					break

			for element in redirect_list:
				if element in content:
					redirect_counter += 1
					# print redirect_counter
					if redirect_counter == 4:
						Content_Features['redirect'] = 1
						#print 'redirect found'
						break

			if redirect_counter == 2 or redirect_counter == 3:
				Content_Features['redirect'] = 0

		#print Content_Features
		return Content_Features
