#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import division
from domnibus import Domnibus
from datetime import datetime
from virus_total_apis import PublicApi as VirusTotalPublicApi
from furl import furl
import requests
import certifi

import csv
from googleapiclient.discovery import build
import urllib2
import ssl
import json


class URLIdentity:
	#Virus Total API
	VT_API_KEY = 'a54a233792caf9a764ca929afe100a86ce4931b9361ee76246dcb7f9c74023e6'
	#DNS
	DNS_HEADER=['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT']
	
	#SSL
	#subject and issuer elements are subject_elements and issuer_elements
	FULL_SSL_HEADER=['crlDistributionPoints', 'subjectAltName', 'notBefore', 'caIssuers', 'OCSP', 'serialNumber', 'notAfter', 'version', 'subject', 'issuer']
	subject_elements=['countryName','stateOrProvinceName','localityName','organizationName','commonName']
	issuer_elements=['countryName', 'organizationName', 'commonName']
	SSL_HEADER=['crlDistributionPoints', 'subjectAltName', 'notBefore', 'caIssuers', 'OCSP', 'serialNumber', 'notAfter', 'version']
	ssl_res={}
	
	#WHOIS
	WHOIS_HEADER=['updated_date', "status", "name", "dnssec", "city", "expiration_date", "zipcode", "domain_name", 
			  "country", "whois_server", "state", "registrar", "referral_url", "address", "name_servers", "org", 
			  "creation_date", "emails" ]
	
	PHISHTANK_KEY = '9945f4bf43e847dacfa9ea097e5dc9fa65bca3f2936d3ab01eb924b25ba5a751'
	
	WHOIS_DATA = {}

	def __init__(self, url):
		self.theUrl = url
		if not self.theUrl.startswith('www.'):
			self.theUrl = 'www.'+self.theUrl
		#print self.theUrl
		u = furl(self.theUrl).host
		#print u
		#print type(u)
		u = u.split('www.')[1] if u.startswith('www.') else u
		self.d = Domnibus(u)
		
	def get_url(self):
		#print self.theUrl
		return self.theUrl
	  
	def get_dns(self):
		a = self.d['dns']
		dns_res={}
		for ele in a:
			dns_res[ele] = ';'.join(str(x).encode('utf-8', 'ignore') for x in a[ele]) if a[ele] else 'null'
		return dns_res
	
	def get_ssl(self):
		ssl_details={}
		global ssl_res
		ssl_res = self.d['ssl']
		ssl_subject_res={}
		c = list(ssl_res['subject'])
		
		if 'subject' in ssl_res:
			for v in URLIdentity.subject_elements:
				for cc in c:
					if v==cc[0][0]:
						ssl_subject_res[v] =  str(cc[0][1]).encode('utf-8', 'ignore') if isinstance(cc[0][1], unicode) else cc[0][1]
						break
					else:
						ssl_subject_res[v] = 'null'
		
		ssl_details['subject_countryName'] = str(ssl_subject_res['countryName'])
		ssl_details['subject_stateOrProvinceName'] = str(ssl_subject_res['stateOrProvinceName'])
		ssl_details['subject_localityName'] =  str(ssl_subject_res['localityName'])
		ssl_details['subject_organizationName'] = str(ssl_subject_res['organizationName'])
		ssl_details['subject_commonName'] = str(ssl_subject_res['commonName'])
		
		ssl_issuer_res={}
		c = list(ssl_res['issuer'])
		if 'issuer' in ssl_res:
			for v in URLIdentity.issuer_elements:
				for cc in c:
					if v==cc[0][0]:
						ssl_issuer_res[v] =  str(cc[0][1]).encode('utf-8', 'ignore') if isinstance(cc[0][1], unicode) else cc[0][1]
						break
					else:
						ssl_issuer_res[v] = 'null'
		
		ssl_details['issuer_countryName'] = str(ssl_issuer_res['countryName'])
		ssl_details['issuer_organizationName'] = str(ssl_issuer_res['organizationName'])
		ssl_details['issuer_commonName'] = str(ssl_issuer_res['commonName'])
		
		
		
		crlDistributionPoints = self.get_element('crl_distribution_points')
		STR_crlDistributionPoints = ';'.join(str(x).encode('utf-8', 'ignore') for x in list(crlDistributionPoints)) if crlDistributionPoints != 'null' else 'null'
		ssl_details['crl_distribution_points']=str(STR_crlDistributionPoints)
		
		subjectAltName = self.get_element('subject_alt_name')
		STR_subjectAltName = ';'.join(str(x[1]) for x in list(subjectAltName)) if subjectAltName != 'null' else 'null'
		ssl_details['subject_alt_name'] = str(STR_subjectAltName)
		
		notBefore = self.get_element('not_before').encode('utf-8', 'ignore')
		ssl_details['not_before']=str(notBefore)
		
		caIssuers = self.get_element('ca_issuers')
		STR_caIssuers = ';'.join(str(x).encode('utf-8', 'ignore') for x in list(caIssuers))
		ssl_details['ca_issuers']=STR_caIssuers
		
		OCSP = self.get_element('OCSP')
		STR_OCSP = ';'.join(str(x).encode('utf-8', 'ignore') for x in list(OCSP))
		ssl_details['OCSP'] = STR_OCSP
		
		serialNumber = self.get_element('serial_number').encode('utf-8', 'ignore')
		ssl_details['serial_number'] = serialNumber
		
		notAfter = self.get_element('not_after')
		ssl_details['not_after'] = str(notAfter)
		
		version = str(self.get_element('version'))
		ssl_details['version'] = str(version)
		
		return ssl_details
		
		
	def get_element(self, ele):
		if ele != 'issuer' or ele !='subject':
			return ssl_res[ele] if ele in ssl_res else 'null'

	'''
	def get_whois2(self):
		a = self.d['whois']
		whois_res={}
		for e in a:
			if e == 'status':
				whois_res['status'] = 'null'
			if isinstance(a[e], list):
				whois_res[e]=';'.join(str(x).encode('utf-8', 'ignore') for x in a[e]) if a[e]!='null' else 'null'
			elif isinstance(a[e], unicode):
				whois_res[e] = str(a[e]).encode('utf-8', 'ignore') if a[e]!='null' else 'null'
			elif isinstance(a[e], datetime):
				whois_res[e] = unicode(a[e]) if a[e]!='null' else 'null'
		
		return whois_res
	'''

	def get_whois(self):
		url = self.get_url()
		API_REQUEST = 'http://api.whoapi.com/?apikey=67b4eaf50ddfde2c6463a4e3d8d9e971&r=whois&domain='
		
		url_domain = str(furl(url).netloc)
		data = {}
		try:
			ctx = ssl.create_default_context()
			ctx.check_hostname = False
			ctx.verify_mode = ssl.CERT_NONE
			f = urllib2.urlopen(API_REQUEST + url_domain, context=ctx)
			data = json.loads(f.read())
		except Exception:
			print 'Informations not available for %s, verify you internet connexion or informations are N/A.'%(url_domain)

		return data

	def get_whois3(self):
		url = self.get_url()

		from WhoisData import parser

		domain = [furl(url).netloc]
		drecords = parser.get_data(domain)

		parser.writedata(drecords)

		#parser.test_record(drecords[0])
		import json
		import os
		BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
		Core_folder_name = os.path.join(BASE_DIR, 'Core')
		data_file = os.path.join(Core_folder_name, 'data')
		file_name = os.path.join(data_file, domain[0] + '.json')
		data = json.loads(open(file_name).read().decode('utf8'))


		return data

	def parse_whois_data(self):
		#we extract only useful information that are extracted

		datas={}
		data = self.get_whois3()

		#print json.dumps(data, indent=4, sort_keys=False)

		if 'WhoisRecord' in data:
			#createdDate
			if 'createdDate' in data['WhoisRecord']:
				datas['createdDate'] = data['WhoisRecord']['createdDate']
			elif 'audit' in data['WhoisRecord']:
					if 'createdDate' in data['WhoisRecord']['audit']:
						datas['createdDate'] = data['WhoisRecord']['audit']['createdDate']
					elif 'registryData' in data['WhoisRecord']:
							if 'createdDate' in data['WhoisRecord']['registryData']:
								datas['createdDate'] = data['WhoisRecord']['registryData']['expiresDate']
			else:
				datas['createdDate'] = data['WhoisRecord']['registryData']['createdDateNormalized']

			if  datas['createdDate']:
				datas['createdDate'] = self.parse_date_formats(datas['createdDate'])


			#expiresDate
			if 'expiresDate' in data['WhoisRecord']:
				datas['expiresDate'] = data['WhoisRecord']['expiresDate']
			elif 'audit' in data['WhoisRecord']:
				if 'expiresDate' in data['WhoisRecord']['audit']:
					datas['expiresDate'] = data['WhoisRecord']['audit']['expiresDate']
				elif 'registryData' in data['WhoisRecord']:
					if 'expiresDate' in data['WhoisRecord']['registryData']:
						datas['expiresDate'] = data['WhoisRecord']['registryData']['expiresDate']
			else:
				datas['expiresDate'] = data['WhoisRecord']['registryData']['expiresDateNormalized']

			if datas['expiresDate']:
				datas['expiresDate'] = self.parse_date_formats(datas['expiresDate'])

			#updatedDate
			if 'updatedDate' in data['WhoisRecord']:
				datas['updatedDate'] = data['WhoisRecord']['updatedDate']
			elif 'audit' in data['WhoisRecord']:
				if 'updatedDate' in data['WhoisRecord']['audit']:
					datas['updatedDate'] = data['WhoisRecord']['audit']['updatedDate']
				elif 'registryData' in data['WhoisRecord']:
					if 'updatedDate' in data['WhoisRecord']['registryData']:
						datas['updatedDate'] = data['WhoisRecord']['registryData']['updatedDate']
			else:
					datas['updatedDate'] = data['WhoisRecord']['registryData']['updatedDateNormalized']

			if datas['updatedDate']:
				datas['updatedDate'] = self.parse_date_formats(datas['updatedDate'])

			#Domain Age
			if 'estimatedDomainAge' in data['WhoisRecord']:
				datas['estimatedDomainAge'] = int(data['WhoisRecord']['estimatedDomainAge'])

			#name_servers
			if 'nameServers' in data['WhoisRecord']:
				if 'hostNames' in data['WhoisRecord']['nameServers']:
					datas['name_servers'] = data['WhoisRecord']['nameServers']['hostNames']
			elif 'registryData' in data['WhoisRecord']:
				if 'nameServers' in data['WhoisRecord']['registryData']:
					datas['name_servers'] = data['WhoisRecord']['registryData']['nameServers']['hostNames']

			#Country
			if 'registrant' in data['WhoisRecord']['registryData']:
				if 'country' in data['WhoisRecord']['registryData']['registrant']:
					datas['country'] = data['WhoisRecord']['registryData']['registrant']['country']
			elif 'registrant' in data['WhoisRecord']:
				if 'country' in data['WhoisRecord']['registrant']:
					datas['country'] = data['WhoisRecord']['registrant']['country']
			else:
				if 'administrativeContact' in data['WhoisRecord']:
					if 'country' in data['WhoisRecord']['administrativeContact']:
						datas['country'] = data['WhoisRecord']['administrativeContact']['country']

		return datas

	def parse_date_formats(self, the_str):
		if 'T' in the_str:
			the_str = the_str.split('T')[0]
		if ' ' in the_str:
			the_str = the_str.split(' ')[0]
		if '#' in the_str:
			the_str = the_str.split('#')[0]

		if '-' not in the_str:
			yyyy = the_str[0:4]
			mm = the_str[4:6]
			dd = the_str[6:8]
			new_str = yyyy+'-'+mm+'-'+dd
			the_str = new_str

		return the_str


	
	def SSLfinal_State(self):
		"""
		import M2Crypto
		url = self.get_url()

		if str(furl(url).scheme).lower() == 'https':

			try:
			#Verify if the URL is active and if it has a trusted certificate issuer
				req = requests.get(url, verify=certifi.where())
				#print req.status_code
				#get certificate and verify its life duration
				#parsedUrl = urlparse(url)
				cert = ssl.get_server_certificate((furl(url).host, 443))
				x509 = M2Crypto.X509.load_cert_string(str(cert))
				certif_duration = x509.get_not_after().get_datetime() - x509.get_not_before().get_datetime()
				#print certif_duration
				#Apply the rule
				if req.status_code==200 and (certif_duration.days >= 365):
					return -1
				elif req.status_code!=200:
					return 0
				else : #req.status_code!=200 and (certif_duration.days < 365):
					return 1
			#except requests.exceptions.SSLError:
				#print url + 'has INVALID SSL certificate!'

			except Exception:
				return 1
		else:
			return -1
		"""
		return 1

	def domain_registeration_length(self):
		data = self.get_whois()
		# whois_data = self.get_whois3()
		whois_data = self.parse_whois_data()

		try:
			if 'expiresDate' in whois_data:
				expiresDate = datetime.strptime(str(whois_data['expiresDate']), '%Y-%m-%d')
				if (expiresDate - datetime.today()).days >= 365:
					return -1
				else:
					return 1
			else:
				date_expires = data['date_expires'] if 'date_expires' in data else 'null'
				if date_expires != 'null':
					expiration_date = date_expires.split(' ')[0]
					expiresDate = datetime.strptime(str(expiration_date), '%Y-%m-%d')
					if (expiresDate - datetime.today()).days >= 365:
						return -1
					else:
						return 1
				else:
					return 1
		except Exception:
			return 1

	def domain_age(self):
		url = self.get_url()
		data = self.get_whois()
		#whois_data = self.get_whois3()
		whois_data = self.parse_whois_data()

		if 'estimatedDomainAge' in whois_data:
			if int(whois_data['estimatedDomainAge']) > 365:
				return -1
			elif int(whois_data['estimatedDomainAge']) <= 365:
				return 1
		else:
			creation_date = ""
			expiration_date = ""
			try:
				date_created = data['date_created']
				# print date_created
				date_expires = data['date_expires']
				# print date_expires

				creation_date = date_created.split(' ')[0]
				expiration_date = date_expires.split(' ')[0]

			except KeyError:
				creation_date = whois_data['createdDate'] if 'createdDate' in whois_data else 'null'
				# print date_created
				expiration_date = whois_data['expiresDate'] if 'expiresDate' in whois_data else 'null'

			if (creation_date == 'null') or (expiration_date == 'null'):
				return 1
			else:
				creation_date_Timeobject = datetime.strptime(str(creation_date), '%Y-%m-%d')
				# print creation_date_Timeobject

				expiration_date_Timeobject = datetime.strptime(str(expiration_date), '%Y-%m-%d')
				# print expiration_date_Timeobject

				if (expiration_date_Timeobject - creation_date_Timeobject).days > 365:
					return -1
				elif (expiration_date_Timeobject - creation_date_Timeobject).days <= 365:
					return 1

		

	def Abnormal_URL(self):
		url = self.get_url()
		url_host = str(furl(url).host).split('www.')[1] if str(furl(url).host).startswith('www.') else str(furl(url).host)
		
		all = []
		try:
			whois_data = self.parse_whois_data()
			name_servers = whois_data['name_servers']
		except KeyError:
			data = self.get_whois()
			name_servers = data['nameservers'] if 'nameservers' in data else 'null'

		if name_servers:
			for element in name_servers:
				if element != 'null':
					all.append(str(element).encode('utf-8').lower())
		else:
			return 1
		
		if len(all) == 0:
			return 1
		
		if url_host in all:
			return -1
		else:
			return 1
	
	def download_file(self, url, file_name):
		
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		f = urllib2.urlopen(url, context=ctx)
		data = f.read()
		with open(file_name, "wb") as code:
			code.write(data)
		code.close()
		
	def Statistical_report(self):
		from URLBlackListFeature import URLBlackList
		bl = URLBlackList(self.get_url())
		res = bl.is_blacklisted()
		if res == 1:
			return 1
		else:
			return -1

	def Google_Index(self):
		service = build("customsearch", "v1", developerKey="AIzaSyDzE5nEugzxP09nufDkiufMOcc7X08lr0Y")
	
		res = service.cse().list(q=self.get_url(), cx='017576662512468239146:omuauf_lfve',).execute()
		#print res
		#print res['searchInformation']['totalResults']
		if int(res['searchInformation']['totalResults']) >= 1:
			return -1
		elif int(res['searchInformation']['totalResults']) == 0:
			return 1
	
	def Page_Rank(self):
		import Algorithmia
		
		try:
			input = furl(self.get_url()).netloc
			client = Algorithmia.client('simwKsFblvA5YYjT3NSUVSvbNWE1')
			algo = client.algo('web/PageRank/0.1.0')
			res = algo.pipe(input).result
			#print res
			page_rank_index = sorted(res.values(), reverse=False)[0]
			#print 'page rank index: {},{}'.format(page_rank_index)
			if page_rank_index < 0.2:
				return 1
			else:
				return -1
		except Exception as error:
			return 1

	def web_traffic(self):
		url = self.get_url()
		API_REQUEST = 'http://api.whoapi.com/?apikey=8129a26f2d414177261381cde030f230&r=ranks&domain='
		
		url_domain = str(furl(url).netloc)
		
		try:
			f = urllib2.urlopen(API_REQUEST + url_domain)
			data = json.loads(f.read())

			result= int(data['alexa_popularity'])
			#print result
			if result == -1:
				#print 'Alexa popularity index not Found.'
				return 1

			if result <= 100000:
				return -1
			elif result > 100000:
				return 1
		except Exception:
			return 1
	
	
	def DNSRecord(self):
		dns_record = self.get_dns()
		
		for ele in dns_record:
			if dns_record[ele] != 'null':
				return -1
			else :
				return 1
