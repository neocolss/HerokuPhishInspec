# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import sys
from URLIdentity import URLIdentity
from URLContent import URLContent
from URLLexicalFeatures import URLLexical
from URLBlackListFeature import URLBlackList
import json
from furl import furl
import Utils
import validators

class Core():
	HTTP_SUCESS_CODES=range(200,211)
	HTTP_SUCESS_CODES.append(226)
	list1=range(400, 419)
	list2=range(421, 432)
	list3=range(449, 452)
	list3.append(456)
	list4 = [444, 495, 496, 497, 499]
	list5=range(500, 512)
	list6= range(520, 528)

	HTTP_ERROR_CODES= list1 + list2 + list3 + list4 + list5 + list6

	def __init__(self, url):
		self.is_redirected = 0
		self.is_error = 0

		self.original_url = url
		self.URL = url

		#Test if the url is technically in valid format
		if self.verify_url_technical_format() == 1:
			#print('URL not valid')
			sys.exit(1)


		import urllib
		self.URL = urllib.quote_plus(self.URL.encode('utf-8'), safe=':/@?')


		# Detect Shortening Services
		self.lexical = URLLexical(self.original_url)
		self.is_short_service = self.lexical.does_it_use_shorteningService()
		#if self.is_short_service == 1:
			#print 'Shortening service detected.'

		import requests
		try:
			r = requests.get(self.URL)
			#print "status code: %s"%r.status_code
			if r.status_code in Core.HTTP_SUCESS_CODES:

				if r.history :
					if r.history[0].status_code in range (300, 311):
						self.is_redirected = 1
						self.URL = r.url
						#print 'the new URL to be treated: %s' % (self.URL)

				#print 'url at this time: %s' % (self.URL)
				# treat punycode URL
				if str(furl(self.URL).netloc).startswith('xn--'):

					# netloc = str(furl(url).netloc)
					# print netloc
					net_loc = Utils.decodePunycode(furl(self.URL).netloc)
					#print 'net_loc: %s' % net_loc
					self.URL = furl(self.URL).scheme + '://' + net_loc + str(furl(self.URL).path)
					#print 'new url : %s' % (self.URL)

				"""
				self.lexical = URLLexical(self.URL)
				self.identity = URLIdentity(self.URL)
				self.content = URLContent(self.URL)
				self.blackListed = URLBlackList(self.URL)
				"""
			elif r.status_code in Core.HTTP_ERROR_CODES:

				self.is_error = 1
				#print r.raise_for_status()
				return
		except requests.exceptions.RequestException as e:
			print "Error with url probably : {}".format(e)
			sys.exit(1)

	def verify_url_technical_format(self):
		url = self.get_parent_url()

		if validators.url(url) == True:
			return 0
		else:
			return 1

	def get_parent_url(self):
		return self.original_url

	def is_redirected(self):
		return self.is_redirected

	def get_new_url(self):
		return self.URL

	def process_test_url(self, url):
		#print 'URL: %s'%self.URL
		lexical = URLLexical(self.URL)
		identity = URLIdentity(self.URL)

		EXTRACTED_FEATURES = {}
		EXTRACTED_FEATURES_LIST = []

		#print '-----------------------------------------------------'
		#print '*_*      GENERAL INFORMATIONS ON THIS DOMAIN:     *_*'
		#data = self.identity.get_whois()
		#print json.dumps(data, indent=4, sort_keys=False)
		#print '*_*      GENERAL INFORMATIONS ON THIS DOMAIN FINISHED.     *_*'
		#print '-----------------------------------------------------'
		#print '* EXTRACTING FEATURES ... ==>'
		# 1.1. Address Bar based Features
		#print '----'
		#print '*** 1.1. Address Bar based Features: ***'
		# 1.1.1.Using the IP Address
		EXTRACTED_FEATURES['having_IP_Address'] = lexical.having_IP_Address()
		#print '1.1.1.Using the IP Address:{}'.format(EXTRACTED_FEATURES['having_IP_Address'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['having_IP_Address']))

		# 1.1.2.Long URL to Hide the Suspicious Part
		EXTRACTED_FEATURES['URL_Length'] = lexical.url_length()
		#print '1.1.2.Long URL to Hide the Suspicious Part:{}'.format(EXTRACTED_FEATURES['URL_Length'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['URL_Length']))

		# 1.1.3.Using URL Shortening Services “TinyURL”
		if self.is_short_service == 1:
			EXTRACTED_FEATURES['Shortining_Service'] = 1
		else:
			EXTRACTED_FEATURES['Shortining_Service'] = -1
		#print '1.1.3.Using URL Shortening Services:{}'.format(EXTRACTED_FEATURES['Shortining_Service'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Shortining_Service']))

		# 1.1.4.URL’s having “@” Symbol
		EXTRACTED_FEATURES['having_At_Symbol'] = lexical.having_At_Symbol()
		#print '1.1.4.URL’s having “@” Symbol:{}'.format(EXTRACTED_FEATURES['having_At_Symbol'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['having_At_Symbol']))

		# 1.1.5.Redirecting using “//”
		EXTRACTED_FEATURES['double_slash_redirecting'] = lexical.double_slash_redirecting()
		#print '1.1.5.Redirecting using “//”:{}'.format(EXTRACTED_FEATURES['double_slash_redirecting'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['double_slash_redirecting']))

		# 1.1.6.Adding Prefix or Suffix Separated by (-) to the Domain
		EXTRACTED_FEATURES['Prefix_Suffix'] = lexical.prefix_suffix()
		#print '1.1.6.Adding Prefix or Suffix Separated by (-) to the Domain:{}'.format(EXTRACTED_FEATURES['Prefix_Suffix'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Prefix_Suffix']))

		# 1.1.7.Sub Domain and Multi Sub Domains
		EXTRACTED_FEATURES['having_Sub_Domain'] = lexical.having_sub_domain()
		#print '1.1.7.Sub Domain and Multi Sub Domains:{}'.format(EXTRACTED_FEATURES['having_Sub_Domain'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['having_Sub_Domain']))

		# 1.1.8.HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)
		EXTRACTED_FEATURES['SSLfinal_State'] = identity.SSLfinal_State()
		#print '1.1.8.HTTPS Final State:{}'.format(EXTRACTED_FEATURES['SSLfinal_State'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['SSLfinal_State']))

		# 1.1.9.Domain Registration Length
		EXTRACTED_FEATURES['Domain_registeration_length'] = identity.domain_registeration_length()
		#print '1.1.9.Domain Registration Length:{}'.format(EXTRACTED_FEATURES['Domain_registeration_length'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Domain_registeration_length']))

		#from time import sleep
		#sleep(5)
		content = URLContent(self.URL)
		# 1.1.10. Favicon
		EXTRACTED_FEATURES['Favicon'] = content.Favicon()
		#print '1.1.10. Favicon:{}'.format(EXTRACTED_FEATURES['Favicon'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Favicon']))

		# 1.1.11. Using Non-Standard Port
		EXTRACTED_FEATURES['port'] = lexical.non_standard_port_use()
		#print '1.1.11. Using Non-Standard Port:{}'.format(EXTRACTED_FEATURES['port'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['port']))

		# 1.1.12. The Existence of “HTTPS” Token in the Domain Part of the URL
		EXTRACTED_FEATURES['HTTPS_token'] = lexical.is_https_in_domain()
		#print '1.1.12. The Existence of “HTTPS” Token in the Domain Part of the URL:{}'.format(EXTRACTED_FEATURES['HTTPS_token'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['HTTPS_token']))

		# 1.2. Abnormal Based Features
		#print '-----'
		#print '*** 1.2. Abnormal Based Features: ***'
		# 1.2.1. Request URL
		EXTRACTED_FEATURES['Request_URL'] = content.Request_URL()
		#print '1.2.1. Request URL:{}'.format(EXTRACTED_FEATURES['Request_URL'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Request_URL']))

		# 1.2.2. URL of Anchor
		EXTRACTED_FEATURES['URL_of_Anchor'] = content.get_anchor_links()
		#print '1.2.2. URL of Anchor:{}'.format(EXTRACTED_FEATURES['URL_of_Anchor'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['URL_of_Anchor']))

		# 1.2.3. Links in <Meta>, <Script> and <Link> tags
		EXTRACTED_FEATURES['Links_in_tags'] = content.get_meta_link_script_links()
		#print '1.2.3. Links in <Meta>, <Script> and <Link> tags:{}'.format(EXTRACTED_FEATURES['Links_in_tags'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Links_in_tags']))

		# 1.2.4. Server Form Handler (SFH)
		EXTRACTED_FEATURES['SFH'] = content.SFH()
		#print '1.2.4. Server Form Handler (SFH):{}'.format(EXTRACTED_FEATURES['SFH'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['SFH']))

		# 1.2.5. Submitting Information to Email
		EXTRACTED_FEATURES['Submitting_to_email'] = content.Submitting_to_email()
		#print '1.2.5. Submitting Information to Email:{}'.format(EXTRACTED_FEATURES['Submitting_to_email'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Submitting_to_email']))

		# 1.2.6. Abnormal URL
		EXTRACTED_FEATURES['Abnormal_URL'] = identity.Abnormal_URL()
		#print '1.2.6. Abnormal URL:{}'.format(EXTRACTED_FEATURES['Abnormal_URL'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Abnormal_URL']))

		# 1.3. HTML and JavaScript based Features
		#print '-------'
		#print '*** 1.3. HTML and JavaScript based Features: ***'
		# 1.3.1. Website Forwarding
		content_features = content.get_Content_Features_directAccess()
		EXTRACTED_FEATURES['Redirect'] = content_features['redirect']
		#print '1.3.1. Website Forwarding: {}'.format(EXTRACTED_FEATURES['Redirect'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Redirect']))

		# 1.3.2. Status Bar Customization
		EXTRACTED_FEATURES['on_mouseover'] = content_features['changeBarStatus']
		#print '1.3.2. Status Bar Customization: {}'.format(EXTRACTED_FEATURES['on_mouseover'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['on_mouseover']))

		# 1.3.3. Disabling Right Click
		EXTRACTED_FEATURES['RightClick'] = content_features['disableRightClick']
		#print '1.3.3. Disabling Right Click: {}'.format(EXTRACTED_FEATURES['RightClick'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['RightClick']))

		# 1.3.4. Using Pop-up Window
		EXTRACTED_FEATURES['popUpWidnow'] = -1
		#print '1.3.4. Using Pop-up Window: {}'.format(EXTRACTED_FEATURES['popUpWidnow'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['popUpWidnow']))

		# 1.3.5. IFrame Redirection
		EXTRACTED_FEATURES['Iframe'] = content.Iframe()
		#print '1.3.5. IFrame Redirection: {}'.format(EXTRACTED_FEATURES['Iframe'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Iframe']))

		# 1.4. Domain based Features
		##print '-----------'
		#print '***  1.4.1. Age of Domain: ***'
		# 1.4.1. Age of Domain
		EXTRACTED_FEATURES['age_of_domain'] = identity.domain_age()
		#print '1.4.1. Age of Domain: {}'.format(EXTRACTED_FEATURES['age_of_domain'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['age_of_domain']))

		# 1.4.2. DNS Record
		EXTRACTED_FEATURES['DNSRecord'] = identity.DNSRecord()
		#print '1.4.2. DNS Record: {}'.format(EXTRACTED_FEATURES['DNSRecord'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['DNSRecord']))

		# 1.4.3. Website Traffic
		EXTRACTED_FEATURES['web_traffic'] = identity.web_traffic()
		#print '1.4.3. Website Traffic: {}'.format(EXTRACTED_FEATURES['web_traffic'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['web_traffic']))

		# 1.4.4. PageRank
		EXTRACTED_FEATURES['Page_Rank'] = identity.Page_Rank()
		#print '1.4.4. PageRank: {}'.format(EXTRACTED_FEATURES['Page_Rank'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Page_Rank']))

		# 1.4.5. Google Index
		EXTRACTED_FEATURES['Google_Index'] = identity.Google_Index()
		#print '1.4.5. Google Index: {}'.format(EXTRACTED_FEATURES['Google_Index'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Google_Index']))

		# 1.4.6. Number of Links Pointing to Page
		EXTRACTED_FEATURES['Links_pointing_to_page'] = content.Links_pointing_to_page()
		#print '1.4.6. Number of Links Pointing to Page: {}'.format(EXTRACTED_FEATURES['Links_pointing_to_page'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Links_pointing_to_page']))

		# 1.4.7. Statistical-Reports Based Feature
		EXTRACTED_FEATURES['Statistical_report'] = identity.Statistical_report()
		#print '1.4.7. Statistical-Reports: {}'.format(EXTRACTED_FEATURES['Statistical_report'])
		EXTRACTED_FEATURES_LIST.append(int(EXTRACTED_FEATURES['Statistical_report']))

		return [EXTRACTED_FEATURES_LIST, EXTRACTED_FEATURES]


	def main_batch(self):
		analysis_results = {}

		url = self.URL

		if self.is_error != 1:

			blackListed = URLBlackList(url)
			is_blacklisted = blackListed.is_blacklisted()
			if  is_blacklisted == 1:
				analysis_results['is_blacklisted'] = '{} is already Blacklisted!'.format(furl(url).netloc)
			else:
				analysis_results['is_blacklisted'] = '{} is not Blacklisted!'.format(furl(url).netloc)

			#print '-- Batch Processing Started: -->'
			# If not continue batch analysis
			result_process = self.process_test_url(url)
			features = result_process[0]

			analysis_results['features_list'] = features
			analysis_results['features_dict'] = result_process[1]

			#print '<-- Batch Processing Finished.'


			#print 'Model Building and Classification Process Started: -->'

			from  Core.machineLearning import SVMClassifier
			svm = SVMClassifier.SVM_Classify(features)
			analysis_results['svm'] = svm
			
			from Core.machineLearning import KNNClassifier
			knn =  KNNClassifier.KNN_Classify(features)
			analysis_results['knn'] = knn

			from Core.machineLearning import DecisionTreeClassifier
			dstree = DecisionTreeClassifier.DecisionTree_Classify(features)
			analysis_results['descionTree'] = dstree

			from Core.machineLearning import NaiveBayesClassifier
			nb = NaiveBayesClassifier.naive_bayes_Classify(features)

			from Core.machineLearning import LogisticRegression
			lr = LogisticRegression.LogisticRegression_Classify(features)
			analysis_results['logisticRegression'] = lr

			from Core.machineLearning import RandomForestClassifier
			rf = RandomForestClassifier.RandomForest_Classify(features)
			analysis_results['RandomForest'] = rf
			

			#print '<-- Model Building and Classification Process Finished.'

			final_result = ''
			for key, value in analysis_results.iteritems():
				if key in ['RandomForest', 'logisticRegression', 'descionTree', 'knn', 'svm']:
					for result in value:
						if int(result) == 1:
							final_result = 'this web page is detected as phishing !'
						else:
							final_result = 'this web page appears safe.'
			
			if (is_blacklisted == 1) and (final_result=='this web page appears safe.'):
				final_result = 'but this web page appears safe.'
			
			
			analysis_results['final_result'] = final_result
			"""
			#delete some files to gain space
			try:
				import os
				BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
				if os.path.exists('data.csv'):
					os.remove('data.csv')
					
				folder_Core = os.path.join(BASE_DIR, 'Core')
				if os.path.exists('data.csv'):
					os.remove('data.csv')

				folder_data = os.path.join(folder_Core, 'data')

				for file in os.listdir(folder_data):
					if file.endswith(".json"):
						os.remove(file)
			except Exception:
				pass
			"""


			return analysis_results
		else:
			return
