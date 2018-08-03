from virus_total_apis import PublicApi as VirusTotalPublicApi
import json


class URLBlackList:
	VT_API_KEY = 'a54a233792caf9a764ca929afe100a86ce4931b9361ee76246dcb7f9c74023e6'
	
	def __init__(self, URL):

		self.url = URL
	
	def is_blacklisted(self):
		#NEED TO BE REVIEWD, use results only of known antivirus: Google,Bittedefender
		vt = VirusTotalPublicApi(self.VT_API_KEY)
		try:
			#code = vt.scan_url(self.url)
			#print json.dumps(code, indent=4, sort_keys=False)

			response = vt.get_url_report(self.url)
			#print json.dumps(response, indent=4, sort_keys=False)

			if response['results']['response_code'] == 0:
				return -1
			#print response['results']['positives']
			elif response['results']['response_code'] ==1 :
				#print ('yes')
				return 1

		except Exception:
			return 1
"""
if __name__ == "__main__":
	#from URLBlackListFeature import URLBlackList
	url = 'http://infinitesols.com/components/vlews/dir/index.htm'
	BL = URLBlackList(url)
	if BL.is_blacklisted() == 1:
		print '{} is already Blacklisted!'.format(url)
			#break
	else:
		print '{} is not yet Blacklisted, It will process batch treatment:'.format(url)
"""
