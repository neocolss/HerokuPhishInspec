# -*- coding: utf-8 -*-
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import os


def RandomForest_Classify(test_array):
	#Get Core Directory
	CORE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	DATA_DIR = os.path.join(CORE_DIR, 'data')
	fname = os.path.join(DATA_DIR, 'data_original.csv')
	# Importing the dataset
	dataset = pd.read_csv(fname)
	#headers=["having_IP_Address","URL_Length,Shortining_Service","having_At_Symbol","double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State","Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL","URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL","Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain","DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page","Statistical_report"]

	X = dataset.iloc[:, 0:-1].values
	#print X
	y = dataset.iloc[:,-1].values
	#print y

	# Feature Scaling
	sc = StandardScaler()
	X_train = sc.fit_transform(X)
	test_array = [test_array]

	results = []
	list_criterion = ['gini', 'entropy']
	for criterion in list_criterion:
		classifier = RandomForestClassifier(n_estimators=10, criterion=criterion, random_state=0)
		classifier.fit(X_train, y)
		predict = classifier.predict(test_array)
		#print predict
		results.append(predict[0])
	return results

"""
if __name__=='__main__':
	test = [-1, 0, 1, -1, -1, -1, 0, -1, 1, -1, -1, -1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, -1, 1, 1, 1, 1, 1]
	print RandomForest_Classify(test)
"""