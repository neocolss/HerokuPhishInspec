def safeStr(obj):
	try: return str(obj)
	except UnicodeEncodeError:
		return obj.encode('ascii', 'ignore').decode('ascii')
	return ""

def decodePunycode(str):
	import idna
	return safeStr(idna.decode(str))