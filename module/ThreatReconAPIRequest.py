# Treath Recon (tm) API requester (modify for Python3 by @yenos)
# more info: https://www.threatrecon.co/api
# original repo: https://github.com/Bart-o/ThreatRecon

import urllib.request
import urllib.parse
import json

def queryTR(indicator, api_key):
    params = urllib.parse.urlencode({'api_key': api_key, 'indicator': indicator}).encode('utf-8')
    f = urllib.request.urlopen("https://api.threatrecon.co/api/v1/search", params).read()
    data = json.loads(f.decode())
    results = data["Results"]
    return results

