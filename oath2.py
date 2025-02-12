import pingid

PROPERTIES_FILE = './pingid.properties'

req_body = {
   "serialNumber": "2307211704602", 
   "otps": [""], 
   "sessionId": [""], 
   "initiatedBy": "ADMIN",
   'userName': 'antonik_adham'
  }

pingid = pingid.PingIDDriver(PROPERTIES_FILE, verbose=True)
response_body = pingid.call('rest/4/resyncoathtoken/do', req_body)

