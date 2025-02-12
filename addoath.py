import pingid

PROPERTIES_FILE = './pingid.properties'

req_body = {
  org_alias: "111",
  tokens: [
    {
    "serialNumber": "2307211704602", 
    "secretKey": "2952925E2BAA6726567FDD450037851B8659D439", 
    "tokenType": "TOTP",
    "timeStep": "60", 
    "otpLength": "6", 
    "initiatedBy": "ADMIN",
    'userName': 'antonik_adham'
   }
  ]
}

pingid = pingid.PingIDDriver(PROPERTIES_FILE, verbose=True)
response_body = pingid.call('rest/4/createorgtokens/do', req_body)

