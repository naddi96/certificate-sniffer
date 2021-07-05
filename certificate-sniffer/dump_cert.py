

import OpenSSL
import time
from dateutil import parser
import binascii
import json

def dump_cert_to_file(cert,file):
    certificato=binascii.b2a_base64( binascii.unhexlify(cert.replace(":",""))).decode('ascii')
    file=open(file,"w")
    file.write(certificato)



nome="smartscreen.microsoft.com.json"

nome="%.cryptocompare.com.json"
cert=open("./cert_errpr/"+nome,"r")
json_dic=json.load(cert)
dump_cert_to_file(json_dic["db"][0],nome+"_db.crt")
dump_cert_to_file(json_dic["snif"][0],nome+"_snif.crt")




'''
cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, binascii.unhexlify(json_dic["snif"][0].replace(":","")))


print(dir(cert))
print(dir(cert))
for i in range(0,cert.get_extension_count()):
    if b'extendedKeyUsage' == cert.get_extension(i).get_short_name():
     #   print( cert.get_extension(i)._subjectAltNameString().replace("DNS:","").split(","))
        if not "client" in cert.get_extension(i).__str__().lower():
            print(cert.get_extension(i).__str__())
'''