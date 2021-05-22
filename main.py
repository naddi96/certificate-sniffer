from datetime import date
from os import name
from sqlite3.dbapi2 import Timestamp
import sys
import time
import json
import binascii
from hashlib import sha256
import OpenSSL
from dateutil import parser
import db
from datetime import datetime
import oscp 
import crl


def process_certificate_data(cert_data):
    
    conn = db.create_connection()
    cert=cert_data["certificate"]
    with conn:
        
        rows=db.get_certificate(cert_data['name'],conn)
        if len(rows)==0:
            print("inserimento", cert_data['name']) 
            db.insert_certificate(cert_data,conn)
        else:
            hash_db= rows[0][0]
            id= rows[0][2]
            freq=rows[0][1]
            
            if hash_db == cert_data['sha256']:
                db.update_certificate(id,freq+1,conn)
                print("fai update",cert_data['name'],freq+1)
            else:
                Timestamp_scadenza=rows[0][3]
                now = datetime.now()
                timestamp = datetime.timestamp(now)
                if Timestamp_scadenza < timestamp:
                    print("certificato scaduto")
                    ca=rows[0][4]
                    if cert_data["CA"]==ca:
                        print("update certificato")
                    else:
                        print("ATTACCOooo")
                else:
                    #scarica crl db e vedi se il certificato db stato revocato
                    #e
                    #controlla oscp
                    print(cert_data['name'],id,"ATTACCOOOOOOOOOOOOOOOOOOOO")
                print()
            
    #print(cert_data)



def load_certificate_info(cer):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, binascii.unhexlify(cer[0].replace(":","")))
    dns_set=set()

    for i in range(0,cert.get_extension_count()):
        if b"subjectAltName" == cert.get_extension(i).get_short_name():
                
                dns_set=set(cert.get_extension(i)
                                ._subjectAltNameString()
                                .replace("DNS:","")
                                .replace("*","%")
                                .replace(" ","")
                                .split(","))
    
    name=""
    for item in cert.get_subject().get_components():
        if item[0]==b"CN":
            name=item[1].decode("utf-8").replace("*","%").replace(" ","")
            dns_set.add(name)       

    valid_from = parser.parse(cert.get_notBefore().decode("UTF-8")).timestamp() #strftime('%Y-%m-%d %H:%M:%S') 
    valid_to = parser.parse(cert.get_notAfter().decode("UTF-8")).timestamp()
    ca=""
    for item in cert.get_issuer().get_components():
        if item[0]==b"CN":
            ca=item[1].decode("utf-8")
    sha_256=sha256(cer[0].encode('utf-8')).hexdigest()
    return {
            "name":name,
            "dns":dns_set,
            "valid_from":valid_from, 
            "valid_to":valid_to,
            "CA":ca,
            "sha256":sha_256 ,
            "certificate":json.dumps(cer)
            }


def process_tls(tls_dict):
    if 'tls_tls_handshake_certificate'in tls_dict:
        certificate_data=load_certificate_info(tls_dict['tls_tls_handshake_certificate'])
        #li=json.loads(certificate_data['certificate'])
        #print(certificate_data['name'])
        #print(oscp.controlla_oscp(li))        
        #print(crl.is_cert_in_crl(li[0]))
        process_certificate_data(certificate_data)

def process_buffer(dict_buffer):
    if 'layers' in dict_buffer:
        try:
            if 'tls' in dict_buffer['layers']:
                ip = dict_buffer['layers']['ip']['ip_ip_src']
                if type( dict_buffer['layers']['tls'])== type([]):
                    for tls in dict_buffer['layers']['tls']:
                        process_tls(tls)
                else:
                    process_tls(dict_buffer['layers']['tls'])
        except Exception as e:
                                print(e.with_traceback)
                                print(e)




if __name__ == '__main__':
# .\Wireshark\tshark.exe -i Ethernet -T ek  -Y tls.handshake.certificate | python main.py
    k=0
    try:
        buff = ''
        while True:
            buff += sys.stdin.read(1)
            if buff.endswith('\n'):
                dict_buffer=json.loads(buff[:-1])
                process_buffer(dict_buffer)    
                
                
                
                
                
                
                buff = ''
                k = k + 1
    except KeyboardInterrupt:
        sys.stdout.flush()
        pass
    