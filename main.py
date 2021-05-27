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
    with conn:
        
        rows=db.get_certificate(cert_data['name'],conn)
        if len(rows)==0:
            print("inserimento", cert_data['name']) 
            db.insert_certificate(cert_data,conn)
        else:
            hash_db= rows[0][0]
            id= rows[0][2]
            freq=rows[0][1]
            ca_db=rows[0][4]
            if hash_db == cert_data['sha256']:
                db.update_Freq_certificate(id,freq+1,conn)
                print("fai update",cert_data['name'],freq+1)
            else:
                Timestamp_scadenza=rows[0][3]
                now = datetime.now()
                timestamp = datetime.timestamp(now)
                
                if (Timestamp_scadenza < timestamp and 
                    cert_data['valid_to'] > timestamp  and
                    cert_data["CA"]==ca_db):
                    db.update_All_certificate(id,
                                            freq+1,
                                            cert_data["sha256"],
                                            cert_data["certificate"],
                                            conn)
                    print(cert_data['name'],freq+1,"update certificato, certificato scaduto db")
                else:
                    
                    certificate_db=json.loads(rows[0][5])
                    result_oscp=oscp.controlla_oscp(certificate_db)
                    cert_annulato_oscp=False
                    print("controllo oscrp",result_oscp)
                    if result_oscp != "OCSP Status: GOOD":
                        cert_annulato_oscp=True

                    cert_annulato_crl=crl.is_cert_in_crl(certificate_db[0])

                    if cert_data["CA"]==ca_db and (cert_annulato_crl or cert_annulato_oscp):
                        db.update_All_certificate(id,
                                            freq+1,
                                            cert_data["sha256"],
                                            cert_data["certificate"],
                                            conn)
                        print(cert_data['name'],freq+1,"update tutto il certificato, certificato db revocato ")
                    else:
                        
                        certificate_db=json.loads(rows[0][5])
                        cert_snif=json.loads(cert_data["certificate"])
                        jso={"db":certificate_db,"snif":cert_snif}
                        now = datetime.now()
                        timestamp = datetime.timestamp(now)
                        with open(cert_data['name']+'.json', 'w+') as f:
                            # this would place the entire output on one line
                            # use json.dump(lista_items, f, indent=4) to "pretty-print" with four spaces per indent
                            json.dump(jso, f)

                        print(cert_data['name'],cert_data['dns'],"ATTACCOOOOOOOOOOOOOOO")
                    
                    #scarica crl db e vedi se il certificato db stato revocato
                    #e
                    #controlla oscp

            
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
    '''
    for i in range(0,cert.get_extension_count()):
        if b'extendedKeyUsage' == cert.get_extension(i).get_short_name():
        #   print( cert.get_extension(i)._subjectAltNameString().replace("DNS:","").split(","))
            if "client" in cert.get_extension(i).__str__().lower():
                print( name,cert.get_extension(i).__str__())
                return "client certificate"
    '''
    
    
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
        #if certificate_data=="client certificate":
        #   return
        #li=json.loads(certificate_data['certificate'])
        #print(certificate_data['name'])
        #print(oscp.controlla_oscp(li))        
        #print(crl.is_cert_in_crl(li[0]))
        process_certificate_data(certificate_data)

def process_buffer(dict_buffer):
    if 'layers' in dict_buffer:
        try:
            #if dict_buffer['layers']['tcp']['tcp_tcp_srcport']!="443":
            #  print("qualcosa")
            #    return
            if 'tls' in dict_buffer['layers']:
                if type( dict_buffer['layers']['tls'])== list:
                    for tls in dict_buffer['layers']['tls']:
                        if 'tls_tls_handshake_certificate'in tls:
                            certificate_data=load_certificate_info(tls['tls_tls_handshake_certificate'])
                            process_certificate_data(certificate_data)
                            #process_tls(tls)
                
                else:
                    if 'tls_tls_handshake_certificate'in dict_buffer['layers']['tls']:
                            certificate_data=load_certificate_info(dict_buffer['layers']['tls']['tls_tls_handshake_certificate'])
                            process_certificate_data(certificate_data)
        
                    #process_tls(dict_buffer['layers']['tls'])
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
                file = open('raw_input.log', 'a')
                file.write(buff)
                file.close()
                buff = ''
                k = k + 1
    except KeyboardInterrupt:
        sys.stdout.flush()
        pass
