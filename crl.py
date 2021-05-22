
import OpenSSL
import time
from dateutil import parser
import binascii
import requests
from validators import domain, url


def convert_to_hex(string):
    an_integer = int(string.decode('utf-8'), 16)
    hex_value = hex(an_integer)
    return hex_value

def get_crl_response(crl_url: str):

    """ Send OCSP request to ocsp responder and retrieve response """

    func_name: str = "get_ocsp_response"
    crl_url=crl_url.replace(" ","")
    # Confirm that the ocsp_url is a valid url
    if not url(crl_url):
        raise Exception(f"{func_name}: URL failed validation for {crl_url}")

    try:
        crl_response = requests.get(
            crl_url,
            timeout=5,
        )

    except requests.exceptions.Timeout:
        raise Exception(f"{func_name}: Request timeout for {crl_url}") from None

    except requests.exceptions.ConnectionError:
        raise Exception(f"{func_name}: Unknown Connection Error to {crl_url}") from None

    except requests.exceptions.RequestException:
        raise Exception(f"{func_name}: Unknown Connection Error to {crl_url}") from None

    return crl_response



def is_cert_in_crl(cert3):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, binascii.unhexlify(cert3.replace(":","")))
    crl_link=[]
    for i in range(0,cert.get_extension_count()):
        if b'crlDistributionPoints' == cert.get_extension(i).get_short_name():
        #   print( cert.get_extension(i)._subjectAltNameString().replace("DNS:","").split(","))
            crl_link=cert.get_extension(i).__str__().replace("\nFull Name:\n","").replace(" URI:","").split("\n")[:-1]
    if crl_link==[]:
        return "MISSING CRL"

    try:
        x=get_crl_response(crl_link[0])

        crl=OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1,x.content)
        cert_serial=hex(cert.get_serial_number())
        for serial in crl.get_revoked():
            crl_hex_serial=convert_to_hex(serial.get_serial())
            if cert_serial== crl_hex_serial:
                return True
        return False
    except:
            return "CONNECTION ERROR"

if __name__ == '__main__':
    cert3= "30:82:07:bd:30:82:05:a5:a0:03:02:01:02:02:13:7f:00:00:60:63:de:96:e9:1c:68:8c:f9:28:00:00:00:00:60:63:30:0d:06:09:2a:86:48:86:f7:0d:01:01:0b:05:00:30:4f:31:0b:30:09:06:03:55:04:06:13:02:55:53:31:1e:30:1c:06:03:55:04:0a:13:15:4d:69:63:72:6f:73:6f:66:74:20:43:6f:72:70:6f:72:61:74:69:6f:6e:31:20:30:1e:06:03:55:04:03:13:17:4d:69:63:72:6f:73:6f:66:74:20:52:53:41:20:54:4c:53:20:43:41:20:30:32:30:1e:17:0d:32:30:31:30:30:35:32:31:32:39:31:31:5a:17:0d:32:31:31:30:30:35:32:31:32:39:31:31:5a:30:26:31:24:30:22:06:03:55:04:03:0c:1b:2a:2e:76:6f:72:74:65:78:2e:64:61:74:61:2e:6d:69:63:72:6f:73:6f:66:74:2e:63:6f:6d:30:82:01:22:30:0d:06:09:2a:86:48:86:f7:0d:01:01:01:05:00:03:82:01:0f:00:30:82:01:0a:02:82:01:01:00:e5:6f:69:77:0a:f7:6d:d2:2e:5d:95:1d:30:64:47:6d:39:b9:2b:55:ea:ad:bb:2d:a6:c9:7e:89:77:92:50:73:87:9e:70:15:b3:7b:5f:64:c4:57:b7:3b:16:55:af:fc:20:c0:02:96:a5:aa:50:76:1e:70:ef:79:c1:4c:b3:5a:91:8e:7d:72:1b:4b:7d:86:54:59:11:14:c6:38:24:12:cb:a4:e6:a3:db:f9:b9:c6:4f:8a:c9:ae:fd:2a:be:e1:b9:6a:17:12:57:a9:e0:1e:cf:44:e4:c9:a9:9b:fc:e5:28:03:94:9a:ee:e6:7e:5a:3a:b0:dd:cc:34:a8:fd:8a:3a:4a:d8:8e:7a:64:3f:ef:b1:23:48:ee:7b:2a:d1:aa:be:6f:aa:51:27:1d:ad:3a:2c:c4:b2:50:0d:2b:32:6a:30:60:10:ec:7d:95:93:0e:d3:45:58:24:01:df:09:17:a0:95:fb:c9:93:86:61:26:8c:65:bc:68:66:77:38:c3:02:9a:c3:72:87:cd:6c:4d:df:68:4f:60:ac:e0:e7:c0:7d:71:af:19:59:6b:09:3e:c3:ac:be:6c:cc:f0:8b:84:62:98:7a:be:4d:99:89:54:a9:f9:59:e1:c2:32:4a:8f:77:f3:38:bf:12:d4:d3:06:a6:30:48:5a:ac:f6:ea:71:02:03:01:00:01:a3:82:03:b9:30:82:03:b5:30:82:01:03:06:0a:2b:06:01:04:01:d6:79:02:04:02:04:81:f4:04:81:f1:00:ef:00:74:00:7d:3e:f2:f8:8f:ff:88:55:68:24:c2:c0:ca:9e:52:89:79:2b:c5:0e:78:09:7f:2e:6a:97:68:99:7e:22:f0:d7:00:00:01:74:fa:b4:4f:32:00:00:04:03:00:45:30:43:02:1f:30:6f:82:59:67:00:b4:0b:9d:eb:ba:8c:b8:fe:4d:a0:24:29:f0:93:95:26:14:f9:7b:e3:f6:24:46:9b:21:02:20:72:a1:32:ef:c2:ec:cf:0d:ed:1a:40:1e:e6:cb:9e:71:da:9f:b4:0e:5f:5e:5d:09:25:6a:19:09:ee:d7:13:93:00:77:00:ee:c0:95:ee:8d:72:64:0f:92:e3:c3:b9:1b:c7:12:a3:69:6a:09:7b:4b:6a:1a:14:38:e6:47:b2:cb:ed:c5:f9:00:00:01:74:fa:b4:51:00:00:00:04:03:00:48:30:46:02:21:00:8f:a5:23:f8:19:8d:c7:58:31:2e:42:d4:fa:4c:47:a8:f3:aa:aa:0a:73:f8:64:44:5c:39:7c:33:58:b0:06:b7:02:21:00:ce:5d:a5:e7:6c:d1:87:4c:86:17:43:f6:bc:9e:9b:be:6f:06:ff:48:cd:b3:2d:f9:f8:2a:05:cb:1c:44:6a:f5:30:27:06:09:2b:06:01:04:01:82:37:15:0a:04:1a:30:18:30:0a:06:08:2b:06:01:05:05:07:03:01:30:0a:06:08:2b:06:01:05:05:07:03:02:30:3e:06:09:2b:06:01:04:01:82:37:15:07:04:31:30:2f:06:27:2b:06:01:04:01:82:37:15:08:87:da:86:75:83:ee:d9:01:82:c9:85:1b:81:b5:9e:61:85:f4:eb:60:81:5d:85:86:8e:41:87:c2:98:50:02:01:64:02:01:25:30:81:87:06:08:2b:06:01:05:05:07:01:01:04:7b:30:79:30:53:06:08:2b:06:01:05:05:07:30:02:86:47:68:74:74:70:3a:2f:2f:77:77:77:2e:6d:69:63:72:6f:73:6f:66:74:2e:63:6f:6d:2f:70:6b:69:2f:6d:73:63:6f:72:70:2f:4d:69:63:72:6f:73:6f:66:74:25:32:30:52:53:41:25:32:30:54:4c:53:25:32:30:43:41:25:32:30:30:32:2e:63:72:74:30:22:06:08:2b:06:01:05:05:07:30:01:86:16:68:74:74:70:3a:2f:2f:6f:63:73:70:2e:6d:73:6f:63:73:70:2e:63:6f:6d:30:1d:06:03:55:1d:0e:04:16:04:14:a9:54:48:21:a7:6e:cd:8c:0e:ca:9c:2c:46:ca:9c:23:32:2e:b8:84:30:0b:06:03:55:1d:0f:04:04:03:02:04:b0:30:41:06:03:55:1d:11:04:3a:30:38:82:1b:2a:2e:76:6f:72:74:65:78:2e:64:61:74:61:2e:6d:69:63:72:6f:73:6f:66:74:2e:63:6f:6d:82:19:76:6f:72:74:65:78:2e:64:61:74:61:2e:6d:69:63:72:6f:73:6f:66:74:2e:63:6f:6d:30:81:b0:06:03:55:1d:1f:04:81:a8:30:81:a5:30:81:a2:a0:81:9f:a0:81:9c:86:4d:68:74:74:70:3a:2f:2f:6d:73:63:72:6c:2e:6d:69:63:72:6f:73:6f:66:74:2e:63:6f:6d:2f:70:6b:69:2f:6d:73:63:6f:72:70:2f:63:72:6c:2f:4d:69:63:72:6f:73:6f:66:74:25:32:30:52:53:41:25:32:30:54:4c:53:25:32:30:43:41:25:32:30:30:32:2e:63:72:6c:86:4b:68:74:74:70:3a:2f:2f:63:72:6c:2e:6d:69:63:72:6f:73:6f:66:74:2e:63:6f:6d:2f:70:6b:69:2f:6d:73:63:6f:72:70:2f:63:72:6c:2f:4d:69:63:72:6f:73:6f:66:74:25:32:30:52:53:41:25:32:30:54:4c:53:25:32:30:43:41:25:32:30:30:32:2e:63:72:6c:30:57:06:03:55:1d:20:04:50:30:4e:30:42:06:09:2b:06:01:04:01:82:37:2a:01:30:35:30:33:06:08:2b:06:01:05:05:07:02:01:16:27:68:74:74:70:3a:2f:2f:77:77:77:2e:6d:69:63:72:6f:73:6f:66:74:2e:63:6f:6d:2f:70:6b:69:2f:6d:73:63:6f:72:70:2f:63:70:73:30:08:06:06:67:81:0c:01:02:01:30:1f:06:03:55:1d:23:04:18:30:16:80:14:ff:2f:7f:e1:06:f4:38:f3:2d:ed:25:8d:98:c2:fe:0e:f6:6c:fc:fa:30:1d:06:03:55:1d:25:04:16:30:14:06:08:2b:06:01:05:05:07:03:01:06:08:2b:06:01:05:05:07:03:02:30:0d:06:09:2a:86:48:86:f7:0d:01:01:0b:05:00:03:82:02:01:00:5d:19:ab:ef:2e:2e:ba:8b:78:b2:8b:12:11:d0:fc:71:77:5c:8f:9f:f5:c5:88:f5:3c:48:9c:2c:3c:98:69:1d:d4:e2:0d:f8:5b:6d:de:52:1c:af:c4:e6:a0:7a:70:c3:87:f8:3c:bd:b0:0b:78:dc:2d:22:bb:5b:c9:b6:77:e6:d4:91:16:83:6e:2b:b0:e3:41:35:ff:75:80:90:22:a3:77:3a:e9:a1:84:e1:e6:62:b4:7b:e5:65:75:ce:0a:b0:14:16:15:10:cb:22:7a:10:37:bb:3a:af:3e:78:e4:58:c6:5f:e5:65:65:12:e2:c1:31:13:49:d8:ba:0e:c4:fe:7e:af:24:5c:c3:75:61:79:3d:ec:96:25:4b:e1:55:5c:9f:56:60:bc:3e:05:87:cc:9a:72:11:47:0d:54:9a:ec:ce:22:5c:9d:26:60:1d:3b:42:07:a3:3b:54:aa:c6:c8:37:b7:a9:5e:ce:a9:ca:fd:df:c3:e4:24:10:10:9b:22:f6:96:d9:bc:fc:e1:b0:43:8e:ab:53:6f:0e:f2:ed:a8:c5:80:b5:33:ea:45:df:9e:08:9a:f3:bc:b3:1a:8e:bd:3f:85:d0:23:0e:ae:92:9a:50:8a:4a:10:5c:bf:3c:b0:88:1f:3d:d0:02:86:d5:e8:2b:c2:31:39:7b:92:86:f3:82:c5:b8:0b:16:c2:dd:be:b6:fd:9e:e2:44:d5:f1:e6:15:86:f4:b6:de:7a:5b:f6:d6:4f:3c:0d:99:51:95:29:28:55:76:ea:2a:82:32:00:b4:43:dd:6f:d6:f9:89:68:42:a9:0b:df:02:e1:8b:79:23:c7:09:1f:3f:9d:ab:4e:03:98:59:80:61:93:dc:c2:cf:e9:4d:6e:da:86:10:41:8c:da:66:41:f2:44:fb:a7:d3:b8:ca:05:bf:f0:90:f1:a9:6a:05:1c:a3:3e:70:44:51:ee:2a:b6:6b:4b:f9:0c:e1:8b:6f:09:51:55:eb:46:7b:5e:10:87:d4:d6:c8:ac:25:ce:8d:f0:c6:11:5a:e1:17:e3:60:79:f2:2c:82:23:6e:c2:06:fe:de:a0:86:eb:f3:77:ef:49:53:d2:5c:90:9b:1a:90:85:14:71:5b:bd:d2:1c:94:b8:d3:88:2d:7a:5c:59:21:4b:19:38:8c:25:98:91:af:2b:04:67:94:fb:16:9a:8e:04:bf:80:0b:e8:1f:77:0d:83:a9:cc:4f:74:7c:0c:49:a7:a1:1d:7a:a4:cc:c4:b8:6d:a2:63:19:ee:07:46:2c:6c:ca:7b:c5:41:52:68:6f:b9:dd:7e:f2:0f:29:a0:e3:07:23:4a:ac:99:b4:40:d3:7b:cd:11:b6:a1"
    print(is_cert_in_crl(cert3))