from flask import Flask,request ,make_response
from flask_cors import CORS, cross_origin

app = Flask(__name__)

CORS(app, origins=["*"], headers=['Content-Type'], expose_headers=['Access-Control-Allow-Origin'], supports_credentials=True)




@app.route('/is_list_fingerprint_ok',methods=["GET"])
def fingerprint_list():
    fingerprint_list = request.args.get('fingerprint').split(",")
    print(fingerprint_list)
    file=open("fingerprint.txt","r").readlines()
    for fingerprint in fingerprint_list:
        for line in file:
            if (line.strip("\n") == fingerprint):
                return "false"
    return "true"
    

@app.route('/is_fingerprint_ok',methods=["GET"])
def fingerprint():
    fingerprint = request.args.get('fingerprint')
    file=open("fingerprint.txt","r")
    for line in file:
        if (line.strip("\n") == fingerprint):
            return "false"
    return "true"
    
@app.route('/is_domain_ok',methods=["GET"])
def domain():
    domain = request.args.get('domain')
    file=open("domain.txt","r")
    for line in file:
        if (domain.startswith(line.strip("\n"))):
            return "false"
    return "true"
    


    


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

