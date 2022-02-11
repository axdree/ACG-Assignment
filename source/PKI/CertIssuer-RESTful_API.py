import datetime, hashlib
from flask import Flask, jsonify, request
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy 
from flask_restful import Api, Resource
from flask_httpauth import HTTPBasicAuth
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes

# FOR ACG DOCUMENTATION PURPOSE: 
# USER: acgadmin 
# PASS: P@$$w0rd
username = "acgadmin"
password = "6b283bb060c269432d08ac33b47a337c0a40035d"

#CI's Private key pre-generated
with open("private.pem", "rb") as key_file:
    CIprivkey = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )
with open("CIpublic.pem", "rb") as key_file:
    CIpubkeyPlainText = key_file.read()
    CIpubkey = serialization.load_pem_public_key(CIpubkeyPlainText)  
    

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///keysdb.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
ma = Marshmallow(app)
api = Api(app)
auth = HTTPBasicAuth()

def generateCert(pubkey):
    subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Singapore"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DISM"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"ACG"),
    ])
    cert = x509.CertificateBuilder().subject_name(
    subject
    ).issuer_name(
        issuer
    ).public_key(
        pubkey
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=999)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(CIprivkey, hashes.SHA256())
    
    return cert.public_bytes(serialization.Encoding.PEM)

# create database model
class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clientID = db.Column(db.String, unique=True)
    clientPubKey = db.Column(db.String)
    serverPubKey = db.Column(db.String)

    def __init__(self, clientID, clientPubKey, serverPubKey):
        self.clientID = clientID
        self.clientPubKey = clientPubKey
        self.serverPubKey = serverPubKey

# create a new marshmallow schema based on post model
class keySchema(ma.Schema):
    class Meta:
        # exposing these 3 fields
        fields = ("clientID", "clientPubKey", "serverPubKey")
        model = Key

key_schema = keySchema()
keys_schema = keySchema(many=True)

# --------------------- FOR TESTING -----------------------------
# @app.route('/clientget', methods=['GET'])
# def tempget():
#     allget= Key.query.all()
#     result = keys_schema.dump(allget)
#     return jsonify(result)

@auth.verify_password
def authentication(uname,pword):
    if uname and pword:
        hashObj = hashlib.sha1(pword.encode())
        passHash = hashObj.hexdigest()
        if uname == username and passHash == password:
            return True
        else:
            return False
    return False

@app.route('/CIPubKey', methods=['GET'])
@auth.login_required
def send_CIkey():
    return {"key": CIpubkeyPlainText.decode()}

@app.route('/client-key', methods=['POST'])
@auth.login_required
def add_clientKey():
    try:
        tmpclientID = request.json['clientID']
        tmpclientPubKey = request.json['clientPubKey']

        if Key.query.filter_by(clientID=tmpclientID).first() is None:
            new_key = Key(tmpclientID, tmpclientPubKey, "")
            db.session.add(new_key)
            db.session.commit()
            return "success"
        else:
            keyEntry = Key.query.filter_by(clientID=tmpclientID).first()
            keyEntry.clientPubKey = tmpclientPubKey
            db.session.commit()
            return "success"
    except Exception as e:
        print(e)
        return "failed"

@app.route('/retr-server-cert/<clientID>', methods=['GET'])
@auth.login_required
def get_serverKey(clientID):
    serverKey = Key.query.filter_by(clientID=clientID).first()
    if serverKey.serverPubKey != "":
        serverPubKey = serialization.load_pem_public_key(serverKey.serverPubKey.encode())
        cert = generateCert(serverPubKey)
        return {"cert": cert.decode()}
    else:
        return "failed"

@app.route('/server-key', methods=['POST'])
@auth.login_required
def add_serverKey():
    try:
        tmpclientID = request.json['clientID']
        tmpserverKey = request.json['serverPubKey']
        keyEntry = Key.query.filter_by(clientID=tmpclientID).first()
        keyEntry.serverPubKey = tmpserverKey
        db.session.commit()
        return "success"
    except Exception as e:
        return f"{e} failed"

@app.route('/retr-client-cert/<clientID>', methods=['GET'])
@auth.login_required
def get_clientKey(clientID):
    try:
        clientKey = Key.query.filter_by(clientID=clientID).first()
        if clientKey.clientPubKey != "":
            clientPubKey = serialization.load_pem_public_key(clientKey.clientPubKey.encode())
            cert = generateCert(clientPubKey)
            return {"cert": cert.decode()}
        else:
            return "failed"
    except:
        return "failed"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5555", debug=True, ssl_context="adhoc")
