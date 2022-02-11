import socketserver, threading, requests, time, pickle, os
from requests.auth import HTTPBasicAuth
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Signature import pkcs1_15 
from Cryptodome.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

scriptpath = os.path.dirname(os.path.abspath(__file__))

clientPubKeys = {}
serverPrivKeys = {}
APIHOST = '127.0.0.1:5555'

# ASSUMING SERVER IS SECURE 
CIusername = "acgadmin"
CIpassword = "P@$$w0rd"

CIPubKeyRESP = requests.get(f'http://{APIHOST}/CIPubKey', auth=HTTPBasicAuth(CIusername, CIpassword))
if not CIPubKeyRESP.ok:
    print("Error Connecting/Authenticating with Certificate Issuer")
    exit()
CIPubKey = load_pem_public_key(CIPubKeyRESP.json()['key'].encode(), default_backend())

class imagePayload():
    def __init__(self):
        self.aesSessionKey = ""
        self.aesiVector = ""
        self.encImage = ""
        self.signature = ""

def generateKeypair():
    keypair = RSA.generate(2048)
    pubKey = keypair.publickey().exportKey().decode()
    privKey = keypair.exportKey().decode()
    return pubKey, privKey

class Service(socketserver.BaseRequestHandler):
    try:
        def handle(self):
            def exitConn():
                self.request.close()
                print(f"[CONNECTION CLOSED] {self.client_address[0]} from port {self.client_address [1]} was closed")

            try:
                print(f"[CONNECTION STARTED] {self.client_address[0]} has connected from port {self.client_address[1]}.")
                firstStatus = self.receive("Connection Established. Listening for status.")
                if "starting key exchange" in firstStatus:
                    cameraID = firstStatus.split(":")[0]
                    serverPubKey, serverPrivKey = generateKeypair()
                    serverPrivKeys[cameraID] = serverPrivKey
                    pubKeyresponse = requests.post(f'http://{APIHOST}/server-key', json={"clientID": str(cameraID), "serverPubKey": serverPubKey}, auth=HTTPBasicAuth(CIusername, CIpassword))
                    self.receive("ServerPubKey sent success")
                    if pubKeyresponse.text == "success":
                        clientCertRESP = requests.get(f'http://{APIHOST}/retr-client-cert/{cameraID}', auth=HTTPBasicAuth(CIusername, CIpassword))
                        clientCert = x509.load_pem_x509_certificate(clientCertRESP.json()["cert"].encode(), backend=default_backend())
                        try:
                            CIPubKey.verify(clientCert.signature, clientCert.tbs_certificate_bytes, padding.PKCS1v15(), clientCert.signature_hash_algorithm)
                            secondStatus = self.receive("verification success")
                            if "verification failed" in secondStatus:
                                exitConn()
                                return
                        except InvalidSignature:
                            print("verification failed")
                            self.send("verification failed")
                            exitConn()
                            return
                        clientPubKey = clientCert.public_key()
                        clientPubKeys[cameraID] = clientPubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                        x = self.receive("Key received")
                        exitConn()
            except:
                print(f"[CONNECTION ERROR] {self.client_address[0]} connected on port {self.client_address[1]} faced an error")
            
    except Exception as e:
        print(f"Error Faced: {e}")

    def send(self, string, newline = True):
        if newline: 
            string = string + "\n"   
        if type(string) == type("string"):            
            string = string.encode()
        self.request.sendall(string)

    def receive(self, prompt = "> "):
        self.send(prompt, newline = False)
        return self.request.recv(4096).strip().decode()

class ThreadedService(socketserver.ThreadingMixIn, socketserver.TCPServer, socketserver.DatagramRequestHandler):
    pass

class subclassedHandler(FTPHandler):
    def on_file_received(self, file):
        cameraID = os.path.basename(file).split("_")[0]
        with open(file, "rb+") as f:
            data = f.read()
            imgPayload = pickle.loads(data)
            rsaKey = RSA.importKey(serverPrivKeys[cameraID])
            rsaCipher = PKCS1_OAEP.new(rsaKey)
            if type(imgPayload) == imagePayload:
                AESsessionkey = rsaCipher.decrypt(imgPayload.aesSessionKey)
                AEScipher = AES.new(AESsessionkey, AES.MODE_CBC, iv=imgPayload.aesiVector)
                decryptedAESCipher = unpad(AEScipher.decrypt(imgPayload.encImage), 16)

                shaDigest = SHA256.new(decryptedAESCipher)
                sigKey = RSA.importKey(clientPubKeys[cameraID])
                sigVerifier = pkcs1_15.new(sigKey)
                try:
                    sigVerifier.verify(shaDigest, imgPayload.signature)
                except:
                    return super().on_file_received(file)
        f.close()
        os.remove(file)
        with open(file + ".jpg", "wb+") as imgFile:
            imgFile.write(decryptedAESCipher)
        imgFile.close()

        return super().on_file_received(file)

def main():
    host = '0.0.0.0'
    port = 2222

    socketserver.TCPServer.allow_reuse_address = True
    sockserver = ThreadedService((host, port), Service)    
    sockserver.allow_reuse_address = True
    sockserver_thread = threading.Thread(target = sockserver.serve_forever)
    sockserver_thread.daemon = True
    sockserver_thread.start()
    
    print(f"Server started on Host: {host} and Port: {port}")

    authorizer = DummyAuthorizer() # handle permission and user
    authorizer.add_user("acgadmin", "ftpP@$$w0rd", scriptpath + "/data/", perm="adfmwM")
    handler = subclassedHandler #  understand FTP protocol
    handler.authorizer = authorizer
    ftpserver = FTPServer(("0.0.0.0", 2121), handler) # bind to high port, port 21 need root permission
    ftpserver.serve_forever()

if __name__ == "__main__":
    main()