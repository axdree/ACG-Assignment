from cgitb import text
import socketserver, threading, requests, time, pickle, os
from tkinter import *
from PIL import Image, ImageTk
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import TLS_FTPHandler
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

latestImage= {}

# ASSUMING SERVER IS SECURE 
CIusername = "acgadmin"
CIpassword = "P@$$w0rd"

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
CIPubKeyRESP = requests.get(f'https://{APIHOST}/CIPubKey', auth=HTTPBasicAuth(CIusername, CIpassword), verify=False)
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
                    pubKeyresponse = requests.post(f'https://{APIHOST}/server-key', json={"clientID": str(cameraID), "serverPubKey": serverPubKey}, auth=HTTPBasicAuth(CIusername, CIpassword), verify=False)
                    self.receive("ServerPubKey sent success")
                    if pubKeyresponse.text == "success":
                        clientCertRESP = requests.get(f'https://{APIHOST}/retr-client-cert/{cameraID}', auth=HTTPBasicAuth(CIusername, CIpassword), verify=False)
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

class subclassedHandler(TLS_FTPHandler):
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
        os.remove(file)
        with open(file + ".png", "wb+") as imgFile:
            imgFile.write(decryptedAESCipher)
        latestImage[cameraID] = file + ".png"
        return super().on_file_received(file)

class serverGUIObj():
    def __init__(self):
        self.buttonsmade = []
        self.GUI = Tk()
        self.GUI.title("ACG-Assignment (Server) GUI")
        self.GUI.configure(background="#4b4c4c")
        self.GUI.minsize(600,500)
        self.GUI.resizable(0,0)
        lbl1 = Label(self.GUI, text="Available Cameras", bg="#4b4c4c", fg="orange", font="none 14 bold", anchor=CENTER)
        lbl1.pack(pady=10)
        lbl2 = Label(self.GUI, text="Click to view live feed", bg="#4b4c4c", fg="white", font="none 10", anchor=CENTER)
        lbl2.pack(pady=10)
        self.btnUpdater()
        self.GUI.mainloop()

    def cameraWindow(self, cameraID):
        def imgUpdater(cameraID):
            try:
                im = Image.open(latestImage[cameraID])
                resizedIM = im.resize((300,300), Image.ANTIALIAS)
                self.photo = ImageTk.PhotoImage(resizedIM)
                canvas.create_image(150,150, image=self.photo)
                filenamelbl.config(text="Filename: " + os.path.basename(latestImage[cameraID]))
            except Exception as e:
                print("e", e)
            newWindow.after(500, lambda:imgUpdater(cameraID))
            
        newWindow = Toplevel(self.GUI)
        newWindow.title(f"Camera {cameraID}")
        newWindow.configure(background="#4b4c4c")
        newWindow.minsize(400,400)
        newWindow.resizable(0,0)
        camlbl = Label(newWindow, text=f"Live Feed for: {cameraID}", bg="#4b4c4c", fg="white", font="none 14 bold", anchor=CENTER)
        camlbl.pack(pady=10)
        filenamelbl = Label(newWindow, text="", bg="#4b4c4c", fg="white", font="none 14 bold", anchor=CENTER)
        filenamelbl.pack()
        canvas = Canvas(newWindow, width=300, height=300, bg="#4b4c4c")
        canvas.pack()
        imgUpdater(cameraID)

    def btnUpdater(self):
        for camera in clientPubKeys.keys():
            if camera not in self.buttonsmade:
                btn = Button(self.GUI, height=4, width=15, text= f"Camera {camera}", command=lambda x=camera: self.cameraWindow(x))
                btn.pack()
                self.buttonsmade.append(camera)
        self.GUI.after(3000, self.btnUpdater)

def ftpServ():
    authorizer = DummyAuthorizer() # handle permission and user
    authorizer.add_user("acgadmin", "ftpP@$$w0rd", scriptpath + "/data/", perm="adfmwM")
    handler = subclassedHandler # FTPS
    handler.authorizer = authorizer
    handler.certfile = scriptpath + "/FTPSCert/keycert.pem"
    handler.keyfile = scriptpath + "/FTPSCert/key.pem"
    handler.tls_control_required = True
    handler.tls_data_required = True
    ftpserver = FTPServer(("0.0.0.0", 2121), handler)
    ftpserver.serve_forever() # bind to high port, port 21 need root permission

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

    ftpThread = threading.Thread(target=ftpServ, daemon=True)
    ftpThread.start()

    serverGUIObj()


if __name__ == "__main__":
    main()