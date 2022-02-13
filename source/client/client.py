#SAMPLE KDC ACCOUNT FOR TESTING
#USERNAME: acgadmin
#PASSWORD: P@$$w0rd
#SAMPLE ftp ACCOUNT FOR TESTING
#USERNAME: acgadmin
#PASSWORD: ftpP@$$w0rd
import base64, time, datetime, ftplib, io, random, getpass, requests, socket, os, pickle
from requests.auth import HTTPBasicAuth
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15 
from Cryptodome.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from urllib3.exceptions import InsecureRequestWarning

clear = lambda: os.system('cls' if os.name in ('nt', 'dos') else 'clear')

# Connection Variables
APIHOST = '127.0.0.1:5555'
SERVERHOST = "127.0.0.1"
SOCKETPORT = 2222
FTPPORT = 2121

# Crypto Variables
BLOCK_SIZE = 16
KEYSIZE = 32

# These variables are to support the mock camera
my_pict = "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"

# System  variable of main program
CAMERA_ID = 102   # Unique identifier for camera

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

def connect_server_send( file_name: str , file_data: bytes ):
    try:
        #if random.randrange(1,10) > 8: raise Exception("Generated Random Network Error")   # create random failed transfer   
        ftp = ftplib.FTP_TLS()  # use init will use port 21 , hence use connect()
        ftp.connect(SERVERHOST, FTPPORT) # use high port 2121 instead of 21
        ftp.auth()
        ftp.prot_p()
        ftp.login(user="acgadmin", passwd='ftpP@$$w0rd')
        ftp.storbinary('STOR ' + file_name, io.BytesIO(file_data))
        ftp.quit()
        return True
    except Exception as e:
        print(e, "while sending", file_name )
        return False

def get_picture():
    time.sleep(1) # simulate slow processor
    if random.randrange(1,10) > 8:  # simulate no motion detected
        return b''
    else:
        return base64.b64decode(my_pict)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
def initialConn():
    clear()
    username = input("\x1b[92mPlease Enter KDC's Username:\x1b[0m ")
    password = getpass.getpass("\x1b[92mPlease Enter KDC's Password: [HIDDEN]\x1b[0m")

    CIPubKeyRESP = requests.get(f'https://{APIHOST}/CIPubKey', auth=HTTPBasicAuth(username, password), verify=False)
    while not CIPubKeyRESP.ok:
        username = input("\n\n\x1b[91mIncorrect Username or Password!\x1b[92m\n\x1b[92mPlease Enter KDC's Username:\x1b[0m ")
        password = getpass.getpass("\x1b[92mPlease Enter KDC's Password: [HIDDEN]\x1b[0m")
    CIPubKey = load_pem_public_key(CIPubKeyRESP.json()['key'].encode(), default_backend())

    clear()
    ftpusername = input("\x1b[92mPlease Enter FTP's Username:\x1b[0m ")
    ftppassword = getpass.getpass("\x1b[92mPlease Enter FTP's Password: [HIDDEN]\x1b[0m")
    while True:
        try:
            ftp = ftplib.FTP_TLS()  # use init will use port 21 , hence use connect()
            ftp.connect(SERVERHOST, FTPPORT)
            ftp.login(user=ftpusername, passwd=ftppassword)
            ftp.quit()
            break
        except ftplib.error_perm:
            ftpusername = input("\n\n\x1b[91mIncorrect Username or Password!\x1b[0m\n\x1b[92mPlease Enter FTP's Username:\x1b[0m ")
            ftppassword = getpass.getpass("\x1b[92mPlease Enter FTP's Password: [HIDDEN]\x1b[0m")
        except:
            print("\x1b[91mError Authenticating with FTPS Server. Exiting App\x1b[0m")
            exit()

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((SERVERHOST, int(SOCKETPORT)))
    received = conn.recv(4096).decode("utf-8")
    if "Listening for status" in received:
        conn.send(f"{CAMERA_ID}:starting key exchange".encode())
        pubKeyresponse = requests.post(f'https://{APIHOST}/client-key', json={"clientID": CAMERA_ID, "clientPubKey": clientPubKey}, auth=HTTPBasicAuth(username, password), verify=False)

        if pubKeyresponse.text == "success":
            received = conn.recv(4096).decode("utf-8")
            conn.send("PubKey sent success".encode())
            if "ServerPubKey sent success" in received:
                serverCertRESP = requests.get(f'https://{APIHOST}/retr-server-cert/{CAMERA_ID}', auth=HTTPBasicAuth(username, password), verify=False)
                serverCert = x509.load_pem_x509_certificate(serverCertRESP.json()["cert"].encode(), backend=default_backend())
                try:
                    CIPubKey.verify(serverCert.signature, serverCert.tbs_certificate_bytes, padding.PKCS1v15(), serverCert.signature_hash_algorithm)
                except InvalidSignature:
                    conn.send("verification failed".encode())
                    print("Certificate Verification Failed. Please try restarting the app.")
                    exit()
                serverPubKeyObj = serverCert.public_key()
                global serverPubKey
                tmpserverPubKey = serverPubKeyObj.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                serverPubKey = RSA.importKey(tmpserverPubKey)
                serverVerification = conn.recv(4096).decode("utf-8")
                if "verification success" in serverVerification:
                    conn.send("verification success".encode())
                else:
                    print("Certificate Verification Failed. Please try restarting the app.")
                    exit()
                confirmationResponse = conn.recv(4096).decode("utf-8")
                if "Key received" in confirmationResponse:
                    conn.send("Closing conn".encode())
                    conn.close()


clear()
print("\x1b[96mPlease Wait... Generating Keys...\x1b[0m")
clientPubKey, tmpclientPrivKey = generateKeypair()
clientPrivKey = RSA.importKey(tmpclientPrivKey)
initialConn()

while True: # Main function
    try:  
        my_image = get_picture()  # get picture
        if len(my_image) == 0:
            time.sleep(10) # sleep for 10 sec if there is no image
            print("Random no motion detected")
        else:
            f_name = str(CAMERA_ID) + "_" +  datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S") 
            # AES ENCRYPTION
            sessionKey = get_random_bytes(KEYSIZE)
            iVector = get_random_bytes(BLOCK_SIZE)
            AEScipher = AES.new(sessionKey, AES.MODE_CBC, iVector)
            AEScipherENC = AEScipher.encrypt(pad(my_image, BLOCK_SIZE))

            # ENCRYPT AES SESSION KEY WITH RSA
            RSAcipher = PKCS1_OAEP.new(serverPubKey)
            RSAcipherENC = RSAcipher.encrypt(sessionKey)

            # CREATE SIGNATURE
            shaDigest =  SHA256.new(my_image)
            signerSigned = pkcs1_15.new(clientPrivKey).sign(shaDigest)

            # Create object
            imgPayload = imagePayload()
            imgPayload.aesSessionKey = RSAcipherENC
            imgPayload.aesiVector = iVector
            imgPayload.encImage = AEScipherENC
            imgPayload.signature = signerSigned

            encPickleObj = pickle.dumps(imgPayload)

            if connect_server_send(f_name, encPickleObj): print(f_name, " sent")
    except KeyboardInterrupt:  exit()  # gracefully exit if control-C detected