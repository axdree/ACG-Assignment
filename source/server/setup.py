# Reference Source: https://github.com/frispete/keyrings.cryptfile
from keyrings.cryptfile.cryptfile import CryptFileKeyring
import os

KEYRING_PASSWD = "P@$$w0rd"
SERVER_ADDRESS = "localhost"
SERVER_USERNAME = "TestUser"
SERVER_PASSWORD = "T3sTp@$$w0rd"

os.environ["KRPasswd"] = KEYRING_PASSWD

kr = CryptFileKeyring()
kr.keyring_key = KEYRING_PASSWD
kr.set_password("system", "server", SERVER_ADDRESS)
kr.set_password("system", "username", SERVER_USERNAME)
kr.set_password("system", "password", SERVER_PASSWORD)
#password P@$$w0rd