from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
import base64

class ObjSAES:
    def pad(self, text):
        return bytes(text,'utf-8') + b"\0" * (AES.block_size - len(text) % AES.block_size)

    def encrypt(data, key):
        plain = self.pad(plain)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(plain))

    def decrypt(data, key):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64decode(cipher.decrypt(ciphertext[AES.block_size:]).rstrip(b'\0'))    