from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
import base64
import pdb

class ObjSAES:
    def pad(self, text):
        return bytes(text,'utf-8') + b"\0" * (AES.block_size - len(text) % AES.block_size)

    def encrypt(key, plain):
        #pdb.set_trace()
        plain = self.pad(plain)
        print(plain)
        print(len(plain))
        iv = Random.new().read(AES.block_size)
        aesKey = aesFromKey(key)
        cipher = AES.new(aesKey, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(plain))

    def decrypt(ciphertext, key):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        aesKey = aesFromKey(key)
        cipher = AES.new(aesKey, AES.MODE_CBC, iv)
        #print(len(cryp[AES.block_size:]))
        return base64.b64decode(cipher.decrypt(ciphertext[AES.block_size:]).rstrip(b'\0'))

    def aesFromKey(key):
        hash_object = SHA256.new()
        hash_object.update(base64.b64encode(bytes(key,'utf-8')))
        self.key = hash_object.digest()
        