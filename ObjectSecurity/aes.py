# adsec15 Fall 2019

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
import base64

class ObjSAES:
    @staticmethod
    def pad(text):
        return text + b"\0" * (AES.block_size - len(text) % AES.block_size)

    @classmethod
    def encrypt(cls, data, key):
        plain = cls.pad(data)
        iv = Random.new().read(AES.block_size)
        aesKey = ObjSAES.aesFromKey(key)
        cipher = AES.new(aesKey, AES.MODE_CBC, iv)
        return base64.b64encode(bytearray(iv) + bytearray(cipher.encrypt(plain)))

    def decrypt(data, key):
        ciphertext = base64.b64decode(data)
        iv = ciphertext[:AES.block_size]
        aesKey = ObjSAES.aesFromKey(key)
        cipher = AES.new(aesKey, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext[AES.block_size:])
        return decrypted.rstrip(b'\0')

    def aesFromKey(key):
        hash_object = SHA256.new()
        hash_object.update(base64.b64encode(bytes(key)))
        return hash_object.digest()
        
