# adsec15 Fall 2019

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto import Random
from Crypto.Hash import SHA256
import ast
import base64
class ObjSRSA:
    def generate_key(length, keyFile):
        random_generator = Random.new().read
        privateKey = RSA.generate(length, random_generator) #generate pub and priv key
        publicKey = privateKey.publickey() # pub key export for exchange
        with open(keyFile,'wb') as f:
            f.write(privateKey.export_key('PEM'))
            f.write(b'  ')
            f.write(publicKey.export_key('PEM'))
        return (publicKey, privateKey)

    def encrypt(data, key):
        cipher = PKCS1_OAEP.new(key)
        encrypted = cipher.encrypt(data)
        return encrypted
    def sign(data, key):
        signer = PKCS1_PSS.new(key)
        hash = ObjSRSA.getHash(data)
        signature = signer.sign(hash)
        return signature

    def decrypt(data, key):
        cipher = PKCS1_OAEP.new(key)
        decrypted = cipher.decrypt(data)
        # decrypted = key.decrypt(ast.literal_eval(str(data)))
        return decrypted
    def separateSignature(message, key):
        border = key.size_in_bytes()
        data = message[:border]
        signature = message[border:]
        return data, signature
    def checkSignature(unencryptedData, key, signature):
        checker = PKCS1_PSS.new(key)
        hash = ObjSRSA.getHash(unencryptedData)
        return checker.verify(hash, signature)
    
    def importServerKey():
        with open('public.pem','rb') as f:
            return RSA.importKey(f.read())
    def getKeys(keyFile):
        privKey = pubKey = None
        with open(keyFile, 'rb') as f:
            result = f.read()
            keys = result.split(b'  ')
            privKey = RSA.importKey(keys[0])
            pubKey = RSA.importKey(keys[1])
        return (privKey, pubKey)
    
    def pubKeyFromLine(line):
        pemStyleString = "-----BEGIN PUBLIC KEY-----\n" + line[0:64] + '\n' + line[64:128] + '\n' + line[128:192] + '\n' + line[192:] + "\n-----END PUBLIC KEY-----"
        return RSA.importKey(pemStyleString)
    
    @staticmethod
    def getHash(bytes):
        hash_object = SHA256.new()
        hash_object.update(base64.b64encode(bytes))
        return hash_object

def main():
    import sys
    length = sys.argv[1]
    fileName = sys.argv[2]
    print("Generating key of length {} in file '{}'".format(length, fileName))
    generate_key(int(length), fileName)

if __name__ == "__main__":
    main()