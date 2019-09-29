import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
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

    def encrypt(key , message):
        encrypted = key.encrypt(bytes(message,'UTF-8'), 32)
        print('encrypted message:' + str(encrypted)) #ciphertext
        return encrypted

    def decrypt(key, ciphertext):
        decrypted = key.decrypt(ast.literal_eval(str(ciphertext)))
        print('decrypted' + str(decrypted))
        return decrypted
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

def main():
    import sys
    length = sys.argv[1]
    fileName = sys.argv[2]
    print("Generating key of length {} in file '{}'".format(length, fileName))
    generate_key(int(length), fileName)

if __name__ == "__main__":
    main()