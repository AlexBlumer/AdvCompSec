from rsa import ObjSRSA

def copyPublicKeysToFile(originalFile, publicFile):
    orig = open(originalFile, 'r')
    pub = open(publicFile, 'a+')
    str = orig.read()
    orig.close()
    # Strip the preface of the public key
    str = str[str.find('-----BEGIN PUBLIC KEY-----'):]
    str = str[str.find('\n'):]
    # Strip the extra at the end of the public key
    str = str[:str.find('-----END PUBLIC KEY-----')]
    # Remove all new line characters
    str = str.replace('\r', '')
    str = str.replace('\n', '')
    
    # Add new lines on both sides for safety
    pub.write("\n" + str + "\n")
    pub.close()

ObjSRSA.generate_key(1024, "serverKey.pem")
ObjSRSA.generate_key(1024, "clientKey.pem")

copyPublicKeysToFile("serverKey.pem", "serverPubKey.txt")
copyPublicKeysToFile("clientKey.pem", "clientPubKey.txt")