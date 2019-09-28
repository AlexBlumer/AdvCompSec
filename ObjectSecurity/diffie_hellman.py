from Crypto import Random

class ObjSDH:
    
    g = 5029469
    n = 18
    @classmethod
    def createDiffieHellmanKey(cls, eceivedValue, secretValue):
        return (receivedValue ** secretValue) % cls.n
    @classmethod
    def createDiffieHellmanValue(cls):
        dhPrivValue = int.from_bytes(Random.new().read(64), 'little')
        dhValue = (cls.g ** dhPrivValue) % cls.n
        return(dhPrivValue,dhValue)
