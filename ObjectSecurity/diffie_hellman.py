from Crypto import Random

class ObjSDH:
    
    g = 5029469
    n = 18
    @classmethod
    def createDiffieHellmanKey(cls, receivedValue, secretValue):
        return (receivedValue ** secretValue) % cls.n
    @classmethod
    def createDiffieHellmanValue(cls):
        dhPrivValue = int.from_bytes(Random.new().read(3), 'little')
        dhValue = (cls.g ** dhPrivValue) % cls.n
        return(dhPrivValue,dhValue)