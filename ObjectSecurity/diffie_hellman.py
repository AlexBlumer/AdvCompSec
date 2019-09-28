from Crypto import Random

class ObjSDH:
    def __init__(self):
        self.g = 5029469
        self.n = 18
    def createDiffieHellmanKey(self, receivedValue, secretValue):
        return (receivedValue ** secretValue) % self.n
    def createDiffieHellmanValue():
        dhPrivValue = Random.new().read
        dhValue = (self.g ** value) % self.n
        return(dhPrivValue,dhValue)
