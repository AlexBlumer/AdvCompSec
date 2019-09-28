from Crypto import Random

class ObjSDH:
    def __init__(self):
        self.g = 5029469
        self.n = 18
    def createDiffieHellmanKey(self, privateVal, sharedVal):
        return (sharedVal ** privateVal) % self.n
    def createDiffieHellmanValue(self):
        dhPrivValue = Random.new().read
        dhValue = (self.g ** value) % self.n
        return(dhValue, dhPrivValue)
