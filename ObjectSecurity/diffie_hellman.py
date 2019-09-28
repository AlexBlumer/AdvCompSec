from Crypto import Random

class ObjSDH:
    def __init__(self):
        self.g = 5029469
        self.n = 18
<<<<<<< HEAD
    def createDiffieHellmanKey(self, privateVal, sharedVal):
        return (sharedVal ** privateVal) % self.n
    def createDiffieHellmanValue(self):
        dhPrivValue = Random.new().read
        dhValue = (self.g ** value) % self.n
        return(dhValue, dhPrivValue)
=======
    def createDiffieHellmanKey(self, receivedValue, secretValue):
        return (receivedValue ** secretValue) % self.n
    def createDiffieHellmanValue():
        dhPrivValue = Random.new().read
        dhValue = (self.g ** value) % self.n
        return(dhPrivValue,dhValue)
>>>>>>> 20982211542924bb24fdedb44263a7181f7d6bfb
