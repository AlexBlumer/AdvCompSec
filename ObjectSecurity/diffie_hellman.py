from Crypto import Random

class ObjSDH:

    def __init__(self):
        self.g = 5029469
        self.n = 18

    def createDiffieHellmanKey(self, privateVal, sharedVal):
        return self.power(sharedVal, privateVal, self.n)
    
    def createDiffieHellmanValue(self):
        dhPrivValue = Random.new().read
        dhValue = self.power(self.g, value, self.n)
        return(dhValue, dhPrivValue)

    # Iterative Function to calculate 
    # (x^y)%p in O(log y)  
    def power(x, y, p) : 
        res = 1     
        x = x % p  
    
        while (y > 0) : 

            if ((y & 1) == 1) : 
                res = (res * x) % p 
    
            y = y >> 1     
            x = (x * x) % p 

        return res 