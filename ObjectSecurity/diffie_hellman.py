# adsec15 Fall 2019

from Crypto import Random

class ObjSDH:


    
    n = 5029469
    g = 18
    @classmethod
    def createDiffieHellmanKey(cls, receivedValue, secretValue):
        return cls.power(receivedValue,secretValue,cls.n)

    @classmethod
    def createDiffieHellmanValue(cls):
        dhPrivValue = int.from_bytes(Random.new().read(3), 'little') % cls.n
        dhValue = cls.power(cls.g, dhPrivValue, cls.n)
        return(dhPrivValue,dhValue)

    # Iterative Function to calculate 
    # (x^y)%p in O(log y)
    
    @staticmethod
    def power(x, y, p) : 
        res = 1     
        x = x % p  
    
        while (y > 0) : 

            if ((y & 1) == 1) : 
                res = (res * x) % p 
    
            y = y >> 1     
            x = (x * x) % p 

        return res 