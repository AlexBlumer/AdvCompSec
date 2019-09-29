from Crypto import Random

class ObjSDH:


    
    g = 5029469
    n = 18
    @classmethod
    def createDiffieHellmanKey(cls, receivedValue, secretValue):
        return cls.power(receivedValue,secretValue,cls.n)

    @classmethod
    def createDiffieHellmanValue(cls):
        dhPrivValue = int.from_bytes(Random.new().read(3), 'little')
        dhValue = cls.power(cls.g, dhPrivValue, cls.n)
        return(dhPrivValue,dhValue)

    # Iterative Function to calculate 
    # (x^y)%p in O(log y)
    
    @classmethod
    def power(x, y, p) : 
        res = 1     
        x = x % p  
    
        while (y > 0) : 

            if ((y & 1) == 1) : 
                res = (res * x) % p 
    
            y = y >> 1     
            x = (x * x) % p 

        return res 