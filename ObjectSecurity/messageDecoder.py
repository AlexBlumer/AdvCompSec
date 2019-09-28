from enum import Enum, IntEnum, unique
import cbor

# TODO maybe add automatic hashes to to/fromBytes(), for integrity purposes
# TODO add timestamp to connect request, response, and diffie hellman response to remove replay attacks

@unique
class MessageType(IntEnum):
    UNINITIALIZED = 0
    CONNECT_REQUEST = 1
    CONNECT_RESPONSE = 2
    DIFFIE_HELLMAN_RESPONSE = 3
    KEY_ADVERTISEMENT = 4
    KEY_ADVERTISEMENT_ACK = 5
    OBJECT_REQUEST = 6
    OBJECT_REQUEST_ACK = 7
    DATA_MESSAGE = 8
    DATA_ACK = 9
    SHUTDOWN_REQUEST = 10
    SHUTDOWN_CLOSEE_ACK = 11
    SHUTDOWN_CLOSER_ACK = 12

@unique
class DataExchangeStatus(IntEnum):
    OBJ_NOT_FOUND = 1
    UNKNOWN_KEY = 2
    # TODO possible others

messageTypeSet = set(item for item in MessageType)

class Message:

    def __init__(self, type, data = None):
        if not type in messageTypeSet or type == MessageType.UNINITIALIZED:
            raise Exception("Invalid type for created Message")
        if data == None and (type != MessageType.KEY_ADVERTISEMENT_ACK and type != MessageType.SHUTDOWN_CLOSER_ACK and type != MessageType.SHUTDOWN_CLOSEE_ACK):
            raise Exception("No data provided for Message type {}. Only KEY_ADVERTISEMENT_ACK, SHUTDOWN_CLOSEE_ACK and SHUTDOWN_CLOSER_ACK can have no data.")
        if not isinstance(data, dict) and (type != MessageType.KEY_ADVERTISEMENT_ACK and type != MessageType.SHUTDOWN_CLOSER_ACK and type != MessageType.SHUTDOWN_CLOSEE_ACK):
            raise Exception("Data must be provided as a dictionary for Message type {}. Only KEY_ADVERTISEMENT_ACK, SHUTDOWN_CLOSEE_ACK and SHUTDOWN_CLOSER_ACK can have no data.")
        
        self.type = type
        self.data = data
        
        # TODO maybe create checks for each field?
        
    @staticmethod
    def fromBytes(bytes):
        map = cbor.loads(bytes)
        type = MessageType(map.pop("type"))
        data = map
        return Message(type, data)
        
    
    # @staticmethod
    # def fromCBOR(object):
        
    
    def toBytes(self):
        map = {"type":self.type.value}
        map.update(self.data)
        return cbor.dumps(map)
        
    
    # def toCBOR(self):
        
    
    def getType(self):
        return self.type

    def getContents(self):
        return self.data

    # Returns public key hash if it is there, None if it is not there, or False if it is the wrong message type
    # Only CONNECT_REQUEST and CONNECT_RESPONSE should have the public key hash
    def getPublicKeyHash(self):
        if self.type != MessageType.CONNECT_REQUEST and self.type != MessageType.CONNECT_RESPONSE:
            return False
        
        return self.data.get("key")
    
    # Returns Diffie-Hellman exchange paramaters if it is there, None if it is not there, or False if it is the wrong message type
    # Only CONNECT_RESPONSE should have this value
    def getDiffieHellmanParameters(self):
        if self.type != MessageType.CONNECT_RESPONSE:
            return False
        
        return self.data.get("exchangeParams")
    
    # Returns Diffie-Hellman exchange value if it is there, None if it is not there, or False if it is the wrong message type
    # Only CONNECT_RESPONSE and DIFFIE_HELLMAN_RESPONSE should have this value
    def getDiffieHellmanValue(self):
        if self.type != MessageType.CONNECT_RESPONSE and self.type != MessageType.DIFFIE_HELLMAN_RESPONSE:
            return False
        
        return self.data.get("exchangeValue")
        
    # Returns they hashes for the object keys if they are there, None if it is not there, or False if it is the wrong message type
    # Only KEY_ADVERTISEMENT should have this value
    def getObjectKeyHashes(self):
        if self.type != MessageType.KEY_ADVERTISEMENT:
            return False
        
        return self.data.get("keys")
    
    # Returns the name of the requested object if it is there, None if it is not there, or False if it is the wrong message type
    # Only OBJECT_REQUEST should have this value
    def getTargetObject(self):
        if self.type != MessageType.OBJECT_REQUEST:
            return False
        
        return self.data.get("target")
        
    # Returns the hash of the key to use for encrypting the object if it is there, None if it is not there, or False if it is the wrong message type
    # Only OBJECT_REQUEST should have this value
    def getRequestedObjectKeyHash(self):
        if self.type != MessageType.OBJECT_REQUEST:
            return False
        
        return self.data.get("keyHash")
    
    # Returns the request number if it is there, None if it is not there, or False if it is the wrong message type
    # Only OBJECT_REQUEST, OBJECT_REQUEST_ACK, DATA_MESSAGE, and DATA_ACK should have this value
    def getRequestNumber(self):
        if self.type != MessageType.OBJECT_REQUEST or self.type != MessageType.OBJECT_REQUEST_ACK or \
            self.type != MessageType.DATA_MESSAGE or self.type != MessageType.DATA_ACK:
            return False
        
        return self.data.get("requestNum")
    
    # Returns the name of the requested object if it is there, None if it is not there, or False if it is the wrong message type
    # Only OBJECT_REQUEST should have this value
    def getTargetObject(self):
        if self.type != MessageType.OBJECT_REQUEST:
            return False
        
        return self.data.get("target")
    
    # Returns the status of the object if it is there, None if it is not there, or False if it is the wrong message type
    # Only OBJECT_REQUEST_ACK should have this value
    def getStatus(self):
        if self.type != MessageType.OBJECT_REQUEST_ACK:
            return False
        
        return self.data.get("status")
    
    # Returns encrypted data if it is there, None if it is not there, or False if it is the wrong message type
    # Only DATA_MESSAGE should have this value
    def getObjectData(self):
        if self.type != MessageType.DATA_MESSAGE:
            return False
        
        return self.data.get("data")
    
    # Returns hash of the unencrypted data if it is there, None if it is not there, or False if it is the wrong message type
    # Only DATA_MESSAGE should have this value
    def getObjectDataHash(self):
        if self.type != MessageType.DATA_MESSAGE:
            return False
        
        return self.data.get("dataHash")