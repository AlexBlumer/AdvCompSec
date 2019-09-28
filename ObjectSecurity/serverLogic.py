import socket
from messageDecoder import *
from enum import IntEnum
from aes import ObjSAES as AES
from diffie_hellman import ObjSDH as DH
from rsa import ObjSRSA as RSA
from Crypto.Hash import SHA256
import base64
from getopt import getopt
# TODO finish helper functions
# TODO figure out actual max length of packets for receiving
# TODO resends

class ClientState(IntEnum):
    UNINITIALZED = 0
    HANDSHAKE_STARTED = 1
    CONNECT_RESPONSE_RECEIVED = 2
    DIFFIE_HELLMAN_SENT = 3
    KEYS_ADVERTISED = 4
    DATA_EXCHANGE = 5
    SHUTDOWN_SENT = 6
    SHUTDOWN_COMPLETE = 7

class ServerState(IntEnum):
    UNINITIALZED = 0
    HANDSHAKE_STARTED = 1
    CONNECT_RESPONSE_SENT = 2
    KEYS_ADVERTISED = 4
    DATA_EXCHANGE = 5   # Also when key advertisement has been acked
    SHUTDOWN_SENT = 6
    SHUTDOWN_COMPLETE = 7

class DataExchangeState(IntEnum):
    UNINITIALIZED = 0
    DATA_SENT = 1
    EXCHANGE_COMPLETE = 2
    
# An object containing all the values the server needs to interface with a client
class ClientData:
    def __init__(self, host=None, port=None, sock=None, pubKey=None, sessionKey=None, objectKeyHashes=[], connectionState=ServerState.UNINITIALZED):
        self.host = host
        self.port = port
        self.pubKey = pubKey
        self.sessionKey = sessionKey
        self.objectKeyHashes = objectKeyHashes
        self.connectionState = connectionState
        self.sock = sock
        self.requestNumbers = {}
        self.requestData = {}
        
    def getHost(self):
        return self.host
    def setHost(self, host):
        self.host = host
    
    def getPort(self):
        return self.port
    def setPort(self, port):
        self.port = port
        
    def getSocket(self):
        return self.sock
    def setSocket(self, sock):
        self.sock = sock
        
    def getPubKey(self):
        return self.pubKey
    def setPubKey(self, pubKey):
        self.pubKey = pubKey
        
    def getSessionKey(self):
        return self.sessionKey
    def setSessionKey(self, sessionKey):
        self.sessionKey = sessionKey
        
    def getObjectKeyHashes(self):
        return self.objectKeyHashes
    def setObjectKeyHashes(self, objectKeyHashes):
        self.objectKeyHashes = objectKeyHashes
    
    def getConnectionState(self):
        return self.connectionState
    def setConnectionState(self, connectionState):
        self.connectionState = connectionState
    
    def getRequestNumberState(self, requestNumber):
        return self.requestNumbers.get(requestNumber)
    def checkRequestNumberUsed(self, requestNumber):
        return self.requestNumbers.get(requestNumber) != None
    def setRequestNumberState(self, requestNumber, state):
        self.requestNumbers[requestNumber] = state
    
    def getRequestNumberData(self):
        return self.requestData
    def setRequestNumberData(self, requestNumber, data):
        self.requestData[requestNumber] = data
    def clearRequestNumberData(self, requestNumber):
        self.pop(requestNumber)


# split into new thread or otherwise do async?
def runServer(clientKeyFile, objectKeyFile, localKeyFile, address='', port=7734): # '' indicates bind to all IP addresses
    global clientKeyDict
    clientKeys = getAllowableKeys(clientKeyFile)
    clientKeyDict = {}
    for key in clientKeys:
        keyHash = getHash(bytes(key,'utf-8'))
        clientKeyDict[keyHash] = key
    global objectKeyDict
    objectKeys = getAllowableKeys(objectKeyFile)
    objectKeyDict = {}
    for key in objectKeys:
        keyHash = getHash(bytes(key,'utf-8'))
        objectKeyDict[keyHash] = key

    if not isinstance(port, int) or port < 0 or port > 65535:
        raise Exception("Invalid port. Should be an integer between 0 and 65535, inclusive.")
    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.bind( (address, port) ) # '' indicates bind to all IP addresses
    
    while True:
        _, recvAddress = sock.recvfrom(512, socket.MSG_PEEK) # Don't read the message, just get the address
        
        connSock = sock.dup()
        connSock.connect(recvAddress)
        
        host = recvAddress[0]
        port = recvAddress[1]
        
        client = ClientData(host=host, port=port, sock=connSock, connectionState=ServerState.HANDSHAKE_STARTED)
        
        print("Connection initiated by IP '{}' and port {}".format(host, port))
        connectionSuccess = completeConnectionServer(client, localKeyFile)
        
        if client.getConnectionState() == ServerState.DATA_EXCHANGE:
            print("Connection from IP '{}' and port {} successful".format(host, port))
        else:
            continue
        
        dataExchangeLoop(client)
        


def completeConnectionServer(client, localKeyFile):

    sock = client.getSocket()
    
    privDhVal = None
    params = None
    sendVal = None
    ownKey = RSA.getKeys(localKeyFile)
    
    connected = True
    sock.settimeout(60)
    # Split or otherwise async?
    while client.getConnectionState() < ServerState.DATA_EXCHANGE: # TODO give max timeouts before assuming connection dead
        # data, _ancData, msgFlags, address= connSock.recvmsg(512)
        # data = connSock.recv(512)
        try:
            data = sock.recv(512)
        except socket.timeout:
            data = -1
        
        state = client.getConnectionState()
        
        if data == -1:
            shutdownConnection(connSock)
        
        if state == ServerState.HANDSHAKE_STARTED:
            success, params, sendVal, privDhVal = handleConnectRequest(client, data)
        elif state == ServerState.CONNECT_RESPONSE_SENT:
            success = handleDiffieHellmanResponse(client, data, privDhVal)
            if not success and client.getConnectionState() <= ServerState.CONNECT_RESPONSE_SENT: # Not a DH-response and not a total failure
                # Resend the connect response
                success, _, _ = handleConnectRequest(client, data, params, sentVal)
        elif state == ServerState.KEYS_ADVERTISED:
            success = handleKeyAdvertisementServer(client, data)
            if not success and client.getConnectionState() <= ServerState.KEYS_ADVERTISED: # Not a DH-response and not a total failure
                # Resend the key advertisement
                success = handleDiffieHellmanResponse(client, data)

def dataExchangeLoop(client):
    sock = client.getSocket()
    state = DataExchangeState.WAITING_FOR_REQUEST
    sessionKey = client.getSessionKey()
    
    sock.settimeout(messageTimeout)
    
    while client.getConnectionState() == ServerState.DATA_EXCHANGE and """curtime""" < lastMessageTime + connectionTimeout:
        try:
            data = sock.recv(512)
        except socket.timeout:
            dat == -1
        
        if data == -1:
            continue
        
        unencryptedData = aesDecrypt(key=sessionKey, data=data)
        
        msg = None
        type = None
        try:
            msg = Message.fromBytes(unencryptedData)
            type = msg.getType()
            
            if type != MessageType.SHUTDOWN_REQUEST and type != MessageType.OBJECT_REQUEST and type != MessageType.DATA_ACK:
                continue
            
            # TODO reset timer if successful
            lastMessageTime = time()
        except: # Invalid message
            continue
            
        if type == MessageType.SHUTDOWN_REQUEST:
            handleShutdown(client)
        elif type == MessageType.OBJECT_REQUEST:
            handleObjectRequest(client, msg)
        elif type == MessageType.DATA_ACK:
            handleDataAck(client, msg)
    

# TODO move this and similar into Client?
"""
Handles connection request messages, sending the response. If called while in HANDSHAKE_STARTED, saves and updates the client's state and public key, and generates the DiffieHellman parameters and value.
If called while in another state, it merely resends the response with the given diffie hellman values

:param client:  A ClientData object.
:param data:    The bytes of the message received
:param dhParams:The parameters for DiffieHellman. Optional/Ignored only if this is the first time the connection received a CONNECT_REQUEST
:param dhVal:   The calue for DiffieHellman. Optional/Ignored only if this is the first time the connection received a CONNECT_REQUEST

:returns:   (success, dhParams, dhVal, privDhVal)
            success is a boolean indicating whether or not the received data was a valid CONNECT_REQUEST message. False may also indicate that the retrieved values (i.e. the pubKeyHash) were invalid
            dhParams is an object containing the parameters for the diffie hellman exchange
            dhVal is the produced Diffie Hellman value for the exchange.
            privDhVal is the private DiffieHellman value, for use in calculating the session key
"""
def handleConnectRequest(client, data, dhParams=None, dhVal=None):
    pubKeyHash = None
    try:
        msg = Message.fromBytes(data)
        pubKeyHash = msg.getPublicKeyHash()
        if pubKeyHash == False or pubKeyHash == None: # Not a valid CONNECT_REQUEST. Probably an encrypted message that start with the right number
            return False, None, None, None
    except: # Not a proper message, likely wrong level of encryption
        return False, None, None, None
    
    privDhVal = None
    if state == ServerState.HANDSHAKE_STARTED: # Need to save data from CONNECT_REQUEST
        clientPublicKey = clientKeyDict.get(pubKeyHash)
        
        if clientPublicKey == None: # An unknown person
            client.setConnectionState(ServerState.SHUTDOWN_COMPLETE)
            return False, None, None, None
        else:
            client.setConnectionState(ServerState.CONNECT_RESPONSE_SENT)
            client.setPubKey(clientPublicKey)
            
            dhParams = getDiffieHellmanParams()
            dhVal, privDhVal = DH.createDiffieHellmanValue()
        
    ownKey = RSA.generate_key()
    sendMsgData = {"key": ownKey, "exchangeParams": params, "exchangeValue": sentVal}
    
    sendMsg = Message(MessageType.CONNECT_RESPONSE, sendMsgData)
    clientPubKey = client.getPubKey()
    sendBytes = rsaEncrypt(data=sendMsg.toBytes(), pubKey=clientPublicKey)
    
    sock = client.getSocket()
    sock.send(sendBytes)
    
    return True, dhParams, dhVal, privDhVal

"""
Handles DiffieHellman response messages and sends the key advertisement response. If called in CONNECT_RESPONSE_SENT, updates the client's state and calculates the session key.

:param client:      A ClientData object.
:param data:        The bytes of the message received
:param privDhVal:   The private DiffieHellman value for calculating the session key. Only required and used when in CONNECT_RESPONSE_SENT

:returns:   success - a boolean indicating whether or not the received message was a valid DiffieHellman response
"""
def handleDiffieHellmanResponse(clientData, data, privDhVal=None):
    dhVal = None
    try:
        privateKey = getOwnPrivateKey()
        clientPubKey = clientData.getPubKey()
        unencryptedData = rsaDecrypt(data=data, key=privateKey)
        unencryptedData = rsaDecrypt(data=unencryptedData, key=clientPubKey)
        msg = Message.fromBytes(unencryptedData)
        dhVal = msg.getDiffieHellmanValue()
        if dhVal == False or dhVal == None: # Not a valid DIFFIE_HELLMAN_RESPONSE. Probably an encrypted message that start with the right number
            return False
    except: # Not a proper message, likely wrong level of encryption
        return False
    
    state = clientData.getConnectionState()
    
    # Update server state and calculate session key
    if state == ServerState.CONNECT_RESPONSE_SENT:
        clientData.setConnectionState(ServerState.KEYS_ADVERTISED)
        sessionKey = createDiffieHellmanKey(privateVal=privDhVal, sharedVal=dhVal)
        clientData.setSessionKey(sessionKey)
    
    sessionKey = clientData.getSessionKey()
    
    allowedKeys = getAllowedKeyHashes()
    sendMsgData = {"keys":allowedKeys}
    sendMsg = Message(MessageType.KEY_ADVERTISEMENT)
    sendMsgBytes = aesEncrypt(data=sendMsg.toBytes(), key=sessionKey)
    
    sock = clientData.getSocket()
    sock.send(sendMsgBytes)
    
"""
Handles key advertisement messages received by the server and sends the key advertisement ack. If called in KEYS_ADVERTISED, updates the client's state and saves the allowed keys.

:param client:      A ClientData object.
:param data:        The bytes of the message received

:returns:   success - a boolean indicating whether or not the received message was a valid KEY_ADVERTISEMENT
"""
def handleKeyAdvertisementServer(clientData, data, privDhVal=None):
    validKeyHashes = None
    try:
        sessionKey = clientData.getSessionKey()
        unencryptedData = aesDecrypt(data=data, key=sessionKey)
        msg = Message.fromBytes(unencryptedData)
        validKeyHashes = msg.getObjectKeyHashes()
        if validKeyHashes == False or validKeyHashes == None: # Not a valid KEY_ADVERTISEMENT.
            return False
    except: # Not a proper message, likely wrong level of encryption
        return False
    
    state = clientData.getConnectionState()
    
    # Update server state and calculate session key
    if state == ServerState.CONNECT_RESPONSE_SENT:
        clientData.setConnectionState(ServerState.DATA_EXCHANGE)
        client.setObjectKeyHashes(validKeyHashes)
    
    sendMsg = Message(MessageType.KEY_ADVERTISEMENT_ACK)
    sendMsgBytes = aesEncrypt(data=sendMsg.toBytes(), key=sessionKey)
    
    sock = clientData.getSocket()
    sock.send(sendMsgBytes)
    
    return True
    
"""
Handles shutdown requests and closes the socket

:param client:      A ClientData object.
"""
def handleShutdown(client):
    client.setConnectionState(ServerState.SHUTDOWN_SENT)

    sock = client.getSocket()
    sock.settimeout(responseTimeout)
    
    maxResendCount = 10
    resendCount = 0
    
    sessionKey = client.getSessionKey()
    sendMsg = Message(MessageType.SHUTDOWN_CLOSEE_ACK)
    sendMsgBytes = aesEncrypt(data=sendMsg, key=sessionKey)
    
    sock.send(sendMsgBytes)
    
    while client.getConnectionState() != ServerState.SHUTDOWN_COMPLETE and resendCount < maxResendCount:
        data = sock.recv(512)
        
        if data == -1:
            sock.send(sendMsgBytes)
        else:
            unencryptedData = aesDecrypt(data=data, key=sessionKey)
            msg = Message.fromBytes(unencryptedData)
            if msg.type == MessageType.SHUTDOWN_CLOSER_ACK:
                client.setConnectionState(ServerState.SHUTDOWN_COMPLETE)
            else:
                sock.send(sendMsgBytes)
        
        resendCount += 1
    
    sock.close() # TODO make sure this doesn't also close the OG sock
    
"""
Handles object requests received by the server and sends the data message. If the request number is new, updates the request number's state and saves the needed data to the client.

:param client:      A ClientData object.
:param msg:         A Message object with type of OBJECT_REQUEST
"""
def handleObjectRequest(client, msg): # TODO add an objReqAck
    reqNum = msg.getRequestNumber()
    target = msg.getTargetObject()
    keyHash = msg.getRequestedObjectKeyHash()
    sock = clientData.getSocket()
    
    # Make sure all values exist
    if reqNum == False or reqNum == None or target == False or target == None or keyHash == False or keyHash == None:
        return
    
    if not isValidRequestNumber(reqNum) or not keyHash in objectKeys.keys(): # TODO create func and decide what makes a request number
        return
    elif not client.checkRequestNumberUsed(reqNum): # A new request
        client.setRequestNumberState(reqNum, DataExchangeState.DATA_SENT)
        
        objectData = obtainData(target)
        objectKey = objectKeys[keyHash]
        # Send an object request ack if either fails
        if objectData == None: # TODO or whatever fail value is for obtainData
            sessionKey = client.getSessionKey()
            sendMsgData = {"status":DataExchangeStatus.OBJ_NOT_FOUND, "requestNum":reqNum}
            sendMsg = Message(MessageType.OBJECT_REQUEST_ACK, sendMsgData)
            sendMsgBytes = aesEncrypt(data=sendMsg.toBytes(), key=sessionKey)
            sock.send(sendMsgBytes)
            return
        elif objectKey == None:
            sessionKey = client.getSessionKey()
            sendMsgData = {"status":DataExchangeStatus.UNKNOWN_KEY, "requestNum":reqNum}
            sendMsg = Message(MessageType.OBJECT_REQUEST_ACK, sendMsgData)
            sendMsgBytes = aesEncrypt(data=sendMsg.toBytes(), key=sessionKey)
            sock.send(sendMsgBytes)
            return
        
        encryptedObjectData = aesEncrypt(data=objectData, key=objectKey)
        preHashValue = bytearray(objectData).append(bytes(target))
        objectHash = hash(bytes(preHashValue)) # TODO make it actually append
        encryptedObjectHash = aesEncrypt(data=objectHash, key=objectKey)
        
        messageData = {"keyHash":keyHash, "dataHash":encryptedObjectHash, "data":encryptedObjectData, "objectName":target, "requestNum":reqNum}
        client.setRequestNumberData(reqNum, messageData) # Save the data to avoid recomputing for resends
        
        sendMsg = Message(MessageType.DATA_MESSAGE, messageData)
        sendMsgBytes = sendMsg.toBytes()
        
        sock.send(sendMsgBytes)
    elif client.getRequestNumberState(reqNum) == DataExchangeState.DATA_SENT: # A resend request
        messageData = client.getRequestNumberData(reqNum)
        sendMsg = Message(MessageType.DATA_MESSAGE, messageData)
        sendMsgBytes = sendMsg.toBytes()
        
        sock.send(sendMsgBytes)
    # Only remaining possibility is a valid request with a request number that has been ACKed, in which case no need to send more data
        
        
    
"""
Handles data acks received by the server. If the request number is extant and unacked, updates the state and forgets the saved data for the request number.

:param client:      A ClientData object.
:param msg:         A Message object with type of DATA_ACK
"""
def handleDataAck(client, msg):
    reqNum = msg.getRequestNumber()
    if reqNum == False or reqNum == None or not isValidRequestNumber(reqNum) or client.getRequestNumberState(reqNum) != DataExchangeState.DATA_SENT:
        return
    
    client.clearRequestNumberData(reqNum)
    client.setRequestNumberState(DataExchangeState.EXCHANGE_COMPLETE)

def getHash(bytes):
    hash_object = SHA256.new()
    hash_object.update(base64.b64encode(bytes))
    return hash_object.digest()

def getAllowableKeys(fileName):
    keys = set()
    with open(fileName, 'r') as f:
        line = f.readline()
        while line:
            keys.add(line)
            line = f.readline()
    return keys

def main():
    """
    usage: python serverLogic.py OPTIONS FILE...
    
    Options:
    -h  <address> --  address to host the server on. can be IPv4 or a url
    -p <port>  --  port to host the server on. Optional, defaults to 7734
    -c <clientKeyFile> -- a file containing the public keys and their hashes for all authorized clients
    -o <objectKeyFile> -- a file containing the keys and their hashes for decrypting objects
    
    The program will request all files from the target server (specifiedin options), saving them locally to files of the same name.
    If no files are specified then a connection attempt will be made, then shutdown immediately
    """
    import sys
    host = None
    port = 7734
    clientKeyFile = None
    objectKeyFile = None
    files = set()
    optlist, remainingArgs = getopt(sys.argv[1:], 'h:p:c:o:l:')
    for optSet in optlist:
        opt = optSet[0]
        if opt == '-h':
            host = optSet[1]
        if opt == '-p':
            port = int(optSet[1])
        if opt == '-c':
            clientKeyFile = optSet[1]
        if opt == '-o':
            objectKeyFile = optSet[1]
        if opt == '-l':
            localKeyFile = optSet[1]
    files = remainingArgs
    
    optionsValid = True
    if clientKeyFile == None:
        optionsValid = False
        print("Client key file must be specified. Use '-s <clientKeyFile>'")
    if host == None:
        optionsValid = False
        print("Target host must be specified. Use '-h <host>'")
    if objectKeyFile == None:
        optionsValid = False
        print("Object key file must be specified. Use '-o <objectKeyFile>'")
    if localKeyFile == None:
        optionsValid = False
        print("local key file must be specified. Use '-l <localKeyFile>'")
    
    if not optionsValid:
        return
    
    runServer(clientKeyFile, objectKeyFile, localKeyFile, host, port)

if __name__ == "__main__":
    main()