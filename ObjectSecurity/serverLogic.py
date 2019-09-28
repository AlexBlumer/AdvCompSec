import socket
from messageDecoder import *
from enum import IntEnum
from aes import ObjSAES as AES
from diffie_hellman import ObjSDH as DH
from rsa import ObjSRSA as RSA
# TODO finish helper functions
# TODO figure out actual max length of packets for receiving

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
def runServer(clientKeyFile, objectKeyFile, address='', port=7734): # '' indicates bind to all IP addresses
    global clientKeys
    clientKeys = RSA.getKeys(clientKeyFile) #RSA keys
    global objectKeys
    objectKeys = getKeys(objectKeyFile) #AES keys

    if not isinstance(port, int) or port < 0 or port > 65535:
        raise Exception("Invalid port. Should be an integer between 0 and 65535, inclusive.")
    sock = socket.socket(type=SOCK_DGRAM)
    sock.bind( (address, port) ) # '' indicates bind to all IP addresses
    
    while True:
        _, recvAddress = sock.recvfrom(512, MSG_NOERROR | MSG_PEEK) # Don't read the message, just get the address
        
        connSock = sock.dup()
        connSock.connect(recvAddress)
        
        host = recvAddress[0]
        port = recvAddress[1]
        
        client = ClientData(host=host, port=port, sock=connSock, connectionState=ServerState.HANDSHAKE_STARTED)
        
        print("Connection initiated by IP '{}' and port {}".format(host, port))
        connectionSuccess = completeConnectionServer(client)
        
        if client.getConnectionState() == ServerState.DATA_EXCHANGE:
            print("Connection from IP '{}' and port {} successful".format(host, port))
        else:
            continue
        
        dataExchangeLoop(client)
        


def completeConnectionServer(client):

    sock = client.getSocket()
    
    privDhVal = None
    params = None
    sendVal = None
    
    connected = True
    sock.setTimeout(60)
    # Split or otherwise async?
    while client.getConnectionState() < ServerState.DATA_EXCHANGE: # TODO give max timeouts before assuming connection dead
        # data, _ancData, msgFlags, address= connSock.recvmsg(512)
        # data = connSock.recv(512)
        data = sock.recv(512, MSG_NOERROR)
        
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
    
    sock.setTimeout(messageTimeout)
    
    while client.getConnectionState() == ServerState.DATA_EXCHANGE and """curtime""" < lastMessageTime + connectionTimeout:
        data = sock.recv(512, MSG_NOERROR)
        
        if data == -1:
            continue
        
        unencryptedData = AES.decrypt(key=sessionKey, data=data)
        
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
        clientPublicKey = clientKeys.get(pubKeyHash)
        
        if clientPublicKey == None: # An unknown person
            client.setConnectionState(ServerState.SHUTDOWN_COMPLETE)
            return False, None, None, None
        else:
            client.setConnectionState(ServerState.CONNECT_RESPONSE_SENT)
            client.setPubKey(clientPublicKey)
            
            dhParams = getDiffieHellmanParams()
            dhVal, privDhVal = DH.createDiffieHellmanValue()
        
    ownKey, _ = RSA.generate_key()
    sendMsgData = {"key": ownKey, "exchangeParams": params, "exchangeValue": dhVal}
    
    sendMsg = Message(MessageType.CONNECT_RESPONSE, sendMsgData)
    sendBytes = RSA.encrypt(data=sendMsg.toBytes(), pubKey=clientPublicKey)
    
    sock = client.getSocket()
    sock.send(sendBytes) # TODO check for success?
    
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
        unencryptedData = RSA.decrypt(data=data, key=privateKey)
        unencryptedData = RSA.decrypt(data=unencryptedData, key=clientPubKey)
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
    sendMsgBytes = AES.encrypt(data=sendMsg.toBytes(), key=sessionKey)
    
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
        unencryptedData = AES.decrypt(data=data, key=sessionKey)
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
    sendMsgBytes = AES.encrypt(data=sendMsg.toBytes(), key=sessionKey)
    
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
    sock.setTimeout(responseTimeout)
    
    maxResendCount = 10
    resendCount = 0
    
    sessionKey = client.getSessionKey()
    sendMsg = Message(MessageType.SHUTDOWN_CLOSEE_ACK)
    sendMsgBytes = AES.encrypt(data=sendMsg, key=sessionKey)
    
    sock.send(sendMsgBytes)
    
    while client.getConnectionState != ServerState.SHUTDOWN_COMPLETE and resendCount < maxResendCount:
        data = sock.recv(512)
        
        if data == -1:
            sock.send(sendMsgBytes)
        else:
            unencryptedData = AES.decrypt(data=data, key=sessionKey)
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
def handleObjectRequest(client, msg):
    reqNum = msg.getRequestNumber()
    target = msg.getTargetObject()
    keyHash = msg.getRequestedObjectKeyHash()
    
    # Make sure all values exist
    if reqNum == False or reqNum == None or target == False or target == None or keyHash == False or keyHash == None:
        return
    
    if not isValidRequestNumber(reqNum) or not keyHash in objectKeys.keys(): # TODO create func and decide what makes a request number
        return
    elif not client.checkRequestNumberUsed(reqNum): # A new request
        client.setRequestNumberState(reqNum, DataExchangeState.DATA_SENT)
        
        objectKey = objectKeys[keyHash]
        objectData = obtainData(target)
        encryptedObjectData = AES.encrypt(data=objectData, key=objectKey)
        objectHash = hash(objectData)
        encryptedObjectHash = AES.encrypt(data=objectHash, key=objectKey)
        
        messageData = {keyHash:keyHash, dataHash:encryptedObjectHash, data:encryptedObjectData, objectName:target, requestNum:reqNum}
        client.setRequestNumberData(reqNum, messageData) # Save the data to avoid recomputing for resends
        
        sendMsg = Message(MessageType.DATA_MESSAGE, messageData)
        sendMsgBytes = sendMsg.toBytes()
        
        sock = clientData.getSocket()
        sock.send(sendMsgBytes)
    elif client.getRequestNumberState(reqNum) == DataExchangeState.DATA_SENT: # A resend request
        messageData = client.getRequestNumberData(reqNum)
        sendMsg = Message(MessageType.DATA_MESSAGE, messageData)
        sendMsgBytes = sendMsg.toBytes()
        
        sock = clientData.getSocket()
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
    
    