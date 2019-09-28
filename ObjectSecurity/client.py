import socket
from messageDecoder import *
from enum import IntEnum
from rsa import ObjSRSA as RSA
from diffie_hellman import ObjSDH as DH 
from aes import ObjSAES as AES
from Crypto.Hash import SHA256

class ClientState(IntEnum):
    UNINITIALZED = 0
    HANDSHAKE_STARTED = 1
    CONNECT_RESPONSE_RECEIVED = 2
    DIFFIE_HELLMAN_SENT = 3
    KEYS_ADVERTISED = 4
    DATA_EXCHANGE = 5
    SHUTDOWN_SENT = 6
    SHUTDOWN_COMPLETE = 7

class ClientData:
    def __init__(self, host=None, port=None, sock=None, pubKey=None, sessionKey=None, objectKeyHashes=[], connectionState=ClientState.UNINITIALZED):
        self.host = host
        self.port = port
        self.pubKey = pubKey
        self.sessionKey = sessionKey
        self.objectKeyHashes = objectKeyHashes
        self.connectionState = connectionState
        self.sock = sock
        self.requestNumbers = {}
        
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


# split into new thread or otherwise do async?
def runClient(serverKeyFile, objectKeyFile, requestedObjects, host, port=7734): # '' indicates bind to all IP addresses
    global serverKeys
    serverKeys = RSA.getKeys(serverKeyFile)
    global objectKeys
    objectKeys = getKeys(objectKeyFile)

    if not isinstance(port, int) or port < 0 or port > 65535:
        raise Exception("Invalid port. Should be an integer between 0 and 65535, inclusive.")
    sock = socket.socket(type=SOCK_DGRAM)
    sock.bind( socket.INADDR_ANY ) # bind to any open socket
    
    sock.connect( (host, port) )
    
    client = ClientData(host=host, port=port, sock=sock, connectionState=ClientState.HANDSHAKE_STARTED)
    
    print("Initiating connection to host '{}' and port {}".format(host, port))
    success = initiateConnection(server)
     
    if not success:
        print("Connection to host '{}' and port {} failed".format(host, port))
        return
    else:
        for object in requestedObjects:
            if server.getConnectionState() != ClientState.DATA_EXCHANGE:
                print("Disconnected from server early")
                break
        
            success, status = dataRequest(server, object)
            if success:
                print("Successfully retrieved object '{}'".format(object))
            else:
                print("Failed to retreive object '{}' with status '{}'".format(object, status))
    
    initiateShutdown(server)
            
"""
Initiates the connection to the server
https://github.com/AlexBlumer/AdvCompSec
:param server:      A ServerData object.

:returns:   success - a boolean representing whether the connection was successful
"""
def initiateConnection(server)

    ownPubKey, ownPrivKey = RSA.generate_key(length = 1024 ,keyFile = '') 
    hash_object = SHA256.new()
    hash_object.update(base64.b64encode(bytes(ownPubKey,'utf-8')))
    ownPubKeyHash = hash_object.digest()
    serverPubKey = RSA.importServerKey()
    sock = server.getSocket()
    sock.setTimeout(responseTimeout)
    # Send connection request
    sendMsgData = {key:ownPubKeyHash}
    sendMsg = Message(MessageType.CONNECT_REQUEST, sendMsgData)
    sendMsgBytes = sendMsg.toBytes()
    sock.send(sendMsgBytes)
    ownDhVal = None

    while server.getConnectionState() < ClientState.DATA_EXCHANGE: # TODO add in max resend
        data = sock.recv(512)
        
        if data == -1:
            # TODO resend previous message
            continue
        
        state = server.getConnectionState()
        if state == ClientState.HANDSHAKE_STARTED:
            success, ownDhVal = handleConnectResponse(server, data, ownPrivKey, ownPubKeyHash)
        elif state == ClientState.DIFFIE_HELLMAN_SENT:
            success = handleKeyAdvertisement(server, data)
            if not success and server.getConnectionState() <= ClientState.DIFFIE_HELLMAN_SENT:
                success, _ = handleConnectResponse(server, data, ownPrivKey, ownPubKeyHash, ownDhVal)
        elif state == ClientState.KEYS_ADVERTISED:
            success = handleKeyAdvertisementAck(server, data)
            if not success and server.getConnectionState() <= ClientState.DIFFIE_HELLMAN_SENT:
                handleKeyAdvertisement(server, data)
"""
Makes a data request to the server for the given object, saving it to a file with the same name as the object

:param server:      A ServerData object.
:param object:      A string identifying the object to be requested

:returns:   (success, status)
            success - a boolean representing whether or not the object was successfully retrieved
            status - a value indicating the status of the object
"""
def dataRequest(server, object):
    

"""
Handles connection response messages, sending the DiffieHellman response. If called while in HANDSHAKE_STARTED, saves and updates the server's state and public key, and generates the DiffieHellman value.
If called while in another state, it merely resends the response with the given diffie hellman values

:param client:  A ClientData object.
:param data:    The bytes of the message received
:param dhVal:   The value for DiffieHellman. Optional/Ignored only if this is the first time the connection received a CONNECT_RESPONSE

:returns:   (success, dhVal)
            success is a boolean indicating whether or not the received data was a valid CONNECT_REQUEST message. False may also indicate that the retrieved values (i.e. the pubKeyHash) were invalid
            dhVal is the produced Diffie Hellman value for the exchange.
"""
def handleConnectResponse(server, data, ownPrivKey, ownPubKeyHash, dhVal=None):
    sock = server.getSocket()
    
    pubKeyHash = None
    serverDhVal = None
    dhParams = None
    try:
        unencryptedData = RSA.decrypt(data=data, privateKey=ownPrivKey)
        msg = Message.fromBytes(unencryptedData)
        pubKeyHash = msg.getPublicKeyHash()
        serverDhVal = msg.getDiffieHellmanValue()
        dhParams = msg.getDiffieHellmanParameters()
        if pubKeyHash == False or pubKeyHash == None or pubKeyHash == False or serverDhVal == None or serverDhVal == False or dhParams == None: # Not a valid CONNECT_RESPONSE. Probably an encrypted message that start with the right number
            return (False, None)
    except: # Not a proper message, likely wrong level of encryption
        return (False, None)
    
    if server.getConnectionState() == ClientState.HANDSHAKE_STARTED:
        server.setConnectionState(ClientState.CONNECT_RESPONSE_RECEIVED)
        serverPubKey = serverKeys.get(pubKeyHash)
        server.setPubKey(serverPubKey)
        if serverPubKey == None:
            print("Cannot find server public key. Exiting...")
            server.setConnectionState(ClientState.SHUTDOWN_COMPLETE)
            return
        
        dhVal, privDhVal = DH.createDiffieHellmanValue()
        
        sessionKey = DH.createDiffieHellmanKey(sharedVal=serverDhVal, privateVal=privDhVal)
        server.setSessionKey(sessionKey)
    
    sendMsgData = {exchangeValue:dhVal}
    sendMsg = Message(MessageType.DIFFIE_HELLMAN_RESPONSE, sendMsgData)
    sendMsgBytes = RSA.encrypt(data=sendMsg.toBytes(), pubKey=server.getPubKey())
    sendMsgBytes = RSA.encrypt(data=sendMsgBytes, privKey=ownPrivKey)
    sock.send(sendMsgBytes)
    
"""
Handles key advertisement messages, sending its own key advertisement response. If called while in DIFFIE_HELLMAN_SENT, saves and updates the server's state and object keys.
If called while in another state, it merely resends the the key advertisement response

:param client:  A ClientData object.
:param data:    The bytes of the message received

:returns:   success - a boolean indicating whether or not the received data was a valid KEY_ADVERTISEMENT message. False may also indicate that the retrieved values (i.e. the keyHashes) were invalid
"""
def handleKeyAdvertisement(server, data):
    sock = server.getSocket()
    
    keyHashes = None
    try:
        unencryptedData = AES.decrypt(data=data, key=server.getSessionKey())
        msg = Message.fromBytes(unencryptedData)
        keyHashes = msg.getObjectKeyHashes()
        if keyHashes in {False, None}:
            return False
    except:
        return False
    
    if server.getConnectionState() == ClientState.DIFFIE_HELLMAN_SENT:
        server.setConnectionState(ClientState.KEYS_ADVERTISED)
        server.setObjectKeyHashes(keyHashes)
    
    allowedKeys = getAllowedKeyHashes()
    sendMsgData = {"keys":allowedKeys}
    sendMsg = Message(MessageType.KEY_ADVERTISEMENT)
    sendMsgBytes = AES.encrypt(data=sendMsg.toBytes(), key=sessionKey)
    sock.send(sendMsgBytes)
    return True

"""
Handles key advertisement acks. If called while in KEYS_ADVERTISED, updates the server's state

:param client:  A ClientData object.
:param data:    The bytes of the message received

:returns:   success - a boolean indicating whether or not the received data was a valid KEY_ADVERTISEMENT message. False may also indicate that the retrieved values (i.e. the keyHashes) were invalid
"""
def handleKeyAdvertisementAck(server, data):
    try:
        unencryptedData = AES.decrypt(data=data, key=server.getSessionKey())
        msg = Message.fromBytes(unencryptedData)
        if msg.getType() != MessageType.KEY_ADVERTISEMENT_ACK:
            return False
    except:
        return False
    
    if server.getConnectionState() == ClientState.KEYS_ADVERTISED:
        server.setConnectionState(ClientState.DATA_EXCHANGE)

# TODO update variable names to work for clientside
def initiateShutdown(server):
    server.setConnectionState(ClientState.SHUTDOWN_SENT)
    
    sock = server.getSocket()
    sock.setTimeout(responseTimeout)
    
    maxResendCount = 10
    resendCount = 0
    
    sessionKey = client.getSessionKey()
    sendMsg = Message(MessageType.SHUTDOWN_REQUEST)
    sendMsgBytes = AES.encrypt(data=sendMsg, key=sessionKey)
    
    sock.send(sendMsgBytes)
    
    while client.getConnectionState != ServerState.SHUTDOWN_COMPLETE and resendCount < maxResendCount:
        data = sock.recv(512)
        
        if data == -1:
            sock.send(sendMsgBytes)
        else:
            unencryptedData = AES.decrypt(data=data, key=sessionKey)
            msg = Message.fromBytes(unencryptedData)
            if msg.type == MessageType.SHUTDOWN_CLOSEE_ACK:
                client.setConnectionState(ServerState.SHUTDOWN_COMPLETE)
                sendMsg = Message(MessageType.SHUTDOWN_CLOSER_ACK)
                sendMsgBytes = AES.encrypt(data=sendMsg, key=sessionKey)
                sock.send(sendMsgBytes)
            else:
                sock.send(sendMsgBytes)
        
        resendCount += 1
    
    sock.close()
    