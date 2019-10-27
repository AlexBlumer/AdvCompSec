# adsec15 Fall 2019

import socket
from messageDecoder import *
from enum import IntEnum
from aes import ObjSAES as AES
from diffie_hellman import ObjSDH as DH
from rsa import ObjSRSA as RSA
from Crypto.Hash import SHA256
import base64
from getopt import getopt
import uuid
from time import gmtime, time
# TODO add cmdline options for intermediary

RESPONSE_TIMEOUT = 0.25 # 250 ms

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
    def __init__(self, host=None, port=None, sock=None, pubKey=None, sessionKey=None, objectKeyHashes=[], connectionState=ServerState.UNINITIALZED, loadFileLocation = ''):
        self.host = host
        self.port = port
        self.pubKey = pubKey
        self.sessionKey = sessionKey
        self.objectKeyHashes = objectKeyHashes
        self.connectionState = connectionState
        self.sock = sock
        self.requestNumbers = {}
        self.requestData = {}
        self.loadFileLocation = loadFileLocation
        self.usingIntermediary = False
        
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
    
    def getLoadFileLocation(self):
        return self.loadFileLocation
    
    def getRequestNumberState(self, requestNumber):
        return self.requestNumbers.get(requestNumber)
    def checkRequestNumberUsed(self, requestNumber):
        return self.requestNumbers.get(requestNumber) != None
    def setRequestNumberState(self, requestNumber, state):
        self.requestNumbers[requestNumber] = state
    
    def setUsingIntermediary(self, val):
        self.usingIntermediary = val
    def isUsingIntermediary(self):
        return self.usingIntermediary
    
    def getRequestNumberData(self, requestNumber):
        return self.requestData.get(requestNumber)
    def setRequestNumberData(self, requestNumber, data):
        self.requestData[requestNumber] = data
    def clearRequestNumberData(self, requestNumber):
        try:
            self.requestData.pop(requestNumber)
        except:
            False # The data was already absent, do nothing


# split into new thread or otherwise do async?
def runServer(clientKeyFile, objectKeyFile, localKeyFile, loadFileLocation, address='', localPort=7734): # '' indicates bind to all IP addresses
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
        
    global ownPrivKey
    global ownPubKey
    global ownPubKeyHash
    
    ownPrivKey, ownPubKey = RSA.getKeys(keyFile = localKeyFile)
    pubKeyString = ownPubKey.exportKey('PEM').decode("utf-8")
    pubKeyString = pubKeyString[(pubKeyString.find('\n') + 1):pubKeyString.rfind('\n')]
    pubKeyString = pubKeyString.replace('\n', '')
    pubKeyString = pubKeyString.replace('\r', '')
    ownPubKeyHash = getHash(bytes(pubKeyString, 'ascii'))

    if not isinstance(localPort, int) or localPort < 0 or localPort > 65535:
        raise Exception("Invalid port. Should be an integer between 0 and 65535, inclusive.")
    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind( (address, localPort) ) # '' indicates bind to all IP addresses
    
    while True:
        sock.settimeout(0.5)
        try:
            _, recvAddress = sock.recvfrom(1024, socket.MSG_PEEK) # Don't read the message, just get the address
        except socket.timeout:
            continue
        # except:
            # continue # TODO check for an exit request? otherwise need ^C to quit
        
        # connSock = socket.socket(type=socket.SOCK_DGRAM)
        # connSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # connSock.bind( (address, localPort) ) # '' indicates bind to all IP addresses
        
        connSock = sock.dup()
        connSock.connect(recvAddress)
        
        host = recvAddress[0]
        port = recvAddress[1]
        
        client = ClientData(host=host, port=port, sock=connSock, connectionState=ServerState.HANDSHAKE_STARTED, loadFileLocation=loadFileLocation)
        
        print("Connection initiated by IP '{}' and port {}".format(host, port))
        connectionSuccess = completeConnectionServer(client)
        
        if client.getConnectionState() == ServerState.DATA_EXCHANGE:
            print("Connection from IP '{}' and port {} successful".format(host, port))
        else:
            print("Connection attempt from IP '{}' and port {} failed\n\n".format(host, port))
            connSock.close()
            sock.close()
            sock = socket.socket(type=socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind( (address, localPort) ) # '' indicates bind to all IP addresses
            continue
        
        dataExchangeLoop(client)
        
        connSock.close()
        sock.close()
        sock = socket.socket(type=socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind( (address, localPort) ) # '' indicates bind to all IP addresses
        
        print("Disconnected from client IP '{}' and port {}\n\n".format(host, port))
        


def completeConnectionServer(client):

    sock = client.getSocket()
    
    privDhVal = None
    params = None
    pubDhVal = None
    
    connected = True
    sock.settimeout(RESPONSE_TIMEOUT)
    resendCount = 0
    maxResendCount = 10
    # Split or otherwise async?
    while client.getConnectionState() < ServerState.DATA_EXCHANGE and resendCount < maxResendCount:
        # data, _ancData, msgFlags, address= connSock.recvmsg(1024)
        # data = connSock.recv(1024)
        try:
            data = sock.recv(1024)
        except socket.timeout:
            data = -1
        except:
            continue
        
        state = client.getConnectionState()
        
        success = False
        if state == ServerState.HANDSHAKE_STARTED:
            if data != -1:
                success, params, pubDhVal, privDhVal = handleConnectRequest(client, data)
            if not success: # It wasn't a valid connection request, so ignore it
                client.setConnectionState(ServerState.SHUTDOWN_COMPLETE)
            else:
                resendCount = 0
        elif state == ServerState.CONNECT_RESPONSE_SENT:
            if data != -1:
                success = handleDiffieHellmanResponse(client, data, privDhVal)
            if not success and client.getConnectionState() <= ServerState.CONNECT_RESPONSE_SENT: # Not a DH-response and not a total failure
                # Resend the connect response
                success, _, _, _ = handleConnectRequest(client, data, params, pubDhVal)
                resendCount += 1
            else:
                resendCount = 0
        elif state == ServerState.KEYS_ADVERTISED:
            if data != -1:
                success = handleKeyAdvertisementServer(client, data)
            if not success and client.getConnectionState() <= ServerState.KEYS_ADVERTISED: # Not a DH-response and not a total failure
                # Resend the key advertisement
                success = handleDiffieHellmanResponse(client, data)
                resendCount += 1
            else:
                resendCount = 0
        
        if resendCount >= maxResendCount:
            print("Max resends hit in connection, marking as shutdown")
            client.setConnectionState(ServerState.SHUTDOWN_COMPLETE)

def dataExchangeLoop(client):
    sock = client.getSocket()
    sessionKey = client.getSessionKey()
    
    sock.settimeout(RESPONSE_TIMEOUT)
    connectionTimeout = 5
    
    lastMessageTime = time()
    while client.getConnectionState() == ServerState.DATA_EXCHANGE and time() < lastMessageTime + connectionTimeout:
        try:
            data = sock.recv(1024)
        except socket.timeout:
            continue
        
        msg = None
        type = None
        try:
            unencryptedData = AES.decrypt(key=sessionKey, data=data)
            msg = Message.fromBytes(unencryptedData)
            type = msg.getType()
            if type != MessageType.SHUTDOWN_REQUEST and type != MessageType.OBJECT_REQUEST and type != MessageType.DATA_ACK and type != KEY_ADVERTISEMENT:
                continue
            
            lastMessageTime = time()
        except: # Probably an OBJECT_REQUEST
            try:
                msg = Message.fromBytes(data)
                if type == MessageType.OBJECT_REQUEST:
                    handleObjectRequest(client, msg)
            except: # An invalid message
                continue
            
        if type == MessageType.SHUTDOWN_REQUEST:
            handleShutdown(client)
        elif type == MessageType.DATA_ACK:
            handleDataAck(client, msg)
        elif type == MessageType.KEY_ADVERTISEMENT:
            handleKeyAdvertisementServer(client, data)
    

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
    clientIp = None
    clientPort = None
    try:
        msg = Message.fromBytes(data)
        pubKeyHash = msg.getPublicKeyHash()
        clientIp = msg.getClientIp()
        clientPort = msg.getClientPort()
        if pubKeyHash == False or pubKeyHash == None: # Not a valid CONNECT_REQUEST. Probably an encrypted message that start with the right number
            return False, None, None, None
    except: # Not a proper message, likely wrong level of encryption
        return False, None, None, None
    
    privDhVal = None
    if client.getConnectionState() == ServerState.HANDSHAKE_STARTED: # Need to save data from CONNECT_REQUEST
        clientPublicKey = clientKeyDict.get(pubKeyHash)
        
        if clientIp != None and clientPort != None:
            client.setUsingIntermediary(True)
            client.setHost(socket.ntohl(clientIp))
            client.setPort(socket.ntohs(clientPort))
        
        if clientPublicKey == None: # An unknown person
            client.setConnectionState(ServerState.SHUTDOWN_COMPLETE)
            return False, None, None, None
        else:
            clientPublicKey = RSA.pubKeyFromLine(clientPublicKey)
            
            client.setConnectionState(ServerState.CONNECT_RESPONSE_SENT)
            client.setPubKey(clientPublicKey)
            
            privDhVal, dhVal = DH.createDiffieHellmanValue()
    
    sendMsgData = {"key": ownPubKeyHash, "exchangeValue": dhVal}
    sendMsg = Message(MessageType.CONNECT_RESPONSE, sendMsgData)
    clientPubKey = client.getPubKey()
    sendMsg = Message(MessageType.CONNECT_RESPONSE, sendMsgData)
    sendBytes = RSA.encrypt(sendMsg.toBytes(), clientPubKey)
    
    sock = client.getSocket()
    sendBytes(client, sendBytes)
    
    return True, dhParams, dhVal, privDhVal

"""
Handles DiffieHellman response messages and sends the key advertisement response. If called in CONNECT_RESPONSE_SENT, updates the client's state and calculates the session key.

:param client:      A ClientData object.
:param data:        The bytes of the message received
:param privDhVal:   The private DiffieHellman value for calculating the session key. Only required and used when in CONNECT_RESPONSE_SENT

:returns:   success - a boolean indicating whether or not the received message was a valid DiffieHellman response
"""
def handleDiffieHellmanResponse(client, data, privDhVal=None):
    dhVal = None
    try:
        clientPubKey = client.getPubKey()
        encryptedData, signature = RSA.separateSignature(data, clientPubKey)
        unencryptedData = RSA.decrypt(data=encryptedData, key=ownPrivKey)
        if not RSA.checkSignature(unencryptedData, clientPubKey, signature):
            return False
        msg = Message.fromBytes(unencryptedData)
        dhVal = msg.getDiffieHellmanValue()
        if dhVal == False or dhVal == None: # Not a valid DIFFIE_HELLMAN_RESPONSE. Probably an encrypted message that start with the right number
            return False
    except: # Not a proper message, likely wrong level of encryption
        if data != -1:
            return False
    
    state = client.getConnectionState()
    
    # Update server state and calculate session key
    if state == ServerState.CONNECT_RESPONSE_SENT:
        client.setConnectionState(ServerState.KEYS_ADVERTISED)
        sessionKey = DH.createDiffieHellmanKey(dhVal, privDhVal)
        client.setSessionKey(sessionKey)
    
    sessionKey = client.getSessionKey()
    
    allowedKeys = list(objectKeyDict.keys())
    sendMsgData = {"keys":allowedKeys}
    sendMsg = Message(MessageType.KEY_ADVERTISEMENT, sendMsgData)
    sendMsgBytes = AES.encrypt(data=sendMsg.toBytes(), key=sessionKey)
    
    sock = client.getSocket()
    sendBytes(client, sendMsgBytes)
    
"""
Handles key advertisement messages received by the server and sends the key advertisement ack. If called in KEYS_ADVERTISED, updates the client's state and saves the allowed keys.

:param client:      A ClientData object.
:param data:        The bytes of the message received

:returns:   success - a boolean indicating whether or not the received message was a valid KEY_ADVERTISEMENT
"""
def handleKeyAdvertisementServer(client, data, privDhVal=None):
    validKeyHashes = None
    try:
        sessionKey = client.getSessionKey()
        unencryptedData = AES.decrypt(data=data, key=sessionKey)
        msg = Message.fromBytes(unencryptedData)
        validKeyHashes = msg.getObjectKeyHashes()
        if validKeyHashes == False or validKeyHashes == None: # Not a valid KEY_ADVERTISEMENT.
            return False
    except: # Not a proper message, likely wrong level of encryption
        raise
        if data != -1:
            return False
    
    state = client.getConnectionState()
    
    # Update server state and calculate session key
    if state == ServerState.KEYS_ADVERTISED:
        client.setConnectionState(ServerState.DATA_EXCHANGE)
        client.setObjectKeyHashes(validKeyHashes)
    
    sendMsg = Message(MessageType.KEY_ADVERTISEMENT_ACK)
    sendMsgBytes = AES.encrypt(data=sendMsg.toBytes(), key=sessionKey)
    
    sock = client.getSocket()
    sendBytes(client, sendMsgBytes)
    
    return True
    
"""
Handles shutdown requests and closes the socket

:param client:      A ClientData object.
"""
def handleShutdown(client):
    client.setConnectionState(ServerState.SHUTDOWN_SENT)

    sock = client.getSocket()
    sock.settimeout(RESPONSE_TIMEOUT)
    
    maxResendCount = 10
    resendCount = 0
    
    sessionKey = client.getSessionKey()
    sendMsg = Message(MessageType.SHUTDOWN_CLOSEE_ACK)
    sendMsgBytes = AES.encrypt(data=sendMsg.toBytes(), key=sessionKey)
    
    sendBytes(client, sendMsgBytes)
    
    while client.getConnectionState() != ServerState.SHUTDOWN_COMPLETE and resendCount < maxResendCount:
        try:
            data = sock.recv(1024)
        except:
            resendCount += 1
            continue
        
        if data == -1:
            sendBytes(client, sendMsgBytes)
        else:
            unencryptedData = AES.decrypt(data=data, key=sessionKey)
            msg = Message.fromBytes(unencryptedData)
            if msg.type == MessageType.SHUTDOWN_CLOSER_ACK:
                client.setConnectionState(ServerState.SHUTDOWN_COMPLETE)
            else:
                sendBytes(client, sendMsgBytes)
        
        resendCount += 1
    
    # sock.close() # TODO make sure this doesn't also close the OG sock
    
"""
Handles object requests received by the server and sends the data message. If the request number is new, updates the request number's state and saves the needed data to the client.

:param client:      A ClientData object.
:param msg:         A Message object with type of OBJECT_REQUEST
"""
def handleObjectRequest(client, msg): # TODO add an objReqAck
    reqNum = msg.getRequestNumber()
    target = msg.getTargetObject()
    keyHash = msg.getRequestedObjectKeyHash()
    sock = client.getSocket()
    
    
    # Make sure all values exist
    if reqNum == False or reqNum == None or target == False or target == None or keyHash == False or keyHash == None:
        return
    
    if not isValidRequestNumber(reqNum) or not keyHash in objectKeyDict.keys(): # TODO create func and decide what makes a request number
        return
    elif not client.checkRequestNumberUsed(reqNum): # A new request
        client.setRequestNumberState(reqNum, DataExchangeState.DATA_SENT)
        
        objectData = retrieveData(target, client.getLoadFileLocation())
        objectKey = objectKeyDict[keyHash]
        # Send an object request ack if either fails
        if objectData == None: # TODO or whatever fail value is for obtainData
            sessionKey = client.getSessionKey()
            sendMsgData = {"status":DataExchangeStatus.OBJ_NOT_FOUND, "requestNum":reqNum}
            sendMsg = Message(MessageType.OBJECT_REQUEST_ACK, sendMsgData)
            sendMsgBytes = AES.encrypt(data=sendMsg.toBytes(), key=sessionKey)
            sendBytes(client, sendMsgBytes)
            print("Requested file not found: '{}'".format(target))
            return
        elif objectKey == None:
            sessionKey = client.getSessionKey()
            sendMsgData = {"status":DataExchangeStatus.UNKNOWN_KEY, "requestNum":reqNum}
            sendMsg = Message(MessageType.OBJECT_REQUEST_ACK, sendMsgData)
            sendMsgBytes = AES.encrypt(data=sendMsg.toBytes(), key=sessionKey)
            sendBytes(client, sendMsgBytes)
            print("Object key unknown for requested file: '{}'".format(target))
            return
        
        objectKey = base64.b64decode(objectKey)
        encryptedObjectData = AES.encrypt(data=objectData, key=objectKey)
        preHashValue = bytearray(objectData) + bytearray(target, "ascii")
        objectHash = getHash(preHashValue) # TODO make it actually append
        encryptedObjectHash = AES.encrypt(data=bytes(objectHash), key=objectKey)
        
        messageData = {"keyHash":keyHash, "dataHash":encryptedObjectHash, "data":encryptedObjectData, "objectName":target, "requestNum":reqNum, "expiration": time() + 3600}
        client.setRequestNumberData(reqNum, messageData) # Save the data to avoid recomputing for resends
        
        sendMsg = Message(MessageType.DATA_MESSAGE, messageData)
        sendMsgBytes = sendMsg.toBytes()
        
        sendBytes(client, sendMsgBytes)
        print("File found and sent: '{}'".format(target))
    elif client.getRequestNumberState(reqNum) == DataExchangeState.DATA_SENT: # A resend request
        messageData = client.getRequestNumberData(reqNum)
        sendMsg = Message(MessageType.DATA_MESSAGE, messageData)
        sendMsgBytes = sendMsg.toBytes()
        
        sendBytes(client, sendMsgBytes)
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
    client.setRequestNumberState(reqNum, DataExchangeState.EXCHANGE_COMPLETE)

def getHash(bytes):
    hash_object = SHA256.new()
    hash_object.update(base64.b64encode(bytes))
    return hash_object.digest()

def getAllowableKeys(fileName):
    keys = set()
    with open(fileName, 'r') as f:
        line = f.readline()
        while line:
            line = line.replace('\r', '')
            line = line.replace('\n', '')
            keys.add(line)
            line = f.readline()
    return keys
    
def isValidRequestNumber(reqNum):
    id = uuid.UUID(int=reqNum)
    # Following line courtesy of user unutbu on the question stackoverflow.com/questions/3795554/extract-the-time-from-a-uuid-v1-in-python
    uuidTime = ((id.time - 0x01b21dd213814000)*100/1e9)
    return time() - uuidTime < 30 # generated within the last 30 seconds

def retrieveData(target, loadFileLocation):
    try:
        with open(loadFileLocation + target, 'rb') as file:
            data = file.read()
            return data
    except:
        return None

def sendBytes(client, sendMsgBytes):
    if client.isUsingIntermediary():
        sendMsgBytes.prepend(htons(client.getPort())) # TODO make this work
        sendMsgBytes.prepend(htonl(client.getHost())) # TODO make this work
    client.getSocket().send(sendMsgBytes)

def main():
    usageStr = """
    usage: python server.py OPTIONS
    
    Options:
    -h  <address> --  address to host the server on. can be IPv4 or a url
    -p <port>  --  port to host the server on. Optional, defaults to 7734
    -c <clientKeyFile> -- a file containing the public keys and their hashes for all authorized clients
    -o <objectKeyFile> -- a file containing the keys and their hashes for decrypting objects
    -f <save file location> -- the path to prepend to all requested files. Default is nothing
    
    The program will request all files from the target server (specifiedin options), saving them locally to files of the same name.
    If no files are specified then a connection attempt will be made, then shutdown immediately
    """
    import sys
    host = None
    port = 7734
    clientKeyFile = None
    localKeyFile = None
    objectKeyFile = None
    loadFileLocation = ""
    files = set()
    optlist, remainingArgs = getopt(sys.argv[1:], 'h:p:c:o:l:f:')
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
        if opt == '-f':
            loadFileLocation = optSet[1]
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
        print(usageStr)
        return
    
    runServer(clientKeyFile, objectKeyFile, localKeyFile, loadFileLocation, host, port)

if __name__ == "__main__":
    main()