# adsec15 Fall 2019

import socket
import os
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


def runIntermediary(saveFileLocation, localPort):
    
    if not isinstance(localPort, int) or localPort < 0 or localPort > 65535:
        raise Exception("Invalid port. Should be an integer between 0 and 65535, inclusive.")
    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind( ('', localPort) ) # '' indicates bind to all IP addresses
    
    while True:
        try:
            data, recvAddress = sock.recvfrom(1024, 0)
        except socket.timeout:
            continue

        print(recvAddress)
        msgBytes = None
        targetIp = None
        targetPort = None
        try:
            msgBytes, targetIp , targetPort = separateMessage(data)
        except: # Probably an insufficiently long message, in which case just ignore it
            continue
        
        try:
            recvMsg = Message.fromBytes(msgBytes)
            
            if recvMsg.getType() == MessageType.DATA_MESSAGE:
                cacheData(recvMsg, saveFileLocation)
            elif recvMsg.getType() == MessageType.OBJECT_REQUEST and isCached(recvMsg, saveFileLocation):
                object, expired = retrieveFromCache(recvMsg, saveFileLocation)
                if not expired:
                    msgData = {
                        "requestNum": recvMsg.getRequestNumber(),
                        "keyHash": recvMsg.getObjectKeyHash(),
                        "objectName": recvMsg.getObjectName(),
                        "data": object.getObjectData(),
                        "dataHash": object.getObjectDataHash(),
                        "expiration": object.getExpiration()
                    }
                    sendMsg = Message(MessageType.DATA_MESSAGE, msgData)
                    try:
                        sock.sendto(sendMsg.toBytes(), recvAddress)
                    except:
                        print("Could not return cached object to IP {} and port {}".format(recvAddress[0], recvAddress[1])) 
                    continue
            elif recvMsg.getType() == MessageType.CONNECT_REQUEST: # Give the server a port-host combo the intermediary can use
                recvMsg.data["clientIp"] = socket.htonl(socket.inet_aton(recvAddress[0]))
                recvMsg.data["clientPort"] = socket.htons(recvAddress[1])
                msgBytes = recvMsg.toBytes()
        
        try:
            sock.sendto(msgBytes, (targetIp, targetPort))
        except:
            print("Could not forward message to IP {} and port {}".format(targetIp, targetPort))
        

def cacheData(msg, saveFileLocation):
    filepath = genObjectFilepath(msg, saveFileLocation)
    
    f = open(filepath, "w+")
    f.write(msg.toBytes())
    f.close()
    
def isCached(msg, saveFileLocation):
    filepath = genObjectFilepath(msg, saveFileLocation)
    
    return os.path.isfile(filepath)

def retrieveFromCache(msg, saveFileLocation):
    filepath = genObjectFilepath(msg, saveFileLocation)
    
    f = open(filepath, "r")
    data = f.read()
    f.close()
    objMsg = None
    try:
        objMsg = Message.fromBytes(data)
    except:
        return None, True
    
    if time() > objMsg.getExpiration():
        os.remove(filepath)
        return None, True

    return objMsg, False
    
def genObjectFilepath(msg, saveFileLocation):
    objName = msg.getObjectName()
    objKeyHash = msg.getObjectKeyHash()
    
    return saveFileLocation + objKeyHash + objName

def separateMessage(data):
    targetIp = ntohl(data[:4])
    targetPort = ntohs(data[4:6])
    message = data[6:]
    
    return (message, targetIp, targetPort)

def main():
    usageStr = """
    usage: python intermediary.py OPTIONS
    
    Options:
    -p <port>  --  port to host the intermediary on. Optional, defaults to 12345
    -f <save file location> -- the path to prepend to all requested files. Default is nothing
    
    The program will request all files from the target server (specifiedin options), saving them locally to files of the same name.
    If no files are specified then a connection attempt will be made, then shutdown immediately
    """
    import sys
    port = 12345
    saveFileLocation = ""
    files = set()
    optlist, remainingArgs = getopt(sys.argv[1:], 'f:p:')
    for optSet in optlist:
        opt = optSet[0]
        if opt == '-p':
            port = int(optSet[1])
        if opt == '-f':
            saveFileLocation = optSet[1]
    
    runIntermediary(saveFileLocation, port)

if __name__ == "__main__":
    main()