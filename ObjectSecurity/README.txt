The implementation is designed to transfer files from the server to the client only.
Usage-Key Generation:
To generate a new public-private RSA key pair for either side run the command on the following line
python genKeys.py

This will (re-)create the files "serverKey.pem" and "clientKey.pem" with public and private keys generated as
the program expects them. These are the files that should be referenced by the '-l' argument in server.py
and client.py. It will also add their public keys to "serverPubKey.txt" and "clientPubKey.txt", which 
are the files that should be referenced by the '-s' and '-c' argument for client.py and server.py,
respectively.

aesKeys.txt contains several strings used to generate AES keys for object encryption.


Usage-Server:
usage: python server.py OPTIONS
    
Options:
-h <address> --  address to host the server on. can be IPv4 or a url
-p <port>  --  port to host the server on. Optional, defaults to 7734
-c <clientKeyFile> -- a file containing the public keys and their hashes for all authorized clients
-o <objectKeyFile> -- a file containing the keys and their hashes for decrypting objects
-f <save file location> -- the path to prepend to all requested files. Default is nothing
    
The program will setup a server to which clients can connect and retrieve files from.

Example usage-Server:
python server.py -h localhost -c clientPubKey.txt -o aesKeys.txt -l serverKey.pem -f serverFiles/
The above command will setup the server at 'localhost' a.k.a 127.0.0.1, use clientPubKey.txt to find
the public keys of clients that may connect to it, use aesKeys.txt to obtain the keys that it can encrypt
objects with, use the keys in serverKey.pem to encrypt the initial handshake, and load any files requested
from the serverFiles folder.

Usage-Client:
usage: python client.py OPTIONS FILE...
    
Options:
-h  <host> --  target host. can be IPv4 or a url
-p <port>  --  target port. Optional, defaults to 7734
-s <serverKeyFile> -- a file containing the public keys for all known servers
-o <objectKeyFile> -- a file containing the keys for decrypting objects
-l <localKeyFile> -- a file containing the public and private keys for this client
-f <save file location> -- the path to prepend to all saved files. default is nothing
    
The program will request all files from the target server (specifiedin options), saving them locally to files
of the same name.
If no files are specified then a connection attempt will be made, then shutdown immediately
note: The largest file this has been successfully tested with is 218 bytes

Example usage-Server:
python client.py -h localhost -s serverPubKey.txt -o aesKeys.txt -l clientKey.pem -f clientFiles/ file1 file2
The above command will try to connect to a server at 'localhost' on port 7734, use serverPubKey.txt to find
the private keys of servers it is willing to connect to, use aesKeys.txt to obtain the keys that it can
use to decrypt objects, use the keys in clientKey.pem to encrypt its messages, and save files to the
clientFiles folder.
If the files 'file1' and 'file2' exist on the target server they will be downloaded. If any do not exist
they will be skipped

Note: Crypto is from the pycrypto package in pip, and cbor from the cbor package