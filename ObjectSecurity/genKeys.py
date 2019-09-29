from rsa import ObjSRSA

ObjSRSA.generate_key(1024, "serverKey.pem")
ObjSRSA.generate_key(1024, "clientKey.pem")