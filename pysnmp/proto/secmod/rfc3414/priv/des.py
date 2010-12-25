import random, string
from pysnmp.proto.secmod.rfc3414.priv import base
from pyasn1.type import univ
from pysnmp.proto import error

try:
    from sys import version_info
except ImportError:
    version_info = ( 0, 0 )   # a really early version

try:
    from Crypto.Cipher import DES
except ImportError:
    DES = None
    
random.seed()

# 8.2.4

class Des(base.AbstractEncryptionService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 2, 2) # usmDESPrivProtocol
    if version_info < (2, 3):
        _localInt = long(random.random()*0xffffffffL)
    else:
        _localInt = random.randrange(0, 0xffffffffL)
    # 8.1.1.1
    def __getEncryptionKey(self, privKey, snmpEngineBoots):
        desKey = privKey[:8]
        preIV = privKey[8:16]

        securityEngineBoots = long(snmpEngineBoots)

        salt = [
            securityEngineBoots>>24&0xff,
            securityEngineBoots>>16&0xff,
            securityEngineBoots>>8&0xff,
            securityEngineBoots&0xff,
            self._localInt>>24&0xff,
            self._localInt>>16&0xff,
            self._localInt>>8&0xff,
            self._localInt&0xff
            ]
        if self._localInt == 0xffffffffL:
            self._localInt = 0
        else:
            self._localInt = self._localInt + 1

        return desKey, \
               string.join(map(chr, salt), ''), \
               string.join(map(lambda x,y: chr(x^ord(y)), salt, preIV), '')

    def __getDecryptionKey(self, privKey, salt):
        return privKey[:8], string.join(
            map(lambda x,y: chr(ord(x)^ord(y)), salt, privKey[8:16]), ''
            )
        
    # 8.2.4.1
    def encryptData(self, encryptKey, privParameters, dataToEncrypt):
        if DES is None:
            raise error.StatusInformation(
                errorIndication=errind.encryptionError
                )

        snmpEngineBoots, snmpEngineTime, salt = privParameters
        
        # 8.3.1.1
        desKey, salt, iv = self.__getEncryptionKey(
            str(encryptKey), snmpEngineBoots
            )

        # 8.3.1.2
        privParameters = univ.OctetString(salt)

        # 8.1.1.2
        desObj = DES.new(desKey, DES.MODE_CBC, iv)
        plaintext =  dataToEncrypt + '\x00' * (8 - len(dataToEncrypt) % 8)
        ciphertext = desObj.encrypt(plaintext)

        # 8.3.1.3 & 4
        return univ.OctetString(ciphertext), privParameters
        
    # 8.2.4.2
    def decryptData(self, decryptKey, privParameters, encryptedData):
        if DES is None:
            raise error.StatusInformation(
                errorIndication=errind.decryptionError
                )

        snmpEngineBoots, snmpEngineTime, salt = privParameters
        
        # 8.3.2.1
        if len(salt) != 8:
            raise error.StatusInformation(
                errorIndication=errind.decryptionError
                )
            
        # 8.3.2.2
        salt = str(salt)

        # 8.3.2.3
        desKey, iv = self.__getDecryptionKey(str(decryptKey), salt)

        # 8.3.2.4 -> 8.1.1.3
        if len(encryptedData) % 8 != 0:
            raise error.StatusInformation(
                errorIndication=errind.decryptionError
                )

        desObj = DES.new(desKey, DES.MODE_CBC, iv)
        
        # 8.3.2.6
        return desObj.decrypt(str(encryptedData))
