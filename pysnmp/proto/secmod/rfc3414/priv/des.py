import random, string
from pysnmp.proto.secmod.rfc3414.priv import base
from pyasn1.type import univ
from pysnmp.proto import error

try:
    from Crypto.Cipher import DES
except ImportError:
    DES = None
    
random.seed()

# 8.2.4

class Des(base.AbstractEncryptionService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 2, 2) # usmDESPrivProtocol
    _localInt = long(random.random()*0xffffffff)
    # 8.1.1.1
    def __getEncryptionKey(self, mibInstrumController, privKey):
        desKey = privKey[:8]
        preIV = privKey[8:16]

        snmpEngineBoots, = mibInstrumController.mibBuilder.importSymbols(
            'SNMP-FRAMEWORK-MIB', 'snmpEngineBoots'
            )
        securityEngineBoots = long(snmpEngineBoots.syntax)

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
        if self._localInt == 0xffffffff:
            self._localInt = 0
        else:
            self._localInt = self._localInt + 1

        return desKey, \
               string.join(map(lambda x: chr(x), salt), ''), \
               string.join(map(lambda x,y: chr(x^ord(y)), salt, preIV), '')

    def __getDecryptionKey(self, mibInstrumController, privKey, salt):
        return privKey[:8], string.join(
            map(lambda x,y: chr(ord(x)^ord(y)), salt, privKey[8:16]), ''
            )
        
    # 8.2.4.1
    def encryptData(self, mibInstrumController, encryptKey, dataToEncrypt):
        if DES is None:
            raise error.StatusInformation(
                errorIndication='encryptionError'
                )
        
        # 8.3.1.1
        desKey, salt, iv = self.__getEncryptionKey(
            mibInstrumController, str(encryptKey)
            )

        # 8.3.1.2
        privParameters = univ.OctetString(salt)

        # 8.1.1.2
        desObj = DES.new(desKey, DES.MODE_CBC, iv) # XXX
        plaintext =  dataToEncrypt + '\x00' * (8 - len(dataToEncrypt) % 8)
        ciphertext = desObj.encrypt(plaintext)

        # 8.3.1.3 & 4
        return univ.OctetString(ciphertext), privParameters
        
    # 8.2.4.2
    def decryptData(self, mibInstrumController, decryptKey,
                    privParameters, encryptedData):
        if DES is None:
            raise error.StatusInformation(
                errorIndication='decryptionError'
                )
        
        # 8.3.2.1
        if len(privParameters) != 8:
            raise error.StatusInformation(
                errorIndication='decryptionError'
                )
            
        # 8.3.2.2
        salt = str(privParameters)

        # 8.3.2.3
        desKey, iv = self.__getDecryptionKey(
            mibInstrumController, str(decryptKey), salt
            )

        # 8.3.2.4 -> 8.1.1.3
        if len(encryptedData) % 8 != 0:
            raise error.StatusInformation(
                errorIndication='decryptionError'
                )

        desObj = DES.new(desKey, DES.MODE_CBC, iv)
        
        # 8.3.2.6
        return desObj.decrypt(str(encryptedData))
