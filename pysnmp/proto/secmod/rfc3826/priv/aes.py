import random, string
from pysnmp.proto.secmod.rfc3414.priv import base
from pysnmp.proto.secmod.rfc3414.auth import hmacmd5, hmacsha
from pysnmp.proto.secmod.rfc3414 import localkey
from pyasn1.type import univ
from pysnmp.proto import errind, error

try:
    from sys import version_info
except ImportError:
    version_info = ( 0, 0 )   # a really early version

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

random.seed()

# RFC3826

# 

class Aes(base.AbstractEncryptionService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 2, 4) # usmAesCfb128Protocol
    keySize = 16
    if version_info < (2, 3):
        _localInt = long(random.random()*0xffffffffffffffffL)
    else:
        _localInt = random.randrange(0, 0xffffffffffffffffL)
    # 3.1.2.1
    def __getEncryptionKey(self, privKey, snmpEngineBoots, snmpEngineTime):
        salt = [
            self._localInt>>56&0xff,
            self._localInt>>48&0xff,
            self._localInt>>40&0xff,
            self._localInt>>32&0xff,
            self._localInt>>24&0xff,
            self._localInt>>16&0xff,
            self._localInt>>8&0xff,
            self._localInt&0xff
            ]
        
        if self._localInt == 0xffffffffffffffffL:
            self._localInt = 0
        else:
            self._localInt = self._localInt + 1

        salt = string.join(map(chr, salt), '')

        return self.__getDecryptionKey(privKey, snmpEngineBoots,
                                       snmpEngineTime, salt) + ( salt, )

    def __getDecryptionKey(self, privKey, snmpEngineBoots,
                           snmpEngineTime, salt):
        snmpEngineBoots, snmpEngineTime, salt = (
            long(snmpEngineBoots), long(snmpEngineTime), str(salt)
            )

        iv = [
            snmpEngineBoots>>24&0xff,
            snmpEngineBoots>>16&0xff,
            snmpEngineBoots>>8&0xff,
            snmpEngineBoots&0xff,
            snmpEngineTime>>24&0xff,
            snmpEngineTime>>16&0xff,
            snmpEngineTime>>8&0xff,
            snmpEngineTime&0xff,
            ord(salt[0]),
            ord(salt[1]),
            ord(salt[2]),
            ord(salt[3]),
            ord(salt[4]),
            ord(salt[5]),
            ord(salt[6]),
            ord(salt[7])
            ]

        return privKey[:self.keySize], string.join(map(chr, iv), '')

    def hashPassphrase(self, authProtocol, privKey):
        if authProtocol == hmacmd5.HmacMd5.serviceID:
            return localkey.hashPassphraseMD5(privKey)
        elif authProtocol == hmacsha.HmacSha.serviceID:
            return localkey.hashPassphraseSHA(privKey)
        else:
            raise error.ProtocolError(
                'Unknown auth protocol %s' % (authProtocol,)
                )
        
    def localizeKey(self, authProtocol, privKey, snmpEngineID):
        if authProtocol == hmacmd5.HmacMd5.serviceID:
            localPrivKey = localkey.localizeKeyMD5(privKey, snmpEngineID)
        elif authProtocol == hmacsha.HmacSha.serviceID:
            localPrivKey = localkey.localizeKeySHA(privKey, snmpEngineID)
        else:
            raise error.ProtocolError(
                'Unknown auth protocol %s' % (authProtocol,)
                )
        return localPrivKey[:16]
    
    # 3.2.4.1
    def encryptData(self, encryptKey, privParameters, dataToEncrypt):
        if AES is None:
            raise error.StatusInformation(
                errorIndication=errind.encryptionError
                )
 
        snmpEngineBoots, snmpEngineTime, salt = privParameters

        # 3.3.1.1
        aesKey, iv, salt = self.__getEncryptionKey(
            str(encryptKey), snmpEngineBoots, snmpEngineTime
            )

        # 3.3.1.3
        aesObj = AES.new(aesKey, AES.MODE_CFB, iv, segment_size=128)

        # PyCrypto seems to require padding
        dataToEncrypt = dataToEncrypt + '\0' * (16-len(dataToEncrypt)%16)

        ciphertext = aesObj.encrypt(dataToEncrypt)

        # 3.3.1.4
        return univ.OctetString(ciphertext), univ.OctetString(salt)
        
    # 3.2.4.2
    def decryptData(self, decryptKey, privParameters, encryptedData):
        if AES is None:
            raise error.StatusInformation(
                errorIndication=errind.decryptionError
                )

        snmpEngineBoots, snmpEngineTime, salt = privParameters
        
        # 3.3.2.1
        if len(salt) != 8:
            raise error.StatusInformation(
                errorIndication=errind.decryptionError
                )

        # 3.3.2.3
        aesKey, iv = self.__getDecryptionKey(
            str(decryptKey), snmpEngineBoots, snmpEngineTime, salt
            )

        aesObj = AES.new(aesKey, AES.MODE_CFB, iv, segment_size=128)

        # PyCrypto seems to require padding
        encryptedData = encryptedData + '\0' * (16-len(encryptedData)%16)

        # 3.3.2.4-6
        return aesObj.decrypt(str(encryptedData))
