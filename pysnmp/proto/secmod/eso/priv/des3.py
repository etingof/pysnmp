# Reeder 3DES-EDE for USM (Internet draft)
# http://www.snmp.com/eso/draft-reeder-snmpv3-usm-3desede-00.txt
import random, string
from pysnmp.proto.secmod.rfc3414.priv import base
from pysnmp.proto.secmod.rfc3414.auth import hmacmd5, hmacsha
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.proto import errind, error
from pyasn1.type import univ

try:
    from sys import version_info
except ImportError:
    version_info = ( 0, 0 )   # a really early version

try:
    from Crypto.Cipher import DES3
except ImportError:
    DES3 = None
    
random.seed()

# 5.1.1

class Des3(base.AbstractEncryptionService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 2, 3) # usm3DESEDEPrivProtocol
    if version_info < (2, 3):
        _localInt = long(random.random()*0xffffffffL)
    else:
        _localInt = random.randrange(0, 0xffffffffL)

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
            localPrivKey = localPrivKey + localkey.localizeKeyMD5(
                localPrivKey, snmpEngineID
                )
        elif authProtocol == hmacsha.HmacSha.serviceID:
            localPrivKey = localkey.localizeKeySHA(privKey, snmpEngineID)
            localPrivKey = localPrivKey + localkey.localizeKeySHA(
                localPrivKey, snmpEngineID
                )
        else:
            raise error.ProtocolError(
                'Unknown auth protocol %s' % (authProtocol,)
                )
        return localPrivKey[:32] # key+IV
        
    # 5.1.1.1
    def __getEncryptionKey(self, privKey, snmpEngineBoots):
        # 5.1.1.1.1
        des3Key = privKey[:24]
        preIV = privKey[24:32]

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

        # salt not yet hashed XXX
        
        return des3Key, \
               string.join(map(chr, salt), ''), \
               string.join(map(lambda x,y: chr(x^ord(y)), salt, preIV), '')

    def __getDecryptionKey(self, privKey, salt):
        return privKey[:24], string.join(
            map(lambda x,y: chr(ord(x)^ord(y)), salt, privKey[24:32]), ''
            )

    # 5.1.1.2
    def encryptData(self, encryptKey, privParameters, dataToEncrypt):
        if DES3 is None:
            raise error.StatusInformation(
                errorIndication=errind.encryptionError
                )

        snmpEngineBoots, snmpEngineTime, salt = privParameters
        
        des3Key, salt, iv = self.__getEncryptionKey(
            str(encryptKey), snmpEngineBoots
            )

        des3Obj = DES3.new(des3Key, DES3.MODE_CBC, iv)
        
        privParameters = univ.OctetString(salt)

        plaintext =  dataToEncrypt + '\x00' * (8 - len(dataToEncrypt) % 8)
        cipherblock = iv
        ciphertext = ''
        while plaintext:
            cipherblock = des3Obj.encrypt(
                string.join(map(lambda x,y: chr(ord(x)^ord(y)), cipherblock, plaintext[:8]), '')
                )
            ciphertext = ciphertext + cipherblock
            plaintext = plaintext[8:]

        return univ.OctetString(ciphertext), privParameters
        
    # 5.1.1.3
    def decryptData(self, decryptKey, privParameters, encryptedData):
        if DES3 is None:
            raise error.StatusInformation(
                errorIndication=errind.decryptionError
                )
        snmpEngineBoots, snmpEngineTime, salt = privParameters
        
        if len(salt) != 8:
            raise error.StatusInformation(
                errorIndication=errind.decryptionError
                )
            
        salt = str(salt)

        des3Key, iv = self.__getDecryptionKey(str(decryptKey), salt)

        if len(encryptedData) % 8 != 0:
            raise error.StatusInformation(
                errorIndication=errind.decryptionError
                )

        des3Obj = DES3.new(des3Key, DES3.MODE_CBC, iv)

        plaintext = ''
        ciphertext = str(encryptedData)
        cipherblock = iv
        while ciphertext:
            plaintext = plaintext + string.join(map(
                lambda x,y: chr(ord(x)^ord(y)),
                cipherblock,
                des3Obj.decrypt(ciphertext[:8])
                ), '')
            cipherblock = ciphertext[:8]
            ciphertext = ciphertext[8:]

        return plaintext
    
