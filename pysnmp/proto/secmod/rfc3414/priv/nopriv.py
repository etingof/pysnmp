from pysnmp.proto.secmod.rfc3414.priv import base
from pysnmp.proto import errind, error

class NoPriv(base.AbstractEncryptionService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 2, 1) # usmNoPrivProtocol
    def encryptData(self, encryptKey, privParameters, dataToEncrypt):
        raise error.StatusInformation(errorIndication=errind.noEncryption)
    
    def decryptData(self, decryptKey, privParameters, encryptedData):
        raise error.StatusInformation(errorIndication=errind.noEncryption)
