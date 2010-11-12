from pysnmp.proto.secmod.rfc3414.priv import base
from pysnmp.proto import error

class NoPriv(base.AbstractEncryptionService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 2, 1) # usmNoPrivProtocol
    def encryptData(self, mibInstrumController, encryptKey,
                    dataToEncrypt):
        raise error.StatusInformation(errorIndication='no encryption')
    
    def decryptData(self, mibInstrumController, decryptKey,
                    privParameters, encryptedData):
        raise error.StatusInformation(errorIndication='no encryption')
