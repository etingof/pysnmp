from pysnmp.proto import error

class AbstractEncryptionService:
    serviceID = None
    def encryptData(self, encryptKey, privParameters, dataToEncrypt):
        raise error.ProtocolError('no encryption')
    
    def decryptData(self, decryptKey, privParameters, encryptedData):
        raise error.ProtocolError('no encryption')
