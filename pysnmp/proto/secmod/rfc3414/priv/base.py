from pysnmp.proto import error

class AbstractEncryptionService:
    serviceID = None
    def encryptData(self, mibInstrumController, encryptKey,
                    dataToEncrypt):
        raise error.ProtocolError('method not implemented')
    
    def decryptData(self, mibInstrumController, decryptKey,
                    privParameters, encryptedData):
        raise error.ProtocolError('method not implemented')
