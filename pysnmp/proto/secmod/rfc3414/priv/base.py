from pysnmp.proto import error

class AbstractEncryptionService:
    serviceID = None
    
    def hashPassphrase(self, authProtocol, privKey):
        raise error.ProtocolError('no encryption')

    def localizeKey(self, authProtocol, privKey, snmpEngineID):
        raise error.ProtocolError('no encryption')
    
    def encryptData(self, encryptKey, privParameters, dataToEncrypt):
        raise error.ProtocolError('no encryption')
    
    def decryptData(self, decryptKey, privParameters, encryptedData):
        raise error.ProtocolError('no encryption')

