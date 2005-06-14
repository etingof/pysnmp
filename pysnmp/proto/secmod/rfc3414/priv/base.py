class AbstractEncryptionService:
    serviceID = None
    def encryptData(self, encryptKey, dataToEncrypt): pass
    def decryptData(self, decryptKey, privParameters, encryptedData): pass
