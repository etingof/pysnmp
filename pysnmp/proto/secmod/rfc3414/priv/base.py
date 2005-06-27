class AbstractEncryptionService:
    serviceID = None
    def encryptData(self, mibInstrumController, encryptKey,
                    dataToEncrypt):pass
    def decryptData(self, mibInstrumController, decryptKey,
                    privParameters, encryptedData): pass
