#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysnmp.sf.net/license.html
#
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
