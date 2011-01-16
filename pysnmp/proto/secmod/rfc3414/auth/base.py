from pysnmp.proto import errind, error

class AbstractAuthenticationService:
    serviceID = None

    def hashPassphrase(self, authKey):
        raise error.ProtocolError(errind.noAuthentication)
    
    def localizeKey(self, authKey, snmpEngineID):
        raise error.ProtocolError(errind.noAuthentication)
    
    # 7.2.4.1
    def authenticateOutgoingMsg(self, authKey, wholeMsg):
        raise error.ProtocolError(errind.noAuthentication)

    # 7.2.4.2
    def authenticateIncomingMsg(self, authKey, authParameters, wholeMsg):
        raise error.ProtocolError(errind.noAuthentication)
