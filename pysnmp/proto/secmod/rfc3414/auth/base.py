from pysnmp.proto import error

class AbstractAuthenticationService:
    serviceID = None
    # 7.2.4.1
    def authenticateOutgoingMsg(self, authKey, wholeMsg):
        raise error.ProtocolError('no authentication')

    # 7.2.4.2
    def authenticateIncomingMsg(self, authKey, authParameters, wholeMsg):
        raise error.ProtocolError('no authentication')
