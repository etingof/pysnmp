class AbstractAuthenticationService:
    serviceID = None
    # 7.2.4.1
    def authenticateOutgoingMsg(self, authKey, wholeMsg):
        pass
    # 7.2.4.2
    def authenticateIncomingMsg(self, authKey, authParameters, wholeMsg):
        pass
