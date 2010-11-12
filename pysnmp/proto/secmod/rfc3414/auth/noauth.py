from pysnmp.proto.secmod.rfc3414.auth import base
from pysnmp.proto import error

class NoAuth(base.AbstractAuthenticationService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 1)  # usmNoAuthProtocol
    # 7.2.4.2
    def authenticateOutgoingMsg(self, authKey, wholeMsg):
        raise error.StatusInformation(errorIndication='no authentication')

    def authenticateIncomingMsg(self, authKey, authParameters, wholeMsg):
        raise error.StatusInformation(errorIndication='no authentication')
