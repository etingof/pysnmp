from pysnmp.proto.secmod.rfc3414.auth import base

class NoAuth(base.AbstractAuthenticationService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 1)  # usmNoAuthProtocol
