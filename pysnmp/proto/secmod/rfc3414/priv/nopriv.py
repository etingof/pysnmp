from pysnmp.proto.secmod.rfc3414.priv import base

class NoPriv(base.AbstractEncryptionService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 2, 1) # usmNoPrivProtocol
