from pysnmp.proto.secmod import error

class AbstractSecurityModel:
    def __init__(self, mibInstrumController=None):
        self.mibInstrumController = mibInstrumController
        self.__cacheEntries = {}
    
    def processIncomingMsg(self, msg, **kwargs):
        raise error.BadArgumentError(
            'Security model %s not implemented' % self
            )

    def generateRequestMsg(self, msg, **kwargs):
        raise error.BadArgumentError(
            'Security model %s not implemented' % self
            )

    def generateResponseMsg(self, msg, **kwargs):
        raise error.BadArgumentError(
            'Security model %s not implemented' % self
            )
