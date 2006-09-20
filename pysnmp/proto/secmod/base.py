from pysnmp.proto import error

class AbstractSecurityModel:
    securityModelID = None
    __stateReference = 0L
    def __init__(self):
        self.__cacheEntries = {}

    def processIncomingMsg(
        self,
        snmpEngine,
        messageProcessingModel,
        maxMessageSize,
        securityParameters,
        securityModel,
        securityLevel,
        wholeMsg,
        msg,
        ):
        raise error.ProtocolError(
            'Security model %s not implemented' % self
            )

    def generateRequestMsg(
        self,
        snmpEngine,
        messageProcessingModel,
        globalData,
        maxMessageSize,
        securityModel,
        securityEngineID,
        securityName,
        securityLevel,
        scopedPDU,
        ):
        raise error.ProtocolError(
            'Security model %s not implemented' % self
            )

    def generateResponseMsg(
        self,
        snmpEngine,
        messageProcessingModel,
        globalData,
        maxMessageSize,
        securityModel,
        securityEngineID,
        securityName,
        securityLevel,
        scopedPDU,
        securityStateReference
        ):
        raise error.ProtocolError(
            'Security model %s not implemented' % self
            )

    # Caching stuff
    
    def _cachePush(self, **securityData):
        stateReference = AbstractSecurityModel.__stateReference
        AbstractSecurityModel.__stateReference = stateReference + 1
        self.__cacheEntries[stateReference] = securityData
        return stateReference
    
    def _cachePop(self, stateReference):
        securityData = self.__cacheEntries.get(stateReference)
        if securityData is None:
            raise error.ProtocolError(
                'Cache miss for stateReference=%s at %s' %
                (stateReference, self)
                )
        del self.__cacheEntries[stateReference]
        return securityData

    def releaseStateInformation(self, stateReference):
        self._cachePop(stateReference)

    def receiveTimerTick(self, snmpEngine, timeNow):
        pass
