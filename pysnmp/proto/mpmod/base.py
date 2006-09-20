# MP-specific cache management
from pysnmp.proto import error

class AbstractMessageProcessingModel:
    messageProcessingModelID = None
    __stateReference = __msgID = 0L
    def __init__(self):
        self.__msgIdIndex = {}
        self.__stateReferenceIndex = {}
        self.__sendPduHandleIdx = {}
        # Message expiration mechanics
        self.__expirationQueue = {}
        self.__expirationTimer = 0L
    
    def prepareOutgoingMessage(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
        contextName,
        pduVersion,
        pdu,
        expectResponse,
        sendPduHandle
        ):
        raise error.ProtocolError('method not implemented')
        
    def prepareResponseMessage(
        self,
        snmpEngine,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
        contextName,
        pduVersion,
        pdu,
        maxSizeResponseScopedPDU,
        stateReference,
        statusInformation
        ):
        raise error.ProtocolError('method not implemented')

    def prepareDataElements(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        wholeMsg
        ):
        raise error.ProtocolError('method not implemented')

    def _newStateReference(self):
        AbstractMessageProcessingModel.__stateReference = (
            AbstractMessageProcessingModel.__stateReference + 1
            )
        return self.__stateReference

    # Server mode cache handling

    def _cachePushByStateRef(self, stateReference, **msgInfo):
        if self.__stateReferenceIndex.has_key(stateReference):
            raise error.ProtocolError(
                'Cache dup for stateReference=%s at %s' %
                (stateReference, self)
                )
        expireAt = self.__expirationTimer+50
        self.__stateReferenceIndex[stateReference] = ( msgInfo, expireAt )

        # Schedule to expire
        if not self.__expirationQueue.has_key(expireAt):
            self.__expirationQueue[expireAt] = {}
        if not self.__expirationQueue[expireAt].has_key('stateReference'):
            self.__expirationQueue[expireAt]['stateReference'] = {}
        self.__expirationQueue[expireAt]['stateReference'][stateReference] = 1
        self.__expireCaches()
        
    def _cachePopByStateRef(self, stateReference):
        cacheInfo = self.__stateReferenceIndex.get(stateReference)
        if cacheInfo is None:
            raise error.ProtocolError(
                'Cache miss for stateReference=%s at %s' %
                (stateReference, self)
                )
        del self.__stateReferenceIndex[stateReference]
        cacheEntry, expireAt = cacheInfo
        del self.__expirationQueue[expireAt]['stateReference'][stateReference]
        return cacheEntry

    # Client mode cache handling

    def _newMsgID(self):
        AbstractMessageProcessingModel.__msgID = (
            AbstractMessageProcessingModel.__msgID + 1
            )
        return self.__msgID

    def _cachePushByMsgId(self, msgId, **msgInfo):
        if self.__msgIdIndex.has_key(msgId):
            raise error.ProtocolError(
                'Cache dup for msgId=%s at %s' % (msgId, self)
                )
        expireAt = self.__expirationTimer+50
        self.__msgIdIndex[msgId] = ( msgInfo, expireAt )

        self.__sendPduHandleIdx[msgInfo['sendPduHandle']] = msgId
        
        # Schedule to expire
        if not self.__expirationQueue.has_key(expireAt):
            self.__expirationQueue[expireAt] = {}
        if not self.__expirationQueue[expireAt].has_key('msgId'):
            self.__expirationQueue[expireAt]['msgId'] = {}
        self.__expirationQueue[expireAt]['msgId'][msgId] = 1
        self.__expireCaches()
        
    def _cachePopByMsgId(self, msgId):
        cacheInfo = self.__msgIdIndex.get(msgId)
        if cacheInfo is None:
            raise error.ProtocolError(
                'Cache miss for msgId=%s at %s' % (msgId, self)
                )
        msgInfo, expireAt = cacheInfo
        del self.__sendPduHandleIdx[msgInfo['sendPduHandle']]
        del self.__msgIdIndex[msgId]
        cacheEntry, expireAt = cacheInfo
        del self.__expirationQueue[expireAt]['msgId'][msgId]
        return cacheEntry

    def _cachePopBySendPduHandle(self, sendPduHandle):
        if self.__sendPduHandleIdx.has_key(sendPduHandle):
            self._cachePopByMsgId(self.__sendPduHandleIdx[sendPduHandle])
        
    def __expireCaches(self):
        # Uses internal clock to expire pending messages
        if self.__expirationQueue.has_key(self.__expirationTimer):
            cacheInfo = self.__expirationQueue[self.__expirationTimer]
            if cacheInfo.has_key('stateReference'):
                for stateReference in cacheInfo['stateReference'].keys():
                    del self.__stateReferenceIndex[stateReference]
            if cacheInfo.has_key('msgId'):
                for msgId in cacheInfo['msgId'].keys():
                    del self.__msgIdIndex[msgId]
            del self.__expirationQueue[self.__expirationTimer]
        self.__expirationTimer = self.__expirationTimer + 1

    def releaseStateInformation(self, sendPduHandle):
        try:
            self._cachePopBySendPduHandle(sendPduHandle)
        except error.ProtocolError:
            pass # XXX maybe these should all follow some scheme?
    
    def receiveTimerTick(self, snmpEngine, timeNow):
        pass
