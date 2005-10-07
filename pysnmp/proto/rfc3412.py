"""SNMP v3 Message Processing and Dispatching (RFC3412)"""
import time
from pysnmp.smi import builder, instrum
from pysnmp.proto import error
from pysnmp.proto.api import verdec # XXX
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.error import PySnmpError

class MsgAndPduDispatcher:
    """SNMP engine PDU & message dispatcher. Exchanges SNMP PDU's with
       applications and serialized messages with transport level.
    """
    def __init__(self):
        self.mibInstrumController = instrum.MibInstrumController(
            builder.MibBuilder()
            )
        self.mibInstrumController.mibBuilder.loadModules(
            'SNMPv2-MIB', 'SNMP-MPD-MIB', 'SNMP-COMMUNITY-MIB', 'SNMP-TARGET-MIB',
            'SNMP-USER-BASED-SM-MIB'
            )
        
        # Registered context engine IDs
        self.__appsRegistration = {}

        # Source of sendPduHandle and cache of requesting apps
        self.__sendPduHandle = 0L
        self.__cacheRepository = {}

    # These routines manage cache of management apps

    def __newSendPduHandle(self):
        sendPduHandle = self.__sendPduHandle = self.__sendPduHandle + 1
        return sendPduHandle
    
    def __cacheAdd(self, index, **kwargs):
        self.__cacheRepository[index] = kwargs
        return index

    def __cachePop(self, index):
        cachedParams = self.__cacheRepository.get(index)
        if cachedParams is None:
            return
        del self.__cacheRepository[index]
        return cachedParams

    def __cacheUpdate(self, index, **kwargs):
        if not self.__cacheRepository.has_key(index):
            raise error.ProtocolError(
                'Cache miss on update for %s' % kwargs
                )
        self.__cacheRepository[index].update(kwargs)

    def __cacheExpire(self, snmpEngine, cbFun):
        for index, cachedParams in self.__cacheRepository.items():
            if cbFun:
                if cbFun(snmpEngine, cachedParams):
                    del self.__cacheRepository[index]                    

    # Application registration with dispatcher

    # 4.3.1
    def registerContextEngineId(self, contextEngineId, pduTypes, processPdu):
        """Register application with dispatcher"""
        # 4.3.2 -> noop
        if contextEngineId is None:
            # Default to local snmpEngineId
            contextEngineId,= self.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'snmpEngineID')
            contextEngineId = contextEngineId.syntax

        # 4.3.3
        for pduType in pduTypes:
            k = (str(contextEngineId), pduType)
            if self.__appsRegistration.has_key(k):
                raise error.ProtocolError(
                    'Duplicate registration %s/%s' % (contextEngineId, pduType)
                    )

            # 4.3.4
            self.__appsRegistration[k] = processPdu
        
    # 4.4.1
    def unregisterContextEngineId(self, contextEngineId, pduTypes):
        """Unregister application with dispatcher"""
        # 4.3.4
        if contextEngineId is None:
            # Default to local snmpEngineId
            contextEngineId, = self.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'snmpEngineID')

        for pduType in pduTypes:
            k = (str(contextEngineId), pduType)
            if self.__appsRegistration.has_key(k):
                del self.__appsRegistration[k]

    def getRegisteredApp(self, contextEngineId, pduType):
        return self.__appsRegistration.get(
            (str(contextEngineId), pduType)
            )

    # Dispatcher <-> application API
    
    # 4.1.1
    
    def sendPdu(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineID,
        contextName,
        pduVersion,
        PDU,
        expectResponse
        ):
        """PDU dispatcher -- prepare and serialize a request or notification"""
#        print 'sendPdu', PDU
#        print transportDomain, transportAddress, messageProcessingModel, securityModel, securityName, securityLevel, contextEngineID, contextName, pduVersion
        # 4.1.1.2
        mpHandler = snmpEngine.messageProcessingSubsystems.get(
            int(messageProcessingModel)
            )
        if mpHandler is None:
            raise error.StatusInformation(
                errorIndication='unsupportedMsgProcessingModel'
                )

        # 4.1.1.3
        sendPduHandle = self.__newSendPduHandle()
        self.__cacheAdd(
            sendPduHandle, expectResponse=expectResponse
            )

        # 4.1.1.4 & 4.1.1.5
        try:
            ( destTransportDomain,
              destTransportAddress,
              outgoingMessage ) = mpHandler.prepareOutgoingMessage(
                snmpEngine,
                transportDomain,
                transportAddress,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineID,
                contextName,
                pduVersion,
                PDU,
                expectResponse,
                sendPduHandle
                )
        except error.StatusInformation, statusInformation:
#            self.releaseStateInformation(snmpEngine, sendPduHandle)
            raise

        # 4.1.1.6
        if snmpEngine.transportDispatcher is None:
            raise error.PySnmpError('Transport dispatcher not set')
        snmpEngine.transportDispatcher.sendMessage(
            outgoingMessage, destTransportDomain, destTransportAddress
            )
        
        # Update cache with orignal req params (used for retrying)
        self.__cacheUpdate(
            sendPduHandle,
            transportDomain=transportDomain,
            transportAddress=transportAddress,
            messageProcessingModel=messageProcessingModel,
            securityModel=securityModel,
            securityName=securityName,
            securityLevel=securityLevel,
            contextEngineID=contextEngineID,
            contextName=contextName,
            pduVersion=pduVersion,
            PDU=PDU,
            expectResponse=expectResponse,
            sendPduHandle=sendPduHandle,
            )

        return sendPduHandle

    # 4.1.2.1
    def returnResponsePdu(
        self,
        snmpEngine,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineID,
        contextName,
        pduVersion,
        PDU,
        maxSizeResponseScopedPDU,
        stateReference,
        statusInformation
        ):
        """PDU dispatcher -- prepare and serialize a response"""
#        print 'returnResponsePdu', PDU, statusInformation
        # Extract input values and initialize defaults
        mpHandler = snmpEngine.messageProcessingSubsystems.get(
            int(messageProcessingModel)
            )
        if mpHandler is None:
            raise error.StatusInformation(
                errorIndication='unsupportedMsgProcessingModel'
                )

        # 4.1.2.2
        try:
            ( destTransportDomain,
              destTransportAddress,
              outgoingMessage ) = mpHandler.prepareResponseMessage(
                snmpEngine,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineID,
                contextName,
                pduVersion,
                PDU,
                maxSizeResponseScopedPDU,
                stateReference,
                statusInformation
                )
        except error.StatusInformation, statusInformation:
            # 4.1.2.3
            raise

        # Handle oversized messages XXX transport constrains?
        snmpEngineMaxMessageSize, = self.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'snmpEngineMaxMessageSize')
        if snmpEngineMaxMessageSize.syntax and \
               len(outgoingMessage) > snmpEngineMaxMessageSize.syntax:
            snmpSilentDrops, = self.mibInstrumController.mibBuilder.importSymbols('SNMPv2-MIB', 'snmpSilentDrops')
            snmpSilentDrops.syntax = snmpSilentDrops.syntax + 1
            raise error.MessageTooBigError()
        
        # 4.1.2.4
        snmpEngine.transportDispatcher.sendMessage(
            outgoingMessage,
            destTransportDomain,
            destTransportAddress
            )

    # 4.2.1    
    def receiveMessage(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        wholeMsg
        ):
        """Message dispatcher -- de-serialize message into PDU"""
#        print 'receiveMessage', time.time() #, repr(wholeMsg)
        # 4.2.1.1
        snmpInPkts, = self.mibInstrumController.mibBuilder.importSymbols(
            'SNMPv2-MIB', 'snmpInPkts'
            )
        snmpInPkts.syntax = snmpInPkts.syntax + 1

        # 4.2.1.2
        try:
            restOfWholeMsg = '' # XXX fix decoder non-recursive return
            msgVersion = verdec.decodeMessageVersion(wholeMsg)
        except PySnmpError:
            snmpInAsn1ParseErrs, = self.mibInstrumController.mibBuilder.importSymbols('SNMPv2-MIB', 'snmpInAsn1ParseErrs')
            snmpInAsn1ParseErrs.syntax = snmpInAsn1ParseErrs.syntax + 1
            return ''  # n.b the whole buffer gets dropped

        messageProcessingModel = msgVersion
        
        mpHandler = snmpEngine.messageProcessingSubsystems.get(
            int(messageProcessingModel)
            )
        if mpHandler is None:
            snmpInBadVersions, = self.mibInstrumController.mibBuilder.importSymbols(
                'SNMPv2-MIB', 'snmpInBadVersions'
                )
            snmpInBadVersions.syntax = snmpInBadVersions.syntax + 1
            return restOfWholeMsg

        # 4.2.1.3 -- no-op

        # 4.2.1.4
        try:
            ( messageProcessingModel,
              securityModel,
              securityName,
              securityLevel,
              contextEngineID,
              contextName,
              pduVersion,
              PDU,
              pduType,
              sendPduHandle,
              maxSizeResponseScopedPDU,
              statusInformation,
              stateReference ) = mpHandler.prepareDataElements(
                snmpEngine,
                transportDomain,
                transportAddress,
                wholeMsg
                )
        except error.StatusInformation, statusInformation:
            if statusInformation.has_key('sendPduHandle'):
                # Dropped REPORT -- re-run pending reqs queue as some
                # of them may be waiting for this REPORT
                self.__expireRequest(
                    snmpEngine,
                    self.__cachePop(statusInformation['sendPduHandle']),
                    statusInformation
                    )
            return restOfWholeMsg

#        print 'recv', PDU
        # 4.2.2
        if sendPduHandle is None:
            # 4.2.2.1 (request or notification)

            # 4.2.2.1.1
            processPdu = self.getRegisteredApp(contextEngineID, pduType)

            # 4.2.2.1.2
            if processPdu is None:
                # 4.2.2.1.2.a
                snmpUnknownPDUHandlers, = self.mibInstrumController.mibBuilder.importSymbols('SNMP-MPD-MIB', 'snmpUnknownPDUHandlers')
                snmpUnknownPDUHandlers.syntax = snmpUnknownPDUHandlers.syntax+1

                # 4.2.2.1.2.b
                statusInformation = {
                    'errorIndication': 'unknownPDUHandler',
                    'oid': snmpUnknownPDUHandlers.name,
                    'val': snmpUnknownPDUHandlers.syntax
                    }                    

                try:
                    ( destTransportDomain,
                      destTransportAddress,
                      outgoingMessage ) = mpHandler.prepareResponseMessage(
                        snmpEngine,
                        messageProcessingModel,
                        securityModel,
                        securityName,
                        securityLevel,
                        contextEngineID,
                        contextName,
                        pduVersion,
                        PDU,
                        maxSizeResponseScopedPDU,
                        stateReference,
                        statusInformation
                        )
                except error.StatusInformation, statusInformation:
                    return restOfWholeMsg
                
                # 4.2.2.1.2.c
                try:
                    snmpEngine.transportDispatcher.sendMessage(
                        outgoingMessage,
                        destTransportDomain,
                        destTransportAddress
                        )
                except PySnmpError: # XXX
                    pass

                # 4.2.2.1.2.d
                return restOfWholeMsg
            else:
                # 4.2.2.1.3
                processPdu(
                    snmpEngine,
                    messageProcessingModel,
                    securityModel,
                    securityName,
                    securityLevel,
                    contextEngineID,
                    contextName,
                    pduVersion,
                    PDU,
                    maxSizeResponseScopedPDU,
                    stateReference
                    )
                return restOfWholeMsg
        else:
            # 4.2.2.2 (response)
            
            # 4.2.2.2.1
            cachedParams = self.__cachePop(sendPduHandle)

            # 4.2.2.2.2
            if cachedParams is None:
                snmpUnknownPDUHandlers, = self.mibInstrumController.mibBuilder.importSymbols('SNMP-MPD-MIB', 'snmpUnknownPDUHandlers')
                snmpUnknownPDUHandlers.syntax = snmpUnknownPDUHandlers.syntax+1
                return restOfWholeMsg

            # 4.2.2.2.3
            # no-op ? XXX

            # 4.2.2.2.4
            processResponsePdu, timeoutAt, cbCtx = cachedParams[
                'expectResponse'
                ]
            processResponsePdu(
                snmpEngine,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineID,
                contextName,
                pduVersion,
                PDU,
                statusInformation,
                cachedParams['sendPduHandle'],
                cbCtx
                )

            return restOfWholeMsg

    def releaseStateInformation(
        self, snmpEngine, sendPduHandle, messageProcessingModel
        ):
        mpHandler = snmpEngine.messageProcessingSubsystems.get(
            int(messageProcessingModel)
            )
        mpHandler.releaseStateInformation(sendPduHandle)
        
    # Cache expiration stuff

    def __expireRequest(self, snmpEngine,cachedParams,statusInformation=None):
        processResponsePdu, timeoutAt, cbCtx = cachedParams['expectResponse']
        if statusInformation is None and time.time() < timeoutAt:
            return
        # Fail timed-out requests        
        if not statusInformation:
            statusInformation = error.StatusInformation(
                errorIndication='requestTimedOut'
                )
        self.releaseStateInformation(
            snmpEngine,
            cachedParams['sendPduHandle'],
            cachedParams['messageProcessingModel']
            )
        processResponsePdu(
            snmpEngine,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            statusInformation,
            cachedParams['sendPduHandle'],
            cbCtx
            )
        return 1
        
    def receiveTimerTick(self, snmpEngine, timeNow):
        self.__cacheExpire(snmpEngine, self.__expireRequest)
