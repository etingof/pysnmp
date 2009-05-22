"""SNMP v3 Message Processing and Dispatching (RFC3412)"""
import time
from pysnmp.smi import builder, instrum
from pysnmp.proto import error
from pysnmp.proto.api import verdec # XXX
from pysnmp.error import PySnmpError
from pysnmp import debug

class MsgAndPduDispatcher:
    """SNMP engine PDU & message dispatcher. Exchanges SNMP PDU's with
       applications and serialized messages with transport level.
    """
    def __init__(self, mibInstrumController=None):
        if mibInstrumController is None:
            self.mibInstrumController = instrum.MibInstrumController(
                builder.MibBuilder()
                )
        else:
            self.mibInstrumController = mibInstrumController
            
        self.mibInstrumController.mibBuilder.loadModules(
            'SNMPv2-MIB', 'SNMP-MPD-MIB', 'SNMP-COMMUNITY-MIB',
            'SNMP-TARGET-MIB', 'SNMP-USER-BASED-SM-MIB'
            )
        
        # Registered context engine IDs
        self.__appsRegistration = {}

        # Source of sendPduHandle and cache of requesting apps
        self.__sendPduHandle = 0L
        self.__cacheRepository = {}

        # To pass transport info to app
        self.__transportInfo = {}

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

    def getTransportInfo(self, stateReference):
        if self.__transportInfo.has_key(stateReference):
            return self.__transportInfo[stateReference]
        else:
            raise error.ProtocolError(
                'No data for stateReference %s' % stateReference
                )
        
    # Application registration with dispatcher

    # 4.3.1
    def registerContextEngineId(self, contextEngineId, pduTypes, processPdu):
        """Register application with dispatcher"""
        # 4.3.2 -> noop

        # 4.3.3
        for pduType in pduTypes:
            k = (str(contextEngineId), pduType)
            if self.__appsRegistration.has_key(k):
                raise error.ProtocolError(
                    'Duplicate registration %s/%s' % (contextEngineId, pduType)
                    )

            # 4.3.4
            self.__appsRegistration[k] = processPdu

        debug.logger & debug.flagDsp and debug.logger('registerContextEngineId: contextEngineId %s pduTypes %s' % (contextEngineId, pduTypes))
    # 4.4.1
    def unregisterContextEngineId(self, contextEngineId, pduTypes):
        """Unregister application with dispatcher"""
        # 4.3.4
        if contextEngineId is None:
            # Default to local snmpEngineId
            contextEngineId, = self.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')

        for pduType in pduTypes:
            k = (str(contextEngineId), pduType)
            if self.__appsRegistration.has_key(k):
                del self.__appsRegistration[k]

        debug.logger & debug.flagDsp and debug.logger('unregisterContextEngineId: contextEngineId %s pduTypes %s' % (contextEngineId, pduTypes))

    def getRegisteredApp(self, contextEngineId, pduType):
        k = ( str(contextEngineId), pduType )
        if self.__appsRegistration.has_key(k):
            return self.__appsRegistration[k]
        k = ( '', pduType )
        if self.__appsRegistration.has_key(k):
            return self.__appsRegistration[k] # wildcard

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
        contextEngineId,
        contextName,
        pduVersion,
        PDU,
        expectResponse
        ):
        """PDU dispatcher -- prepare and serialize a request or notification"""
        # 4.1.1.2
        mpHandler = snmpEngine.messageProcessingSubsystems.get(
            int(messageProcessingModel)
            )
        if mpHandler is None:
            raise error.StatusInformation(
                errorIndication='unsupportedMsgProcessingModel'
                )

        debug.logger & debug.flagDsp and debug.logger('sendPdu: PDU %s' % PDU.prettyPrint())

        # 4.1.1.3
        sendPduHandle = self.__newSendPduHandle()
        if expectResponse:
            self.__cacheAdd(
                sendPduHandle,
                messageProcessingModel=messageProcessingModel,
                sendPduHandle=sendPduHandle,
                expectResponse=expectResponse
                )

        debug.logger & debug.flagDsp and debug.logger('sendPdu: new sendPduHandle %s' % sendPduHandle)

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
                contextEngineId,
                contextName,
                pduVersion,
                PDU,
                expectResponse,
                sendPduHandle
                )
            debug.logger & debug.flagDsp and debug.logger('sendPdu: MP succeeded')
        except error.StatusInformation, statusInformation:
# XXX is it still needed here?
#            self.releaseStateInformation(snmpEngine, sendPduHandle, messageProcessingModel)
            raise

        # 4.1.1.6
        if snmpEngine.transportDispatcher is None:
            raise error.PySnmpError('Transport dispatcher not set')
        snmpEngine.transportDispatcher.sendMessage(
            outgoingMessage, destTransportDomain, destTransportAddress
            )
        
        # Update cache with orignal req params (used for retrying)
        if expectResponse:
            self.__cacheUpdate(
                sendPduHandle,
                transportDomain=transportDomain,
                transportAddress=transportAddress,
                securityModel=securityModel,
                securityName=securityName,
                securityLevel=securityLevel,
                contextEngineId=contextEngineId,
                contextName=contextName,
                pduVersion=pduVersion,
                PDU=PDU
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
        contextEngineId,
        contextName,
        pduVersion,
        PDU,
        maxSizeResponseScopedPDU,
        stateReference,
        statusInformation
        ):
        """PDU dispatcher -- prepare and serialize a response"""
        # Extract input values and initialize defaults
        mpHandler = snmpEngine.messageProcessingSubsystems.get(
            int(messageProcessingModel)
            )
        if mpHandler is None:
            raise error.StatusInformation(
                errorIndication='unsupportedMsgProcessingModel'
                )

        debug.logger & debug.flagDsp and debug.logger('returnResponsePdu: PDU %s' % (PDU and PDU.prettyPrint() or "<empty>",))

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
                contextEngineId,
                contextName,
                pduVersion,
                PDU,
                maxSizeResponseScopedPDU,
                stateReference,
                statusInformation
                )
            debug.logger & debug.flagDsp and debug.logger('returnResponsePdu: MP suceeded')
        except error.StatusInformation, statusInformation:
            # 4.1.2.3
            raise

        # Handle oversized messages XXX transport constrains?
        snmpEngineMaxMessageSize, = self.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineMaxMessageSize')
        if snmpEngineMaxMessageSize.syntax and \
               len(outgoingMessage) > snmpEngineMaxMessageSize.syntax:
            snmpSilentDrops, = self.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpSilentDrops')
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
        # 4.2.1.1
        snmpInPkts, = self.mibInstrumController.mibBuilder.importSymbols(
            '__SNMPv2-MIB', 'snmpInPkts'
            )
        snmpInPkts.syntax = snmpInPkts.syntax + 1

        # 4.2.1.2
        try:
            restOfWholeMsg = '' # XXX fix decoder non-recursive return
            msgVersion = verdec.decodeMessageVersion(wholeMsg)
        except PySnmpError:
            snmpInAsn1ParseErrs, = self.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpInAsn1ParseErrs')
            snmpInAsn1ParseErrs.syntax = snmpInAsn1ParseErrs.syntax + 1
            return ''  # n.b the whole buffer gets dropped

        debug.logger & debug.flagDsp and debug.logger('receiveMessage: msgVersion %s, msg decoded' % msgVersion)

        messageProcessingModel = msgVersion
        
        mpHandler = snmpEngine.messageProcessingSubsystems.get(
            int(messageProcessingModel)
            )
        if mpHandler is None:
            snmpInBadVersions, = self.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpInBadVersions')
            snmpInBadVersions.syntax = snmpInBadVersions.syntax + 1
            return restOfWholeMsg

        # 4.2.1.3 -- no-op

        # 4.2.1.4
        try:
            ( messageProcessingModel,
              securityModel,
              securityName,
              securityLevel,
              contextEngineId,
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
            debug.logger & debug.flagDsp and debug.logger('receiveMessage: MP succeded')
        except error.StatusInformation, statusInformation:
            if statusInformation.has_key('sendPduHandle'):
                # Dropped REPORT -- re-run pending reqs queue as some
                # of them may be waiting for this REPORT
                debug.logger & debug.flagDsp and debug.logger('receiveMessage: MP failed, statusInformation %s' % statusInformation)
                self.__expireRequest(
                    snmpEngine,
                    self.__cachePop(statusInformation['sendPduHandle']),
                    statusInformation
                    )
            return restOfWholeMsg

        debug.logger & debug.flagDsp and debug.logger('receiveMessage: PDU %s' % PDU.prettyPrint())

        # 4.2.2
        if sendPduHandle is None:
            # 4.2.2.1 (request or notification)

            debug.logger & debug.flagDsp and debug.logger('receiveMessage: pduType %s' % pduType)
            # 4.2.2.1.1
            processPdu = self.getRegisteredApp(contextEngineId, pduType)
            
            # 4.2.2.1.2
            if processPdu is None:
                # 4.2.2.1.2.a
                snmpUnknownPDUHandlers, = self.mibInstrumController.mibBuilder.importSymbols('__SNMP-MPD-MIB', 'snmpUnknownPDUHandlers')
                snmpUnknownPDUHandlers.syntax = snmpUnknownPDUHandlers.syntax+1

                # 4.2.2.1.2.b
                statusInformation = {
                    'errorIndication': 'unknownPDUHandler',
                    'oid': snmpUnknownPDUHandlers.name,
                    'val': snmpUnknownPDUHandlers.syntax
                    }                    

                debug.logger & debug.flagDsp and debug.logger('receiveMessage: unhandled PDU type')
                
                # XXX fails on unknown PDU
                
                try:
                    ( destTransportDomain,
                      destTransportAddress,
                      outgoingMessage ) = mpHandler.prepareResponseMessage(
                        snmpEngine,
                        messageProcessingModel,
                        securityModel,
                        securityName,
                        securityLevel,
                        contextEngineId,
                        contextName,
                        pduVersion,
                        PDU,
                        maxSizeResponseScopedPDU,
                        stateReference,
                        statusInformation
                        )
                except error.StatusInformation, statusInformation:
                    debug.logger & debug.flagDsp and debug.logger('receiveMessage: report failed, statusInformation %s' % statusInformation)
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

                debug.logger & debug.flagDsp and debug.logger('receiveMessage: reporting succeeded')
                
                # 4.2.2.1.2.d
                return restOfWholeMsg
            else:
                # Pass transport info to app
                if stateReference is not None:
                    self.__transportInfo[stateReference] = (
                        transportDomain, transportAddress
                        )
                # 4.2.2.1.3
                processPdu(
                    snmpEngine,
                    messageProcessingModel,
                    securityModel,
                    securityName,
                    securityLevel,
                    contextEngineId,
                    contextName,
                    pduVersion,
                    PDU,
                    maxSizeResponseScopedPDU,
                    stateReference
                    )
                if stateReference is not None:
                    del self.__transportInfo[stateReference]
                debug.logger & debug.flagDsp and debug.logger('receiveMessage: processPdu succeeded')
                return restOfWholeMsg
        else:
            # 4.2.2.2 (response)
            
            # 4.2.2.2.1
            cachedParams = self.__cachePop(sendPduHandle)

            # 4.2.2.2.2
            if cachedParams is None:
                snmpUnknownPDUHandlers, = self.mibInstrumController.mibBuilder.importSymbols('__SNMP-MPD-MIB', 'snmpUnknownPDUHandlers')
                snmpUnknownPDUHandlers.syntax = snmpUnknownPDUHandlers.syntax+1
                return restOfWholeMsg

            debug.logger & debug.flagDsp and debug.logger('receiveMessage: cache read by sendPduHandle %s' % sendPduHandle)
            
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
                contextEngineId,
                contextName,
                pduVersion,
                PDU,
                statusInformation,
                cachedParams['sendPduHandle'],
                cbCtx
                )
            debug.logger & debug.flagDsp and debug.logger('receiveMessage: processResponsePdu succeeded')
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

        debug.logger & debug.flagDsp and debug.logger('__expireRequest: req cachedParams %s' % cachedParams)

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
