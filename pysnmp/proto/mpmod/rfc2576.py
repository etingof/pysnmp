# SNMP v1 & v2c message processing models implementation
from pyasn1.codec.ber import decoder
from pysnmp.proto.mpmod.base import AbstractMessageProcessingModel
from pysnmp.proto.secmod import rfc2576
from pysnmp.proto import rfc3411, error
from pysnmp.proto.api import v1, v2c
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error
from pysnmp import debug

# Since I have not found a detailed reference to v1MP/v2cMP
# inner workings, the following has been patterned from v3MP. Most
# references here goes to RFC3412.

class SnmpV1MessageProcessingModel(AbstractMessageProcessingModel):
    messageProcessingModelID = 0 # SNMPv1
    _snmpMsgSpec = v1.Message()
    # rfc3412: 7.1
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
        snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
        snmpEngineID = snmpEngineID.syntax
        
        # rfc3412: 7.1.1b
        if rfc3411.confirmedClassPDUs.has_key(pdu.tagSet):
            pdu.setComponentByPosition(1)
            msgID = pdu.getComponentByPosition(0)
            
        # rfc3412: 7.1.4
        # Since there's no SNMP engine identification in v1/2c,
        # set destination contextEngineId to ours
        if not contextEngineId:
            contextEngineId = snmpEngineID

        # rfc3412: 7.1.5
        if not contextName:
            contextName = ''

        debug.logger & debug.flagMP and debug.logger('prepareOutgoingMessage: using contextEngineId %s contextName %s' % (contextEngineId, contextName))

        # rfc3412: 7.1.6
        scopedPDU = ( contextEngineId, contextName, pdu )

        msg = self._snmpMsgSpec.clone()
        msg.setComponentByPosition(0, self.messageProcessingModelID)
        msg.setComponentByPosition(2)
        msg.getComponentByPosition(2).setComponentByType(pdu.tagSet, pdu)

        # rfc3412: 7.1.7
        globalData = ( msg, )

        smHandler = snmpEngine.securityModels.get(int(securityModel))
        if smHandler is None:
            raise error.StatusInformation(
                errorIndication = 'unsupportedSecurityModel'
                )

        # rfc3412: 7.1.9.a & rfc2576: 5.2.1 --> no-op

        snmpEngineMaxMessageSize, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineMaxMessageSize')
            
        # rfc3412: 7.1.9.b
        ( securityParameters,
          wholeMsg ) = smHandler.generateRequestMsg(
            snmpEngine,
            self.messageProcessingModelID,
            globalData,
            snmpEngineMaxMessageSize.syntax,
            securityModel,
            snmpEngineID,
            securityName,
            securityLevel,
            scopedPDU
            )

        # rfc3412: 7.1.9.c
        if rfc3411.confirmedClassPDUs.has_key(pdu.tagSet):
            # XXX rfc bug? why stateReference should be created?
            self._cachePushByMsgId(
                long(msgID),
                sendPduHandle=sendPduHandle,
                msgID=msgID,
                snmpEngineID=snmpEngineID,
                securityModel=securityModel,
                securityName=securityName,
                securityLevel=securityLevel,
                contextEngineId=contextEngineId,
                contextName=contextName,
                transportDomain=transportDomain,
                transportAddress=transportAddress
                )

        return ( transportDomain, transportAddress, wholeMsg )
            
    # rfc3412: 7.1
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
        snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
        snmpEngineID = snmpEngineID.syntax

        # rfc3412: 7.1.2.b
        cachedParams = self._cachePopByStateRef(stateReference)
        msgID = cachedParams['msgID']
        contextEngineId = cachedParams['contextEngineId']
        contextName = cachedParams['contextName']
        securityModel = cachedParams['securityModel']
        securityName = cachedParams['securityName']
        securityLevel = cachedParams['securityLevel']
        securityStateReference = cachedParams['securityStateReference']
        maxMessageSize = cachedParams['msgMaxSize']
        transportDomain = cachedParams['transportDomain']
        transportAddress = cachedParams['transportAddress']

        debug.logger & debug.flagMP and debug.logger('prepareResponseMessage: cache read msgID %s transportDomain %s transportAddress %s by stateReference %s' % (msgID, transportDomain, transportAddress, stateReference))

        # rfc3412: 7.1.3
        if statusInformation:
            # rfc3412: 7.1.3a (N/A)
            
            # rfc3412: 7.1.3b (always discard)
            raise error.StatusInformation(
                errorIndication = 'nonReportable'
                )

        # rfc3412: 7.1.4
        # Since there's no SNMP engine identification in v1/2c,
        # set destination contextEngineId to ours
        if not contextEngineId:
            contextEngineId = snmpEngineID

        # rfc3412: 7.1.5
        if not contextName:
            contextName = ''

        # rfc3412: 7.1.6
        scopedPDU = ( contextEngineId, contextName, pdu )

        debug.logger & debug.flagMP and debug.logger('prepareResponseMessage: using contextEngineId %s contextName %s' % (contextEngineId, contextName))
        
        msg = self._snmpMsgSpec.clone()
        msg.setComponentByPosition(0, messageProcessingModel)
        msg.setComponentByPosition(2)
        msg.getComponentByPosition(2).setComponentByType(pdu.tagSet, pdu)

        # att: msgId not set back to PDU as it's up to responder app
        
        # rfc3412: 7.1.7
        globalData = ( msg, )

        smHandler = snmpEngine.securityModels.get(int(securityModel))
        if smHandler is None:
            raise error.StatusInformation(
                errorIndication = 'unsupportedSecurityModel'
                )

        securityEngineId = snmpEngineID

        # rfc3412: 7.1.8.a
        ( securityParameters,
          wholeMsg ) = smHandler.generateResponseMsg(
            snmpEngine,
            self.messageProcessingModelID,
            globalData,
            maxMessageSize,
            securityModel,
            snmpEngineID,
            securityName,
            securityLevel,
            scopedPDU,
            securityStateReference
            )

        return ( transportDomain, transportAddress, wholeMsg )

    # rfc3412: 7.2.1

    def prepareDataElements(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        wholeMsg
        ):
        # rfc3412: 7.2.2 
        try:
            msg, restOfwholeMsg = decoder.decode(
                wholeMsg, asn1Spec=self._snmpMsgSpec
                )
        except PyAsn1Error:
            snmpInASNParseErrs, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpInASNParseErrs')
            snmpInASNParseErrs.syntax = snmpInASNParseErrs.syntax + 1
            raise error.StatusInformation(
                errorIndication = 'parseError'
                )

        debug.logger & debug.flagMP and debug.logger('prepareDataElements: msg decoded')

        # rfc3412: 7.2.3
        msgVersion = messageProcessingModel = msg.getComponentByPosition(0)
        pdu = msg.getComponentByPosition(2).getComponent()
        # (wild hack: use PDU reqID at MsgID)
        msgID = pdu.getComponentByPosition(0)

        # rfc2576: 5.2.1
        snmpEngineMaxMessageSize, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineMaxMessageSize')
        securityParameters = (
            msg.getComponentByPosition(1),
            (transportDomain, transportAddress),
            ('0.0.0.0', 0)  # XXX
            )
        messageProcessingModel = int(msg.getComponentByPosition(0))
        securityModel = messageProcessingModel + 1
        securityLevel = 1
    
        # rfc3412: 7.2.4 -- 7.2.5 -> noop

        smHandler = snmpEngine.securityModels.get(int(securityModel))
        if smHandler is None:
            raise error.StatusInformation(
                errorIndication = 'unsupportedSecurityModel'
                )

        # rfc3412: 7.2.6
        ( securityEngineID,
          securityName,
          scopedPDU,
          maxSizeResponseScopedPDU,
          securityStateReference ) = smHandler.processIncomingMsg(
            snmpEngine,
            messageProcessingModel,
            snmpEngineMaxMessageSize.syntax,
            securityParameters,
            securityModel,
            securityLevel,
            wholeMsg,
            msg
            )

        debug.logger & debug.flagMP and debug.logger('prepareDataElements: SM returned securityEngineID %s securityName %s' % (securityEngineID, securityName))

        # rfc3412: 7.2.6a --> noop

        # rfc3412: 7.2.7
        contextEngineId, contextName, pdu = scopedPDU

        # rfc2576: 5.2.1
        pduVersion = msgVersion
        pduType = pdu.tagSet
        
        # XXX use cache
        # set stateref to null as in v3 model
        stateReference = securityStateReference

        # rfc3412: 7.2.8, 7.2.9 -> noop

        # rfc3412: 7.2.10
        if rfc3411.responseClassPDUs.has_key(pduType):
            # 7.2.10a
            try:
                cachedReqParams = self._cachePopByMsgId(long(msgID))
            except error.ProtocolError:
                smHandler.releaseStateInformation(securityStateReference)
                raise error.StatusInformation(
                    errorIndication = 'dataMismatch'
                    )

            # 7.2.10b            
            sendPduHandle = cachedReqParams['sendPduHandle']
        else:
            sendPduHandle = None

        statusInformation = None

        # rfc3412: 7.2.11 -> noop

        # rfc3412: 7.2.12
        if rfc3411.responseClassPDUs.has_key(pduType):
            # rfc3412: 7.2.12a -> noop
            # rfc3412: 7.2.12b
            if securityModel != cachedReqParams['securityModel'] or \
               securityName != cachedReqParams['securityName'] or \
               securityLevel != cachedReqParams['securityLevel'] or \
               contextEngineId != cachedReqParams['contextEngineId'] or \
               contextName != cachedReqParams['contextName']:
                smHandler.releaseStateInformation(securityStateReference)
                raise error.StatusInformation(
                    errorIndication = 'dataMismatch'
                    )
            
            # rfc3412: 7.2.12c
            smHandler.releaseStateInformation(securityStateReference)

            # rfc3412: 7.2.12d
            return ( messageProcessingModel,
                     securityModel,
                     securityName,
                     securityLevel,
                     contextEngineId,
                     contextName,
                     pduVersion,
                     pdu,
                     pduType,
                     sendPduHandle,
                     maxSizeResponseScopedPDU,
                     statusInformation,
                     stateReference )

        # rfc3412: 7.2.13
        if rfc3411.confirmedClassPDUs.has_key(pduType):
            # rfc3412: 7.2.13a
            snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
            if securityEngineID != snmpEngineID.syntax:
                smHandler.releaseStateInformation(securityStateReference)
                raise error.StatusInformation(
                    errorIndication = 'engineIDMispatch'
                    )

            # rfc3412: 7.2.13b
            stateReference = self._newStateReference()
            self._cachePushByStateRef(
                stateReference,
                msgVersion=messageProcessingModel,
                msgID=msgID,
                contextEngineId=contextEngineId,
                contextName=contextName,
                securityModel=securityModel,
                securityName=securityName,
                securityLevel=securityLevel,
                securityStateReference=securityStateReference,
                msgMaxSize=snmpEngineMaxMessageSize.syntax,
                maxSizeResponseScopedPDU=maxSizeResponseScopedPDU,
                transportDomain=transportDomain,
                transportAddress=transportAddress
                )

            debug.logger & debug.flagMP and debug.logger('prepareDataElements: cached by new stateReference %s' % stateReference)
                
            # rfc3412: 7.2.13c
            return ( messageProcessingModel,
                     securityModel,
                     securityName,
                     securityLevel,
                     contextEngineId,
                     contextName,
                     pduVersion,
                     pdu,
                     pduType,
                     sendPduHandle,
                     maxSizeResponseScopedPDU,
                     statusInformation,
                     stateReference )

        # rfc3412: 7.2.14
        if rfc3411.unconfirmedClassPDUs.has_key(pduType):
            # This is not specified explicitly in RFC
            smHandler.releaseStateInformation(securityStateReference)
            return ( messageProcessingModel,
                     securityModel,
                     securityName,
                     securityLevel,
                     contextEngineId,
                     contextName,
                     pduVersion,
                     pdu,
                     pduType,
                     sendPduHandle,
                     maxSizeResponseScopedPDU,
                     statusInformation,
                     stateReference )

        smHandler.releaseStateInformation(securityStateReference)
        raise error.StatusInformation(
            errorIndication = 'unsupportedPDUtype'
            )
        
class SnmpV2cMessageProcessingModel(SnmpV1MessageProcessingModel):
    messageProcessingModelID = 1 # SNMPv2c
    _snmpMsgSpec = v2c.Message()
