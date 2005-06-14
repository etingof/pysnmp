# SNMP v1 & v2c message processing models implementation
from pysnmp.proto.mpmod.base import AbstractMessageProcessingModel
from pysnmp.proto.secmod import rfc2576
from pysnmp.proto import rfc1157, rfc1905, rfc3411, error
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error

# Since I have not found a detailed reference to v1MP/v2cMP
# inner workings, the following has been patterned from v3MP. Most
# references here goes to RFC3412.

class SnmpV1MessageProcessingModel(AbstractMessageProcessingModel):
    messageProcessingModelID = 0
    defaultMsgMaxSize = 64000  # impl choice
    _protoMsg = rfc1157.Message()
    # rfc3412: 7.1
    def prepareOutgoingMessage(
        self,
        snmpEngine,
        mibInstrumController,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineID,
        contextName,
        pduVersion,
        pdu,
        expectResponse,
        sendPduHandle
        ):
        snmpEngineID, = mibInstrumController.mibBuilder.importSymbols(
            'SNMP-FRAMEWORK-MIB', 'snmpEngineID'
            )
        snmpEngineID = snmpEngineID.syntax

        # rfc3412: 7.1.1b
        if rfc3411.notificationClassPDUs.has_key(pdu.tagSet):
            msgID = 0 # XXX
        else:
            pdu.setComponentByPosition(1)
            msgID = pdu.getComponentByPosition(0)
            
        # rfc3412: 7.1.4
        # Since there's no SNMP engine identification in v1/2c,
        # set destination contextEngineID to ours
        if not contextEngineID:
            contextEngineID = snmpEngineID

        # rfc3412: 7.1.5
        if not contextName:
            contextName = ''

        # rfc3412: 7.1.6
        scopedPDU = ( contextEngineID, contextName, pdu )

        # rfc3412: 7.1.7
        if rfc3411.notificationClassPDUs.has_key(pdu.tagSet):
            globalData = { 'msgID': 0 } # XXX
        else:
            globalData = {
                'msgID': pdu.getComponentByPosition(1)
                }

        smHandler = snmpEngine.securityModels.get(int(securityModel))
        if smHandler is None:
            raise error.StatusInformation(
                errorIndication = 'unsupportedSecurityModel'
                )

        # rfc3412: 7.1.9.a & rfc2576: 5.2.1
        if rfc3411.unconfirmedClassPDUs.has_key(pdu.tagSet):
            securityEngineID = snmpEngineID
            
        # rfc3412: 7.1.9.b
        try:
            ( securityParameters,
              scopedPDU ) = smHandler.generateRequestMsg(
                snmpEngine,
                self.messageProcessingModelID,
                globalData,
                self.defaultMsgMaxSize,
                securityModel,
                snmpEngineID,
                securityName,
                securityLevel,
                scopedPDU
                )
        except error.StatusInformation, statusInformation:
            raise
        
        # rfc3412: 7.1.9.c
        if rfc3411.confirmedClassPDUs.has_key(pdu.tagSet):
            # XXX rfc bug? why stateReference should be created?
            self._cachePushByMsgId(
                msgID,
                sendPduHandle=sendPduHandle,
                msgID=msgID,
                snmpEngineID=snmpEngineID,
                securityModel=securityModel,
                securityName=securityName,
                securityLevel=securityLevel,
                contextEngineID=contextEngineID,
                contextName=contextName,
                transportDomain=transportDomain,
                transportAddress=transportAddress
                )

        msg = self._protoMsg.clone()
        msg.setComponentByPosition(messageProcessingModel)
        msg.setComponentByPosition(1, securityParameters)
        msg.setComponentByPosition(2)
        msg.getComponentByPosition(2).setComponentByType(pdu.tagSet, pdu)

        return ( destTransportDomain,
                 destTransportAddress,
                 encoder.encode(msg) )
            
    # rfc3412: 7.1
    def prepareResponseMessage(
        self,
        snmpEngine,
        mibInstrumController,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineID,
        contextName,
        pduVersion,
        pdu,
        maxSizeResponseScopedPDU,
        stateReference,
        statusInformation
        ):
        snmpEngineID, = mibInstrumController.mibBuilder.importSymbols(
            'SNMP-FRAMEWORK-MIB', 'snmpEngineID'
            )
        snmpEngineID = snmpEngineID.syntax

        # rfc3412: 7.1.2.b
        cachedReqData = self._cachePopByStateRef(mpInParams['stateReference'])

        # rfc3412: 7.1.3
        if statusInformation:
            # rfc3412: 7.1.3a (N/A)
            
            # rfc3412: 7.1.3b (always discard)
            raise error.StatusInformation(
                errorIndication = 'nonReportable'
                )

        # rfc3412: 7.1.4
        # Since there's no SNMP engine identification in v1/2c,
        # set destination contextEngineID to ours
        if not contextEngineID:
            contextEngineID = snmpEngineID

        # rfc3412: 7.1.5
        if not contextName:
            contextName = ''

        # rfc3412: 7.1.6
        scopedPDU = ( contextEngineID, contextName, pdu )

        # rfc3412: 7.1.7
        globalData = {
            'msgID': cachedReqData['msgID']
            }

        smHandler = snmpEngine.securityModels.get(int(securityModel))
        if smHandler is None:
            raise error.StatusInformation(
                errorIndication = 'unsupportedSecurityModel'
                )

        securityEngineId = snmpEngineID

        # rfc3412: 7.1.8.a
        try:
            ( securityParameters,
              scopedPDU ) = smHandler.generateResponseMsg(
                snmpEngine,
                self.messageProcessingModelID,
                globalData,
                self.defaultMsgMaxSize,
                securityModel,
                snmpEngineID,
                securityName,
                securityLevel,
                scopedPDU,
                securityStateReference
                )
        except error.StatusInformation, statusInformation:
            # rfc3412: 7.1.8.b
            raise

        msg = self._protoMsg.clone()
        msg.setComponentByPosition(messageProcessingModel)
        msg.setComponentByPosition(1, securityParameters)
        msg.setComponentByPosition(2)
        msg.getComponentByPosition(2).setComponentByType(pdu.tagSet, pdu)

        return ( destTransportDomain,
                 destTransportAddress,
                 encoder.encode(msg) )

    # rfc3412: 7.2.1

    def prepareDataElements(
        self,
        snmpEngine,
        mibInstrumController,
        transportDomain,
        transportAddress,
        wholeMsg
        ):
        # rfc3412: 7.2.2 
        try:
            msg, wholeMsg = decoder.decode(
                wholeMsg, asn1Spec=self._protoMsg
                )
        except PyAsn1Error:
            snmpInASNParseErrs, = mibInstrumController.mibBuilder.importSymbols('SNMPv2-MIB', 'snmpInASNParseErrs')
            snmpInASNParseErrs.syntax = snmpInASNParseErrs.syntax + 1
            raise error.StatusInformation(
                errorIndication = 'parseError'
                )

        # rfc3412: 7.2.3
        msgVersion = messageProcessingModel = msg.getComponentByPosition(0)
        # (wild hack: use PDU reqID at MsgID)
        msgID = pdu.getComponentByPosition(0)
        
        # rfc2576: 5.2.1
        maxMessageSize = self.defaultMsgMaxSize
        securityParameters = (
            msg.getComponentByPosition(1),
            transportDomain,
            transportAddress
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
        try:
            ( securityEngineID,
              securityName,
              scopedPDU,
              maxSizeResponseScopedPDU,
              securityStateReference ) = smHandler.processIncomingMsg(
                snmpEngine,
                messageProcessingModel,
                maxMessageSize,
                securityParameters,
                securityModel,
                securityLevel,
                wholeMsg,
                msg
                )
        except error.StatusInformation, statusInformation:
            # 7.2.6b
            raise
        else:
            statusInformation = None
            
        # rfc3412: 7.2.6a --> noop

        # rfc3412: 7.2.7
        contextEngineID, contextName, pdu = scopedPDU

        # rfc2576: 5.2.1
        pduVersion = msgVersion
        pduType = pdu.tagSet
        
        # XXX use cache
        # set stateref to null as in v3 model
        stateReference = securityStateReference

        # rfc3412: 7.2.8, 7.2.9 -> noop

        # rfc3412: 7.2.10
        if rfc3411.responseClassPDUs.has_key(pdu.tagSet):
            # rfc3412: 7.2.10a
            cachedReqParams = self._cachePopByMsgId(msgID)

            # rfc3412: 7.2.10b
            sendPduHandle = cachedReqParams['sendPduHandle']
        else:
            sendPduHandle = None

        # rfc3412: 7.2.11 -> noop

        # rfc3412: 7.2.12
        if rfc3411.responseClassPDUs.has_key(pdu.tagSet):
            # rfc3412: 7.2.12a -> noop
            # rfc3412: 7.2.12b
            if securityModel != cachedReqParams['securityModel'] or \
               securityName != cachedReqParams['securityName'] or \
               securityLevel != cachedReqParams['securityLevel'] or \
               contextEngineID != cachedReqParams['contextEngineID'] or \
               contextName != cachedReqParams['contextName']:
                raise error.StatusInformation(
                    errorIndication = 'dataMispatch'
                    )
            
            # rfc3412: 7.2.12c -> noop

            # rfc3412: 7.2.12d
            return ( messageProcessingModel,
                     securityModel,
                     securityName,
                     securityLevel,
                     contextEngineID,
                     contextName,
                     pduVersion,
                     pdu,
                     pduType,
                     sendPduHandle,
                     maxSizeResponseScopedPDU,
                     statusInformation,
                     stateReference )

        # rfc3412: 7.2.13
        if rfc3411.confirmedClassPDUs.has_key(pdu.tagSet):
            # rfc3412: 7.2.13a
            snmpEngineID, = mibInstrumController.mibBuilder.importSymbols(
                'SNMP-FRAMEWORK-MIB', 'snmpEngineID'
                )
            if securityEngineID != snmpEngineID.syntax:
                raise error.StatusInformation(
                    errorIndication = 'engineIDMispatch'
                    )

            # rfc3412: 7.2.13b
            stateReference = self._newStateReference()
            self._cachePushByStateRef(
                stateReference,
                msgVersion=msgVersion,
                msgID=msgID,
                securityLevel=securityLevel,
                msgMaxSize=maxMessageSize,
                securityModel=securityModel,
                maxSizeResponseScopedPDU=maxSizeResponseScopedPDU,
                securityStateReference=securityStateReference,
                transportDomain=transportDomain,
                transportAddress=transportAddress
                )
            
            # rfc3412: 7.2.13c
            return ( messageProcessingModel,
                     securityModel,
                     securityName,
                     securityLevel,
                     contextEngineID,
                     contextName,
                     pduVersion,
                     pdu,
                     pduType,
                     sendPduHandle,
                     maxSizeResponseScopedPDU,
                     statusInformation,
                     stateReference )

        # rfc3412: 7.2.14
        if rfc3411.unconfirmedClassPDUs.has_key(pdu.tagSet):
            return ( messageProcessingModel,
                     securityModel,
                     securityName,
                     securityLevel,
                     contextEngineID,
                     contextName,
                     pduVersion,
                     pdu,
                     pduType,
                     sendPduHandle,
                     maxSizeResponseScopedPDU,
                     statusInformation,
                     stateReference )
        
class SnmpV2cMessageProcessingModel(SnmpV1MessageProcessingModel):
    messageProcessingModelID = 1
    
# XXX
# cache expiration
# why ResponsePdu accepts non ASN1 objects?
