# SNMP v3 message processing model implementation
from pysnmp.proto.mpmod.base import AbstractMessageProcessingModel
from pysnmp.proto.secmod import rfc3414
from pysnmp.proto import rfc1905, rfc3411, error, api
from pyasn1.type import univ, namedtype, constraint
from pyasn1.codec.ber import decoder
from pyasn1.error import PyAsn1Error
from pysnmp import debug

# API to rfc1905 protocol objects
pMod = api.protoModules[api.protoVersion2c]

# SNMPv3 message format

class ScopedPDU(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contextEngineId', univ.OctetString()),
        namedtype.NamedType('contextName', univ.OctetString()),
        namedtype.NamedType('data', rfc1905.PDUs())
        )
    
class ScopedPduData(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('plaintext', ScopedPDU()),
        namedtype.NamedType('encryptedPDU', univ.OctetString()),
        )
    
class HeaderData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('msgID', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 2147483647L))),
        namedtype.NamedType('msgMaxSize', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(484, 2147483647L))),
        namedtype.NamedType('msgFlags', univ.OctetString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, 1))),
        namedtype.NamedType('msgSecurityModel', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(1, 2147483647L)))
        )

class SNMPv3Message(univ.Sequence):
    componentType = namedtype.NamedTypes(
         namedtype.NamedType('msgVersion', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 2147483647L))),
         namedtype.NamedType('msgGlobalData', HeaderData()),
         namedtype.NamedType('msgSecurityParameters', univ.OctetString()),
         namedtype.NamedType('msgData', ScopedPduData())
         )

# XXX move somewhere?
_snmpErrors = {
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0): 'unsupportedSecLevel',
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0): 'notInTimeWindow', 
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0): 'unknownUserName',
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0): 'unknownEngineID',
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0): 'wrongDigest',
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0): 'decryptionError',
    }

class SnmpV3MessageProcessingModel(AbstractMessageProcessingModel):
    messageProcessingModelID = 3 # SNMPv3
    _snmpMsgSpec = SNMPv3Message()
    def __init__(self):
        AbstractMessageProcessingModel.__init__(self)
        self.__engineIDs = {}
        self.__engineIDsExpQueue = {}
        self.__expirationTimer = 0L
        
    # 7.1.1a
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

        # 7.1.1b
        msgID = self._newMsgID()

        debug.logger & debug.flagMP and debug.logger('prepareOutgoingMessage: new msgID %s' % msgID)
        
        peerSnmpEngineData = self.__engineIDs.get(
            (transportDomain, transportAddress)
            )

        debug.logger & debug.flagMP and debug.logger('prepareOutgoingMessage: peer SNMP engine data %s for transport %s, address %s' % (peerSnmpEngineData, transportDomain, transportAddress))
        
        # 7.1.4
        if contextEngineId is None:
            if peerSnmpEngineData is None:
                contextEngineId = snmpEngineID
            else:
                contextEngineId = peerSnmpEngineData['contextEngineId']
                # Defaulting contextEngineID to securityEngineID should
                # probably be done on Agent side (see 7.1.3.d.2,) so this
                # is a sort of workaround.
                if not contextEngineId:
                    contextEngineId = peerSnmpEngineData['securityEngineID']
        # 7.1.5
        if not contextName:
            contextName = ''

        debug.logger & debug.flagMP and debug.logger('prepareOutgoingMessage: using contextEngineId %s, contextName %s' % (contextEngineId, contextName))
        
        # 7.1.6
        scopedPDU = ScopedPDU()
        scopedPDU.setComponentByPosition(0, contextEngineId)
        scopedPDU.setComponentByPosition(1, contextName)
        scopedPDU.setComponentByPosition(2)
        scopedPDU.getComponentByPosition(2).setComponentByType(
            pdu.tagSet, pdu
            )

        # 7.1.7
        msg = SNMPv3Message()
        
        # 7.1.7a
        msg.setComponentByPosition(0, 3) # version

        headerData = msg.setComponentByPosition(1).getComponentByPosition(1)

        # 7.1.7b
        headerData.setComponentByPosition(0, msgID)

        snmpEngineMaxMessageSize, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineMaxMessageSize')

        # 7.1.7c
        # XXX need to coerce MIB value as it has incompatible constraints set
        headerData.setComponentByPosition(1, int(snmpEngineMaxMessageSize.syntax))

        # 7.1.7d
        msgFlags = 0
        if securityLevel == 1:
            pass
        elif securityLevel == 2:
            msgFlags = msgFlags | 0x01
        elif securityLevel == 3:
            msgFlags = msgFlags | 0x03
        else:
            raise error.ProtocolError(
                'Unknown securityLevel %s' % securityLevel
                )

        if rfc3411.confirmedClassPDUs.has_key(pdu.tagSet):
            msgFlags = msgFlags | 0x04

        headerData.setComponentByPosition(2, chr(msgFlags))

        # 7.1.7e
        # XXX need to coerce MIB value as it has incompatible constraints set
        headerData.setComponentByPosition(3, int(securityModel))

        debug.logger & debug.flagMP and debug.logger('prepareOutgoingMessage: %s' % (msg.prettyPrint(),))

        smHandler = snmpEngine.securityModels.get(securityModel)
        if smHandler is None:
            raise error.StatusInformation(
                errorIndication = 'unsupportedSecurityModel'
                )

        # 7.1.9.a
        if rfc3411.unconfirmedClassPDUs.has_key(pdu.tagSet):
            securityEngineID = snmpEngineID
        else:
            if peerSnmpEngineData is None:
                # Force engineID discovery (rfc3414, 4)
                securityEngineID = securityName = ''
                securityLevel = 1
                # Clear possible auth&priv flags
                headerData.setComponentByPosition(2, chr(msgFlags & 0xfc))
                # XXX
                scopedPDU = ScopedPDU()
                scopedPDU.setComponentByPosition(0, '')
                scopedPDU.setComponentByPosition(1, '')
                scopedPDU.setComponentByPosition(2)

                # Use dead-empty PDU for engine-discovery report
                emptyPdu = pdu.clone()
                pMod.apiPDU.setDefaults(emptyPdu)

                scopedPDU.getComponentByPosition(2).setComponentByType(
                    emptyPdu.tagSet, emptyPdu
                )
                debug.logger & debug.flagMP and debug.logger('prepareOutgoingMessage: force engineID discovery')
            else:
                securityEngineID = peerSnmpEngineData['securityEngineID']

        debug.logger & debug.flagMP and debug.logger('prepareOutgoingMessage: securityEngineID %s' % securityEngineID)
             
        # 7.1.9.b
        ( securityParameters,
          wholeMsg ) = smHandler.generateRequestMsg(
            snmpEngine,
            self.messageProcessingModelID,
            msg,
            snmpEngineMaxMessageSize.syntax,
            securityModel,
            securityEngineID,
            securityName,
            securityLevel,
            scopedPDU
            )

        # Message size constraint verification
        if len(wholeMsg) > snmpEngineMaxMessageSize.syntax:
            raise error.StatusInformation(errorIndication='tooBig')
        
        # 7.1.9.c
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
                contextEngineId=contextEngineId,
                contextName=contextName,
                transportDomain=transportDomain,
                transportAddress=transportAddress
                )

        return ( transportDomain,
                 transportAddress,
                 wholeMsg )
    
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

        # 7.1.2.b
        cachedParams = self._cachePopByStateRef(stateReference)
        msgID = cachedParams['msgID']
        contextEngineId = cachedParams['contextEngineId']
        contextName = cachedParams['contextName']
        securityModel = cachedParams['securityModel']
        securityName = cachedParams['securityName']
        securityLevel = cachedParams['securityLevel']
        securityStateReference = cachedParams['securityStateReference']
        reportableFlag = cachedParams['reportableFlag']
        maxMessageSize = cachedParams['msgMaxSize']
        transportDomain = cachedParams['transportDomain']
        transportAddress = cachedParams['transportAddress']

        debug.logger & debug.flagMP and debug.logger('prepareResponseMessage: stateReference %s' % (stateReference))
        
        # 7.1.3
        if statusInformation is not None and statusInformation.has_key('oid'):
            # 7.1.3a
            if pdu is not None:
                requestID = pdu.getComponentByPosition(0)
                pduType = pdu.tagSet
            else:
                pduType = None

            # 7.1.3b
            if pdu is None and not reportableFlag or \
                   pduType is not None and \
                   not rfc3411.confirmedClassPDUs.has_key(pduType):
                raise error.StatusInformation(
                    errorIndication = 'loopTerminated'
                    )
            
            # 7.1.3c
            reportPDU = rfc1905.ReportPDU()
            pMod.apiPDU.setVarBinds(
                reportPDU,
                ((statusInformation['oid'], statusInformation['val']),)
                )
            pMod.apiPDU.setErrorStatus(reportPDU, 0)
            pMod.apiPDU.setErrorIndex(reportPDU, 0)
            if pdu is None:
                pMod.apiPDU.setRequestID(reportPDU, 0)
            else:
                pMod.apiPDU.setRequestID(reportPDU, requestID)

            # 7.1.3d.1
            if statusInformation.has_key('securityLevel'):
                securityLevel = statusInformation['securityLevel']
            else:
                securityLevel = 1

            # 7.1.3d.2
            if statusInformation.has_key('contextEngineId'):
                contextEngineId = statusInformation['contextEngineId']
            else:
                contextEngineId = snmpEngineID

            # 7.1.3d.3
            if statusInformation.has_key('contextName'):
                contextName = statusInformation['contextName']
            else:
                contextName = ""

            # 7.1.3e
            pdu = reportPDU

            debug.logger & debug.flagMP and debug.logger('prepareResponseMessage: prepare report PDU for statusInformation %s' % statusInformation)
        # 7.1.4
        if not contextEngineId:
            contextEngineId = snmpEngineID  # XXX impl-dep manner

        # 7.1.5
        if not contextName:
            contextName = ''

        debug.logger & debug.flagMP and debug.logger('prepareResponseMessage: using contextEngineId %s, contextName %s' % (contextEngineId, contextName))

        # 7.1.6
        scopedPDU = ScopedPDU()
        scopedPDU.setComponentByPosition(0, contextEngineId)
        scopedPDU.setComponentByPosition(1, contextName)
        scopedPDU.setComponentByPosition(2)
        scopedPDU.getComponentByPosition(2).setComponentByType(
            pdu.tagSet, pdu
            )

        # 7.1.7
        msg = SNMPv3Message()
        
        # 7.1.7a
        msg.setComponentByPosition(0, 3) # version

        headerData = msg.setComponentByPosition(1).getComponentByPosition(1)

        # 7.1.7b
        headerData.setComponentByPosition(0, msgID)

        snmpEngineMaxMessageSize, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineMaxMessageSize')

        # 7.1.7c
        # XXX need to coerce MIB value as it has incompatible constraints set
        headerData.setComponentByPosition(1, int(snmpEngineMaxMessageSize.syntax))

        # 7.1.7d
        msgFlags = 0
        if securityLevel == 1:
            pass
        elif securityLevel == 2:
            msgFlags = msgFlags | 0x01
        elif securityLevel == 3:
            msgFlags = msgFlags | 0x03
        else:
            raise error.ProtocolError(
                'Unknown securityLevel %s' % securityLevel
                )

        if rfc3411.confirmedClassPDUs.has_key(pdu.tagSet):  # XXX not needed?
            msgFlags = msgFlags | 0x04

        headerData.setComponentByPosition(2, chr(msgFlags))

        # 7.1.7e
        headerData.setComponentByPosition(3, securityModel)

        debug.logger & debug.flagMP and debug.logger('prepareResponseMessage: %s' % (msg.prettyPrint(),))

        smHandler = snmpEngine.securityModels.get(securityModel)
        if smHandler is None:
            raise error.StatusInformation(
                errorIndication = 'unsupportedSecurityModel'
                )

        # 7.1.8a
        try:
            ( securityParameters,
              wholeMsg ) = smHandler.generateResponseMsg(
                snmpEngine,
                self.messageProcessingModelID,
                msg,
                snmpEngineMaxMessageSize.syntax,
                securityModel,
                snmpEngineID,
                securityName,
                securityLevel,
                scopedPDU,
                securityStateReference
                )
        except error.StatusInformation, statusInformation:
            # 7.1.8.b            
            raise

        debug.logger & debug.flagMP and debug.logger('prepareResponseMessage: SM finished')

        # Message size constraint verification
        if len(wholeMsg) > min(snmpEngineMaxMessageSize.syntax, maxMessageSize):
            raise error.StatusInformation(errorIndication='tooBig')

        return ( transportDomain, transportAddress, wholeMsg )

    # 7.2.1
    
    def prepareDataElements(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        wholeMsg
        ):
        # 7.2.2
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

        debug.logger & debug.flagMP and debug.logger('prepareDataElements: %s' % (msg.prettyPrint(),))

        # 7.2.3
        headerData = msg.getComponentByPosition(1)
        msgVersion = messageProcessingModel = msg.getComponentByPosition(0)
        msgID = headerData.getComponentByPosition(0)
        msgFlags = ord(str(headerData.getComponentByPosition(2)))
        maxMessageSize = headerData.getComponentByPosition(1)
        securityModel = headerData.getComponentByPosition(3)
        securityParameters = msg.getComponentByPosition(2)

        debug.logger & debug.flagMP and debug.logger('prepareDataElements: msg data msgVersion %s msgID %s securityModel %s' % (msgVersion, msgID, securityModel))
        
        # 7.2.4
        if not snmpEngine.securityModels.has_key(securityModel):
            snmpUnknownSecurityModels, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpUnknownSecurityModels')
            snmpUnknownSecurityModels.syntax = snmpUnknownSecurityModels.syntax + 1
            raise error.StatusInformation(
                errorIndication = 'unsupportedSecurityModel'
                )

        # 7.2.5
        if msgFlags & 0x03 == 0x00:
            securityLevel = 1
        elif (msgFlags & 0x03) == 0x01:
            securityLevel = 2
        elif (msgFlags & 0x03) == 0x03:
            securityLevel = 3
        else:
            snmpInvalidMsgs = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpInvalidMsgs')
            snmpInvalidMsgs.syntax = snmpInvalidMsgs.syntax + 1
            raise error.StatusInformation(
                errorIndication = 'invalidMsg'
                )

        if msgFlags & 0x04:
            reportableFlag = 1
        else:
            reportableFlag = 0

        # 7.2.6
        smHandler = snmpEngine.securityModels[securityModel]
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
            debug.logger & debug.flagMP and debug.logger('prepareDataElements: SM succeeded')
        except error.StatusInformation, statusInformation:
            debug.logger & debug.flagMP and debug.logger('prepareDataElements: SM failed, statusInformation %s' % statusInformation)
            if statusInformation.has_key('errorIndication'):
                # 7.2.6a
                if statusInformation.has_key('oid'):
                    # 7.2.6a1
                    securityStateReference = statusInformation[
                        'securityStateReference'
                        ]
                    contextEngineId = statusInformation['contextEngineId']
                    contextName = statusInformation['contextName']
                    scopedPDU = statusInformation.get('scopedPDU')
                    if scopedPDU is not None:
                        pdu = scopedPDU.getComponentByPosition(2).getComponent()
                    else:
                        pdu = None
                    maxSizeResponseScopedPDU = statusInformation[
                        'maxSizeResponseScopedPDU'
                        ]
                    securityName = None  # XXX secmod cache used

                    # 7.2.6a2
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
                        reportableFlag=reportableFlag,
                        msgMaxSize=maxMessageSize,
                        maxSizeResponseScopedPDU=maxSizeResponseScopedPDU,
                        transportDomain=transportDomain,
                        transportAddress=transportAddress
                        )
    
                    # 7.2.6a3
                    try:
                        snmpEngine.msgAndPduDsp.returnResponsePdu(
                            snmpEngine,
                            3,
                            securityModel,
                            securityName,
                            securityLevel,
                            contextEngineId,
                            contextName,
                            1,
                            pdu,
                            maxSizeResponseScopedPDU,
                            stateReference,
                            statusInformation
                            )
                    except error.StatusInformation:
                        pass
                    
                    debug.logger & debug.flagMP and debug.logger('prepareDataElements: error reported')
            # 7.2.6b
            raise statusInformation
        else:
            # Sniff for engineIDs
            k = (transportDomain, transportAddress)
            if not self.__engineIDs.has_key(k):
                contextEngineId, contextName, pdu = scopedPDU
                
                self.__engineIDs[k] = {
                    'securityEngineID': securityEngineID,
                    'contextEngineId': contextEngineId,
                    'contextName': contextName
                    }

                expireAt = self.__expirationTimer + 300
                if not self.__engineIDsExpQueue.has_key(expireAt):
                    self.__engineIDsExpQueue[expireAt] = []
                self.__engineIDsExpQueue[expireAt].append(k)
                    
                debug.logger & debug.flagMP and debug.logger('prepareDataElements: cache securityEngineID %s for %s %s' % (securityEngineID, transportDomain, transportAddress))

        snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
        snmpEngineID = snmpEngineID.syntax

        # 7.2.7 XXX PDU would be parsed here?
        contextEngineId, contextName, pdu = scopedPDU
        pdu = pdu.getComponent() # PDUs
            
        # 7.2.8
        pduVersion = api.protoVersion2c
        
        # 7.2.9
        pduType = pdu.tagSet

        # 7.2.10
        if rfc3411.responseClassPDUs.has_key(pduType) or \
               rfc3411.internalClassPDUs.has_key(pduType):
            # 7.2.10a
            try:
                cachedReqParams = self._cachePopByMsgId(msgID)
            except error.ProtocolError:
                smHandler.releaseStateInformation(securityStateReference)
                raise error.StatusInformation(
                    errorIndication = 'dataMismatch'
                    )
            # 7.2.10b            
            sendPduHandle = cachedReqParams['sendPduHandle']
        else:
            sendPduHandle = None

        debug.logger & debug.flagMP and debug.logger('prepareDataElements: using sendPduHandle %s for msgID %s' % (sendPduHandle, msgID))
        
        # 7.2.11
        if rfc3411.internalClassPDUs.has_key(pduType):
            # 7.2.11a
            varBinds = pMod.apiPDU.getVarBinds(pdu)
            if varBinds:
                statusInformation = error.StatusInformation(
                    errorIndication=_snmpErrors.get(
                    varBinds[0][0], 'errorReportReceived'
                    ),
                    oid=varBinds[0][0],
                    val=varBinds[0][1],
                    sendPduHandle=sendPduHandle
                    )
                
            # 7.2.11b (incomplete implementation)

            # 7.2.11c
            smHandler.releaseStateInformation(securityStateReference)

            # 7.2.11d
            stateReference = None

            # 7.2.11e XXX may need to pass Reports up to app in some cases...
            raise statusInformation

        statusInformation = None  # no errors ahead

        # 7.2.12
        if rfc3411.responseClassPDUs.has_key(pduType):
            # 7.2.12a -> noop

            # 7.2.12b
            if securityModel != cachedReqParams['securityModel'] or \
               securityName != cachedReqParams['securityName'] or \
               securityLevel != cachedReqParams['securityLevel'] or \
               contextEngineId != cachedReqParams['contextEngineId'] or \
               contextName != cachedReqParams['contextName']:
                smHandler.releaseStateInformation(securityStateReference)
                raise error.StatusInformation(
                    errorIndication = 'dataMispatch'
                    )
                        
            # 7.2.12c
            smHandler.releaseStateInformation(securityStateReference)
            stateReference = None

            # 7.2.12d
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

        # 7.2.13
        if rfc3411.confirmedClassPDUs.has_key(pduType):
            # 7.2.13a
            if securityEngineID != snmpEngineID:
                smHandler.releaseStateInformation(securityStateReference)
                raise error.StatusInformation(
                    errorIndication = 'engineIDMispatch'
                    )

            # 7.2.13b
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
                reportableFlag=reportableFlag,
                msgMaxSize=maxMessageSize,
                maxSizeResponseScopedPDU=maxSizeResponseScopedPDU,
                transportDomain=transportDomain,
                transportAddress=transportAddress
                )            

            debug.logger & debug.flagMP and debug.logger('prepareDataElements: new stateReference %s' % stateReference)

            # 7.2.13c
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

        # 7.2.14
        if rfc3411.unconfirmedClassPDUs.has_key(pduType):
            # Pass new stateReference to let app browse request details
            stateReference = self._newStateReference()
            
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
            errorIndication = 'unknownPDU'
            )

    def __expireEnginesInfo(self):
        if self.__engineIDsExpQueue.has_key(self.__expirationTimer):
            for engineKey in self.__engineIDsExpQueue[self.__expirationTimer]:
                del self.__engineIDs[engineKey]
                debug.logger & debug.flagMP and debug.logger('__expireEnginesInfo: expiring %s' % (engineKey,))
            del self.__engineIDsExpQueue[self.__expirationTimer]
        self.__expirationTimer = self.__expirationTimer + 1
        
    def receiveTimerTick(self, snmpEngine, timeNow):
        self.__expireEnginesInfo()
