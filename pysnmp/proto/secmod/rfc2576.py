# SNMP v1 & v2c security models implementation
from pyasn1.codec.ber import encoder
from pysnmp.proto.secmod import base
from pysnmp.smi.error import NoSuchInstanceError
from pysnmp.proto import error
from pysnmp import debug

class SnmpV1SecurityModel(base.AbstractSecurityModel):
    securityModelID = 1
    # According to rfc2576, community name <-> contextEngineId/contextName
    # mapping is up to MP module for notifications but belongs to secmod
    # responsibility for other PDU types. Since I do not yet understand
    # the reason for this de-coupling, I've moved this code from MP-scope
    # in here.

    def generateRequestMsg(
        self,
        snmpEngine,
        messageProcessingModel,
        globalData,
        maxMessageSize,
        securityModel,
        securityEngineId,
        securityName,
        securityLevel,
        scopedPDU
        ):
        msg, = globalData
        contextEngineId, contextName, pdu = scopedPDU
        
        # rfc2576: 5.2.3
        ( snmpCommunityName,
          snmpCommunitySecurityName, 
          snmpCommunityContextEngineId, 
          snmpCommunityContextName ) = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
            'SNMP-COMMUNITY-MIB',
            'snmpCommunityName',
            'snmpCommunitySecurityName',
            'snmpCommunityContextEngineID',
            'snmpCommunityContextName'
            )
        mibNodeIdx = snmpCommunitySecurityName
        while 1:
            try:
                mibNodeIdx = snmpCommunitySecurityName.getNextNode(
                    mibNodeIdx.name
                    )
            except NoSuchInstanceError:
                break
            if mibNodeIdx.syntax != securityName:
                continue
            instId = mibNodeIdx.name[len(snmpCommunitySecurityName.name):]
            mibNode = snmpCommunityContextEngineId.getNode(
                snmpCommunityContextEngineId.name + instId
                )
            if mibNode.syntax != contextEngineId:
                continue
            mibNode = snmpCommunityContextName.getNode(
                snmpCommunityContextName.name + instId
                )
            if mibNode.syntax != contextName:
                continue
            # XXX TODO: snmpCommunityTransportTag
            mibNode = snmpCommunityName.getNode(
                snmpCommunityName.name + instId
                )
            securityParameters = mibNode.syntax
            
            debug.logger & debug.flagSM and debug.logger('generateRequestMsg: found community %s for securityName %s contextEngineId %s contextName %s' % (securityParameters, securityName, contextEngineId, contextName))
            
            msg.setComponentByPosition(1, securityParameters)
            msg.setComponentByPosition(2)
            msg.getComponentByPosition(2).setComponentByType(pdu.tagSet, pdu)
            wholeMsg = encoder.encode(msg)
            return ( securityParameters, wholeMsg )

        raise error.StatusInformation(
            errorIndication = 'unknownCommunityName'
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
        # rfc2576: 5.2.2
        msg, = globalData
        contextEngineId, contextName, pdu = scopedPDU
        cachedSecurityData = self._cachePop(securityStateReference)
        communityName = cachedSecurityData['communityName']

        debug.logger & debug.flagSM and debug.logger('generateResponseMsg: recovered community %s by securityStateReference %s' % (communityName, securityStateReference))
        
        msg.setComponentByPosition(1, communityName)
        msg.setComponentByPosition(2)
        msg.getComponentByPosition(2).setComponentByType(pdu.tagSet, pdu)
        
        wholeMsg = encoder.encode(msg)
        return ( communityName, wholeMsg )

    def processIncomingMsg(
        self,
        snmpEngine,
        messageProcessingModel,
        maxMessageSize,
        securityParameters,
        securityModel,
        securityLevel,
        wholeMsg,
        msg
        ):
        # rfc2576: 5.2.1
        ( communityName, srcTransport, destTransport ) = securityParameters
        ( snmpCommunityName,
          snmpCommunitySecurityName,
          snmpCommunityContextEngineId,
          snmpCommunityContextName
          ) = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
            'SNMP-COMMUNITY-MIB',
            'snmpCommunityName',
            'snmpCommunitySecurityName',
            'snmpCommunityContextEngineID',
            'snmpCommunityContextName'
            )
        mibNodeIdx = snmpCommunityName
        while 1:
            try:
                mibNodeIdx = snmpCommunityName.getNextNode(
                    mibNodeIdx.name
                    )
            except NoSuchInstanceError:
                snmpInBadCommunityNames, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpInBadCommunityNames')
                snmpInBadCommunityNames.syntax = snmpInBadCommunityNames.syntax+1
                raise error.StatusInformation(
                    errorIndication = 'unknownCommunityName'
                    )
            if mibNodeIdx.syntax == communityName:
                break
        
        # XXX TODO: snmpCommunityTransportTag 
        instId = mibNodeIdx.name[len(snmpCommunityName.name):]
        communityName = snmpCommunityName.getNode(
            snmpCommunityName.name + instId
            )
        securityName = snmpCommunitySecurityName.getNode(
            snmpCommunitySecurityName.name + instId
            )
        contextEngineId = snmpCommunityContextEngineId.getNode(
            snmpCommunityContextEngineId.name + instId
            )
        contextName = snmpCommunityContextName.getNode(
            snmpCommunityContextName.name + instId
            )
        snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')

        debug.logger & debug.flagSM and debug.logger('processIncomingMsg: looked up securityName %s contextEngineId %s contextName %s by communityName %s' % (securityName, contextEngineId, contextName, communityName))

        stateReference = self._cachePush(
            communityName=communityName.syntax
            )
        
        securityEngineID = snmpEngineID.syntax
        securityName = securityName.syntax
        scopedPDU = (
            contextEngineId.syntax, contextName.syntax,
            msg.getComponentByPosition(2).getComponent()
            )
        maxSizeResponseScopedPDU = maxMessageSize - 128
        securityStateReference = stateReference

        debug.logger & debug.flagSM and debug.logger('processIncomingMsg: generated maxSizeResponseScopedPDU %s securityStateReference %s' % (maxSizeResponseScopedPDU, securityStateReference))
        
        return ( securityEngineID,
                 securityName,
                 scopedPDU,
                 maxSizeResponseScopedPDU,
                 securityStateReference )
    
class SnmpV2cSecurityModel(SnmpV1SecurityModel):
    securityModelID = 2
    
# XXX
# contextEngineId/contextName goes to globalData
