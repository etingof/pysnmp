# SNMP v1 & v2c security models implementation
from pysnmp.proto.secmod import base
from pysnmp.proto import rfc1157, rfc1905, rfc3411
from pysnmp.smi.error import NoSuchInstanceError
from pysnmp.proto import error

class SnmpV1SecurityModel(base.AbstractSecurityModel):
    securityModelID = 1
    # According to rfc2576, community name <-> contextEngineID/contextName
    # mapping is up to MP module for notifications but belongs to secmod
    # responsibility for other PDU types. Since I do not yet understand
    # the reason for this distribution, I moved this code from MP-scope
    # in here.

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
        scopedPDU
        ):
        contextEngineID, contextName, pdu = scopedPDU
        
        # rfc2576: 5.2.3
        ( snmpCommunityName,
          snmpCommunitySecurityName, 
          snmpCommunityContextEngineID, 
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
            mibNode = snmpCommunityContextEngineID.getNode(
                snmpCommunityContextEngineID.name + instId
                )
            if mibNode.syntax != contextEngineID:
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
            communityName = mibNode.syntax
            securityParameters = communityName
            return ( securityParameters, scopedPDU )

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
        cachedData = self._cachePop(securityStateReference)
        securityParameters = (
            cachedData['communityName'],
            cachedData['srcTransport'],
            cachedData['destTransport']
            )
        return ( securityParameters, scopedPDU )

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
          snmpCommunityContextEngineID,
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
                break
            if mibNodeIdx.syntax != communityName:
                continue
            break
        else:
            snmpInBadCommunityNames, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-COMMUNITY-MIB', 'snmpInBadCommunityNames')
            snmpInBadCommunityNames.syntax = snmpInBadCommunityNames.syntax+1
            raise error.StatusInformation(
                errorIndication = 'unknownCommunityName'
                )

        # XXX TODO: snmpCommunityTransportTag 
        instId = mibNodeIdx.name[len(snmpCommunityName.name):]
        communityName = snmpCommunityName.getNode(
            snmpCommunityName.name + instId
            )
        securityName = snmpCommunitySecurityName.getNode(
            snmpCommunitySecurityName.name + instId
            )
        contextEngineID = snmpCommunityContextEngineID.getNode(
            snmpCommunityContextEngineID.name + instId
            )
        contextName = snmpCommunityContextName.getNode(
            snmpCommunityContextName.name + instId
            )
        snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
            'SNMP-FRAMEWORK-MIB', 'snmpEngineID'
            )

        stateReference = self._cachePush(
            communityName=communityName.syntax,
            srcTransport=srcTransport,
            destTransport=destTransport
            )
        
        securityEngineID = snmpEngineID.syntax
        securityName = securityName.syntax
        scopedPDU = (
            contextEngineID.syntax, contextName.syntax,
            msg.getComponentByPosition(2).getComponent()
            )
        maxSizeResponseScopedPDU = maxMessageSize - 128
        securityStateReference = stateReference
        
        return ( securityEngineID,
                 securityName,
                 scopedPDU,
                 maxSizeResponseScopedPDU,
                 securityStateReference )
    
class SnmpV2cSecurityModel(SnmpV1SecurityModel):
    securityModelID = 2
    _protoMsg = rfc1157.Message() # XXX re-assign PDUs
    
# XXX
# use biling api?
# move to pyunit
# v2c support
# where to set defaults to PDU?
# contextEngineId/contextName goes to globalData
