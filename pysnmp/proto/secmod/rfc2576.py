# SNMP v1 & v2c security models implementation
from pyasn1.codec.ber import encoder
from pysnmp.proto.secmod import base
from pysnmp.carrier.asynsock.dgram import udp, udp6
from pysnmp.smi.error import NoSuchInstanceError
from pysnmp.proto import errind, error
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
          snmpCommunityContextName,
          snmpCommunityTransportTag ) = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
            'SNMP-COMMUNITY-MIB',
            'snmpCommunityName',
            'snmpCommunitySecurityName',
            'snmpCommunityContextEngineID',
            'snmpCommunityContextName',
            'snmpCommunityTransportTag'
            )
        nextMibNode = snmpCommunitySecurityName
        while 1:
            try:
                nextMibNode = snmpCommunitySecurityName.getNextNodeWithValue(
                    nextMibNode.name, securityName
                    )
            except NoSuchInstanceError:
                break

            instId = nextMibNode.name[len(snmpCommunitySecurityName.name):]
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
            mibNode = snmpCommunityName.getNode(
                snmpCommunityName.name + instId
                )
            securityParameters = mibNode.syntax

            # XXX snmpCommunityTransportTag matching should probably be here
          
            debug.logger & debug.flagSM and debug.logger('generateRequestMsg: using community %r for securityName %r, contextEngineId %r contextName %r' % (securityParameters, securityName, contextEngineId, contextName))
            
            msg.setComponentByPosition(1, securityParameters)
            msg.setComponentByPosition(2)
            msg.getComponentByPosition(2).setComponentByType(
                pdu.tagSet, pdu, verifyConstraints=False
                )

            debug.logger & debug.flagMP and debug.logger('generateRequestMsg: %s' % (msg.prettyPrint(),))

            wholeMsg = encoder.encode(msg)
            return ( securityParameters, wholeMsg )

        raise error.StatusInformation(
            errorIndication = errind.unknownCommunityName
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
        cachedSecurityData = self._cache.pop(securityStateReference)
        communityName = cachedSecurityData['communityName']

        debug.logger & debug.flagSM and debug.logger('generateResponseMsg: recovered community %r by securityStateReference %s' % (communityName, securityStateReference))
        
        msg.setComponentByPosition(1, communityName)
        msg.setComponentByPosition(2)
        msg.getComponentByPosition(2).setComponentByType(
            pdu.tagSet, pdu, verifyConstraints=False
            )
        
        debug.logger & debug.flagMP and debug.logger('generateResponseMsg: %s' % (msg.prettyPrint(),))

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
          snmpCommunityContextName,
          snmpCommunityTransportTag ) = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
            'SNMP-COMMUNITY-MIB',
            'snmpCommunityName',
            'snmpCommunitySecurityName',
            'snmpCommunityContextEngineID',
            'snmpCommunityContextName',
            'snmpCommunityTransportTag'
            )
        nextMibNode = snmpCommunityName
        addrToTagMap = {} # cache to save on inner loop
        while 1:
            try:
                nextMibNode = snmpCommunityName.getNextNodeWithValue(
                    nextMibNode.name, communityName
                    )
            except NoSuchInstanceError:
                snmpInBadCommunityNames, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpInBadCommunityNames')
                snmpInBadCommunityNames.syntax = snmpInBadCommunityNames.syntax+1
                raise error.StatusInformation(
                    errorIndication = errind.unknownCommunityName
                    )

            instId = nextMibNode.name[len(snmpCommunityName.name):]

            # snmpCommunityTransportTag matching
            mibNode = snmpCommunityTransportTag.getNode(
                snmpCommunityTransportTag.name + instId
                )
            if mibNode.syntax:
                if not addrToTagMap:
                    # Build a cache of addr->tag map
                    ( snmpTargetAddrTDomain,
                      snmpTargetAddrTAddress,
                      snmpTargetAddrTagList ) = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-TARGET-MIB', 'snmpTargetAddrTDomain', 'snmpTargetAddrTAddress', 'snmpTargetAddrTagList')
                    __nextMibNode = snmpTargetAddrTagList
                    while 1:
                        try:
                            __nextMibNode = snmpTargetAddrTagList.getNextNode(
                                __nextMibNode.name
                                )
                        except NoSuchInstanceError:
                            break
                        __instId = __nextMibNode.name[
                            len(snmpTargetAddrTagList.name):
                            ]
                        targetAddrTDomain = snmpTargetAddrTDomain.getNode(
                            snmpTargetAddrTDomain.name + __instId
                            ).syntax
                        targetAddrTAddress = snmpTargetAddrTAddress.getNode(
                            snmpTargetAddrTAddress.name + __instId
                            ).syntax

                        targetAddrTDomain = tuple(targetAddrTDomain)
                        
                        if targetAddrTDomain[:len(udp.snmpUDPDomain)] == udp.snmpUDPDomain:
                            SnmpUDPAddress, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMPv2-TM', 'SnmpUDPAddress')
                            targetAddrTAddress = tuple(
                                SnmpUDPAddress(targetAddrTAddress)
                                )
                        elif targetAddrTDomain[:len(udp6.snmpUDP6Domain)] == udp6.snmpUDP6Domain:
                            TransportAddressIPv6, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('TRANSPORT-ADDRESS-MIB', 'TransportAddressIPv6')
                            targetAddrTAddress = tuple(
                                TransportAddressIPv6(targetAddrTAddress)
                                )
                        targetAddr = targetAddrTDomain, targetAddrTAddress
                        targetAddrTagList = snmpTargetAddrTagList.getNode(
                            snmpTargetAddrTagList.name + __instId
                            ).syntax
                        if targetAddr not in addrToTagMap:
                            addrToTagMap[targetAddr] = {}
                        for tag in targetAddrTagList.asOctets().split():
                            addrToTagMap[targetAddr][tag] = 1

                    debug.logger & debug.flagSM and debug.logger('processIncomingMsg: address-to-tag map %s' % addrToTagMap)
                        
                # XXX snmpTargetAddrTMask matching not implemented
                
                if srcTransport in addrToTagMap:
                    for tag in mibNode.syntax.asOctets().split():
                        if tag in addrToTagMap[srcTransport]:
                            debug.logger & debug.flagSM and debug.logger('processIncomingMsg: tag %s matched transport %s' % (tag, srcTransport))
                            break
                    else:
                        continue
            break
        
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

        debug.logger & debug.flagSM and debug.logger('processIncomingMsg: looked up securityName %r contextEngineId %r contextName %r by communityName %r' % (securityName.syntax, contextEngineId.syntax, contextName.syntax, communityName.syntax))

        stateReference = self._cache.push(
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
