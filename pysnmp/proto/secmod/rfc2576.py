#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp import debug
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.carrier.asyncore.dgram import udp6
from pysnmp.proto import errind
from pysnmp.proto import error
from pysnmp.proto.secmod import base
from pysnmp.smi.error import NoSuchInstanceError

from pyasn1.codec.ber import encoder
from pyasn1.error import PyAsn1Error


class SnmpV1SecurityModel(base.AbstractSecurityModel):
    SECURITY_MODEL_ID = 1

    # According to rfc2576, community name <-> contextEngineId/contextName
    # mapping is up to MP module for notifications but belongs to secmod
    # responsibility for other PDU types. Since I do not yet understand
    # the reason for this de-coupling, I've moved this code from MP-scope
    # in here.

    def __init__(self):
        self._transportBranchId = -1
        self._paramsBranchId = -1
        self._communityBranchId = -1
        self._securityBranchId = -1

        base.AbstractSecurityModel.__init__(self)

    def _sec2com(self, snmpEngine, securityName, contextEngineId, contextName):
        mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

        snmpTargetParamsSecurityName, = mibBuilder.importSymbols(
            'SNMP-TARGET-MIB', 'snmpTargetParamsSecurityName')

        if self._paramsBranchId != snmpTargetParamsSecurityName.branchVersionId:
            snmpTargetParamsSecurityModel, = mibBuilder.importSymbols(
                'SNMP-TARGET-MIB', 'snmpTargetParamsSecurityModel')

            self._nameToModelMap = {}

            nextMibNode = snmpTargetParamsSecurityName

            while True:
                try:
                    nextMibNode = snmpTargetParamsSecurityName.getNextNode(
                        nextMibNode.name)

                except NoSuchInstanceError:
                    break

                instId = nextMibNode.name[len(snmpTargetParamsSecurityName.name):]

                mibNode = snmpTargetParamsSecurityModel.getNode(
                    snmpTargetParamsSecurityModel.name + instId)

                try:
                    if mibNode.syntax not in self._nameToModelMap:
                        self._nameToModelMap[nextMibNode.syntax] = set()

                    self._nameToModelMap[nextMibNode.syntax].add(mibNode.syntax)

                except PyAsn1Error:
                    debug.logger & debug.FLAG_SM and debug.logger(
                        '_sec2com: table entries %r/%r hashing '
                        'failed' % (nextMibNode.syntax, mibNode.syntax))
                    continue

            self._paramsBranchId = snmpTargetParamsSecurityName.branchVersionId

            # invalidate next map as it include this one
            self._securityBranchId = -1

        snmpCommunityName, = mibBuilder.importSymbols(
            'SNMP-COMMUNITY-MIB', 'snmpCommunityName')

        if self._securityBranchId != snmpCommunityName.branchVersionId:
            (snmpCommunitySecurityName,
             snmpCommunityContextEngineId,
             snmpCommunityContextName) = mibBuilder.importSymbols(
                'SNMP-COMMUNITY-MIB', 'snmpCommunitySecurityName',
                'snmpCommunityContextEngineID', 'snmpCommunityContextName'
            )

            self._securityMap = {}

            nextMibNode = snmpCommunityName

            while True:
                try:
                    nextMibNode = snmpCommunityName.getNextNode(nextMibNode.name)

                except NoSuchInstanceError:
                    break

                instId = nextMibNode.name[len(snmpCommunityName.name):]

                _securityName = snmpCommunitySecurityName.getNode(
                    snmpCommunitySecurityName.name + instId).syntax

                _contextEngineId = snmpCommunityContextEngineId.getNode(
                    snmpCommunityContextEngineId.name + instId).syntax

                _contextName = snmpCommunityContextName.getNode(
                    snmpCommunityContextName.name + instId).syntax

                key = _securityName, _contextEngineId, _contextName

                try:
                    self._securityMap[key] = nextMibNode.syntax

                except PyAsn1Error:
                    debug.logger & debug.FLAG_SM and debug.logger(
                        '_sec2com: table entries %r/%r/%r hashing failed' % key)
                    continue

            self._securityBranchId = snmpCommunityName.branchVersionId

            debug.logger & debug.FLAG_SM and debug.logger(
                '_sec2com: built securityName to communityName map, version '
                '%s: %s' % (self._securityBranchId, self._securityMap))

        key = securityName, contextEngineId, contextName

        try:
            return self._securityMap[key]

        except KeyError:
            raise error.StatusInformation(
                errorIndication=errind.unknownCommunityName)

    def _com2sec(self, snmpEngine, communityName, transportInformation):
        mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

        snmpTargetAddrTAddress, = mibBuilder.importSymbols(
            'SNMP-TARGET-MIB', 'snmpTargetAddrTAddress')

        if self._transportBranchId != snmpTargetAddrTAddress.branchVersionId:
            (SnmpTagValue, snmpTargetAddrTDomain,
             snmpTargetAddrTagList) = mibBuilder.importSymbols(
                'SNMP-TARGET-MIB', 'SnmpTagValue', 'snmpTargetAddrTDomain',
                'snmpTargetAddrTagList')

            self._emptyTag = SnmpTagValue('')

            self._transportToTagMap = {}

            nextMibNode = snmpTargetAddrTagList

            while True:
                try:
                    nextMibNode = snmpTargetAddrTagList.getNextNode(nextMibNode.name)

                except NoSuchInstanceError:
                    break

                instId = nextMibNode.name[len(snmpTargetAddrTagList.name):]

                targetAddrTDomain = snmpTargetAddrTDomain.getNode(
                    snmpTargetAddrTDomain.name + instId).syntax
                targetAddrTAddress = snmpTargetAddrTAddress.getNode(
                    snmpTargetAddrTAddress.name + instId).syntax

                targetAddrTDomain = tuple(targetAddrTDomain)

                if (targetAddrTDomain[:len(udp.SNMP_UDP_DOMAIN)] ==
                        udp.SNMP_UDP_DOMAIN):
                    SnmpUDPAddress, = mibBuilder.importSymbols(
                        'SNMPv2-TM', 'SnmpUDPAddress')
                    targetAddrTAddress = tuple(SnmpUDPAddress(targetAddrTAddress))

                elif (targetAddrTDomain[:len(udp6.SNMP_UDP6_DOMAIN)] ==
                        udp6.SNMP_UDP6_DOMAIN):
                    TransportAddressIPv6, = mibBuilder.importSymbols(
                        'TRANSPORT-ADDRESS-MIB', 'TransportAddressIPv6')

                    targetAddrTAddress = tuple(TransportAddressIPv6(targetAddrTAddress))

                targetAddr = targetAddrTDomain, targetAddrTAddress

                targetAddrTagList = snmpTargetAddrTagList.getNode(
                    snmpTargetAddrTagList.name + instId).syntax

                if targetAddr not in self._transportToTagMap:
                    self._transportToTagMap[targetAddr] = set()

                try:
                    if targetAddrTagList:
                        self._transportToTagMap[targetAddr].update(
                            [SnmpTagValue(x)
                             for x in targetAddrTagList.asOctets().split()])

                    else:
                        self._transportToTagMap[targetAddr].add(self._emptyTag)

                except PyAsn1Error:
                    debug.logger & debug.FLAG_SM and debug.logger(
                        '_com2sec: table entries %r/%r hashing failed' % (
                            targetAddr, targetAddrTagList))
                    continue

            self._transportBranchId = snmpTargetAddrTAddress.branchVersionId

            debug.logger & debug.FLAG_SM and debug.logger(
                '_com2sec: built transport-to-tag map version %s: '
                '%s' % (self._transportBranchId, self._transportToTagMap))

        snmpTargetParamsSecurityName, = mibBuilder.importSymbols(
            'SNMP-TARGET-MIB', 'snmpTargetParamsSecurityName')

        if self._paramsBranchId != snmpTargetParamsSecurityName.branchVersionId:
            snmpTargetParamsSecurityModel, = mibBuilder.importSymbols(
                'SNMP-TARGET-MIB', 'snmpTargetParamsSecurityModel')

            self._nameToModelMap = {}

            nextMibNode = snmpTargetParamsSecurityName

            while True:
                try:
                    nextMibNode = snmpTargetParamsSecurityName.getNextNode(nextMibNode.name)

                except NoSuchInstanceError:
                    break

                instId = nextMibNode.name[len(snmpTargetParamsSecurityName.name):]

                mibNode = snmpTargetParamsSecurityModel.getNode(
                    snmpTargetParamsSecurityModel.name + instId)

                try:
                    if nextMibNode.syntax not in self._nameToModelMap:
                        self._nameToModelMap[nextMibNode.syntax] = set()

                    self._nameToModelMap[nextMibNode.syntax].add(mibNode.syntax)

                except PyAsn1Error:
                    debug.logger & debug.FLAG_SM and debug.logger(
                        '_com2sec: table entries %r/%r hashing '
                        'failed' % (nextMibNode.syntax, mibNode.syntax))
                    continue

            self._paramsBranchId = snmpTargetParamsSecurityName.branchVersionId

            # invalidate next map as it include this one
            self._communityBranchId = -1

            debug.logger & debug.FLAG_SM and debug.logger(
                '_com2sec: built securityName to securityModel map, version '
                '%s: %s' % (self._paramsBranchId, self._nameToModelMap))

        snmpCommunityName, = mibBuilder.importSymbols(
            'SNMP-COMMUNITY-MIB', 'snmpCommunityName')

        if self._communityBranchId != snmpCommunityName.branchVersionId:
            (snmpCommunitySecurityName, snmpCommunityContextEngineId,
             snmpCommunityContextName,
             snmpCommunityTransportTag) = mibBuilder.importSymbols(
                'SNMP-COMMUNITY-MIB', 'snmpCommunitySecurityName',
                'snmpCommunityContextEngineID', 'snmpCommunityContextName',
                'snmpCommunityTransportTag'
            )

            self._communityToTagMap = {}
            self._tagAndCommunityToSecurityMap = {}

            nextMibNode = snmpCommunityName

            while True:
                try:
                    nextMibNode = snmpCommunityName.getNextNode(nextMibNode.name)

                except NoSuchInstanceError:
                    break

                instId = nextMibNode.name[len(snmpCommunityName.name):]

                securityName = snmpCommunitySecurityName.getNode(
                    snmpCommunitySecurityName.name + instId).syntax

                contextEngineId = snmpCommunityContextEngineId.getNode(
                    snmpCommunityContextEngineId.name + instId).syntax

                contextName = snmpCommunityContextName.getNode(
                    snmpCommunityContextName.name + instId).syntax

                transportTag = snmpCommunityTransportTag.getNode(
                    snmpCommunityTransportTag.name + instId).syntax

                _tagAndCommunity = transportTag, nextMibNode.syntax

                try:
                    if _tagAndCommunity not in self._tagAndCommunityToSecurityMap:
                        self._tagAndCommunityToSecurityMap[_tagAndCommunity] = set()

                    self._tagAndCommunityToSecurityMap[_tagAndCommunity].add(
                        (securityName, contextEngineId, contextName))

                    if nextMibNode.syntax not in self._communityToTagMap:
                        self._communityToTagMap[nextMibNode.syntax] = set()

                    self._communityToTagMap[nextMibNode.syntax].add(transportTag)

                except PyAsn1Error:
                    debug.logger & debug.FLAG_SM and debug.logger(
                        '_com2sec: table entries %r/%r hashing '
                        'failed' % (_tagAndCommunity, nextMibNode.syntax))
                    continue

            self._communityBranchId = snmpCommunityName.branchVersionId

            debug.logger & debug.FLAG_SM and debug.logger(
                '_com2sec: built communityName to tag map '
                '(securityModel %s), version %s: '
                '%s' % (self.SECURITY_MODEL_ID, self._communityBranchId,
                        self._communityToTagMap))

            debug.logger & debug.FLAG_SM and debug.logger(
                '_com2sec: built tag & community to securityName map '
                '(securityModel %s), version %s: '
                '%s' % (self.SECURITY_MODEL_ID, self._communityBranchId,
                        self._tagAndCommunityToSecurityMap))

        if communityName in self._communityToTagMap:
            if transportInformation in self._transportToTagMap:
                tags = self._transportToTagMap[transportInformation].intersection(
                    self._communityToTagMap[communityName])

            elif self._emptyTag in self._communityToTagMap[communityName]:
                tags = [self._emptyTag]

            else:
                raise error.StatusInformation(
                    errorIndication=errind.unknownCommunityName)

            candidateSecurityNames = []

            securityNamesSets = [
                self._tagAndCommunityToSecurityMap[(t, communityName)]
                for t in tags
            ]

            for x in securityNamesSets:
                candidateSecurityNames.extend(list(x))

            if candidateSecurityNames:
                candidateSecurityNames.sort(key=self._orderSecurityNames)

                chosenSecurityName = candidateSecurityNames[0]  # min()

                debug.logger & debug.FLAG_SM and debug.logger(
                    '_com2sec: securityName candidates for communityName %s '
                    'are %s; choosing securityName '
                    '%s' % (communityName, candidateSecurityNames,
                            chosenSecurityName[0]))

                return chosenSecurityName

        raise error.StatusInformation(
            errorIndication=errind.unknownCommunityName)

    # 5.2.1 (row selection in snmpCommunityTable)
    # Picks first match but favors entries already in targets table
    def _orderSecurityNames(self, securityName):
        return (not int(securityName[0] in self._nameToModelMap and
                        self.SECURITY_MODEL_ID in self._nameToModelMap[securityName[0]]),
                str(securityName[0]))

    def generateRequestMsg(self, snmpEngine, messageProcessingModel,
                           globalData, maxMessageSize, securityModel,
                           securityEngineId, securityName, securityLevel,
                           scopedPDU):
        msg, = globalData

        contextEngineId, contextName, pdu = scopedPDU

        # rfc2576: 5.2.3
        communityName = self._sec2com(
            snmpEngine, securityName, contextEngineId, contextName)

        debug.logger & debug.FLAG_SM and debug.logger(
            'generateRequestMsg: using community %r for securityModel %r, '
            'securityName %r, contextEngineId %r contextName '
            '%r' % (communityName, securityModel, securityName,
                    contextEngineId, contextName))

        securityParameters = communityName

        msg.setComponentByPosition(1, securityParameters)
        msg.setComponentByPosition(2)
        msg.getComponentByPosition(2).setComponentByType(
            pdu.tagSet, pdu, verifyConstraints=False, matchTags=False,
            matchConstraints=False)

        debug.logger & debug.FLAG_MP and debug.logger(
            'generateRequestMsg: %s' % (msg.prettyPrint(),))

        try:
            return securityParameters, encoder.encode(msg)

        except PyAsn1Error as exc:
            debug.logger & debug.FLAG_MP and debug.logger(
                'generateRequestMsg: serialization failure: %s' % exc)

            raise error.StatusInformation(
                errorIndication=errind.serializationError)

    def generateResponseMsg(self, snmpEngine, messageProcessingModel,
                            globalData, maxMessageSize, securityModel,
                            securityEngineID, securityName, securityLevel,
                            scopedPDU, securityStateReference):
        # rfc2576: 5.2.2
        msg, = globalData

        contextEngineId, contextName, pdu = scopedPDU

        cachedSecurityData = self._cache.pop(securityStateReference)

        communityName = cachedSecurityData['communityName']

        debug.logger & debug.FLAG_SM and debug.logger(
            'generateResponseMsg: recovered community %r by '
            'securityStateReference '
            '%s' % (communityName, securityStateReference))

        msg.setComponentByPosition(1, communityName)
        msg.setComponentByPosition(2)
        msg.getComponentByPosition(2).setComponentByType(
            pdu.tagSet, pdu, verifyConstraints=False, matchTags=False,
            matchConstraints=False)

        debug.logger & debug.FLAG_MP and debug.logger(
            'generateResponseMsg: %s' % (msg.prettyPrint(),))

        try:
            return communityName, encoder.encode(msg)

        except PyAsn1Error as exc:
            debug.logger & debug.FLAG_MP and debug.logger(
                'generateResponseMsg: serialization failure: %s' % exc)

            raise error.StatusInformation(errorIndication=errind.serializationError)

    def processIncomingMsg(self, snmpEngine, messageProcessingModel,
                           maxMessageSize, securityParameters, securityModel,
                           securityLevel, wholeMsg, msg):
        mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

        # rfc2576: 5.2.1
        communityName, transportInformation = securityParameters

        scope = dict(communityName=communityName,
                     transportInformation=transportInformation)

        snmpEngine.observer.storeExecutionContext(
            snmpEngine, 'rfc2576.processIncomingMsg:writable', scope
        )

        snmpEngine.observer.clearExecutionContext(
            snmpEngine, 'rfc2576.processIncomingMsg:writable'
        )

        try:
            securityName, contextEngineId, contextName = self._com2sec(
                snmpEngine, scope.get('communityName', communityName),
                scope.get('transportInformation', transportInformation)
            )

        except error.StatusInformation:
            snmpInBadCommunityNames, = mibBuilder.importSymbols(
                '__SNMPv2-MIB', 'snmpInBadCommunityNames')
            snmpInBadCommunityNames.syntax += 1

            raise error.StatusInformation(
                errorIndication=errind.unknownCommunityName,
                communityName=communityName
            )

        snmpEngineID, = mibBuilder.importSymbols(
            '__SNMP-FRAMEWORK-MIB', 'snmpEngineID')

        securityEngineID = snmpEngineID.syntax

        snmpEngine.observer.storeExecutionContext(
            snmpEngine, 'rfc2576.processIncomingMsg',
            dict(transportInformation=transportInformation,
                 securityEngineId=securityEngineID,
                 securityName=securityName,
                 communityName=communityName,
                 contextEngineId=contextEngineId,
                 contextName=contextName)
        )

        snmpEngine.observer.clearExecutionContext(
            snmpEngine, 'rfc2576.processIncomingMsg'
        )

        debug.logger & debug.FLAG_SM and debug.logger(
            'processIncomingMsg: looked up securityName %r securityModel %r '
            'contextEngineId %r contextName %r by communityName %r '
            'AND transportInformation '
            '%r' % (securityName, self.SECURITY_MODEL_ID, contextEngineId,
                    contextName, communityName, transportInformation))

        stateReference = self._cache.push(communityName=communityName)

        scopedPDU = (contextEngineId, contextName,
                     msg.getComponentByPosition(2).getComponent())

        maxSizeResponseScopedPDU = maxMessageSize - 128

        securityStateReference = stateReference

        debug.logger & debug.FLAG_SM and debug.logger(
            'processIncomingMsg: generated maxSizeResponseScopedPDU '
            '%s securityStateReference '
            '%s' % (maxSizeResponseScopedPDU, securityStateReference))

        return (securityEngineID, securityName, scopedPDU,
                maxSizeResponseScopedPDU, securityStateReference)


class SnmpV2cSecurityModel(SnmpV1SecurityModel):
    SECURITY_MODEL_ID = 2

# XXX
# contextEngineId/contextName goes to globalData
