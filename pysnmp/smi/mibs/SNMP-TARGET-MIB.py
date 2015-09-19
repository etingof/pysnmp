#
# PySNMP MIB module SNMP-TARGET-MIB (http://pysnmp.sf.net)
# ASN.1 source file:///usr/share/snmp/mibs/SNMP-TARGET-MIB.txt
# Produced by pysmi-0.0.5 at Sat Sep 19 23:04:28 2015
# On host grommit.local platform Darwin version 14.4.0 by user ilya
# Using Python version 2.7.6 (default, Sep  9 2014, 15:04:36) 
#
( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsUnion, SingleValueConstraint, ConstraintsIntersection, ValueSizeConstraint, ValueRangeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsUnion", "SingleValueConstraint", "ConstraintsIntersection", "ValueSizeConstraint", "ValueRangeConstraint")
( SnmpSecurityModel, SnmpMessageProcessingModel, SnmpSecurityLevel, SnmpAdminString, ) = mibBuilder.importSymbols("SNMP-FRAMEWORK-MIB", "SnmpSecurityModel", "SnmpMessageProcessingModel", "SnmpSecurityLevel", "SnmpAdminString")
( NotificationGroup, ModuleCompliance, ObjectGroup, ) = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance", "ObjectGroup")
( Integer32, MibScalar, MibTable, MibTableRow, MibTableColumn, NotificationType, MibIdentifier, IpAddress, TimeTicks, Counter64, Unsigned32, iso, Gauge32, snmpModules, ModuleIdentity, ObjectIdentity, Bits, Counter32, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "NotificationType", "MibIdentifier", "IpAddress", "TimeTicks", "Counter64", "Unsigned32", "iso", "Gauge32", "snmpModules", "ModuleIdentity", "ObjectIdentity", "Bits", "Counter32")
( TimeInterval, TextualConvention, StorageType, TestAndIncr, RowStatus, DisplayString, TAddress, TDomain, ) = mibBuilder.importSymbols("SNMPv2-TC", "TimeInterval", "TextualConvention", "StorageType", "TestAndIncr", "RowStatus", "DisplayString", "TAddress", "TDomain")

#
# WARNING: some of the classes below are manually implemented
#

class SnmpTagList(TextualConvention, OctetString):
    displayHint = "255t"
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(0,255)
    encoding = 'utf-8'
    _delimiters = (' ', '\n', '\t', '\t')
    def prettyIn(self, value):
        inDelim = True
        for v in str(value):
            if v in self._delimiters:
                if inDelim:
                    raise error.SmiError('Leading or multiple delimiters not allowed in tag list %r' % value)
                inDelim = True
            else:
                inDelim = False
        if value and inDelim:
            raise error.SmiError('Dangling delimiter not allowed in tag list %r' % value)
        return OctetString.prettyIn(self, value)
    
class SnmpTagValue(TextualConvention, OctetString):
    displayHint = "255t"
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(0,255)
    encoding = 'utf-8'
    _delimiters = (' ', '\n', '\t', '\t')
    def prettyIn(self, value):
        for v in str(value):
            if v in self._delimiters:
                raise error.SmiError('Delimiters not allowed in tag value')
        return OctetString.prettyIn(self, value)


snmpTargetMIB = ModuleIdentity((1, 3, 6, 1, 6, 3, 12)).setRevisions(("2002-10-14 00:00", "1998-08-04 00:00", "1997-07-14 00:00",))
if mibBuilder.loadTexts: snmpTargetMIB.setLastUpdated('200210140000Z')
if mibBuilder.loadTexts: snmpTargetMIB.setOrganization('IETF SNMPv3 Working Group')
if mibBuilder.loadTexts: snmpTargetMIB.setContactInfo('WG-email:   snmpv3@lists.tislabs.com\n         Subscribe:  majordomo@lists.tislabs.com\n                     In message body:  subscribe snmpv3\n\n         Co-Chair:   Russ Mundy\n                     Network Associates Laboratories\n         Postal:     15204 Omega Drive, Suite 300\n                     Rockville, MD 20850-4601\n                     USA\n         EMail:      mundy@tislabs.com\n         Phone:      +1 301-947-7107\n\n         Co-Chair:   David Harrington\n                     Enterasys Networks\n         Postal:     35 Industrial Way\n                     P. O. Box 5004\n                     Rochester, New Hampshire 03866-5005\n                     USA\n         EMail:      dbh@enterasys.com\n         Phone:      +1 603-337-2614\n\n         Co-editor:  David B. Levi\n                     Nortel Networks\n         Postal:     3505 Kesterwood Drive\n                     Knoxville, Tennessee 37918\n         EMail:      dlevi@nortelnetworks.com\n         Phone:      +1 865 686 0432\n\n         Co-editor:  Paul Meyer\n                     Secure Computing Corporation\n         Postal:     2675 Long Lake Road\n\n                     Roseville, Minnesota 55113\n         EMail:      paul_meyer@securecomputing.com\n         Phone:      +1 651 628 1592\n\n         Co-editor:  Bob Stewart\n                     Retired')
if mibBuilder.loadTexts: snmpTargetMIB.setDescription('This MIB module defines MIB objects which provide\n         mechanisms to remotely configure the parameters used\n         by an SNMP entity for the generation of SNMP messages.\n\n         Copyright (C) The Internet Society (2002). This\n         version of this MIB module is part of RFC 3413;\n         see the RFC itself for full legal notices.\n        ')
snmpTargetObjects = MibIdentifier((1, 3, 6, 1, 6, 3, 12, 1))
snmpTargetConformance = MibIdentifier((1, 3, 6, 1, 6, 3, 12, 3))
snmpTargetSpinLock = MibScalar((1, 3, 6, 1, 6, 3, 12, 1, 1), TestAndIncr()).setMaxAccess("readwrite")
if mibBuilder.loadTexts: snmpTargetSpinLock.setDescription('This object is used to facilitate modification of table\n         entries in the SNMP-TARGET-MIB module by multiple\n         managers.  In particular, it is useful when modifying\n         the value of the snmpTargetAddrTagList object.\n\n         The procedure for modifying the snmpTargetAddrTagList\n         object is as follows:\n\n             1.  Retrieve the value of snmpTargetSpinLock and\n                 of snmpTargetAddrTagList.\n\n             2.  Generate a new value for snmpTargetAddrTagList.\n\n             3.  Set the value of snmpTargetSpinLock to the\n                 retrieved value, and the value of\n                 snmpTargetAddrTagList to the new value.  If\n                 the set fails for the snmpTargetSpinLock\n                 object, go back to step 1.')
snmpTargetAddrTable = MibTable((1, 3, 6, 1, 6, 3, 12, 1, 2), )
if mibBuilder.loadTexts: snmpTargetAddrTable.setDescription('A table of transport addresses to be used in the generation\n         of SNMP messages.')
snmpTargetAddrEntry = MibTableRow((1, 3, 6, 1, 6, 3, 12, 1, 2, 1), ).setIndexNames((1, "SNMP-TARGET-MIB", "snmpTargetAddrName"))
if mibBuilder.loadTexts: snmpTargetAddrEntry.setDescription('A transport address to be used in the generation\n         of SNMP operations.\n\n         Entries in the snmpTargetAddrTable are created and\n         deleted using the snmpTargetAddrRowStatus object.')
snmpTargetAddrName = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 1), SnmpAdminString().subtype(subtypeSpec=ValueSizeConstraint(1,32)))
if mibBuilder.loadTexts: snmpTargetAddrName.setDescription('The locally arbitrary, but unique identifier associated\n         with this snmpTargetAddrEntry.')
snmpTargetAddrTDomain = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 2), TDomain()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetAddrTDomain.setDescription('This object indicates the transport type of the address\n         contained in the snmpTargetAddrTAddress object.')
snmpTargetAddrTAddress = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 3), TAddress()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetAddrTAddress.setDescription('This object contains a transport address.  The format of\n         this address depends on the value of the\n         snmpTargetAddrTDomain object.')
snmpTargetAddrTimeout = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 4), TimeInterval().clone(1500)).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetAddrTimeout.setDescription('This object should reflect the expected maximum round\n         trip time for communicating with the transport address\n         defined by this row.  When a message is sent to this\n         address, and a response (if one is expected) is not\n         received within this time period, an implementation\n         may assume that the response will not be delivered.\n\n         Note that the time interval that an application waits\n         for a response may actually be derived from the value\n         of this object.  The method for deriving the actual time\n         interval is implementation dependent.  One such method\n         is to derive the expected round trip time based on a\n         particular retransmission algorithm and on the number\n         of timeouts which have occurred.  The type of message may\n         also be considered when deriving expected round trip\n         times for retransmissions.  For example, if a message is\n         being sent with a securityLevel that indicates both\n\n         authentication and privacy, the derived value may be\n         increased to compensate for extra processing time spent\n         during authentication and encryption processing.')
snmpTargetAddrRetryCount = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 5), Integer32().subtype(subtypeSpec=ValueRangeConstraint(0,255)).clone(3)).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetAddrRetryCount.setDescription('This object specifies a default number of retries to be\n         attempted when a response is not received for a generated\n         message.  An application may provide its own retry count,\n         in which case the value of this object is ignored.')
snmpTargetAddrTagList = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 6), SnmpTagList()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetAddrTagList.setDescription('This object contains a list of tag values which are\n         used to select target addresses for a particular\n         operation.')
snmpTargetAddrParams = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 7), SnmpAdminString().subtype(subtypeSpec=ValueSizeConstraint(1,32))).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetAddrParams.setDescription('The value of this object identifies an entry in the\n         snmpTargetParamsTable.  The identified entry\n         contains SNMP parameters to be used when generating\n         messages to be sent to this transport address.')
snmpTargetAddrStorageType = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 8), StorageType().clone('nonVolatile')).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetAddrStorageType.setDescription("The storage type for this conceptual row.\n         Conceptual rows having the value 'permanent' need not\n         allow write-access to any columnar objects in the row.")
snmpTargetAddrRowStatus = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 9), RowStatus()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetAddrRowStatus.setDescription("The status of this conceptual row.\n\n         To create a row in this table, a manager must\n         set this object to either createAndGo(4) or\n         createAndWait(5).\n\n         Until instances of all corresponding columns are\n         appropriately configured, the value of the\n         corresponding instance of the snmpTargetAddrRowStatus\n         column is 'notReady'.\n\n         In particular, a newly created row cannot be made\n         active until the corresponding instances of\n         snmpTargetAddrTDomain, snmpTargetAddrTAddress, and\n         snmpTargetAddrParams have all been set.\n\n         The following objects may not be modified while the\n         value of this object is active(1):\n             - snmpTargetAddrTDomain\n             - snmpTargetAddrTAddress\n         An attempt to set these objects while the value of\n         snmpTargetAddrRowStatus is active(1) will result in\n         an inconsistentValue error.")
snmpTargetParamsTable = MibTable((1, 3, 6, 1, 6, 3, 12, 1, 3), )
if mibBuilder.loadTexts: snmpTargetParamsTable.setDescription('A table of SNMP target information to be used\n         in the generation of SNMP messages.')
snmpTargetParamsEntry = MibTableRow((1, 3, 6, 1, 6, 3, 12, 1, 3, 1), ).setIndexNames((1, "SNMP-TARGET-MIB", "snmpTargetParamsName"))
if mibBuilder.loadTexts: snmpTargetParamsEntry.setDescription('A set of SNMP target information.\n\n         Entries in the snmpTargetParamsTable are created and\n         deleted using the snmpTargetParamsRowStatus object.')
snmpTargetParamsName = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 3, 1, 1), SnmpAdminString().subtype(subtypeSpec=ValueSizeConstraint(1,32)))
if mibBuilder.loadTexts: snmpTargetParamsName.setDescription('The locally arbitrary, but unique identifier associated\n         with this snmpTargetParamsEntry.')
snmpTargetParamsMPModel = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 3, 1, 2), SnmpMessageProcessingModel()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetParamsMPModel.setDescription('The Message Processing Model to be used when generating\n         SNMP messages using this entry.')
snmpTargetParamsSecurityModel = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 3, 1, 3), SnmpSecurityModel().subtype(subtypeSpec=ValueRangeConstraint(1,2147483647))).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetParamsSecurityModel.setDescription('The Security Model to be used when generating SNMP\n          messages using this entry.  An implementation may\n          choose to return an inconsistentValue error if an\n          attempt is made to set this variable to a value\n          for a security model which the implementation does\n          not support.')
snmpTargetParamsSecurityName = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 3, 1, 4), SnmpAdminString()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetParamsSecurityName.setDescription('The securityName which identifies the Principal on\n         whose behalf SNMP messages will be generated using\n         this entry.')
snmpTargetParamsSecurityLevel = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 3, 1, 5), SnmpSecurityLevel()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetParamsSecurityLevel.setDescription('The Level of Security to be used when generating\n         SNMP messages using this entry.')
snmpTargetParamsStorageType = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 3, 1, 6), StorageType().clone('nonVolatile')).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetParamsStorageType.setDescription("The storage type for this conceptual row.\n         Conceptual rows having the value 'permanent' need not\n         allow write-access to any columnar objects in the row.")
snmpTargetParamsRowStatus = MibTableColumn((1, 3, 6, 1, 6, 3, 12, 1, 3, 1, 7), RowStatus()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: snmpTargetParamsRowStatus.setDescription("The status of this conceptual row.\n\n         To create a row in this table, a manager must\n         set this object to either createAndGo(4) or\n         createAndWait(5).\n\n         Until instances of all corresponding columns are\n         appropriately configured, the value of the\n         corresponding instance of the snmpTargetParamsRowStatus\n         column is 'notReady'.\n\n         In particular, a newly created row cannot be made\n         active until the corresponding\n         snmpTargetParamsMPModel,\n         snmpTargetParamsSecurityModel,\n         snmpTargetParamsSecurityName,\n         and snmpTargetParamsSecurityLevel have all been set.\n\n         The following objects may not be modified while the\n         value of this object is active(1):\n             - snmpTargetParamsMPModel\n             - snmpTargetParamsSecurityModel\n             - snmpTargetParamsSecurityName\n             - snmpTargetParamsSecurityLevel\n         An attempt to set these objects while the value of\n         snmpTargetParamsRowStatus is active(1) will result in\n         an inconsistentValue error.")
snmpUnavailableContexts = MibScalar((1, 3, 6, 1, 6, 3, 12, 1, 4), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: snmpUnavailableContexts.setDescription('The total number of packets received by the SNMP\n         engine which were dropped because the context\n         contained in the message was unavailable.')
snmpUnknownContexts = MibScalar((1, 3, 6, 1, 6, 3, 12, 1, 5), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: snmpUnknownContexts.setDescription('The total number of packets received by the SNMP\n         engine which were dropped because the context\n         contained in the message was unknown.')
snmpTargetCompliances = MibIdentifier((1, 3, 6, 1, 6, 3, 12, 3, 1))
snmpTargetGroups = MibIdentifier((1, 3, 6, 1, 6, 3, 12, 3, 2))
snmpTargetCommandResponderCompliance = ModuleCompliance((1, 3, 6, 1, 6, 3, 12, 3, 1, 1)).setObjects(*(("SNMP-TARGET-MIB", "snmpTargetCommandResponderGroup"),))
if mibBuilder.loadTexts: snmpTargetCommandResponderCompliance.setDescription('The compliance statement for SNMP entities which include\n         a command responder application.')
snmpTargetBasicGroup = ObjectGroup((1, 3, 6, 1, 6, 3, 12, 3, 2, 1)).setObjects(*(("SNMP-TARGET-MIB", "snmpTargetSpinLock"), ("SNMP-TARGET-MIB", "snmpTargetAddrTDomain"), ("SNMP-TARGET-MIB", "snmpTargetAddrTAddress"), ("SNMP-TARGET-MIB", "snmpTargetAddrTagList"), ("SNMP-TARGET-MIB", "snmpTargetAddrParams"), ("SNMP-TARGET-MIB", "snmpTargetAddrStorageType"), ("SNMP-TARGET-MIB", "snmpTargetAddrRowStatus"), ("SNMP-TARGET-MIB", "snmpTargetParamsMPModel"), ("SNMP-TARGET-MIB", "snmpTargetParamsSecurityModel"), ("SNMP-TARGET-MIB", "snmpTargetParamsSecurityName"), ("SNMP-TARGET-MIB", "snmpTargetParamsSecurityLevel"), ("SNMP-TARGET-MIB", "snmpTargetParamsStorageType"), ("SNMP-TARGET-MIB", "snmpTargetParamsRowStatus"),))
if mibBuilder.loadTexts: snmpTargetBasicGroup.setDescription('A collection of objects providing basic remote\n         configuration of management targets.')
snmpTargetResponseGroup = ObjectGroup((1, 3, 6, 1, 6, 3, 12, 3, 2, 2)).setObjects(*(("SNMP-TARGET-MIB", "snmpTargetAddrTimeout"), ("SNMP-TARGET-MIB", "snmpTargetAddrRetryCount"),))
if mibBuilder.loadTexts: snmpTargetResponseGroup.setDescription('A collection of objects providing remote configuration\n         of management targets for applications which generate\n         SNMP messages for which a response message would be\n         expected.')
snmpTargetCommandResponderGroup = ObjectGroup((1, 3, 6, 1, 6, 3, 12, 3, 2, 3)).setObjects(*(("SNMP-TARGET-MIB", "snmpUnavailableContexts"), ("SNMP-TARGET-MIB", "snmpUnknownContexts"),))
if mibBuilder.loadTexts: snmpTargetCommandResponderGroup.setDescription('A collection of objects required for command responder\n         applications, used for counting error conditions.')
mibBuilder.exportSymbols("SNMP-TARGET-MIB", snmpTargetAddrTAddress=snmpTargetAddrTAddress, snmpTargetAddrStorageType=snmpTargetAddrStorageType, snmpTargetParamsName=snmpTargetParamsName, snmpTargetParamsRowStatus=snmpTargetParamsRowStatus, snmpTargetCommandResponderCompliance=snmpTargetCommandResponderCompliance, snmpTargetAddrTagList=snmpTargetAddrTagList, snmpTargetObjects=snmpTargetObjects, snmpTargetAddrTable=snmpTargetAddrTable, PYSNMP_MODULE_ID=snmpTargetMIB, snmpTargetGroups=snmpTargetGroups, snmpTargetAddrTDomain=snmpTargetAddrTDomain, snmpUnavailableContexts=snmpUnavailableContexts, snmpTargetParamsStorageType=snmpTargetParamsStorageType, snmpTargetParamsSecurityModel=snmpTargetParamsSecurityModel, snmpTargetMIB=snmpTargetMIB, snmpTargetAddrRowStatus=snmpTargetAddrRowStatus, snmpTargetCompliances=snmpTargetCompliances, snmpTargetParamsSecurityLevel=snmpTargetParamsSecurityLevel, snmpTargetResponseGroup=snmpTargetResponseGroup, snmpTargetCommandResponderGroup=snmpTargetCommandResponderGroup, snmpTargetAddrTimeout=snmpTargetAddrTimeout, snmpTargetAddrEntry=snmpTargetAddrEntry, snmpTargetParamsEntry=snmpTargetParamsEntry, snmpTargetAddrName=snmpTargetAddrName, snmpTargetAddrParams=snmpTargetAddrParams, snmpUnknownContexts=snmpUnknownContexts, snmpTargetParamsSecurityName=snmpTargetParamsSecurityName, snmpTargetConformance=snmpTargetConformance, SnmpTagList=SnmpTagList, snmpTargetSpinLock=snmpTargetSpinLock, SnmpTagValue=SnmpTagValue, snmpTargetParamsMPModel=snmpTargetParamsMPModel, snmpTargetParamsTable=snmpTargetParamsTable, snmpTargetBasicGroup=snmpTargetBasicGroup, snmpTargetAddrRetryCount=snmpTargetAddrRetryCount)
