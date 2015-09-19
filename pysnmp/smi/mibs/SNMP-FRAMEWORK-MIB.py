#
# PySNMP MIB module SNMP-FRAMEWORK-MIB (http://pysnmp.sf.net)
# ASN.1 source file:///usr/share/snmp/mibs/SNMP-FRAMEWORK-MIB.txt
# Produced by pysmi-0.0.5 at Sat Sep 19 19:37:28 2015
# On host grommit.local platform Darwin version 14.4.0 by user ilya
# Using Python version 2.7.6 (default, Sep  9 2014, 15:04:36) 
#
( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsUnion, SingleValueConstraint, ConstraintsIntersection, ValueSizeConstraint, ValueRangeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsUnion", "SingleValueConstraint", "ConstraintsIntersection", "ValueSizeConstraint", "ValueRangeConstraint")
( NotificationGroup, ModuleCompliance, ObjectGroup, ) = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance", "ObjectGroup")
( Integer32, MibScalar, MibTable, MibTableRow, MibTableColumn, NotificationType, MibIdentifier, IpAddress, TimeTicks, Counter64, Unsigned32, ModuleIdentity, Gauge32, snmpModules, iso, ObjectIdentity, Bits, Counter32, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "NotificationType", "MibIdentifier", "IpAddress", "TimeTicks", "Counter64", "Unsigned32", "ModuleIdentity", "Gauge32", "snmpModules", "iso", "ObjectIdentity", "Bits", "Counter32")
( DisplayString, TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention")

try:
    import os
except ImportError:
    pass
import time

snmpFrameworkMIB = ModuleIdentity((1, 3, 6, 1, 6, 3, 10)).setRevisions(("2002-10-14 00:00", "1999-01-19 00:00", "1997-11-20 00:00",))
if mibBuilder.loadTexts: snmpFrameworkMIB.setLastUpdated('200210140000Z')
if mibBuilder.loadTexts: snmpFrameworkMIB.setOrganization('SNMPv3 Working Group')
if mibBuilder.loadTexts: snmpFrameworkMIB.setContactInfo('WG-EMail:   snmpv3@lists.tislabs.com\n                  Subscribe:  snmpv3-request@lists.tislabs.com\n\n                  Co-Chair:   Russ Mundy\n                              Network Associates Laboratories\n                  postal:     15204 Omega Drive, Suite 300\n                              Rockville, MD 20850-4601\n                              USA\n                  EMail:      mundy@tislabs.com\n                  phone:      +1 301-947-7107\n\n                  Co-Chair &\n                  Co-editor:  David Harrington\n                              Enterasys Networks\n                  postal:     35 Industrial Way\n                              P. O. Box 5005\n                              Rochester, New Hampshire 03866-5005\n                              USA\n                  EMail:      dbh@enterasys.com\n                  phone:      +1 603-337-2614\n\n                  Co-editor:  Randy Presuhn\n                              BMC Software, Inc.\n                  postal:     2141 North First Street\n                              San Jose, California 95131\n                              USA\n                  EMail:      randy_presuhn@bmc.com\n                  phone:      +1 408-546-1006\n\n                  Co-editor:  Bert Wijnen\n                              Lucent Technologies\n                  postal:     Schagen 33\n                              3461 GL Linschoten\n                              Netherlands\n\n                  EMail:      bwijnen@lucent.com\n                  phone:      +31 348-680-485\n                    ')
if mibBuilder.loadTexts: snmpFrameworkMIB.setDescription('The SNMP Management Architecture MIB\n\n                     Copyright (C) The Internet Society (2002). This\n                     version of this MIB module is part of RFC 3411;\n                     see the RFC itself for full legal notices.\n                    ')

#
# WARNING: some of the classes below are manually implemented
#

class SnmpAdminString(TextualConvention, OctetString):
    displayHint = "255t"
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(0,255)
    encoding = 'utf-8'
 
class SnmpEngineID(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(5,32)
    defaultValue = [128, 0, 79, 184, 5]
    try:
        # Attempt to base engine ID on local system name and properties
        defaultValue += [ ord(x) for x in os.uname()[1][:16] ]
    except:
        pass
    try:
        # Attempt to base engine ID on PID
        defaultValue += [ os.getpid() >> 8 & 0xff, os.getpid() & 0xff ]
    except:
        pass
    # add pseudo-random text ID
    defaultValue += [ id(defaultValue) >> 8 & 0xff, id(defaultValue) & 0xff ]
    defaultValue = OctetString(defaultValue).asOctets()

class SnmpEngineTime(Integer32):
    def clone(self, value=None, tagSet=None, subtypeSpec=None):
        if value is None:
            try:
                value = time.time() - self
            except:
                pass
        return Integer32.clone(self, value, tagSet, subtypeSpec)

class SnmpSecurityModel(Integer32, TextualConvention):
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(0,2147483647)

class SnmpMessageProcessingModel(Integer32, TextualConvention):
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(0,2147483647)

class SnmpSecurityLevel(Integer32, TextualConvention):
    subtypeSpec = Integer32.subtypeSpec+SingleValueConstraint(1, 2, 3,)
    namedValues = NamedValues(("noAuthNoPriv", 1), ("authNoPriv", 2), ("authPriv", 3),)

snmpFrameworkAdmin = MibIdentifier((1, 3, 6, 1, 6, 3, 10, 1))
snmpFrameworkMIBObjects = MibIdentifier((1, 3, 6, 1, 6, 3, 10, 2))
snmpFrameworkMIBConformance = MibIdentifier((1, 3, 6, 1, 6, 3, 10, 3))
snmpEngine = MibIdentifier((1, 3, 6, 1, 6, 3, 10, 2, 1))
snmpEngineID = MibScalar((1, 3, 6, 1, 6, 3, 10, 2, 1, 1), SnmpEngineID()).setMaxAccess("readonly")
if mibBuilder.loadTexts: snmpEngineID.setDescription("An SNMP engine's administratively-unique identifier.\n\n                 This information SHOULD be stored in non-volatile\n                 storage so that it remains constant across\n                 re-initializations of the SNMP engine.\n                ")
snmpEngineBoots = MibScalar((1, 3, 6, 1, 6, 3, 10, 2, 1, 2), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1,2147483647))).setMaxAccess("readonly")
if mibBuilder.loadTexts: snmpEngineBoots.setDescription('The number of times that the SNMP engine has\n                 (re-)initialized itself since snmpEngineID\n                 was last configured.\n                ')
snmpEngineTime = MibScalar((1, 3, 6, 1, 6, 3, 10, 2, 1, 3), SnmpEngineTime().subtype(subtypeSpec=ValueRangeConstraint(0,2147483647))).setUnits('seconds').setMaxAccess("readonly")
if mibBuilder.loadTexts: snmpEngineTime.setDescription("The number of seconds since the value of\n                 the snmpEngineBoots object last changed.\n                 When incrementing this object's value would\n                 cause it to exceed its maximum,\n                 snmpEngineBoots is incremented as if a\n                 re-initialization had occurred, and this\n                 object's value consequently reverts to zero.\n                ")
snmpEngineMaxMessageSize = MibScalar((1, 3, 6, 1, 6, 3, 10, 2, 1, 4), Integer32().subtype(subtypeSpec=ValueRangeConstraint(484,2147483647))).setMaxAccess("readonly")
if mibBuilder.loadTexts: snmpEngineMaxMessageSize.setDescription('The maximum length in octets of an SNMP message\n                 which this SNMP engine can send or receive and\n                 process, determined as the minimum of the maximum\n                 message size values supported among all of the\n                 transports available to and supported by the engine.\n                ')
snmpAuthProtocols = ObjectIdentity((1, 3, 6, 1, 6, 3, 10, 1, 1))
if mibBuilder.loadTexts: snmpAuthProtocols.setDescription('Registration point for standards-track\n                  authentication protocols used in SNMP Management\n                  Frameworks.\n                 ')
snmpPrivProtocols = ObjectIdentity((1, 3, 6, 1, 6, 3, 10, 1, 2))
if mibBuilder.loadTexts: snmpPrivProtocols.setDescription('Registration point for standards-track privacy\n                  protocols used in SNMP Management Frameworks.\n                 ')
snmpFrameworkMIBCompliances = MibIdentifier((1, 3, 6, 1, 6, 3, 10, 3, 1))
snmpFrameworkMIBGroups = MibIdentifier((1, 3, 6, 1, 6, 3, 10, 3, 2))
snmpFrameworkMIBCompliance = ModuleCompliance((1, 3, 6, 1, 6, 3, 10, 3, 1, 1)).setObjects(*(("SNMP-FRAMEWORK-MIB", "snmpEngineGroup"),))
if mibBuilder.loadTexts: snmpFrameworkMIBCompliance.setDescription('The compliance statement for SNMP engines which\n                 implement the SNMP Management Framework MIB.\n                ')
snmpEngineGroup = ObjectGroup((1, 3, 6, 1, 6, 3, 10, 3, 2, 1)).setObjects(*(("SNMP-FRAMEWORK-MIB", "snmpEngineID"), ("SNMP-FRAMEWORK-MIB", "snmpEngineBoots"), ("SNMP-FRAMEWORK-MIB", "snmpEngineTime"), ("SNMP-FRAMEWORK-MIB", "snmpEngineMaxMessageSize"),))
if mibBuilder.loadTexts: snmpEngineGroup.setDescription('A collection of objects for identifying and\n                 determining the configuration and current timeliness\n\n                 values of an SNMP engine.\n                ')
mibBuilder.exportSymbols("SNMP-FRAMEWORK-MIB", snmpPrivProtocols=snmpPrivProtocols, snmpEngine=snmpEngine, snmpEngineMaxMessageSize=snmpEngineMaxMessageSize, snmpAuthProtocols=snmpAuthProtocols, PYSNMP_MODULE_ID=snmpFrameworkMIB, snmpFrameworkMIBConformance=snmpFrameworkMIBConformance, snmpEngineGroup=snmpEngineGroup, SnmpAdminString=SnmpAdminString, snmpEngineID=snmpEngineID, snmpFrameworkAdmin=snmpFrameworkAdmin, snmpFrameworkMIBObjects=snmpFrameworkMIBObjects, SnmpSecurityLevel=SnmpSecurityLevel, snmpFrameworkMIBCompliance=snmpFrameworkMIBCompliance, snmpFrameworkMIBGroups=snmpFrameworkMIBGroups, snmpFrameworkMIB=snmpFrameworkMIB, snmpFrameworkMIBCompliances=snmpFrameworkMIBCompliances, SnmpEngineID=SnmpEngineID, snmpEngineBoots=snmpEngineBoots, SnmpSecurityModel=SnmpSecurityModel, SnmpMessageProcessingModel=SnmpMessageProcessingModel, snmpEngineTime=snmpEngineTime)
