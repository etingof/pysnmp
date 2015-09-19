#
# PySNMP MIB module SNMP-USM-AES-MIB (http://pysnmp.sf.net)
# ASN.1 source file:///usr/share/snmp/mibs/SNMP-USM-AES-MIB.txt
# Produced by pysmi-0.0.5 at Sat Sep 19 23:11:55 2015
# On host grommit.local platform Darwin version 14.4.0 by user ilya
# Using Python version 2.7.6 (default, Sep  9 2014, 15:04:36) 
#
( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsUnion, SingleValueConstraint, ConstraintsIntersection, ValueSizeConstraint, ValueRangeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsUnion", "SingleValueConstraint", "ConstraintsIntersection", "ValueSizeConstraint", "ValueRangeConstraint")
( snmpPrivProtocols, ) = mibBuilder.importSymbols("SNMP-FRAMEWORK-MIB", "snmpPrivProtocols")
( NotificationGroup, ModuleCompliance, ) = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance")
( Integer32, MibScalar, MibTable, MibTableRow, MibTableColumn, NotificationType, MibIdentifier, IpAddress, TimeTicks, Counter64, Unsigned32, iso, Gauge32, snmpModules, ModuleIdentity, ObjectIdentity, Bits, Counter32, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "NotificationType", "MibIdentifier", "IpAddress", "TimeTicks", "Counter64", "Unsigned32", "iso", "Gauge32", "snmpModules", "ModuleIdentity", "ObjectIdentity", "Bits", "Counter32")
( DisplayString, TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention")
snmpUsmAesMIB = ModuleIdentity((1, 3, 6, 1, 6, 3, 20)).setRevisions(("2004-06-14 00:00",))
if mibBuilder.loadTexts: snmpUsmAesMIB.setLastUpdated('200406140000Z')
if mibBuilder.loadTexts: snmpUsmAesMIB.setOrganization('IETF')
if mibBuilder.loadTexts: snmpUsmAesMIB.setContactInfo('Uri Blumenthal\n                  Lucent Technologies / Bell Labs\n                  67 Whippany Rd.\n                  14D-318\n                  Whippany, NJ  07981, USA\n                  973-386-2163\n                  uri@bell-labs.com\n\n                  Fabio Maino\n                  Andiamo Systems, Inc.\n                  375 East Tasman Drive\n                  San Jose, CA  95134, USA\n                  408-853-7530\n                  fmaino@andiamo.com\n\n                  Keith McCloghrie\n                  Cisco Systems, Inc.\n                  170 West Tasman Drive\n                  San Jose, CA  95134-1706, USA\n\n                  408-526-5260\n                  kzm@cisco.com')
if mibBuilder.loadTexts: snmpUsmAesMIB.setDescription("Definitions of Object Identities needed for\n                  the use of AES by SNMP's User-based Security\n                  Model.\n\n                  Copyright (C) The Internet Society (2004).\n\n            This version of this MIB module is part of RFC 3826;\n            see the RFC itself for full legal notices.\n            Supplementary information may be available on\n            http://www.ietf.org/copyrights/ianamib.html.")
usmAesCfb128Protocol = ObjectIdentity((1, 3, 6, 1, 6, 3, 10, 1, 2, 4))
if mibBuilder.loadTexts: usmAesCfb128Protocol.setDescription('The CFB128-AES-128 Privacy Protocol.')
mibBuilder.exportSymbols("SNMP-USM-AES-MIB", usmAesCfb128Protocol=usmAesCfb128Protocol, snmpUsmAesMIB=snmpUsmAesMIB, PYSNMP_MODULE_ID=snmpUsmAesMIB)
