#
# PySNMP MIB module SNMP-USER-BASED-SM-3DES-MIB (http://pysnmp.sf.net)
# ASN.1 source http://mibs.snmplabs.com:80/asn1/SNMP-USER-BASED-SM-3DES-MIB
# Produced by pysmi-0.0.5 at Sat Sep 19 23:09:40 2015
# On host grommit.local platform Darwin version 14.4.0 by user ilya
# Using Python version 2.7.6 (default, Sep  9 2014, 15:04:36) 
#
( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsUnion, SingleValueConstraint, ConstraintsIntersection, ValueSizeConstraint, ValueRangeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsUnion", "SingleValueConstraint", "ConstraintsIntersection", "ValueSizeConstraint", "ValueRangeConstraint")
( snmpPrivProtocols, ) = mibBuilder.importSymbols("SNMP-FRAMEWORK-MIB", "snmpPrivProtocols")
( NotificationGroup, ModuleCompliance, ) = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance")
( Integer32, MibScalar, MibTable, MibTableRow, MibTableColumn, NotificationType, MibIdentifier, IpAddress, TimeTicks, Counter64, Unsigned32, iso, Gauge32, snmpModules, ModuleIdentity, ObjectIdentity, Bits, Counter32, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "NotificationType", "MibIdentifier", "IpAddress", "TimeTicks", "Counter64", "Unsigned32", "iso", "Gauge32", "snmpModules", "ModuleIdentity", "ObjectIdentity", "Bits", "Counter32")
( DisplayString, TextualConvention, AutonomousType, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention", "AutonomousType")
snmpUsmMIB = ModuleIdentity((1, 3, 6, 1, 6, 3, 15)).setRevisions(("1999-10-06 00:00",))
if mibBuilder.loadTexts: snmpUsmMIB.setLastUpdated('9910060000Z')
if mibBuilder.loadTexts: snmpUsmMIB.setOrganization('SNMPv3 Working Group')
if mibBuilder.loadTexts: snmpUsmMIB.setContactInfo('WG-email:   snmpv3@lists.tislabs.com\n                        Subscribe:  majordomo@lists.tislabs.com\n                                    In msg body:  subscribe snmpv3\n\n                        Chair:      Russ Mundy\n                                    NAI Labs\n                        postal:     3060 Washington Rd\n                                    Glenwood MD 21738\n                                    USA\n                        email:      mundy@tislabs.com\n                        phone:      +1-443-259-2307\n\n                        Co-editor:  David Reeder\n                                    NAI Labs\n                        postal:     3060 Washington Road (Route 97)\n                                    Glenwood, MD  21738\n                                    USA\n                        email:      dreeder@tislabs.com\n                        phone:      +1-443-259-2348\n\n                        Co-editor:  Olafur Gudmundsson\n                                    NAI Labs\n                        postal:     3060 Washington Road (Route 97)\n                                    Glenwood, MD  21738\n                                    USA\n                        email:      ogud@tislabs.com\n                        phone:      +1-443-259-2389\n                       ')
if mibBuilder.loadTexts: snmpUsmMIB.setDescription("Extension to the SNMP User-based Security Model\n                        to support Triple-DES EDE in 'Outside' CBC\n                        (cipher-block chaining) Mode.\n                       ")
usm3DESEDEPrivProtocol = ObjectIdentity((1, 3, 6, 1, 6, 3, 10, 1, 2, 3))
if mibBuilder.loadTexts: usm3DESEDEPrivProtocol.setDescription('The 3DES-EDE Symmetric Encryption Protocol.')
mibBuilder.exportSymbols("SNMP-USER-BASED-SM-3DES-MIB", snmpUsmMIB=snmpUsmMIB, usm3DESEDEPrivProtocol=usm3DESEDEPrivProtocol, PYSNMP_MODULE_ID=snmpUsmMIB)
