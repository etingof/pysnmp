from string import join, split
from socket import gethostbyname, gethostname
from pysnmp.asn1 import subtypes

OctetString, Integer = mibBuilder.importSymbols(
    'ASN1', 'OctetString', 'Integer'
    )
ModuleIdentity, ObjectIdentity, MibIdentifier, \
                MibVariable, snmpModules = mibBuilder.importSymbols(
    'SNMPv2-SMI', 'ModuleIdentity', 'ObjectIdentity', 'MibIdentifier',
    'MibVariable', 'snmpModules'
    )
TextualConvention, = mibBuilder.importSymbols('SNMPv2-TC', 'TextualConvention')

snmpFrameworkMIB = ModuleIdentity(snmpModules.name + (10,))

# TC's

class SnmpEngineID(TextualConvention, OctetString):
    subtypeConstraints = OctetString.subtypeConstraints + (
        subtypes.ValueSizeConstraint(5, 32),
        )
    initialValue = '80004fb8'
    try:
        # Attempt to base engine ID on local IP address
        initialValue = initialValue + '1' + join(
            map(lambda x: ('%2.2x' % int(x)),
                split(gethostbyname(gethostname()), '.')), ''
            )
    except:
        # ...otherwise, use rudimentary text ID
        initialValue = initialValue + '4' + 'mozhinka'

class SnmpSecurityModel(TextualConvention, Integer):
    subtypeConstraints = Integer.subtypeConstraints + (
        subtypes.ValueRangeConstraint(0, 2147483647),
        )

class SnmpMessageProcessingModel(TextualConvention, Integer):
    subtypeConstraints = Integer.subtypeConstraints + (
        subtypes.ValueRangeConstraint(0, 2147483647),
        )

class SnmpSecurityLevel(TextualConvention, Integer):
    subtypeConstraints = Integer.subtypeConstraints + (
        subtypes.SingleValueConstraint(1, 2, 3),
        )
    namedValues = Integer.namedValues.clone(
        ('noAuthNoPriv', 1), ('authNoPriv', 2), ('authPriv', 3)
        )
    initialValue = 1

class SnmpAdminString(TextualConvention, OctetString):
    subtypeConstraints = OctetString.subtypeConstraints + (
        subtypes.ValueSizeConstraint(0, 255),
        )
    displayHint = "255a"
    
snmpFrameworkAdmin = MibIdentifier(snmpFrameworkMIB.name + (1,))
snmpFrameworkMIBObjects = MibIdentifier(snmpFrameworkMIB.name + (2,))
snmpFrameworkMIBConformance = MibIdentifier(snmpFrameworkMIB.name + (3,))

snmpEngine = MibIdentifier(snmpFrameworkMIBObjects.name + (1,))

# MIB objects

snmpEngineID = MibVariable(snmpEngine.name + (1,), SnmpEngineID())
snmpEngineBoots = MibVariable(
    snmpEngine.name + (2,), Integer().addConstraints(
    subtypes.ValueRangeConstraint(0, 2147483647)
    )
    )
snmpEngineTime = MibVariable(
    snmpEngine.name + (3,), Integer().addConstraints(
    subtypes.ValueRangeConstraint(0, 2147483647)
    )
    )
snmpEngineMaxMessageSize = MibVariable(
    snmpEngine.name + (4,), Integer().addConstraints(
    subtypes.ValueRangeConstraint(484, 2147483647)
    )
    )

# OI's
snmpAuthProtocols = ObjectIdentity(snmpFrameworkAdmin.name + (1,))
snmpPrivProtocols = ObjectIdentity(snmpFrameworkAdmin.name + (2,))

mibBuilder.exportSymbols(
    'SNMP-FRAMEWORK-MIB',
    snmpFrameworkMIB=snmpFrameworkMIB,
    SnmpEngineID=SnmpEngineID,
    SnmpSecurityModel=SnmpSecurityModel,
    SnmpMessageProcessingModel=SnmpMessageProcessingModel,
    SnmpSecurityLevel=SnmpSecurityLevel,
    SnmpAdminString=SnmpAdminString,
    snmpFrameworkAdmin=snmpFrameworkAdmin, 
    snmpFrameworkMIBObjects=snmpFrameworkMIBObjects,
    snmpFrameworkMIBConformance=snmpFrameworkMIBConformance,
    snmpEngine=snmpEngine,
    snmpEngineID=snmpEngineID,
    snmpEngineBoots=snmpEngineBoots,
    snmpEngineTime=snmpEngineTime,
    snmpEngineMaxMessageSize=snmpEngineMaxMessageSize,
    snmpAuthProtocols=snmpAuthProtocols,
    snmpPrivProtocols=snmpPrivProtocols
    )
