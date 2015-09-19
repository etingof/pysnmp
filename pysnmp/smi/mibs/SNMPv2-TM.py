#
# WARNING: some of the classes below are manually implemented
#
try:
    from socket import inet_ntop, inet_pton, AF_INET
except ImportError:
    from socket import inet_ntoa, inet_aton, AF_INET
    inet_ntop = lambda x,y: inet_ntoa(y)
    inet_pton = lambda x,y: inet_aton(y)

from pyasn1.compat.octets import int2oct, oct2int

( OctetString, ) = mibBuilder.importSymbols('ASN1', 'OctetString')
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( ModuleIdentity, MibIdentifier, ObjectIdentity, snmpModules, snmpDomains, snmpProxys ) = mibBuilder.importSymbols('SNMPv2-SMI', 'ModuleIdentity', 'MibIdentifier', 'ObjectIdentity', 'snmpModules', 'snmpDomains', 'snmpProxys')
( TextualConvention, ) = mibBuilder.importSymbols('SNMPv2-TC', 'TextualConvention')

snmpv2tm = ModuleIdentity(snmpModules.name + (19,)).setRevisions(("2002-10-16 00:00",))

snmpUDPDomain = ObjectIdentity(snmpDomains.name + (1,))

class SnmpUDPAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(6, 6)
    displayHint = "1d.1d.1d.1d/2d"

    def prettyIn(self, value):
        if isinstance(value, tuple):
            # Wild hack -- need to implement TextualConvention.prettyIn
            value = inet_pton(AF_INET, value[0]) + \
                    int2oct((value[1] >> 8) & 0xff) + \
                    int2oct(value[1] & 0xff)
        return OctetString.prettyIn(self, value)

    # Socket address syntax coercion
    def __getitem__(self, i):
        if not hasattr(self, '__tuple_value'):
            v = self.asOctets()
            self.__tuple_value = (
                inet_ntop(AF_INET, v[:4]),
                oct2int(v[4]) << 8 | oct2int(v[5])
            )
        return self.__tuple_value[i]
 
snmpCLNSDomain = ObjectIdentity(snmpDomains.name + (2,))
snmpCONSDomain = ObjectIdentity(snmpDomains.name + (3,))

class SnmpOSIAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(1, 85)
    displayHint = "*1x:/1x:"
    
snmpDDPDomain = ObjectIdentity(snmpDomains.name + (4,))

class SnmpNBPAddress(OctetString, TextualConvention):
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(3, 99)
    
snmpIPXDomain = ObjectIdentity(snmpDomains.name + (5,))

class SnmpIPXAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(12, 12)
    displayHint = "4x.1x:1x:1x:1x:1x:1x.2d"

rfc1157Proxy = MibIdentifier(snmpProxys.name + (1,))
rfc1157Domain = MibIdentifier(rfc1157Proxy.name + (1,))

# Module identity
mibBuilder.exportSymbols("SNMPv2-TM", PYSNMP_MODULE_ID=snmpv2tm)

mibBuilder.exportSymbols(
    'SNMPv2-TM', snmpv2tm=snmpv2tm, snmpUDPDomain=snmpUDPDomain,
    SnmpUDPAddress=SnmpUDPAddress,
    snmpCLNSDomain=snmpCLNSDomain, snmpCONSDomain=snmpCONSDomain,
    SnmpOSIAddress=SnmpOSIAddress, snmpDDPDomain=snmpDDPDomain,
    SnmpNBPAddress=SnmpNBPAddress, snmpIPXDomain=snmpIPXDomain,
    SnmpIPXAddress=SnmpIPXAddress, rfc1157Proxy=rfc1157Proxy,
    rfc1157Domain=rfc1157Domain
    )
