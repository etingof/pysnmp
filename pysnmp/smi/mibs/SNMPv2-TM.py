import types, string
from pyasn1.type import constraint

OctetString, = mibBuilder.importSymbols('ASN1', 'OctetString')
( ModuleIdentity, MibIdentifier, ObjectIdentity, snmpModules, 
  snmpDomains, snmpProxys ) = mibBuilder.importSymbols(
    'SNMPv2-SMI', 'ModuleIdentity', 'MibIdentifier', 'ObjectIdentity',
    'snmpModules', 'snmpDomains', 'snmpProxys'
    )
TextualConvention, = mibBuilder.importSymbols('SNMPv2-TC', 'TextualConvention')

snmpv2tm = ModuleIdentity(snmpModules.name + (19,)).setRevisions(("2002-10-16 00:00",))

snmpUDPDomain = ObjectIdentity(snmpDomains.name + (1,))

class SnmpUDPAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + constraint.ValueSizeConstraint(6, 6)
    displayHint = "1d.1d.1d.1d/2d"

    def prettyIn(self, value):
        if type(value) == types.TupleType:
            # Wild hack -- need to implement TextualConvention.prettyIn
            return reduce(lambda x,y: x+y, map(lambda x: chr(string.atoi(x)), string.split(value[0], '.'))) + chr((value[1] >> 8) & 0xff) +  chr((value[1] & 0xff))
        else:
            return OctetString.prettyIn(self, value)

    # Socket address syntax coercion
    def __getitem__(self, i):
        value = (
            string.join(map(lambda x: str(ord(x)), self._value[:4]), '.'),
            (ord(self._value[4:5])) << 8 | ord(self._value[5:6])
            )
        return value[i]
    
snmpCLNSDomain = ObjectIdentity(snmpDomains.name + (2,))
snmpCONSDomain = ObjectIdentity(snmpDomains.name + (3,))

class SnmpOSIAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + constraint.ValueSizeConstraint(1, 85)
    displayHint = "*1x:/1x:"
    
snmpDDPDomain = ObjectIdentity(snmpDomains.name + (4,))

class SnmpNBPAddress(OctetString, TextualConvention):
    subtypeSpec = OctetString.subtypeSpec + constraint.ValueSizeConstraint(3, 99)
    
snmpIPXDomain = ObjectIdentity(snmpDomains.name + (5,))

class SnmpIPXAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + constraint.ValueSizeConstraint(12, 12)
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
