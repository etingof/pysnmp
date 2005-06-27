import string
from pyasn1.type import univ, tag, constraint, namedtype
from pyasn1.error import PyAsn1Error
from pysnmp.proto import error

def ipAddressPrettyIn(value):
    if len(value) == 4:
        return value  # IP as an octet stream
    try:
        packed = string.split(value, '.')
    except:
        raise error.ProtocolError(
            'Bad IP address syntax %s' %  value
                )
    if len(packed) != 4:
        raise error.ProtocolError(
            'Bad IP address syntax %s' %  value
            )
    try:
        return reduce(
            lambda x, y: x+y,
            map(lambda x: chr(string.atoi(x)), packed)
            )
    except string.atoi_error:
        raise error.ProtocolError(
            'Bad IP address value %s' %  value
            )

def ipAddressPrettyOut(value):
    if value:
        return '%d.%d.%d.%d' % (
            ord(value[0]), ord(value[1]), ord(value[2]), ord(value[3])
            )
    else:
        return ''
    
class IpAddress(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x00)
        )
    subtypeSpec = univ.OctetString.subtypeSpec+constraint.ValueSizeConstraint(
        4, 4
        )

    def prettyIn(self, value): return ipAddressPrettyIn(value)
    def prettyOut(self, value): return ipAddressPrettyOut(value)
    
class Counter(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x01)
        )
    subtypeSpec = univ.Integer.subtypeSpec+constraint.ValueRangeConstraint(
        0, 4294967295L
        )

class NetworkAddress(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('internet', IpAddress())
        )

class Gauge(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x02)
        )
    subtypeSpec = univ.Integer.subtypeSpec+constraint.ValueRangeConstraint(
        0, 4294967295L
        )

class TimeTicks(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x03)
        )
    subtypeSpec = univ.Integer.subtypeSpec+constraint.ValueRangeConstraint(
        0, 4294967295L
        )

class Opaque(univ.OctetString):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x04)
        )

class ObjectName(univ.ObjectIdentifier): pass

class TypeCoercionHackMixIn: # XXX
    # Reduce ASN1 type check to simple tag check as SMIv2 objects may
    # not be constraints-compatible with those used in SNMP PDU.
    def _verifyComponent(self, idx, value):
        componentType = self._componentType
        if componentType:
            if idx >= len(componentType):
                raise PyAsn1Error(
                    'Component type error out of range'
                    )
            t = componentType[idx].getType()
            if not t.getTagSet().isSuperTagSetOf(value.getTagSet()):
                raise PyAsn1Error('Component type error %s vs %s' %
                                  (repr(t), repr(value)))
    
class SimpleSyntax(TypeCoercionHackMixIn, univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('number', univ.Integer()),
        namedtype.NamedType('string', univ.OctetString()),
        namedtype.NamedType('object', univ.ObjectIdentifier()),
        namedtype.NamedType('empty', univ.Null())
        )

class ApplicationSyntax(TypeCoercionHackMixIn, univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('address', NetworkAddress()),
        namedtype.NamedType('counter', Counter()),
        namedtype.NamedType('gauge', Gauge()),
        namedtype.NamedType('ticks', TimeTicks()),
        namedtype.NamedType('arbitrary', Opaque())
        )

class ObjectSyntax(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('simple', SimpleSyntax()),
        namedtype.NamedType('application-wide', ApplicationSyntax())
        )
