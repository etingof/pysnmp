import string
from pyasn1.type import univ, tag, constraint, namedtype
from pysnmp.proto import error

def ipAddressPrettyIn(self, value):
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

def ipAddressPrettyOut(self, value):
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
    _prettyIn = ipAddressPrettyIn
    _prettyOut = ipAddressPrettyOut
    
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

class SimpleSyntax(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('number', univ.Integer()),
        namedtype.NamedType('string', univ.OctetString()),
        namedtype.NamedType('object', univ.ObjectIdentifier()),
        namedtype.NamedType('empty', univ.Null())
        )

class ApplicationSyntax(univ.Choice):
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
