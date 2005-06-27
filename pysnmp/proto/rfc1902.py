from pyasn1.type import univ, tag, constraint, namedtype, namedval
from pysnmp.proto import rfc1155

class Integer(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec+constraint.ValueRangeConstraint(
        -2147483648L, 2147483647L
        )

class Integer32(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec+constraint.ValueRangeConstraint(
        -2147483648L, 2147483647L
        )
    
class OctetString(univ.OctetString):
    subtypeSpec = univ.Integer.subtypeSpec+constraint.ValueSizeConstraint(
        0, 65535
        )

class IpAddress(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x00)
        )
    subtypeSpec = univ.OctetString.subtypeSpec+constraint.ValueSizeConstraint(
        4, 4
        )
    _prettyIn = rfc1155.ipAddressPrettyIn
    _prettyOut = rfc1155.ipAddressPrettyOut

class Counter32(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x01)
        )
    subtypeSpec = univ.Integer.subtypeSpec+constraint.ValueRangeConstraint(
        0, 4294967295L
        )

class Gauge32(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x02)
        )
    subtypeSpec = univ.Integer.subtypeSpec+constraint.ValueRangeConstraint(
        0, 4294967295L
        )

class Unsigned32(univ.Integer):
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
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x04)
        )

class Counter64(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x06)
        )
    subtypeSpec = univ.Integer.subtypeSpec+constraint.ValueRangeConstraint(
        0, 18446744073709551615L
        )

class Bits(univ.OctetString):
    namedValues = namedval.NamedValues()
    def __init__(self, value=None, tagSet=None, subtypeSpec=None,
                 namedValues=None):
        if namedValues is None:
            self.__namedValues = self.namedValues
        else:
            self.__namedValues = namedValues
        univ.OctetString.__init__(
            self, value, tagSet, subtypeSpec
            )

    def _prettyIn(self, bits):
        if type(bits) == types.StringType:
            return bits # raw bitstring
        octets = []
        for bit in bits: # tuple of named bits
            v = self.namedValues.getValue(bit)
            if v is None:
                raise error.ProtocolError(
                    'Unknown named bit %s' % bit
                    )
            d, m = divmod(v, 8)
            if d >= len(octets):
                octets.extend((0,) * (d - len(octets) + 1))
            octets[d] = octets[d] | 0x01 << (7-m)
        return join(map(lambda x: chr(x), octets))

    def _prettyOut(self, value):
        names = []
        octets = tuple(map(None, value))
        i = 0
        while i < len(octets):
            v = ord(octets[i])
            j = 7
            while j > 0:
                if v & (0x01<<j):
                    name = self.namedValues.getName(i*8+7-j)
                    if name is None:
                        raise error.ProtocolError(
                            'Unknown named value %s' % v
                            )
                    names.append(name)
                j = j - 1
            i = i + 1
        return tuple(names)

    def clone(self, value=None, tagSet=None, subtypeSpec=None,
              namedValues=None):
        if value is None: value = self._value
        if tagSet is None: tagSet = self._tagSet
        if subtypeSpec is None: subtypeSpec = self._subtypeSpec
        if namedValues is None: namedValues = self.__namedValues
        return self.__class__(value, tagSet, subtypeSpec, namedValues)

class ObjectName(univ.ObjectIdentifier): pass

class SimpleSyntax(rfc1155.TypeCoercionHackMixIn, univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('integer-value', Integer()),
        namedtype.NamedType('string-value', OctetString()),
        namedtype.NamedType('objectID-value', univ.ObjectIdentifier())
        )

class ApplicationSyntax(rfc1155.TypeCoercionHackMixIn, univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ipAddress-value', IpAddress()),
        namedtype.NamedType('counter-value', Counter32()),
        namedtype.NamedType('timeticks-value', TimeTicks()),
        namedtype.NamedType('arbitrary-value', Opaque()),
        namedtype.NamedType('big-counter-value', Counter64()),
# This conflicts with Counter32
#        namedtype.NamedType('unsigned-integer-value', Unsigned32()),
        namedtype.NamedType('gauge32-value', Gauge32())
        ) # BITS misplaced?

class ObjectSyntax(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('simple', SimpleSyntax()),
        namedtype.NamedType('application-wide', ApplicationSyntax())
        )
