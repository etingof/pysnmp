"""Implementation of data types defined by SNMP SMI (RFC1902)"""
from string import join
from pysnmp.proto import rfc1155, error
from pysnmp.asn1 import univ, tags, subtypes, namedval

__all__ = [
    'Integer', 'Integer32', 'OctetString', 'Null', 'ObjectIdentifier',
    'IpAddress', 'Counter32', 'Gauge32', 'Unsigned32', 'TimeTicks',
    'Opaque',  'Counter64', 'Sequence', 'Bits', 'SequenceOf', 'Choice',
    'ObjectName', 'SimpleSyntax', 'ApplicationSyntax', 'ObjectSyntax'
    ]

# SimpleSyntax

class Integer(univ.Integer):
    # Subtyping -- value range constraint
    subtypeConstraints = (
        subtypes.ValueRangeConstraint(-2147483648L, 2147483647L),
    )

class Integer32(univ.Integer):
    # Subtyping -- value range constraint
    subtypeConstraints = (
        subtypes.ValueRangeConstraint(-2147483648L, 2147483647L),
    )
    
class OctetString(univ.OctetString):
    # Subtyping -- size constraint    
    subtypeConstraints = ( subtypes.ValueSizeConstraint(0, 65535), )

Null = univ.Null
ObjectIdentifier = univ.ObjectIdentifier

# ApplicationSyntax

class IpAddress(rfc1155.IpAddressInterfaceMixIn, univ.OctetString):
    tagSet = univ.OctetString.tagSet.clone(
        tagClass=tags.tagClassApplication, tagId=0x00
        )
    # Subtyping -- size constraint
    subtypeConstraints = ( subtypes.ValueSizeConstraint(4, 4), )
    initialValue = '\000\000\000\000'

class Counter32(univ.Integer):
    tagSet = univ.Integer.tagSet.clone(
        tagClass=tags.tagClassApplication, tagId=0x01
        )
    # Subtyping -- value range constraint
    subtypeConstraints = ( subtypes.ValueRangeConstraint(0, 4294967295L), )

class Gauge32(univ.Integer):
    tagSet = univ.Integer.tagSet.clone(
        tagClass=tags.tagClassApplication, tagId=0x02
        )
    # Subtyping -- value range constraint
    subtypeConstraints = ( subtypes.ValueRangeConstraint(0, 4294967295L), )

class Unsigned32(univ.Integer):
    tagSet = univ.Integer.tagSet.clone(
        tagClass=tags.tagClassApplication, tagId=0x02
        )
    # Subtyping -- value range constraint
    subtypeConstraints = ( subtypes.ValueRangeConstraint(0, 4294967295L), )

class TimeTicks(univ.Integer):
    tagSet = univ.Integer.tagSet.clone(
        tagClass=tags.tagClassApplication, tagId=0x03
        )
    # Subtyping -- value range constraint
    subtypeConstraints = ( subtypes.ValueRangeConstraint(0, 4294967295L), )

class Opaque(univ.OctetString):
    tagSet = univ.OctetString.tagSet.clone(
        tagClass=tags.tagClassApplication, tagId=0x04
        )

class Counter64(univ.Integer):
    tagSet = univ.Integer.tagSet.clone(
        tagClass=tags.tagClassApplication, tagId=0x06
        )
    # Subtyping -- value range constraint
    subtypeConstraints = (
        subtypes.ValueRangeConstraint(0, 18446744073709551615L),
    )

class Bits(univ.OctetString):
    namedValues = namedval.NamedValues()
    
    def _iconv(self, bits):
        octets = []
        for bit in bits:
            v = self.namedValues.getValue(bit)
            if v is None:
                raise error.BadArgumentError(
                    'Unknown named bit %s' % bit
                    )
            d, m = divmod(v, 8)
            if d >= len(octets):
                octets.extend((0,) * (d - len(octets) + 1))
            octets[d] = octets[d] | 0x01 << (7-m)
        return join(map(lambda x: chr(x), octets))

    def _oconv(self, value):
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
                        raise error.BadArgumentError(
                            'Unknown named value %s' % v
                            )
                    names.append(name)
                j = j - 1
            i = i + 1
        return tuple(names)

    def addNamedValues(self, *namedValues):
        self.namedValues = apply(self.namedValues.clone, namedValues)
        return self

    def clone(self, value=None):
        myClone = univ.OctetString.clone(self, value)
        myClone.namedValues = self.namedValues
        return myClone
    
Sequence = univ.Sequence
SequenceOf = univ.SequenceOf
Choice = univ.Choice

class ObjectName(ObjectIdentifier): pass

class SimpleSyntax(univ.Choice):
    protoComponents = {
        'integer_value': Integer(),
        'string_value': OctetString(),
        'objectID_value': ObjectIdentifier()
        }

class ApplicationSyntax(univ.Choice):
    protoComponents = {
        'ipAddress_value': IpAddress(),
        'counter_value': Counter32(),
        'timeticks_value': TimeTicks(),
        'arbitrary_value': Opaque(),
        'big_counter_value': Counter64(),
        'unsigned_integer_value': Unsigned32(),
        'gauge32_value': Gauge32(),
        } # BITS misplaced?

class ObjectSyntax(univ.Choice):
    protoComponents = {
        'simple_syntax': SimpleSyntax(),
        'application_syntax': ApplicationSyntax(),
        }
