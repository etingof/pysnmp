"""Implementation of data types defined by SNMP SMI (RFC1155, RFC1212)"""
from string import split, atoi, atoi_error
from types import StringType
from pysnmp.asn1 import univ, tags, subtypes
import pysnmp.asn1.encoding.ber
from pysnmp.proto import error

__all__ = [
    'Integer', 'OctetString', 'Null', 'ObjectIdentifier',
    'IpAddress', 'Counter', 'Gauge', 'TimeTicks', 'Opaque',
    'Sequence', 'SequenceOf', 'Choice', 'NetworkAddress',
    'ObjectName', 'SimpleSyntax', 'ApplicationSyntax', 'ObjectSyntax'
    ]

# SimpleSyntax

Integer = univ.Integer
OctetString = univ.OctetString
Null = univ.Null
ObjectIdentifier = univ.ObjectIdentifier

# ApplicationSyntax

class IpAddressInterfaceMixIn:
    def _iconv(self, value):
        # Convert IP address given in dotted notation into an unsigned
        # int value
        try:
            packed = split(value, '.')

        except:
            raise error.BadArgumentError(
                'Malformed IP address %s for %s' %
                (str(value), self.__class__.__name__)
            )
        
        # Make sure it is four octets length
        if len(packed) != 4:
            raise error.BadArgumentError(
                'Malformed IP address %s for %s' %
                (str(value), self.__class__.__name__)
            )

        # Convert string octets into integer counterparts
        try:
            return reduce(lambda x, y: x+y, \
                          map(lambda x: chr(atoi(x)), packed))

        except atoi_error:
            raise error.BadArgumentError(
                'Malformed IP address %s for %s' %
                (str(value), self.__class__.__name__)
            )

    def _oconv(self, value):
        if value:
            # Convert unsigned int value into IP address dotted representation
            return '%d.%d.%d.%d' % (ord(value[0]), ord(value[1]), \
                                    ord(value[2]), ord(value[3]))
        else: return value
    
class IpAddress(IpAddressInterfaceMixIn, univ.OctetString):
    tagSet = univ.OctetString.tagSet.clone(
        tagClass=tags.tagClassApplication, tagId=0x00
        )
    # Subtyping -- size constraint
    subtypeConstraints = ( subtypes.ValueSizeConstraint(4, 4), )
    initialValue = '\000\000\000\000'
    
class Counter(univ.Integer):
    tagSet = univ.Integer.tagSet.clone(
        tagClass=tags.tagClassApplication, tagId=0x01
        )
    # Subtyping -- value range constraint
    subtypeConstraints = ( subtypes.ValueRangeConstraint(0, 4294967295L), )

class Gauge(univ.Integer):
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

Sequence = univ.Sequence
SequenceOf = univ.SequenceOf
Choice = univ.Choice

class NetworkAddress(univ.Choice):
    protoComponents = { 'internet': IpAddress() }

    # Initialize to Internet address
    initialComponentKey = 'internet'

ObjectName = univ.ObjectIdentifier

class SimpleSyntax(univ.Choice):
    protoComponents = {
        'number': Integer(),
        'string': OctetString(),
        'object': ObjectIdentifier(),
        'empty': Null()
        }
    initialComponentKey = 'empty'

class ApplicationSyntax(univ.Choice):
    protoComponents = {
        'address': NetworkAddress(),
        'counter': Counter(),
        'gauge': Gauge(),
        'ticks': TimeTicks(),
        'arbitrary': Opaque()
        }

class ObjectSyntax(univ.Choice):
    protoComponents = {
        'simple': SimpleSyntax(),
        'application_wide': ApplicationSyntax(),
        }
    initialComponentKey = 'simple'
