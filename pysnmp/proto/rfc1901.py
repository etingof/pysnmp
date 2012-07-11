from pyasn1.type import univ, namedtype, namedval
from pysnmp.proto import rfc1905

_version =  univ.Integer(namedValues = namedval.NamedValues(('version-2c', 1)))

class Message(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', _version),
        namedtype.NamedType('community', univ.OctetString()),
        namedtype.NamedType('data', rfc1905.PDUs())
        )
