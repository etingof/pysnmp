from pyasn1.type import univ, tag, constraint, namedtype, namedval
from pysnmp.proto import rfc1902

# Value reference -- max bindings in VarBindList
max_bindings = rfc1902.Integer(2147483647L)

class _BindValue(univ.Choice): # Made a separate class for better readability
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('value', rfc1902.ObjectSyntax()),
        namedtype.NamedType('unSpecified', univ.Null()),
        namedtype.NamedType('noSuchObject', univ.Null().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x00))),
        namedtype.NamedType('noSuchInstance', univ.Null().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x01))),
        namedtype.NamedType('endOfMibView', univ.Null().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x02)))
        )
        
class VarBind(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', rfc1902.ObjectName()),
        namedtype.NamedType('', _BindValue())
        )
    
class VarBindList(univ.SequenceOf):
    componentType = VarBind()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(
        0, max_bindings
        )

# Base class for a non-bulk PDU
class PDU(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('request-id', rfc1902.Integer32()),
        namedtype.NamedType('error-status', univ.Integer(namedValues=namedval.NamedValues(('noError', 0), ('tooBig', 1), ('noSuchName', 2), ('badValue', 3), ('readOnly', 4), ('genErr', 5), ('noAccess', 6), ('wrongType', 7), ('wrongLength', 8), ('wrongEncoding', 9), ('wrongValue', 10), ('noCreation', 11), ('inconsistentValue', 12), ('resourceUnavailable', 13), ('commitFailed', 14), ('undoFailed', 15), ('authorizationError', 16), ('notWritable', 17), ('inconsistentName', 18)))),
        namedtype.NamedType('error-index', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, max_bindings))),
        namedtype.NamedType('variable-bindings', VarBindList())
        )

# Base class for bulk PDU
class BulkPDU(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('request-id', rfc1902.Integer32()),
        namedtype.NamedType('non-repeaters', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, max_bindings))),
        namedtype.NamedType('max-repetitions', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, max_bindings))),
        namedtype.NamedType('variable-bindings', VarBindList())
        )

class GetRequestPDU(PDU):
    tagSet = PDU.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )

class GetNextRequestPDU(PDU):
    tagSet = PDU.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )

class ResponsePDU(PDU):
    tagSet = PDU.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
        )

class SetRequestPDU(PDU):
    tagSet = PDU.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
        )

class GetBulkRequestPDU(BulkPDU):
    tagSet = PDU.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5)
        )

class InformRequestPDU(PDU):
    tagSet = PDU.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6)
        )

class SNMPv2TrapPDU(PDU):
    tagSet = PDU.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 7)
        )

class ReportPDU(PDU):
    tagSet = PDU.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8)
        )

class PDUs(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('get-request', GetRequestPDU()),
        namedtype.NamedType('get-next-request', GetNextRequestPDU()),
        namedtype.NamedType('get-bulk-request', GetBulkRequestPDU()),
        namedtype.NamedType('response', ResponsePDU()),
        namedtype.NamedType('set-request', SetRequestPDU()),
        namedtype.NamedType('inform-request', InformRequestPDU()),
        namedtype.NamedType('snmpV2-trap', SNMPv2TrapPDU()),
        namedtype.NamedType('report', ReportPDU())
        )
