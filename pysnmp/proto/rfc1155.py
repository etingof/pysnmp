#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pyasn1.type import univ, tag, constraint, namedtype
from pyasn1.error import PyAsn1Error
from pysnmp.smi.error import SmiError
from pysnmp.proto import error

__all__ = ['Opaque', 'NetworkAddress', 'ObjectName', 'TimeTicks',
           'Counter', 'Gauge', 'IpAddress']


class IpAddress(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x00)
    )
    subtypeSpec = univ.OctetString.subtypeSpec + constraint.ValueSizeConstraint(
        4, 4
    )

    def prettyIn(self, value):
        if isinstance(value, str) and len(value) != 4:
            try:
                value = [int(x) for x in value.split('.')]
            except:
                raise error.ProtocolError('Bad IP address syntax %s' % value)
        if len(value) != 4:
            raise error.ProtocolError('Bad IP address syntax')
        return univ.OctetString.prettyIn(self, value)

    def prettyOut(self, value):
        if value:
            return '.'.join(['%d' % x for x in self.__class__(value).asNumbers()])
        else:
            return ''


class Counter(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x01)
    )
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 4294967295
    )


class NetworkAddress(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('internet', IpAddress())
    )

    def clone(self, value=univ.noValue, **kwargs):
        """Clone this instance.

        If *value* is specified, use its tag as the component type selector,
        and itself as the component value.

        :param value: (Optional) the component value.
        :type value: :py:obj:`pyasn1.type.base.Asn1ItemBase`
        :return: the cloned instance.
        :rtype: :py:obj:`pysnmp.proto.rfc1155.NetworkAddress`
        :raise: :py:obj:`pysnmp.smi.error.SmiError`:
            if the type of *value* is not allowed for this Choice instance.
        """
        cloned = univ.Choice.clone(self, **kwargs)
        if value is not univ.noValue:
            if isinstance(value, NetworkAddress):
                value = value.getComponent()
            elif not isinstance(value, IpAddress):
                # IpAddress is the only supported type, perhaps forever because
                # this is SNMPv1.
                value = IpAddress(value)
            try:
                tagSet = value.tagSet
            except AttributeError:
                raise PyAsn1Error('component value %r has no tag set' % (value,))
            cloned.setComponentByType(tagSet, value)
        return cloned

    # RFC 1212, section 4.1.6:
    #
    #    "(5)  NetworkAddress-valued: `n+1' sub-identifiers, where `n'
    #          depends on the kind of address being encoded (the first
    #          sub-identifier indicates the kind of address, value 1
    #          indicates an IpAddress);"

    def cloneFromName(self, value, impliedFlag, parentRow, parentIndices):
        kind = value[0]
        clone = self.clone()
        if kind == 1:
            clone['internet'] = tuple(value[1:5])
            return clone, value[5:]
        else:
            raise SmiError('unknown NetworkAddress type %r' % (kind,))

    def cloneAsName(self, impliedFlag, parentRow, parentIndices):
        kind = self.getName()
        component = self.getComponent()
        if kind == 'internet':
            return (1,) + tuple(component.asNumbers())
        else:
            raise SmiError('unknown NetworkAddress type %r' % (kind,))



class Gauge(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x02)
    )
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 4294967295
    )


class TimeTicks(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x03)
    )
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 4294967295
    )


class Opaque(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0x04)
    )


class ObjectName(univ.ObjectIdentifier):
    pass


class TypeCoercionHackMixIn:  # XXX keep this old-style class till pyasn1 types becomes new-style
    # Reduce ASN1 type check to simple tag check as SMIv2 objects may
    # not be constraints-compatible with those used in SNMP PDU.
    def _verifyComponent(self, idx, value, **kwargs):
        componentType = self._componentType
        if componentType:
            if idx >= len(componentType):
                raise PyAsn1Error('Component type error out of range')
            t = componentType[idx].getType()
            if not t.getTagSet().isSuperTagSetOf(value.getTagSet()):
                raise PyAsn1Error('Component type error %r vs %r' % (t, value))


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
