#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pyasn1.type import univ
from pyasn1.codec.ber import decoder, eoo
from pyasn1.error import PyAsn1Error
from pysnmp.proto.error import ProtocolError


def decodeMessageVersion(wholeMsg):
    try:
        seq, wholeMsg = decoder.decode(
            wholeMsg, asn1Spec=univ.Sequence(),
            recursiveFlag=False, substrateFun=lambda a, b, c: (a, b[:c])
        )
        ver, wholeMsg = decoder.decode(
            wholeMsg, asn1Spec=univ.Integer(),
            recursiveFlag=False, substrateFun=lambda a, b, c: (a, b[:c])
        )
        if eoo.endOfOctets.isSameTypeWith(ver):
            raise ProtocolError('EOO at SNMP version component')
        return ver
    except PyAsn1Error:
        raise ProtocolError('Invalid BER at SNMP version component')
