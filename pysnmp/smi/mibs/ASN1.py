# Base ASN.1 objects

from pysnmp.asn1 import univ

Integer = univ.Integer
OctetString = univ.OctetString
BitString = univ.BitString
Null = univ.Null
ObjectIdentifier = univ.ObjectIdentifier

mibBuilder.exportSymbols(
    'ASN1', Integer=Integer, OctetString=OctetString,
    BitString=BitString, Null=Null, ObjectIdentifier=ObjectIdentifier
    )
