# ASN.1 objects used in SNMP
from pyasn1.type import univ
from pysnmp.proto import rfc1902

Integer = rfc1902.Integer32
OctetString = rfc1902.OctetString

# Instead of using base ASN,1 types we use SNMPv2 SMI ones to make
# SMI objects type-compatible with SNMP protocol values

# Integer = univ.Integer
# OctetString = univ.OctetString
BitString = univ.BitString
Null = univ.Null
ObjectIdentifier = univ.ObjectIdentifier

mibBuilder.exportSymbols(
    'ASN1', Integer=Integer, OctetString=OctetString,
    BitString=BitString, Null=Null, ObjectIdentifier=ObjectIdentifier
    )
