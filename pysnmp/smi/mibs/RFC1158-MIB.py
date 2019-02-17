#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source http://mibs.snmplabs.com:80/asn1/RFC1158-MIB
# Produced by pysmi-0.4.0 at Thu Feb 14 23:20:17 2019
#
# It is a stripped version of MIB that contains only symbols that is
# unique to SMIv1 and have no analogues in SMIv2
#

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

(Counter32,
 MibScalar) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "Counter32",
    "MibScalar")

_SnmpInBadTypes_Type = Counter32
_SnmpInBadTypes_Object = MibScalar
snmpInBadTypes = _SnmpInBadTypes_Object(
    (1, 3, 6, 1, 2, 1, 11, 7),
    _SnmpInBadTypes_Type()
)
snmpInBadTypes.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    snmpInBadTypes.setStatus("mandatory")

_SnmpOutReadOnlys_Type = Counter32
_SnmpOutReadOnlys_Object = MibScalar
snmpOutReadOnlys = _SnmpOutReadOnlys_Object(
    (1, 3, 6, 1, 2, 1, 11, 23),
    _SnmpOutReadOnlys_Type()
)
snmpOutReadOnlys.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    snmpOutReadOnlys.setStatus("mandatory")

mibBuilder.exportSymbols(
    "RFC1158-MIB",
    **{"snmpInBadTypes": snmpInBadTypes,
       "snmpOutReadOnlys": snmpOutReadOnlys}
)
