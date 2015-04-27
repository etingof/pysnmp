#
# PySNMP MIB module RFC1158-MIB (http://pysnmp.sf.net)
# It is a stripped version of MIB that contains only symbols that is
# unique to SMIv1 and have no analogues in SMIv2
#
( Integer32, MibScalar, MibTable, MibTableRow, MibTableColumn, TimeTicks, iso, Gauge32, MibIdentifier, Bits, Counter32, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "TimeTicks", "iso", "Gauge32", "MibIdentifier", "Bits", "Counter32")
snmpInBadTypes = MibScalar((1, 3, 6, 1, 2, 1, 11, 7), Counter32()).setMaxAccess("readonly")
snmpOutReadOnlys = MibScalar((1, 3, 6, 1, 2, 1, 11, 23), Counter32()).setMaxAccess("readonly")
mibBuilder.exportSymbols("RFC1158-MIB", snmpOutReadOnlys=snmpOutReadOnlys, snmpInBadTypes=snmpInBadTypes)
