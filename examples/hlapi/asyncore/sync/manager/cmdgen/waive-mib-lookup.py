#
# GETNEXT Command Generator Application
#
# Perform SNMP GETNEXT operation with the following options:
#
# * with SNMPv2c, community 'public'
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for an OID in string form
# * resolve response OIDs and values into human-freidly form
# * stop when response OIDs leave the scopes of initial OIDs
#
# This script performs similar to the following Net-SNMP command:
# 
# $ snmpwalk -v2c -c public demo.snmplabs.com 1.3.6.1.2.1.1
#
# The lookupNames and lookupValues keyword arguments will make pysnmp
# trying to resolve OIDs and values, in response variable-bindings,
# into human-friendly form. If response OIDs do not belong to any of 
# currently loaded MIBs, unresolved OIDs and values will still be
# returned.
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
    cmdgen.CommunityData('public'),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    '1.3.6.1.2.1.1',
    lookupNames=True, lookupValues=True
)

if errorIndication:
    print(errorIndication)
else:
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'
            )
        )
    else:
        for varBindTableRow in varBindTable:
            for name, val in varBindTableRow:
                print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
