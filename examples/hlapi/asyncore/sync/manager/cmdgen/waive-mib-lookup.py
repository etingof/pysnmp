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
from pysnmp.entity.rfc3413.oneliner.cmdgen import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in nextCmd(SnmpEngine(),
                        CommunityData('public'),
                        UdpTransportTarget(('demo.snmplabs.com', 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1')),
                        lookupNames=True, lookupValues=True):
    # Check for errors and print out results
    if errorIndication:
        print(errorIndication)
        break
    else:
        if errorStatus:
            print('%s at %s' % (
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex)-1][0] or '?'
                )
            )
            break
        else:
            for varBind in varBinds:
                print(' = '.join([ x.prettyPrint() for x in varBind ]))
