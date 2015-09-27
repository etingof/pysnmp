"""
Bulk walk MIB
+++++++++++++

Send a series of SNMP GETBULK requests using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* with values non-repeaters = 0, max-repetitions = 25
* for two OIDs in string form
* stop when response OIDs leave the scopes of initial OIDs

Functionally similar to:

| $ snmpbulkwalk -v2c -c public demo.snmplabs.com \
|        -Cn0 -Cr25 \
|        1.3.6.1.2.1.2.2 1.3.6.1.2.1.2.3

"""#
from pysnmp.hlapi import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in bulkCmd(SnmpEngine(),
                        CommunityData('public'),
                        UdpTransportTarget(('demo.snmplabs.com', 161)),
                        ContextData(),
                        0, 25,
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2')),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.2.3')),
                        lexicographicMode=False):

    if errorIndication:
        print(errorIndication)
        break
    elif errorStatus:
        print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        )
        break
    else:
        for varBind in varBinds:
            print(' = '.join([ x.prettyPrint() for x in varBind ]))
