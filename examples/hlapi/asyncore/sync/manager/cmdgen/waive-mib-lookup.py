"""
Waive MIB lookup
++++++++++++++++

Perform SNMP GETNEXT operation with the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for an OID in string form
* do not resolve response OIDs and values into human-freidly form

False lookupMib keyword arguments could make pysnmp waiving 
OIDs and values resolution in response variable-bindings, into human
friendly form.

Functionally similar to:

| $ snmpwalk -v2c -c public -ObentU demo.snmplabs.com 1.3.6.1.2.1

"""#
from pysnmp.hlapi import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in nextCmd(SnmpEngine(),
                        CommunityData('public'),
                        UdpTransportTarget(('demo.snmplabs.com', 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1')),
                        lookupMib=False):

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
