"""
SNMPv2c
+++++++

Send SNMP GET request using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for two var-bindings with  OIDs in string form 

Functionally similar to:

| $ snmpget -v2c -c public demo.snmplabs.com 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.6.0

"""#
from pysnmp.hlapi.v1arch import *

iterator = getCmd(
    SnmpDispatcher(),
    CommunityData('public'),
    UdpTransportTarget(('demo.snmplabs.com', 161)),
    ('1.3.6.1.2.1.1.1.0', None),
    ('1.3.6.1.2.1.1.6.0', None)
)

for response in iterator:

    errorIndication, errorStatus, errorIndex, varBinds = response

    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
