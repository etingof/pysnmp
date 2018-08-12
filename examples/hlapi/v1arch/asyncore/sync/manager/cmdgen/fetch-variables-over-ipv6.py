"""
GET over IPv6
+++++++++++++

Send SNMP GET request using the following options:

* with SNMPv2c, community 'public'
* over IPv6/UDP
* to an Agent at [::1]:161
* for three OIDs in string form

Functionally similar to:

| $ snmpget -v2c -c public udp6:[::1]:161 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.2.0 1.3.6.1.2.1.1.3.0
"""#
from pysnmp.hlapi.v1arch import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(SnmpDispatcher(),
           CommunityData('public'),
           Udp6TransportTarget(('::1', 161)),
           ('1.3.6.1.2.1.1.1.0', None),
           ('1.3.6.1.2.1.1.2.0', None),
           ('1.3.6.1.2.1.1.3.0', None))
)

if errorIndication:
    print(errorIndication)

elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
