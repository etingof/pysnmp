"""
Fetch table row by composite index
++++++++++++++++++++++++++++++++++

Send SNMP GET request using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for TCP-MIB::tcpConnLocalAddress."0.0.0.0".22."0.0.0.0".0 MIB object
* with MIB lookup enabled

Functionally similar to:

| $ snmpget -v2c -c public demo.snmplabs.com TCP-MIB::tcpConnLocalAddress."0.0.0.0".22."0.0.0.0".0

"""#
from pysnmp.hlapi.v1arch import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(SnmpDispatcher(),
           CommunityData('public'),
           UdpTransportTarget(('demo.snmplabs.com', 161)),
           ObjectType(ObjectIdentity('TCP-MIB',
                                     'tcpConnLocalAddress',
                                     '0.0.0.0', 22,
                                     '0.0.0.0', 0)),
           lookupMib=True)
)

if errorIndication:
    print(errorIndication)

elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
