"""
Walk whole MIB
++++++++++++++

Send a series of SNMP GETNEXT requests using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs in IF-MIB
* with MIB lookup enabled

Functionally similar to:

| $ snmpwalk -v2c -c public demo.snmplabs.com  IF-MIB::

"""#
from pysnmp.hlapi.v1arch import *

iterator = nextCmd(
    SnmpDispatcher(),
    CommunityData('public'),
    UdpTransportTarget(('demo.snmplabs.com', 161)),
    ObjectType(ObjectIdentity('IF-MIB'))
)

for errorIndication, errorStatus, errorIndex, varBinds in interator:

    if errorIndication:
        print(errorIndication)
        break

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        break

    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
