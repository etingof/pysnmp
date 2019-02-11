"""
Preload PySNMP MIBs
+++++++++++++++++++

Send a series of SNMP GETNEXT requests using the following options:

* with SNMPv2c, community name "public"
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs starting from 1.3.6
* with MIB lookup enabled
* preload all Python MIB modules found in search path

Functionally similar to:

| $ snmpwalk -v2c -c public -m ALL demo.snmplabs.com:161 1.3.6

"""#
from pysnmp.hlapi.v1arch import *

iterator = nextCmd(
    SnmpDispatcher(),
    CommunityData('public'),
    UdpTransportTarget(('demo.snmplabs.com', 161)),
    ObjectType(ObjectIdentity('1.3.6').loadMibs()),
    lookupMib=True
)

for errorIndication, errorStatus, errorIndex, varBinds in iterator:

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
