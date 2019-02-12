"""
Sequence Of GET's
+++++++++++++++++

Send two SNMP GET requests in a row using the following options:

* with SNMPv2c, community name "public"
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for IF-MIB::ifInOctets.1 and IF-MIB::ifOutOctets.1 MIB objects
* with MIB lookup enabled

Use a queue of MIB objects to query.

The next() call is used to forward Python iterator to the position where it
could consume input

Functionally similar to:

| $ snmpget -v2c -c public demo.snmplabs.com IF-MIB::ifInOctets.1

"""#
from pysnmp.hlapi.v1arch import *

queue = [
    [ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets', 1))],
    [ObjectType(ObjectIdentity('IF-MIB', 'ifOutOctets', 1))]
]

iterator = getCmd(
    SnmpDispatcher(),
    CommunityData('public'),
    UdpTransportTarget(('demo.snmplabs.com', 161)),
    lookupMib=True
)

next(iterator)

while queue:
    errorIndication, errorStatus, errorIndex, varBinds = iterator.send(queue.pop())

    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
