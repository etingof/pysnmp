"""
GET table row
+++++++++++++

Send SNMP GET request using the following options:

* with SNMPv2c, community name "public"
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* with MIB lookup enabled
* for IF-MIB::ifInOctets.1 and IF-MIB::ifOutOctets.1 MIB object

Functionally similar to:

| $ snmpget -v 2c -c public demo.snmplabs.com IF-MIB::ifInOctets.1 IF-MIB::ifOutOctets.1

"""#
from pysnmp.hlapi.v1arch import *

iterator = getCmd(
    SnmpDispatcher(),
    CommunityData('public'),
    UdpTransportTarget(('demo.snmplabs.com', 161)),
    ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets', 1)),
    ObjectType(ObjectIdentity('IF-MIB', 'ifOutOctets', 1)),
    lookupMib=True
)

errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

if errorIndication:
    print(errorIndication)

elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
