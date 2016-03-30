"""
Coerce value to SET to MIB spec
+++++++++++++++++++++++++++++++

Send SNMP SET request using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* setting SNMPv2-MIB::sysName.0 to new value (type taken from MIB)

Functionally similar to:

| $ snmpset -v2c -c public demo.snmplabs.com SNMPv2-MIB::sysDescr.0 = "new system name"

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    setCmd(SnmpEngine(),
           CommunityData('public'),
           UdpTransportTarget(('demo.snmplabs.com', 161)),
           ContextData(),
           ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysORDescr', 1),
                      'new system name'))
)

if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
