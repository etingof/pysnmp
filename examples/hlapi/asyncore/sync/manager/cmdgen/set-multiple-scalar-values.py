"""
SET scalars values
++++++++++++++++++

Send SNMP SET request using the following options:

* with SNMPv1, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* setting three var-bindings to new values

Please note, that in this example MIB lookup is only used
for the second var-bindins. For the rest, value types are
inferred from passed objects.

Functionally similar to:

| $ snmpset -v1 -c public demo.snmplabs.com \
|                    1.3.6.1.2.1.1.9.1.2.1 o 1.3.6.1.4.1.20408.1.1 \
|                    1.3.6.1.2.1.1.9.1.2.1 = 1.3.6.1.4.1.20408.1.1 \
|                    1.3.6.1.2.1.1.9.1.3.1 s "new system name"

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    setCmd(SnmpEngine(),
           CommunityData('public', mpModel=0),
           UdpTransportTarget(('demo.snmplabs.com', 161)),
           ContextData(),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.9.1.2.1'),
                      ObjectIdentifier('1.3.6.1.4.1.20408.1.1')),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.9.1.2.1'),
                      '1.3.6.1.4.1.20408.1.1'),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.9.1.3.1'),
                      OctetString('new system name')))
)

if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1][0] or '?'
        )
    )
else:
    for varBind in varBinds:
        print(' = '.join([ x.prettyPrint() for x in varBind ]))
