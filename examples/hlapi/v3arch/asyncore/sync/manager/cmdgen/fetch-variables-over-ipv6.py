"""
GET over IPv6
+++++++++++++

Send SNMP GET request using the following options:

* with SNMPv3 with user 'usr-md5-des', MD5 auth and DES privacy protocols
* over IPv6/UDP
* to an Agent at [::1]:161
* for three OIDs in string form

Functionally similar to:

| $ snmpget -v3 -l authPriv -u usr-md5-des -A authkey1 -X privkey1 udp6:[::1]:161 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.2.0 1.3.6.1.2.1.1.3.0
"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(SnmpEngine(),
           UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
           Udp6TransportTarget(('::1', 161)),
           ContextData(),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.2.0')),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0')))
)

if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
