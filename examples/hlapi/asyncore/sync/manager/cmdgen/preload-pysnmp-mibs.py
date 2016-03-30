"""
Preload PySNMP MIBs
+++++++++++++++++++

Send a series of SNMP GETNEXT requests using the following options:

* with SNMPv3 with user 'usr-md5-des', MD5 auth and DES privacy protocols
* over IPv6/UDP
* to an Agent at [::1]:161
* for all OIDs starting from 1.3.6
* preload all Python MIB modules found in search path

Functionally similar to:

| $ snmpwalk -v3 -l authPriv -u usr-md5-des -A authkey1 -X privkey1 -m ALL udp6:[::1]:161 1.3.6

"""#
from pysnmp.hlapi import *

for (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) in nextCmd(SnmpEngine(),
                          UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
                          Udp6TransportTarget(('::1', 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity('1.3.6').loadMibs())):

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
