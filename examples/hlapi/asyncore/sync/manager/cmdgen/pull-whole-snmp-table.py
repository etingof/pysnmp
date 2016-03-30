"""
Fetch whole SNMP table
++++++++++++++++++++++

Send a series of SNMP GETNEXT requests using the following options:

* with SNMPv1, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for some columns of the IF-MIB::ifEntry table
* stop when response OIDs leave the scopes of initial OIDs

Functionally similar to:

| $ snmpwalk -v1 -c public demo.snmplabs.com IF-MIB::ifDescr IF-MIB::ifType IF-MIB::ifMtu IF-MIB::ifSpeed IF-MIB::ifPhysAddress IF-MIB::ifType

"""#
from pysnmp.hlapi import *

for (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) in nextCmd(SnmpEngine(),
                          CommunityData('public', mpModel=0),
                          UdpTransportTarget(('demo.snmplabs.com', 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity('IF-MIB', 'ifDescr')),
                          ObjectType(ObjectIdentity('IF-MIB', 'ifType')),
                          ObjectType(ObjectIdentity('IF-MIB', 'ifMtu')),
                          ObjectType(ObjectIdentity('IF-MIB', 'ifSpeed')),
                          ObjectType(ObjectIdentity('IF-MIB', 'ifPhysAddress')),
                          ObjectType(ObjectIdentity('IF-MIB', 'ifType')),
                          lexicographicMode=False):

    if errorIndication:
        print(errorIndication)
        break
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex)-1][0] or '?'))
        break
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
