"""
Fetch scalar and table variables
++++++++++++++++++++++++++++++++

Send a series of SNMP GETBULK requests using the following options:

* with SNMPv3 with user 'usr-md5-des', MD5 auth and DES privacy protocols
* over IPv6/UDP
* to an Agent at [::1]:161
* with values non-repeaters = 1, max-repetitions = 25
* for IP-MIB::ipAdEntAddr and all columns of the IF-MIB::ifEntry table
* stop when response OIDs leave the scopes of the table

Functionally similar to:

| $ snmpbulkwalk -v3 -lauthPriv -u usr-md5-des -A authkey1 -X privkey1 -Cn1, -Cr25 demo.snmplabs.com IP-MIB::ipAdEntAddr IP-MIB::ipAddrEntry

"""#
from pysnmp.hlapi import *

for (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) in bulkCmd(SnmpEngine(),
                          UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
                          Udp6TransportTarget(('::1', 161)),
                          ContextData(),
                          1, 25,
                          ObjectType(ObjectIdentity('IP-MIB', 'ipAdEntAddr')),
                          ObjectType(ObjectIdentity('IP-MIB', 'ipAddrEntry')),
                          lexicographicMode=False):

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
