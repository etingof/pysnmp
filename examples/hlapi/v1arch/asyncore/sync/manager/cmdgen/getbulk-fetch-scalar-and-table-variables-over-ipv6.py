"""
Fetch scalar and table variables
++++++++++++++++++++++++++++++++

Send a series of SNMP GETBULK requests using the following options:

* with SNMPv2c, community name "public"
* over IPv6/UDP
* to an Agent at demo.snmplabs.com:161
* with MIB lookup enabled
* with values non-repeaters = 1, max-repetitions = 25
* for IP-MIB::ipAdEntAddr and all columns of the IF-MIB::ifEntry table
* stop when response OIDs leave the scopes of the table

Functionally similar to:

| $ snmpbulkwalk -v2c -c public -Cn1, -Cr25 demo.snmplabs.com IP-MIB::ipAdEntAddr IP-MIB::ipAddrEntry

"""#
from pysnmp.hlapi.v1arch import *

for (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) in bulkCmd(SnmpDispatcher(),
                          CommunityData('public'),
                          UdpTransportTarget(('demo.snmplabs.com', 161)),
                          1, 25,
                          ObjectType(ObjectIdentity('IP-MIB', 'ipAdEntAddr')),
                          ObjectType(ObjectIdentity('IP-MIB', 'ipAddrEntry')),
                          lookupMib=True,
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
