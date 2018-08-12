"""
Walk Agent, limit number of packets 
+++++++++++++++++++++++++++++++++++

Send a series of SNMP GETBULK requests using the following options:

* with SNMPv2c, community name "public"
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs past SNMPv2-MIB::system
* with MIB lookup enabled
* run till end-of-mib condition is reported by Agent OR 
  maxCalls == 10 request-response interactions occur

Functionally similar to:

| $ snmpbulkwalk -v2c -c public -Cn0 -Cr50 demo.snmplabs.com SNMPv2-MIB::system

"""#
from pysnmp.hlapi.v1arch import *

for (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) in bulkCmd(SnmpDispatcher(),
                          CommunityData('public'),
                          UdpTransportTarget(('demo.snmplabs.com', 161)),
                          0, 50,
                          ObjectType(ObjectIdentity('SNMPv2-MIB', 'system')),
                          lookupMib=True,
                          maxCalls=10):

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
