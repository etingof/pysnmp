"""
Walk Agent, limit number of packets 
+++++++++++++++++++++++++++++++++++

Send a series of SNMP GETBULK requests using the following options:

* with SNMPv3, user 'usr-none-none', no authentication, no privacy
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs past SNMPv2-MIB::system
* run till end-of-mib condition is reported by Agent OR 
  maxCalls == 10 request-response interactions occur

Functionally similar to:

| $ snmpbulkwalk -v3 -lnoAuthNoPriv -u usr-none-none -Cn0 -Cr50 demo.snmplabs.com  SNMPv2-MIB::system

"""#
from pysnmp.hlapi import *

for (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) in bulkCmd(SnmpEngine(),
                          UsmUserData('usr-none-none'),
                          UdpTransportTarget(('demo.snmplabs.com', 161)),
                          ContextData(),
                          0, 50,
                          ObjectType(ObjectIdentity('SNMPv2-MIB', 'system')),
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
