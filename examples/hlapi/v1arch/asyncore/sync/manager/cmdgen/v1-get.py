"""
SNMPv1
++++++

Send SNMP GET request using the following options:

  * with SNMPv1, community 'public'
  * over IPv4/UDP
  * to an Agent at demo.snmplabs.com:161
  * for an instance of SNMPv2-MIB::sysDescr.0 MIB object
  * having MIB lookup feature enabled

Functionally similar to:

| $ snmpget -v1 -c public demo.snmplabs.com SNMPv2-MIB::sysDescr.0

"""#
from pysnmp.hlapi.v1arch import *

for response in getCmd(SnmpDispatcher(),
                       CommunityData('public', mpModel=0),
                       UdpTransportTarget(('demo.snmplabs.com', 161)),
                       ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
                       lookupMib=True):

    errorIndication, errorStatus, errorIndex, varBinds = response

    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
