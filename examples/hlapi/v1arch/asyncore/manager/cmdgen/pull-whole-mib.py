"""
Walk whole MIB
++++++++++++++

Send a series of SNMP GETBULK requests using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs past 1.3.6.1.4.1

Functionally similar to:

| $ snmpwalk -v2c -c public demo.snmplabs.com 1.3.6.1.4.1
"""#
from pysnmp.hlapi.v1arch.asyncore import *


def cbFun(errorIndication, errorStatus, errorIndex, varBindTable, **context):
    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

    else:
        for varBindRow in varBindTable:
            for varBind in varBindRow:
                print(' = '.join([x.prettyPrint() for x in varBind]))

        return context.get('nextVarBinds')


snmpDispatcher = SnmpDispatcher()

# Submit initial GETBULK request
bulkCmd(snmpDispatcher,
        CommunityData('public'),
        UdpTransportTarget(('demo.snmplabs.com', 161)),
        0, 25,
        ('1.3.6.1.4.1', None),
        cbFun=cbFun)

snmpDispatcher.transportDispatcher.runDispatcher()
