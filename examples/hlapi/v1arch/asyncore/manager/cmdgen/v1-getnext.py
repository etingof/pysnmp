"""
SNMP GETNEXT over SNMPv1
++++++++++++++++++++++++

Send a series of SNMP GETNEXT requests using the following options:

  * with SNMPv1, community 'public'
  * over IPv4/UDP
  * to an Agent at demo.snmplabs.com:161
  * for the 1.3.6.1.2.1.1 OID (e.g. SNMPv2-MIB::system MIB branch)

Functionally similar to:

| $ snmpwalk -v1 -c public demo.snmplabs.com 1.3.6.1.2.1.1

"""#

from pysnmp.hlapi.v1arch.asyncore import *


def cbFun(errorIndication, errorStatus, errorIndex, varBindTable, **context):
    if errorIndication:
        print(errorIndication)
        return

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBindTable[-1][int(errorIndex) - 1][0] or '?'))
        return

    else:
        for varBindRow in varBindTable:
            for varBind in varBindRow:
                print(' = '.join([x.prettyPrint() for x in varBind]))

    return context.get('nextVarBinds')


snmpDispatcher = SnmpDispatcher()

stateHandle = nextCmd(
    snmpDispatcher,
    CommunityData('public', mpModel=0),
    UdpTransportTarget(('demo.snmplabs.com', 161)),
    ('1.3.6.1.5.1.1', None),
    cbFun=cbFun
)

snmpDispatcher.transportDispatcher.runDispatcher()
