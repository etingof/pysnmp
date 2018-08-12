"""
SNMP GET over SNMPv2c
+++++++++++++++++++++

Send SNMP GET request using the following options:

  * with SNMPv2c, community 'public'
  * over IPv4/UDP
  * to an Agent at demo.snmplabs.com:161
  * for the 1.3.6.1.2.1.1.1.0 OID (e.g. SNMPv2-MIB::sysDescr.0 MIB object)

Functionally similar to:

| $ snmpget -v2c -c public demo.snmplabs.com 1.3.6.1.2.1.1.1.0

"""#

from pysnmp.hlapi.v1arch.asyncore import *


def cbFun(errorIndication, errorStatus, errorIndex, varBinds, **context):
    if errorIndication:
        print(errorIndication)
        return
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBindTable[-1][int(errorIndex) - 1][0] or '?'))
        return
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))


snmpDispatcher = SnmpDispatcher()

stateHandle = getCmd(
    snmpDispatcher,
    CommunityData('public'),
    UdpTransportTarget(('demo.snmplabs.com', 161)),
    ('1.3.6.1.2.1.1.1.0', None),
    cbFun=cbFun
)

snmpDispatcher.transportDispatcher.runDispatcher()
