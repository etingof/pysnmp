"""
SNMPv1
++++++

Send SNMP GET request using the following options:

  * with SNMPv1, community 'public'
  * over IPv4/UDP
  * to an Agent at demo.snmplabs.com:161
  * for the 1.3.6.1.2.1.1.1.0 OID (e.g. SNMPv2-MIB::sysDescr.0 MIB object)
  * Based on asyncio I/O framework

Functionally similar to:

| $ snmpget -v1 -c public demo.snmplabs.com SNMPv2-MIB::sysDescr.0

"""#
import asyncio

from pysnmp.hlapi.v1arch.asyncio import *


@asyncio.coroutine
def run():
    snmpDispatcher = SnmpDispatcher()

    iterator = getCmd(
        snmpDispatcher,
        CommunityData('public', mpModel=0),
        UdpTransportTarget(('demo.snmplabs.com', 161)),
        ('1.3.6.1.2.1.1.1.0', None)
    )

    errorIndication, errorStatus, errorIndex, varBinds = yield from iterator

    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'
        )
              )
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))

    snmpDispatcher.transportDispatcher.closeDispatcher()


asyncio.get_event_loop().run_until_complete(run())
