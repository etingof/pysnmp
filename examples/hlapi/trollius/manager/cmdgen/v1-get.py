"""
SNMPv1
++++++

Send SNMP GET request using the following options:

  * with SNMPv1, community 'public'
  * over IPv4/UDP
  * to an Agent at demo.snmplabs.com:161
  * for an instance of SNMPv2-MIB::sysDescr.0 MIB object
  * Based on trollius I/O framework

Functionally similar to:

| $ snmpget -v1 -c public demo.snmplabs.com SNMPv2-MIB::sysDescr.0

"""#
import trollius
from pysnmp.hlapi.asyncio import *

@trollius.coroutine
def run():
    snmpEngine = SnmpEngine()
    errorIndication, errorStatus, \
    errorIndex, varBinds = yield trollius.From(
        getCmd(snmpEngine,
               CommunityData('public', mpModel=0),
               UdpTransportTarget(('demo.snmplabs.com', 161)),
               ContextData(),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
    )

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        )
    else:
        for varBind in varBinds:
            print(' = '.join([ x.prettyPrint() for x in varBind ]))

    snmpEngine.transportDispatcher.closeDispatcher()

trollius.get_event_loop().run_until_complete(run())
