"""
Sequential queries
++++++++++++++++++

Send multiple SNMP GET requests one by one using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to multiple Agents at demo.snmplabs.com
* for instance of SNMPv2-MIB::sysDescr.0 MIB object
* based on asyncio I/O framework

Functionally similar to:

| $ snmpget -v2c -c public demo.snmplabs.com:1161 SNMPv2-MIB::sysDescr.0
| $ snmpget -v2c -c public demo.snmplabs.com:2161 SNMPv2-MIB::sysDescr.0
| $ snmpget -v2c -c public demo.snmplabs.com:3161 SNMPv2-MIB::sysDescr.0

"""#
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *


@asyncio.coroutine
def getone(snmpEngine, hostname):
    errorIndication, errorStatus, errorIndex, varBinds = yield from getCmd(
        snmpEngine,
        CommunityData('public'),
        UdpTransportTarget(hostname),
        ContextData(),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
    )

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


@asyncio.coroutine
def getall(snmpEngine, hostnames):
    for hostname in hostnames:
        yield from getone(snmpEngine, hostname)


snmpEngine = SnmpEngine()

loop = asyncio.get_event_loop()
loop.run_until_complete(getall(snmpEngine, [('demo.snmplabs.com', 1161),
                                            ('demo.snmplabs.com', 2161),
                                            ('demo.snmplabs.com', 3161)]))
