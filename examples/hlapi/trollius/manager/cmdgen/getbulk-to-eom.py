"""
Bulk walk MIB
+++++++++++++

Send a series of SNMP GETBULK requests using the following options:

* with SNMPv3, user 'usr-none-none', no authentication, no privacy
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs past SNMPv2-MIB::system
* run till end-of-mib condition is reported by Agent
* based on trollius I/O framework

Functionally similar to:

| $ snmpbulkwalk -v3 -lnoAuthNoPriv -u usr-none-none -Cn0 -Cr50 demo.snmplabs.com  SNMPv2-MIB::system

"""#
import trollius
from pysnmp.hlapi.asyncio import *


@trollius.coroutine
def run(varBinds):
    snmpEngine = SnmpEngine()
    while True:
        (errorIndication,
         errorStatus,
         errorIndex,
         varBindTable) = yield trollius.From(
            bulkCmd(snmpEngine,
                    UsmUserData('usr-none-none'),
                    UdpTransportTarget(('demo.snmplabs.com', 161)),
                    ContextData(),
                    0, 50,
                    *varBinds)
        )

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            for varBindRow in varBindTable:
                for varBind in varBindRow:
                    print(' = '.join([x.prettyPrint() for x in varBind]))

        varBinds = varBindTable[-1]
        if isEndOfMib(varBinds):
            break

    snmpEngine.transportDispatcher.closeDispatcher()


loop = trollius.get_event_loop()

loop.run_until_complete(
    run([ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr'))])
)
