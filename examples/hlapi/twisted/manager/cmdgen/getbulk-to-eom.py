"""
Bulk walk MIB
+++++++++++++

Send a series of SNMP GETBULK requests using the following options:

* with SNMPv3, user 'usr-none-none', no authentication, no privacy
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs past SNMPv2-MIB::system
* run till end-of-mib condition is reported by Agent
* based on Twisted I/O framework

Functionally similar to:

| $ snmpbulkwalk -v3 -lnoAuthNoPriv -u usr-none-none -Cn0 -Cr50 demo.snmplabs.com  SNMPv2-MIB::system

"""#
from twisted.internet.task import react
from pysnmp.hlapi.twisted import *


def success(args, reactor, snmpEngine):
    (errorStatus, errorIndex, varBindTable) = args

    if errorStatus:
        print('%s: %s at %s' % (hostname,
                                errorStatus.prettyPrint(),
                                errorIndex and varBindTable[0][int(errorIndex) - 1][0] or '?'))
    else:
        for varBindRow in varBindTable:
            for varBind in varBindRow:
                print(' = '.join([x.prettyPrint() for x in varBind]))

        if not isEndOfMib(varBindTable[-1]):
            return getbulk(reactor, snmpEngine, *varBindTable[-1])


def failure(errorIndication):
    print(errorIndication)


def getbulk(reactor, snmpEngine, varBinds):
    d = bulkCmd(snmpEngine,
                UsmUserData('usr-none-none'),
                UdpTransportTarget(('demo.snmplabs.com', 161)),
                ContextData(),
                0, 50,
                varBinds)
    d.addCallback(success, reactor, snmpEngine).addErrback(failure)
    return d


react(getbulk, [SnmpEngine(), ObjectType(ObjectIdentity('SNMPv2-MIB', 'system'))])
