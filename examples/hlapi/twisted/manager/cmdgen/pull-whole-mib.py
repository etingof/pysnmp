"""
Walk whole MIB
++++++++++++++

Send a series of SNMP GETNEXT requests using the following options:

* with SNMPv3, user 'usr-md5-none', MD5 authentication, no privacy
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs in IF-MIB
* based on Twisted I/O framework

Functionally similar to:

| $ snmpwalk -v3 -lauthPriv -u usr-md5-none -A authkey1 -X privkey1 demo.snmplabs.com  IF-MIB::

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
            return getnext(reactor, snmpEngine, *varBindTable[-1])


def failure(errorIndication):
    print(errorIndication)


def getnext(reactor, snmpEngine, varBinds):
    d = nextCmd(snmpEngine,
                UsmUserData('usr-md5-none', 'authkey1'),
                UdpTransportTarget(('demo.snmplabs.com', 161)),
                ContextData(),
                varBinds)
    d.addCallback(success, reactor, snmpEngine).addErrback(failure)
    return d


react(getnext, [SnmpEngine(), ObjectType(ObjectIdentity('SNMPv2-MIB', 'system'))])
