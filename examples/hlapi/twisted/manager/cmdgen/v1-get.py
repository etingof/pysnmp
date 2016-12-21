"""
SNMPv1
++++++

Send SNMP GET request using the following options:

* with SNMPv1, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for two instances of SNMPv2-MIB::sysDescr.0 MIB object,
* based on Twisted I/O framework

Functionally similar to:

| $ snmpget -v1 -c public demo.snmplabs.com SNMPv2-MIB::sysDescr.0

"""#
from twisted.internet.task import react
from pysnmp.hlapi.twisted import *


def success(args, hostname):
    (errorStatus, errorIndex, varBinds) = args

    if errorStatus:
        print('%s: %s at %s' % (hostname,
                                errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))


def failure(errorIndication, hostname):
    print('%s failure: %s' % (hostname, errorIndication))


# noinspection PyUnusedLocal
def getSysDescr(reactor, hostname):
    d = getCmd(SnmpEngine(),
               CommunityData('public', mpModel=0),
               UdpTransportTarget((hostname, 161)),
               ContextData(),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))

    d.addCallback(success, hostname).addErrback(failure, hostname)

    return d


react(getSysDescr, ['demo.snmplabs.com'])
