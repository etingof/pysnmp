"""
Concurrent queries
++++++++++++++++++

Send multiple SNMP GET requests at once using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for two instances of SNMPv2-MIB::sysDescr.0 and SNMPv2-MIB::sysLocation.0
  MIB object,
* based on Twisted I/O framework

Functionally similar to:

| $ snmpget -v2c -c public demo.snmplabs.com SNMPv2-MIB::sysDescr.0
| $ snmpget -v2c -c public demo.snmplabs.com SNMPv2-MIB::sysLocation.0

"""#
from twisted.internet.defer import DeferredList
from twisted.internet.task import react
from pysnmp.hlapi.v3arch.twisted import *


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
def getSystem(reactor, hostname):
    snmpEngine = SnmpEngine()

    def getScalar(objectType):
        d = getCmd(snmpEngine,
                   CommunityData('public', mpModel=0),
                   UdpTransportTarget((hostname, 161)),
                   ContextData(),
                   objectType)
        d.addCallback(success, hostname).addErrback(failure, hostname)
        return d

    return DeferredList(
        [getScalar(ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))),
         getScalar(ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0)))]
    )


react(getSystem, ['demo.snmplabs.com'])
