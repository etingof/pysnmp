"""
SNMPv2c
+++++++

Send SNMP GET request using the following options:

  * with SNMPv2c, community 'public'
  * over IPv4/UDP with non-default timeout and no retries
  * to an Agent at demo.snmplabs.com:161
  * for two instances of SNMPv2-MIB::sysDescr.0 MIB object,
  * based on Twisted I/O framework

Functionally similar to:

| $ snmpget -v2c -c public -r 0 -t 2 demo.snmplabs.com SNMPv2-MIB::sysDescr.0

"""#
from twisted.internet.task import react
from pysnmp.hlapi.twisted import *

def success((errorStatus, errorIndex, varBinds), hostname):
    if errorStatus:
        print('%s: %s at %s' % (
                hostname,
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        )
    else:
        for varBind in varBinds:
            print(' = '.join([ x.prettyPrint() for x in varBind ]))

def failure(errorIndication, hostname):
    print('%s failure: %s' % (hostname, errorIndication))

def getSysDescr(reactor, hostname):
    snmpEngine = SnmpEngine()

    d = getCmd(snmpEngine,
               CommunityData('public'),
               UdpTransportTarget((hostname, 161), timeout=2.0, retries=0),
               ContextData(),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))

    d.addCallback(success, hostname).addErrback(failure, hostname)

    return d

react(getSysDescr, ['demo.snmplabs.com'])
