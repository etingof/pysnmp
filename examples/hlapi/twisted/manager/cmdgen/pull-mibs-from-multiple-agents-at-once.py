"""
Walk multiple Agents at once
++++++++++++++++++++++++++++

* with SNMPv3 with user 'usr-md5-none', MD5 auth and no privacy protocols
* over IPv4/UDP
* to Agents at demo.snmplabs.com:161 and demo.snmplabs.com:1161 
* for multiple MIB subtrees and tables
* for whole MIB
* based on Twisted I/O framework

Functionally similar to:

| $ snmpget -v2c -c public demo.snmplabs.com:161 SNMPv2-MIB::system
| $ snmpget -v2c -c public demo.snmplabs.comL1161 SNMPv2-MIB::system

"""#
from twisted.internet.defer import DeferredList
from twisted.internet.task import react
from pysnmp.hlapi.twisted import *

def success((errorStatus, errorIndex, varBindTable), reactor, snmpEngine, hostname):
    if errorStatus:
        print('%s: %s at %s' % (
                hostname,
                errorStatus.prettyPrint(),
                errorIndex and varBindTable[0][int(errorIndex)-1][0] or '?'
            )
        )
    else:
        for varBindRow in varBindTable:
            for varBind in varBindRow:
                print(' = '.join([ x.prettyPrint() for x in varBind ]))

        if not isEndOfMib(varBindTable[-1]):
            return getbulk(reactor, snmpEngine, hostname, *varBindTable[-1])

def failure(errorIndication):
    print(errorIndication)

def getbulk(reactor, snmpEngine, hostname, varBinds):
    d = bulkCmd(snmpEngine,
                UsmUserData('usr-md5-none', 'authkey1'),
                UdpTransportTarget(hostname),
                ContextData(),
                0, 25,
                varBinds)
    d.addCallback(success, reactor, snmpEngine, hostname).addErrback(failure)
    return d

def getall(reactor, hostnames):
    snmpEngine = SnmpEngine()

    return DeferredList(
        [ getbulk(reactor, snmpEngine, hostname,
                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'system')))
          for hostname in hostnames ]
    )

react(getall, [(('demo.snmplabs.com', 161), ('demo.snmplabs.com', 1161))])

