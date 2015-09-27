"""
Multiple concurrent notifications
+++++++++++++++++++++++++++++++++

Send multiple SNMP notifications at once using the following options:

* SNMPv2c and SNMPv3
* with community name 'public' or USM username usr-md5-des
* over IPv4/UDP
* send INFORM notification
* to multiple Managers
* with TRAP ID 'coldStart' specified as a MIB symbol
* include managed object information specified as var-bind objects pair

Here we tag each SNMP-COMMUNITY-MIB::snmpCommunityTable row
with the same tag as SNMP-TARGET-MIB::snmpTargetAddrTable row
what leads to excessive tables information.

Functionally similar to:

| $ snmpinform -v2c -c public demo.snmplabs.com 12345 1.3.6.1.6.3.1.1.5.2
|
| $ snmpinform -v3 -l authNoPriv -u usr-md5-none -A authkey1 \
|              demo.snmplabs.com \
|              12345 \
|              1.3.6.1.6.3.1.1.5.2

"""#
from twisted.internet.defer import DeferredList
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

def sendone(reactor, snmpEngine, hostname, notifyType):
    d = sendNotification(
        snmpEngine,
        CommunityData('public', tag=hostname),
        UdpTransportTarget((hostname, 162), tagList=hostname),
        ContextData(),
        notifyType,
        NotificationType(
            ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
        ).addVarBinds(
            ('1.3.6.1.6.3.1.1.4.3.0', '1.3.6.1.4.1.20408.4.1.1.2'),
            ('1.3.6.1.2.1.1.1.0', OctetString('my system'))
        )
    )
    d.addCallback(success, hostname).addErrback(failure, hostname)
    return d

def sendall(reactor, destinations):
    snmpEngine = SnmpEngine()

    return DeferredList(
        [ sendone(reactor, snmpEngine, hostname, notifyType)
          for hostname, notifyType in destinations ]
    )

react(sendall, [[('localhost', 'trap'), ('localhost', 'inform')]])
