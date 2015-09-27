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

"""#
from pysnmp.hlapi.asyncore import *

# List of targets in the followin format:
# ( ( authData, transportTarget ), ... )
targets = (
    # 1-st target (SNMPv2c over IPv4/UDP)
    ( CommunityData('public'),
      UdpTransportTarget(('localhost', 162)),
      ContextData() ),
    # 2-nd target (SNMPv3 over IPv4/UDP)
    ( UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
      UdpTransportTarget(('localhost', 162)),
      ContextData() ),
)

def cbFun(snmpEngine, sendRequestHandle, errorIndication, 
          errorStatus, errorIndex, varBinds, cbctx):
    if errorIndication:
        print('Notification %s not sent: %s' % (sendRequestHandle, errorIndication))
    elif errorStatus:
        print('Notification Receiver returned error for %s: %s @%s' %
              (sendRequestHandle, errorStatus, errorIndex))
    else:
        print('Notification %s delivered:' % sendRequestHandle)
        for name, val in varBinds:
            print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))

snmpEngine = SnmpEngine()

for authData, transportTarget, contextData in targets:
    sendPduHandle = sendNotification(
        snmpEngine,
        authData,
        transportTarget,
        contextData,
        'inform',       # NotifyType
        NotificationType(
            ObjectIdentity('SNMPv2-MIB', 'coldStart')
        ).addVarBinds( ( '1.3.6.1.2.1.1.1.0', 'my name' ) ),
        cbFun=cbFun
    )

snmpEngine.transportDispatcher.runDispatcher()
