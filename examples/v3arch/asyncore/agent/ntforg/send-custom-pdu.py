"""
Send crafted TRAP PDU
+++++++++++++++++++++

Initialize TRAP PDU and pass it over to unified SNMPv3 message processing
framework for further treatment.

* SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send TRAP notification
* initialize TRAP PDU with the following var-binds:
  1.3.6.1.2.1.1.3.0 = 123
  1.3.6.1.6.3.1.1.4.1.0 = 1.3.6.1.6.3.1.1.5.1

Functionally similar to:

| $ snmptrap -v1 -c public 127.0.0.1 1.3.6.1.6.3.1.1.5.1 0.0.0.0 1 0 123

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntforg
from pysnmp.proto.api import v2c

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public')

# Specify security settings per SecurityName (SNMPv2c -> 1)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 1)

# Setup transport endpoint and bind it with security settings yielding
# a target name
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
)

# Create named target
config.addTargetAddr(
    snmpEngine, 'my-nms',
    udp.domainName, ('127.0.0.1', 162),
    'my-creds'
)

# *** SNMP engine configuration is complete by this line ***

# Create SNMP v2c TRAP PDU with defaults
trapPDU =  v2c.TrapPDU()
v2c.apiTrapPDU.setDefaults(trapPDU)

# Set custom var-binds to TRAP PDU
v2c.apiTrapPDU.setVarBinds(
    trapPDU, [
        # sysUpTime
        ( v2c.ObjectIdentifier('1.3.6.1.2.1.1.3.0'), v2c.TimeTicks(123) ),
        # snmpTrapPDU
        ( (1,3,6,1,6,3,1,1,4,1,0), v2c.ObjectIdentifier((1,3,6,1,6,3,1,1,5,1)) )
    ]
)

# Create Notification Originator App instance. 
ntfOrg = ntforg.NotificationOriginator()

# Error/confirmation receiver
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBinds, cbCtx):
    print('Notification %s, status - %s' % (
        sendRequestHandle, errorIndication and errorIndication or 'delivered'
      )
    )

# Build and submit notification message to dispatcher
ntfOrg.sendPdu(
    snmpEngine,
    # Notification targets
    'my-nms',           # target address
    None, '',           # contextEngineId, contextName
    trapPDU,
    cbFun
)

print('Notification is scheduled to be sent')

# Run I/O dispatcher which would send pending message and process response
snmpEngine.transportDispatcher.runDispatcher()
