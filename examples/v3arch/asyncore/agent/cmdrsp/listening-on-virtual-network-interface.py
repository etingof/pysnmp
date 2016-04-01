"""
Running at secondary network interface
++++++++++++++++++++++++++++++++++++++

Listen on all local IPv4 interfaces respond to SNMP GET/SET/GETNEXT/GETBULK
queries with the following options:

* SNMPv3
* with USM user 'usr-md5-des', auth: MD5, priv DES
* allow access to SNMPv2-MIB objects (1.3.6.1.2.1)
* over IPv4/UDP, listening at 0.0.0.0:161
* preserve local IP address when responding (Python 3.3+ required)

The following Net-SNMP command will walk this Agent:

| $ snmpwalk -v3 -u usr-md5-des -l authPriv -A authkey1 -X privkey1 localhost .1.3.6

In the situation when UDP responder receives a datagram targeted to
a secondary (AKA virtial) IP interface or a non-local IP interface
(e.g. routed through policy routing or iptables TPROXY facility),
OS stack will by default put primary local IP interface address into
the IP source field of the response IP packet. Such datagram may not 
reach the sender as either the sender itself or a stateful firewall
somewhere in between would not be able to match response to original 
request.

The following script solves this problem by preserving original request
destination IP address and put it back into response IP packet's source
address field.

To respond from a non-local (e.g. spoofed) IP address, uncomment the
.enableTransparent() method call and run this script as root.

"""#
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp

# Create SNMP engine
snmpEngine = engine.SnmpEngine()

# Transport setup

# Initialize asyncore-based UDP/IPv4 transport
udpSocketTransport = udp.UdpSocketTransport().openServerMode(('0.0.0.0', 161))

# Use sendmsg()/recvmsg() for socket communication (used for preserving
# original destination IP address when responding)
udpSocketTransport.enablePktInfo()

# Enable IP source spoofing (requires root privileges)
# udpSocketTransport.enableTransparent()

# Register this transport at SNMP Engine
config.addTransport(
    snmpEngine,
    udp.domainName,
    udpSocketTransport
)

# SNMPv3/USM setup

# user: usr-md5-des, auth: MD5, priv DES
config.addV3User(
    snmpEngine, 'usr-md5-des',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    config.usmDESPrivProtocol, 'privkey1'
)

# Allow full MIB access for each user at VACM
config.addVacmUser(snmpEngine, 3, 'usr-md5-des', 'authPriv', (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1))

# Get default SNMP context this SNMP engine serves
snmpContext = context.SnmpContext(snmpEngine)

# Register SNMP Applications at the SNMP engine for particular SNMP context
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

# Register an imaginary never-ending job to keep I/O dispatcher running forever
snmpEngine.transportDispatcher.jobStarted(1)

# Run I/O dispatcher which would receive queries and send responses
try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.observer.unregisterObserver()
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
