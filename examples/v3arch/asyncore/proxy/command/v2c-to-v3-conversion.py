"""
SNMPv2c-to-SNMPv3 conversion
++++++++++++++++++++++++++++

Act as a local SNMPv1/v2c Agent, relay messages to distant SNMPv3 Agent:
* over IPv4/UDP
* with local SNMPv2c community 'public'
* local Agent listening at 127.0.0.1:161
* remote SNMPv3 user usr-md5-none, MD5 auth and no privacy protocols
* remote Agent listening at 195.218.195.228:161

This script can be queried with the following Net-SNMP command:

| $ snmpget -v2c -c public 127.0.0.1:161 1.3.6.1.2.1.1.1.0

due to proxy, it is equivalent to

| $ snmpget -v3 -l authNoPriv -u usr-md5-none -A authkey1 -ObentU 195.218.195.228:161  1.3.6.1.2.1.1.1.0

Warning: for production operation you would need to modify this script
so that it will re-map possible duplicate request-ID values, coming in
initial request PDUs from different Managers, into unique values to
avoid sending duplicate request-IDs to Agents.

"""#
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, cmdgen, context
from pysnmp.proto.api import v2c
from pysnmp import error

# Create SNMP engine with autogenernated engineID and pre-bound
# to socket transport dispatcher
snmpEngine = engine.SnmpEngine()

#
# Transport setup
#

# Agent section

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName + (1,),
    udp.UdpTransport().openServerMode(('127.0.0.1', 161))
)

# Manager section

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName + (2,),
    udp.UdpTransport().openClientMode()
)

#
# SNMPv1/2c setup (Agent role)
#

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public')

#
# SNMPv3/USM setup (Manager role)
#

# user: usr-md5-none, auth: MD5, priv NONE
config.addV3User(
    snmpEngine, 'usr-md5-none', config.usmHMACMD5AuthProtocol, 'authkey1'
)

#
# Transport target used by Manager
#

config.addTargetParams(
    snmpEngine, 'distant-agent-auth', 'usr-md5-none', 'authNoPriv'
)
config.addTargetAddr(
        snmpEngine, 'distant-agent', 
        udp.domainName + (2,), ('195.218.195.228', 161),
        'distant-agent-auth', retryCount=0
)

# Default SNMP context
config.addContext(snmpEngine, '')

class CommandResponder(cmdrsp.CommandResponderBase):
    cmdGenMap = { 
        v2c.GetRequestPDU.tagSet: cmdgen.GetCommandGenerator(),
        v2c.SetRequestPDU.tagSet: cmdgen.SetCommandGenerator(),
        v2c.GetNextRequestPDU.tagSet: cmdgen.NextCommandGeneratorSingleRun(),
        v2c.GetBulkRequestPDU.tagSet: cmdgen.BulkCommandGeneratorSingleRun() 
    }
    pduTypes = cmdGenMap.keys()  # This app will handle these PDUs

    # SNMP request relay
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName,
                            PDU, acInfo):
        cbCtx = stateReference, PDU
        contextEngineId = None  # address authoritative SNMP Engine
        try:
            self.cmdGenMap[PDU.tagSet].sendPdu(
                snmpEngine, 'distant-agent',
                contextEngineId, contextName,
                PDU,
                self.handleResponsePdu, cbCtx
            )
        except error.PySnmpError:
            self.handleResponsePdu(
                stateReference,  'error', None, cbCtx
            )

    # SNMP response relay
    def handleResponsePdu(self, snmpEngine, sendRequestHandle,
                          errorIndication, PDU, cbCtx):
        stateReference, reqPDU = cbCtx

        if errorIndication:
            PDU = v2c.apiPDU.getResponse(reqPDU)
            PDU.setErrorStatus(PDU, 5)

        self.sendPdu(
            snmpEngine, stateReference, PDU
        )

        self.releaseStateInformation(stateReference)

CommandResponder(snmpEngine, context.SnmpContext(snmpEngine))

snmpEngine.transportDispatcher.jobStarted(1) # this job would never finish

# Run I/O dispatcher which would receive queries and send responses
try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
