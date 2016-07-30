"""
SNMPv2c-to-SNMPv1 conversion
++++++++++++++++++++++++++++

Act as a local SNMPv2c Agent, relay messages to distant SNMPv1 Agent:

* over IPv4/UDP
* with local SNMPv2c community public
* local Agent listening at 127.0.0.1:161
* remote SNMPv1, community public
* remote Agent listening at 104.236.166.95:161

This script can be queried with the following Net-SNMP command:

| $ snmpbulkwalk -v2c -c public -ObentU 127.0.0.1:161 system

due to proxy, it is equivalent to

| $ snmpwalk -v1 -c public 104.236.166.95:161 system

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
# SNMPv2c setup (Agent role)
#

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public')

#
# SNMPv1 setup (Manager role)
#

# SecurityName <-> CommunityName <-> Transport mapping
config.addV1System(snmpEngine, 'distant-area', 'public', transportTag='distant')

#
# Transport target used by Manager
#

# Specify security settings per SecurityName (SNMPv1 - 0, SNMPv2c - 1)
config.addTargetParams(snmpEngine, 'distant-agent-auth', 'distant-area',
                       'noAuthNoPriv', 0)

config.addTargetAddr(
    snmpEngine, 'distant-agent',
    udp.domainName + (2,), ('104.236.166.95', 161),
    'distant-agent-auth', retryCount=0, tagList='distant'
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
                snmpEngine, stateReference, 'error', None, cbCtx
            )

    # SNMP response relay
    # noinspection PyUnusedLocal
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

snmpEngine.transportDispatcher.jobStarted(1)  # this job would never finish

# Run I/O dispatcher which would receive queries and send responses
try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
