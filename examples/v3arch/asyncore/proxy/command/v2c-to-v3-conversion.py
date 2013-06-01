#
# SNMP Command Proxy example
#
# Act as a local SNMPv1/v2c Agent, relay messages to distant SNMPv3 Agent:
#     over IPv4/UDP
#     with local SNMPv2c community 'public'
#     local Agent listening at 127.0.0.1:161
#     remote SNMPv3 user usr-md5-none, MD5 auth and no privacy protocols
#     remote Agent listening at 195.218.195.228:161
#
# This script can be queried with the following Net-SNMP command:
#
# $ snmpget -v2c -c public 127.0.0.1:161 1.3.6.1.2.1.1.1.0
#
# due to proxy, it is equivalent to
#
# $ snmpget -v3 -l authNoPriv -u usr-md5-none -A authkey1 -ObentU 195.218.195.228:161  1.3.6.1.2.1.1.1.0
#
from pysnmp.carrier.asynsock.dgram import udp
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
        cbCtx = snmpEngine, stateReference
        varBinds = v2c.apiPDU.getVarBinds(PDU)
        try:
            if PDU.tagSet == v2c.GetBulkRequestPDU.tagSet:
                self.cmdGenMap[PDU.tagSet].sendReq(
                    snmpEngine, 'distant-agent', 
                    v2c.apiBulkPDU.getNonRepeaters(PDU),
                    v2c.apiBulkPDU.getMaxRepetitions(PDU),
                    varBinds,
                    self.handleResponse, cbCtx
                )
            elif PDU.tagSet in self.cmdGenMap:
                self.cmdGenMap[PDU.tagSet].sendReq(
                    snmpEngine, 'distant-agent', varBinds,
                    self.handleResponse, cbCtx
                )
        except error.PySnmpError:
            self.handleResponse(
                stateReference,  'error', 0, 0, varBinds, cbCtx
            )

    # SNMP response relay
    def handleResponse(self, sendRequestHandle, errorIndication, 
                       errorStatus, errorIndex, varBinds, cbCtx):
        if errorIndication:
            errorStatus = 5
            errorIndex = 0
            varBinds = ()

        snmpEngine, stateReference = cbCtx

        self.sendRsp(
            snmpEngine, stateReference,  errorStatus, errorIndex, varBinds
        )

CommandResponder(snmpEngine, context.SnmpContext(snmpEngine))

snmpEngine.transportDispatcher.jobStarted(1) # this job would never finish

# Run I/O dispatcher which would receive queries and send responses
try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
