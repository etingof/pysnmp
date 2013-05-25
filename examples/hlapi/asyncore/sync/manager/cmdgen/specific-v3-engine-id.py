#
# Command Generator
#
# Send SNMP GET request using the following scenario and options:
#
# * try to communicate with a SNMPv3 Engine using:
# ** a non-existing user
# ** over IPv4/UDP
# ** to an Agent at demo.snmplabs.com:161
# * if remote SNMP Engine ID is discovered, send SNMP GET request:
# ** with SNMPv3, user 'usr-md5-none', MD5 authentication, no privacy
#    at discovered securityEngineId
# ** to the same SNMP Engine ID
# ** for an OID in text form
#
from pysnmp.entity import engine
from pysnmp.entity.rfc3413.oneliner import cmdgen

snmpEngine = engine.SnmpEngine()

cmdGen = cmdgen.CommandGenerator(snmpEngine)

transportTarget = cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161))

#
# Discover remote SNMP EngineID
#

authData = cmdgen.UsmUserData('non-existing-user')

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    authData, transportTarget
)

# Check for errors and print out results
if errorIndication == 'unknownUserName':
    snmpV3MessageProcessor = snmpEngine.messageProcessingSubsystems[3]
    securityEngineId, contextEngineId, contextName = snmpV3MessageProcessor.getPeerEngineInfo(*transportTarget.getTransportInfo())
    if securityEngineId:
        print('securityEngineId = %s' % securityEngineId.prettyPrint())
    else:
        print('Peer EngineID not available')
        raise Exception()
else:
    print('Can\'t discover peer EngineID', errorIndication)
    raise Exception()

#
# Query remote SNMP Engine using usmUserTable entry configured for it
#

authData = cmdgen.UsmUserData('usr-md5-none', 'authkey1', 
                               securityEngineId=securityEngineId)

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    authData, transportTarget, '1.3.6.1.2.1.1.1.0'
)

# Check for errors and print out results
if errorIndication:
    print(errorIndication)
else:
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        )
    else:
        for name, val in varBinds:
            print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
