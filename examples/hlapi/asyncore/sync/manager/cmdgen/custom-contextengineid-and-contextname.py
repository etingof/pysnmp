#
# Command Generator
#
# Send SNMP SET request using the following options:
#
# * with SNMPv3 with user 'usr-none-none', no auth and no privacy protocols
# * over IPv4/UDP
# * to an Agent at localhost:161
# * addressing particular set of Managed Objects at remote SNMP Engine by:
#   * contextEngineId 0x8000000001020304 and
#   * contextName 'my-context'
# * setting SNMPv2-MIB::sysName.0 to new value (type taken from MIB)
#
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.setCmd(
    cmdgen.UsmUserData('usr-none-none'),
    cmdgen.UdpTransportTarget(('localhost', 161)),
    (cmdgen.MibVariable('SNMPv2-MIB', 'sysName', 0), 'new system name'),
    contextEngineId=rfc1902.OctetString(hexValue='8000000001020304'),
    contextName='my-context'
)

# Check for errors and print out results
if errorIndication:
    print(errorIndication)
else:
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1] or '?'
            )
        )
    else:
        for name, val in varBinds:
            print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
