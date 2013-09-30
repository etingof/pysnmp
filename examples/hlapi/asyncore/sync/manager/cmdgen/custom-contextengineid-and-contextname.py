#
# Command Generator
#
# Send SNMP SET request using the following options:
#
# * with SNMPv3 with user 'usr-md5-none', MD5 auth and no privacy protocols
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * addressing particular set of Managed Objects at remote SNMP Engine by:
#   * contextEngineId 0x80004fb805636c6f75644dab22cc and
#   * contextName 'a172334d7d97871b72241397f713fa12'
# * setting SNMPv2-MIB::sysName.0 to new value (type taken from MIB)
#
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.setCmd(
    cmdgen.UsmUserData('usr-md5-none', 'authkey1'),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    (cmdgen.MibVariable('SNMPv2-MIB', 'sysORDescr', 1), 'new system name'),
    contextEngineId=rfc1902.OctetString(hexValue='80004fb805636c6f75644dab22cc'),
    contextName='da761cfc8c94d3aceef4f60f049105ba'
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
