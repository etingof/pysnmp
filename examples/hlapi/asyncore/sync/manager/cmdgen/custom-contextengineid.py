#
# Command Generator
#
# Send SNMP GET request using the following options:
#
# * with SNMPv3 with user 'usr-md5-des', MD5 auth and DES privacy protocols
# * use remote SNMP Engine ID 0x80004fb805636c6f75644dab22cc (USM
#   autodiscovery will run)
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * setting SNMPv2-MIB::sysName.0 to new value (type taken from MIB)
#
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.setCmd(
    cmdgen.UsmUserData(
        'usr-md5-des', 'authkey1', 'privkey1',
        securityEngineId=rfc1902.OctetString(
            hexValue='80004fb805636c6f75644dab22cc'
        )
    ),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    (cmdgen.MibVariable('SNMPv2-MIB', 'sysORDescr', 1), 'new system name'),
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
