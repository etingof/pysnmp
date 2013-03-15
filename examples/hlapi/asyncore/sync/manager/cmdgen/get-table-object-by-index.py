#
# Command Generator
#
# Send SNMP GET request using the following options:
#
# * with SNMPv3, user 'usr-none-none', no authentication, no privacy
# * over IPv4/UDP
# * to an Agent at localhost:161
# * for IP-MIB::ipAdEntAddr.127.0.0.1 MIB object
# * perform response OIDs and values resolution at MIB
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    cmdgen.UsmUserData('usr-none-none'),
    cmdgen.UdpTransportTarget(('localhost', 161)),
    cmdgen.MibVariable('IP-MIB', 'ipAdEntAddr', '127.0.0.1'),
    lookupNames=True, lookupValues=True
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
