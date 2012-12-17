#
# Command Generator
#
# Send SNMP GET request using the following options:
#
# * with SNMPv3, user 'usr-md5-none', MD5 authentication, no privacy
# * over IPv4/UDP
# * to an Agent at localhost:161
# * for IP-MIB::ipAdEntAddr.127.0.0.1 MIB object
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    cmdgen.UsmUserData('usr-md5-none', 'authkey1'),
    cmdgen.UdpTransportTarget(('localhost', 161)),
    cmdgen.MibVariable('IP-MIB', 'ipAdEntAddr', '127.0.0.1')
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
