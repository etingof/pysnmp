#
# Command Generator
#
# Send SNMP GET request using the following options:
#
# * with SNMPv3, user 'usr-sha-aes128', SHA auth, AES128 privacy
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for TCP-MIB::tcpConnLocalAddress."0.0.0.0".22."0.0.0.0".0 MIB object
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    cmdgen.UsmUserData('usr-sha-aes128', 'authkey1', 'privkey1',
                       authProtocol=cmdgen.usmHMACSHAAuthProtocol,
                       privProtocol=cmdgen.usmAesCfb128Protocol ),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    cmdgen.MibVariable('TCP-MIB', 'tcpConnLocalAddress', '0.0.0.0', 22, '0.0.0.0', 0)
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
