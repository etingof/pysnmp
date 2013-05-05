#
# Command Generator
#
# Send SNMP GETNEXT request using the following options:
#
# * with SNMPv1, community 'public'
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for some columns of the IF-MIB::ifEntry table
# * stop when response OIDs leave the scopes of initial OIDs
#
# make sure IF-MIB.py is in search path
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
    cmdgen.CommunityData('public', mpModel=0),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    cmdgen.MibVariable('IF-MIB', 'ifDescr'),
    cmdgen.MibVariable('IF-MIB', 'ifType'),
    cmdgen.MibVariable('IF-MIB', 'ifMtu'),
    cmdgen.MibVariable('IF-MIB', 'ifSpeed'),
    cmdgen.MibVariable('IF-MIB', 'ifPhysAddress')
)

if errorIndication:
    print(errorIndication)
else:
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBindTable[-1][int(errorIndex)-1][0] or '?'
            )
        )
    else:
        for varBindTableRow in varBindTable:
            for name, val in varBindTableRow:
                print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
