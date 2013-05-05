#
# Command Generator
#
# Send SNMP GETNEXT requests using the following options:
#
# * with SNMPv3, user 'usr-md5-none', MD5 authentication, no privacy
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for all OIDs in IF-MIB
# * stop when response OIDs leave the scopes of the table
# * perform response values resolution at MIB
#
# make sure IF-MIB.py is in search path
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
    cmdgen.UsmUserData('usr-md5-none', 'authkey1'),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    cmdgen.MibVariable('IF-MIB', ''),
    lookupValues=True
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
